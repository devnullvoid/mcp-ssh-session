"""SSH session manager using Paramiko."""
import paramiko
from typing import Dict, Optional, Tuple, Any
import threading
import os
from pathlib import Path
import time
import re
import logging
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
import signal
import posixpath
import stat
import shlex


class CommandValidator:
    """Validates commands for safety before execution."""

    # Maximum output size in bytes (10MB)
    MAX_OUTPUT_SIZE = 10 * 1024 * 1024

    # Patterns that indicate streaming/indefinite commands
    STREAMING_PATTERNS = [
        r'\btail\s+.*-f\b',
        r'\btail\s+.*--follow\b',
        r'^watch\b',  # watch at start of command
        r'\|\s*watch\b',  # watch in pipeline
        r'^top\b',  # top at start of command
        r'\|\s*top\b',  # top in pipeline
        r'^htop\b',
        r'\|\s*htop\b',
        r'^less\b',  # less at start of command
        r'\|\s*less\b',  # less in pipeline
        r'^more\b',  # more at start of command
        r'\|\s*more\b',  # more in pipeline
        r'^vi\s',  # vi with arguments
        r'^vim\s',  # vim with arguments
        r'^nano\s',  # nano with arguments
        r'^emacs\s',  # emacs with arguments
        r'\b--follow\b',
        r'\b-f\b.*\btail\b',
        r'\bnc\s+.*-l\b',  # netcat listen mode
        r'\bnetcat\s+.*-l\b',
        r'^ssh\s',  # ssh command at start (nested SSH)
        r'\|\s*ssh\s',  # ssh in pipeline
        r'^telnet\s',  # telnet at start
        r'\|\s*telnet\s',  # telnet in pipeline
        r'^tcpdump\b',  # tcpdump at start
        r'\|\s*tcpdump\b',  # tcpdump in pipeline
        r'\bping\s+(?!.*-c\s+\d+)',  # ping without count flag
        r'^monitor\s',  # Network device monitor commands at start
        r'^debug\s',  # Debug commands at start
    ]

    # Patterns for background processes
    BACKGROUND_PATTERNS = [
        r'&\s*$',  # Command ending with &
        r'\bnohup\b',
        r'\bdisown\b',
        r'\bscreen\b',
        r'\btmux\b',
    ]

    # Potentially dangerous commands (optional - can be enabled/disabled)
    DANGEROUS_PATTERNS = [
        r'\brm\s+.*-rf\s+/(?!home|tmp)',  # rm -rf on root paths
        r'\bdd\s+.*of=/dev/',  # dd to device files
        r'\b:\(\)\{.*:\|:.*\};:',  # fork bomb
        r'\bmkfs\b',
        r'\bformat\b',
    ]

    @classmethod
    def validate_command(cls, command: str, check_dangerous: bool = False) -> Tuple[bool, Optional[str]]:
        """
        Validate a command for safety.

        Args:
            command: The command to validate
            check_dangerous: Whether to check for dangerous patterns

        Returns:
            Tuple of (is_valid: bool, error_message: Optional[str])
        """
        command_lower = command.lower().strip()

        # Check for streaming patterns
        for pattern in cls.STREAMING_PATTERNS:
            if re.search(pattern, command, re.IGNORECASE):
                return False, f"Streaming/interactive command blocked: Matches pattern '{pattern}'. Use finite operations (e.g., 'tail -n 100' instead of 'tail -f')."

        # Check for background processes
        for pattern in cls.BACKGROUND_PATTERNS:
            if re.search(pattern, command, re.IGNORECASE):
                return False, f"Background process blocked: Matches pattern '{pattern}'. Background processes are not allowed."

        # Check for dangerous commands (optional)
        if check_dangerous:
            for pattern in cls.DANGEROUS_PATTERNS:
                if re.search(pattern, command, re.IGNORECASE):
                    return False, f"Dangerous command blocked: Matches pattern '{pattern}'. This operation is not allowed for safety."

        return True, None


class OutputLimiter:
    """Limits output size to prevent memory issues."""

    def __init__(self, max_size: int = CommandValidator.MAX_OUTPUT_SIZE):
        self.max_size = max_size
        self.current_size = 0
        self.truncated = False

    def add_chunk(self, chunk: str) -> Tuple[str, bool]:
        """
        Add a chunk of output, enforcing size limits.

        Args:
            chunk: The chunk of output to add

        Returns:
            Tuple of (chunk_to_add: str, should_continue: bool)
        """
        chunk_size = len(chunk.encode('utf-8'))

        if self.current_size + chunk_size > self.max_size:
            # Calculate how much we can still add
            remaining = self.max_size - self.current_size
            if remaining > 0:
                # Truncate the chunk
                truncated_chunk = chunk.encode('utf-8')[:remaining].decode('utf-8', errors='ignore')
                self.current_size = self.max_size
                self.truncated = True
                truncation_msg = f"\n\n[OUTPUT TRUNCATED: Maximum output size of {self.max_size} bytes exceeded]"
                return truncated_chunk + truncation_msg, False
            else:
                return "", False

        self.current_size += chunk_size
        return chunk, True


class SSHSessionManager:
    """Manages persistent SSH sessions with safety protections."""

    # Default timeouts
    DEFAULT_COMMAND_TIMEOUT = 30
    MAX_COMMAND_TIMEOUT = 300  # 5 minutes maximum

    # Enable mode timeout
    ENABLE_MODE_TIMEOUT = 10

    # Thread pool for timeout enforcement
    MAX_WORKERS = 10

    # Maximum bytes allowed for file read/write operations (2MB)
    MAX_FILE_TRANSFER_SIZE = 2 * 1024 * 1024

    def __init__(self):
        self._sessions: Dict[str, paramiko.SSHClient] = {}
        self._enable_mode: Dict[str, bool] = {}  # Track which sessions are in enable mode
        self._session_shells: Dict[str, Any] = {}  # Track persistent shells for stateful sessions
        self._lock = threading.Lock()
        self._ssh_config = self._load_ssh_config()
        self._command_validator = CommandValidator()
        self._executor = ThreadPoolExecutor(max_workers=self.MAX_WORKERS, thread_name_prefix="ssh_cmd")
        self._active_channels: Dict[str, Any] = {}  # Track active channels for cleanup

        # Setup logging
        log_dir = Path('/tmp/mcp_ssh_session_logs')
        log_dir.mkdir(exist_ok=True, parents=True)
        log_file = log_dir / 'mcp_ssh_session.log'

        # Configure logger - only log to file, not to stdout (which would send MCP notifications)
        self.logger = logging.getLogger('ssh_session')
        self.logger.setLevel(logging.INFO)  # Changed to INFO to reduce verbosity
        self.logger.propagate = False  # Don't propagate to root logger

        # Only add file handler (no StreamHandler to avoid MCP notifications)
        file_handler = logging.FileHandler(str(log_file))
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        ))
        self.logger.addHandler(file_handler)
        self.logger.info("SSHSessionManager initialized")

    def _resolve_connection(self, host: str, username: Optional[str], port: Optional[int]) -> tuple[Dict[str, Any], str, str, int, str]:
        """Resolve SSH connection parameters using config precedence."""
        host_config = self._ssh_config.lookup(host)
        resolved_host = host_config.get('hostname', host)
        resolved_username = username or host_config.get('user', os.getenv('USER', 'root'))
        resolved_port = port or int(host_config.get('port', 22))
        session_key = f"{resolved_username}@{resolved_host}:{resolved_port}"
        return host_config, resolved_host, resolved_username, resolved_port, session_key

    def _load_ssh_config(self) -> paramiko.SSHConfig:
        """Load SSH config from default locations."""
        ssh_config = paramiko.SSHConfig()
        config_path = Path.home() / '.ssh' / 'config'

        if config_path.exists():
            with open(config_path) as f:
                ssh_config.parse(f)

        return ssh_config

    def get_or_create_session(self, host: str, username: Optional[str] = None,
                              password: Optional[str] = None,
                              key_filename: Optional[str] = None,
                              port: Optional[int] = None) -> paramiko.SSHClient:
        """Get existing session or create a new one.

        Args:
            host: Hostname or SSH config alias
            username: SSH username (optional, will use config if available)
            password: Password (optional)
            key_filename: Path to SSH key file (optional, will use config if available)
            port: SSH port (optional, will use config if available, default 22)
        """
        # Get SSH config for this host
        host_config, resolved_host, resolved_username, resolved_port, session_key = self._resolve_connection(
            host, username, port
        )
        resolved_key = key_filename or host_config.get('identityfile', [None])[0]

        with self._lock:
            if session_key in self._sessions:
                client = self._sessions[session_key]
                # Check if connection is still alive
                try:
                    transport = client.get_transport()
                    if transport and transport.is_active():
                        return client
                except:
                    pass
                # Connection is dead, remove it
                self._close_session(session_key)

            # Create new session
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            connect_kwargs = {
                'hostname': resolved_host,
                'port': resolved_port,
                'username': resolved_username,
            }

            if password:
                connect_kwargs['password'] = password
            elif resolved_key:
                # Expand ~ in key path
                connect_kwargs['key_filename'] = os.path.expanduser(resolved_key)

            client.connect(**connect_kwargs)
            self._sessions[session_key] = client
            return client

    def _enter_enable_mode(self, session_key: str, client: paramiko.SSHClient,
                          enable_password: str, enable_command: str = "enable",
                          timeout: int = 10) -> tuple[bool, str]:
        """Enter enable mode on a network device.

        Args:
            session_key: Session identifier
            client: SSH client connection
            timeout: Timeout in seconds for prompt responses

        Returns:
            Tuple of (success: bool, output: str)
        """
        logger = self.logger.getChild(f'enable_mode_{id(self)}')
        logger.info("=" * 80)
        logger.info(f"Starting new enable mode session for {session_key}")
        logger.info(f"Enable command: {enable_command}")
        logger.info("=" * 80)

        shell = None
        try:
            logger.debug(f"[ENABLE_MODE] Starting enable mode for session: {session_key}")

            # Get an interactive shell
            logger.debug("[ENABLE_MODE] Opening shell channel...")
            shell = client.invoke_shell()
            time.sleep(1)  # Wait for initial prompt
            logger.debug("[ENABLE_MODE] Shell channel opened")

            # Set terminal length to avoid paging
            logger.debug("[ENABLE_MODE] Setting terminal length to 0...")
            shell.send("terminal length 0\n")
            time.sleep(0.5)

            # Read and log initial output
            output = ""
            if shell.recv_ready():
                output = shell.recv(4096).decode('utf-8', errors='ignore')
                logger.debug(f"[ENABLE_MODE] Initial shell output: {output!r}")

            # Send enable command with a small delay
            logger.debug(f"[ENABLE_MODE] Sending enable command: {enable_command}")
            shell.send(f"{enable_command}\n")
            time.sleep(0.5)

            # Wait for password prompt (case insensitive)
            logger.debug("[ENABLE_MODE] Waiting for password prompt...")
            start_time = time.time()
            password_sent = False
            while time.time() - start_time < timeout:
                if shell.recv_ready():
                    chunk = shell.recv(4096).decode('utf-8', errors='ignore')
                    output += chunk
                    logger.debug(f"[ENABLE_MODE] Received chunk: {chunk!r}")

                    # Check for password prompt or already in enable mode
                    if re.search(r'[Pp]assword:', output) or '#' in output:
                        if '#' in output:
                            logger.debug("[ENABLE_MODE] Already in enable mode")
                            self._enable_mode[session_key] = True
                            return True, "Already in enable mode"

                        logger.debug("[ENABLE_MODE] Password prompt detected, sending password...")
                        shell.send(f"{enable_password}\n")
                        time.sleep(0.5)
                        password_sent = True
                        break
                time.sleep(0.1)

            if not password_sent:
                error_msg = f"[ENABLE_MODE] Timeout waiting for password prompt. Output: {output}"
                logger.error(error_msg)
                return False, error_msg

            # Wait for enable prompt
            logger.debug("[ENABLE_MODE] Waiting for enable prompt...")
            output = ""
            start_time = time.time()
            while time.time() - start_time < timeout:
                if shell.recv_ready():
                    chunk = shell.recv(4096).decode('utf-8', errors='ignore')
                    output += chunk
                    logger.debug(f"[ENABLE_MODE] Received chunk: {chunk!r}")

                    # Check for enable prompt (ends with #)
                    if '#' in output:
                        logger.debug("[ENABLE_MODE] Enable prompt detected")
                        self._enable_mode[session_key] = True
                        # Don't close the shell, return it to the caller
                        return True, (shell, output.strip())
                time.sleep(0.1)

            error_msg = f"[ENABLE_MODE] Timeout waiting for enable prompt. Output: {output}"
            logger.error(error_msg)
            if shell:
                shell.close()
            return False, error_msg

        except Exception as e:
            error_msg = f"[ENABLE_MODE] Error in enable mode: {str(e)}"
            logger.error(error_msg, exc_info=True)
            if shell:
                shell.close()
            return False, error_msg

    def close_session(self, host: str, username: Optional[str] = None, port: Optional[int] = None):
        """Close a specific session.

        Args:
            host: Hostname or SSH config alias
            username: SSH username (optional, will use config if available)
            port: SSH port (optional, will use config if available)
        """
        _, _, _, _, session_key = self._resolve_connection(host, username, port)
        with self._lock:
            self._close_session(session_key)

    def _close_session(self, session_key: str):
        """Internal method to close a session (not thread-safe)."""
        # Close persistent shell if exists
        if session_key in self._session_shells:
            try:
                self._session_shells[session_key].close()
            except:
                pass
            del self._session_shells[session_key]
        
        if session_key in self._sessions:
            try:
                self._sessions[session_key].close()
            except:
                pass
            del self._sessions[session_key]
        # Clean up enable mode tracking
        if session_key in self._enable_mode:
            del self._enable_mode[session_key]

    def close_all(self):
        """Close all sessions and cleanup resources."""
        with self._lock:
            # Close all persistent shells
            for shell in self._session_shells.values():
                try:
                    shell.close()
                except:
                    pass
            self._session_shells.clear()
            
            # Close all active channels
            for channel_id in list(self._active_channels.keys()):
                try:
                    self._force_close_channel(channel_id)
                except:
                    pass

            # Close all SSH sessions
            for client in self._sessions.values():
                try:
                    client.close()
                except:
                    pass
            self._sessions.clear()
            self._enable_mode.clear()

        # Shutdown the executor
        try:
            self._executor.shutdown(wait=False, cancel_futures=True)
        except:
            pass

    def __del__(self):
        """Cleanup when the session manager is destroyed."""
        try:
            self.close_all()
        except:
            pass

    def list_sessions(self) -> list[str]:
        """List all active session keys."""
        with self._lock:
            return list(self._sessions.keys())

    def _force_close_channel(self, channel_id: str):
        """Force close a hung channel."""
        logger = self.logger.getChild('force_close')
        try:
            if channel_id in self._active_channels:
                channel = self._active_channels[channel_id]
                logger.warning(f"Force closing hung channel: {channel_id}")
                try:
                    channel.close()
                except:
                    pass
                del self._active_channels[channel_id]
        except Exception as e:
            logger.error(f"Error force closing channel {channel_id}: {str(e)}")

    def _ensure_remote_dirs(self, sftp: paramiko.SFTPClient, remote_dir: str):
        """Ensure remote directory structure exists when writing files."""
        if not remote_dir or remote_dir in (".", "/"):
            return

        directories = []
        current = remote_dir

        while current and current not in (".", "/"):
            directories.append(current)
            next_dir = posixpath.dirname(current)
            if next_dir == current:
                break
            current = next_dir

        for directory in reversed(directories):
            try:
                attrs = sftp.stat(directory)
                if not stat.S_ISDIR(attrs.st_mode):
                    raise IOError(f"Remote path exists and is not a directory: {directory}")
            except FileNotFoundError:
                sftp.mkdir(directory)

    def _execute_with_thread_timeout(self, func, timeout: int, *args, **kwargs) -> Tuple[str, str, int]:
        """
        Execute a function with a thread-based timeout.

        This provides a hard timeout that will interrupt even blocking I/O operations.

        Args:
            func: The function to execute
            timeout: Timeout in seconds
            *args, **kwargs: Arguments to pass to the function

        Returns:
            Tuple of (stdout: str, stderr: str, exit_status: int)
        """
        logger = self.logger.getChild('thread_timeout')

        try:
            logger.info(f"Executing with timeout: {timeout}s")
            # Execute directly without thread pool to avoid hanging the server
            result = func(*args, **kwargs)
            logger.debug(f"Command completed successfully")
            return result

        except Exception as e:
            logger.error(f"Error executing command: {str(e)}", exc_info=True)
            return "", f"Error: {str(e)}", 1

    def _execute_sudo_command_internal(self, client: paramiko.SSHClient, command: str,
                                      sudo_password: str, timeout: int = 30) -> tuple[str, str, int]:
        """Internal method to execute a command with sudo, handling password prompt.

        Args:
            client: SSH client connection
            command: Command to execute
            sudo_password: Password for sudo
            timeout: Timeout in seconds for command execution

        Returns:
            Tuple of (stdout: str, stderr: str, exit_status: int)
        """
        logger = self.logger.getChild('sudo_command')
        shell = None

        try:
            # Enforce timeout limits
            timeout = min(timeout, self.MAX_COMMAND_TIMEOUT)

            # Ensure command starts with sudo
            if not command.strip().startswith('sudo'):
                command = f"sudo {command}"

            shell = client.invoke_shell()
            shell.settimeout(timeout)
            time.sleep(0.5)

            # Clear any initial output
            if shell.recv_ready():
                shell.recv(4096).decode('utf-8', errors='ignore')

            # Send command
            shell.send(command + '\n')
            time.sleep(0.5)

            # Wait for password prompt or command output with output limiting
            output_limiter = OutputLimiter()
            output = ""
            password_sent = False
            start_time = time.time()

            while time.time() - start_time < timeout:
                if shell.recv_ready():
                    chunk = shell.recv(4096).decode('utf-8', errors='ignore')

                    # Apply output limiting
                    limited_chunk, should_continue = output_limiter.add_chunk(chunk)
                    output += limited_chunk

                    if not should_continue:
                        logger.warning(f"Output size limit exceeded for sudo command")
                        break

                    # Look for sudo password prompt
                    if not password_sent and re.search(r'\[sudo\].*password|password.*:', output, re.IGNORECASE):
                        shell.send(sudo_password + '\n')
                        password_sent = True
                        time.sleep(0.3)
                        continue

                    # Check if command completed (got prompt back)
                    lines = output.split('\n')
                    if len(lines) > 1 and lines[-1].strip().endswith(('$', '#', '>')):
                        # Wait a bit more to ensure all output is received
                        time.sleep(0.3)
                        if shell.recv_ready():
                            more_chunk = shell.recv(4096).decode('utf-8', errors='ignore')
                            limited_more, _ = output_limiter.add_chunk(more_chunk)
                            output += limited_more
                        break
                else:
                    time.sleep(0.1)
            else:
                # Timeout occurred
                logger.warning(f"Sudo command timed out after {timeout} seconds")
                return "", f"Command timed out after {timeout} seconds", 124

            # Clean up the output - remove command echo and prompt
            lines = output.split('\n')
            # Remove first line (command echo), password prompt line if present, and last line (prompt)
            cleaned_lines = []
            for line in lines[1:-1]:  # Skip first and last
                # Skip the sudo password prompt line
                if not re.search(r'\[sudo\].*password|password.*:', line, re.IGNORECASE):
                    cleaned_lines.append(line)

            output = '\n'.join(cleaned_lines).strip()

            # Check for sudo errors
            if 'Sorry, try again' in output or 'incorrect password' in output.lower():
                return "", "sudo: incorrect password", 1

            return output, "", 0

        except paramiko.SSHException as e:
            logger.error(f"SSH error in sudo command: {str(e)}")
            return "", f"SSH error: {str(e)}", 1
        except Exception as e:
            logger.error(f"Error executing sudo command: {str(e)}", exc_info=True)
            return "", f"Error executing sudo command: {str(e)}", 1
        finally:
            if shell:
                try:
                    shell.close()
                except:
                    pass

    def _execute_sudo_command(self, client: paramiko.SSHClient, command: str,
                             sudo_password: str, timeout: int = 30) -> tuple[str, str, int]:
        """Execute a command with sudo, with thread-based timeout protection."""
        return self._execute_with_thread_timeout(
            self._execute_sudo_command_internal,
            timeout,
            client, command, sudo_password, timeout
        )

    def _execute_enable_mode_command_internal(self, client: paramiko.SSHClient, session_key: str,
                                              command: str, enable_password: str,
                                              enable_command: str, timeout: int) -> tuple[str, str, int]:
        """Internal method to execute command in enable mode on network device."""
        logger = self.logger.getChild('enable_mode_command')

        # Check if we need to enter enable mode
        shell = None
        if not self._enable_mode.get(session_key, False):
            success, result = self._enter_enable_mode(session_key, client, enable_password, enable_command)
            if not success:
                return "", f"Failed to enter enable mode: {result}", 1
            # We got the shell from _enter_enable_mode
            shell, output = result
        else:
            # We're already in enable mode, get a new shell
            shell = client.invoke_shell()
            time.sleep(0.5)
            # Read and discard initial output
            output = ""
            if shell.recv_ready():
                output = shell.recv(4096).decode('utf-8', errors='ignore')
                logger.debug(f"[EXEC_CMD] Initial shell output: {output!r}")

        try:
            # Set timeout on the shell
            shell.settimeout(timeout)

            # If we're in enable mode, execute the command
            if self._enable_mode.get(session_key, False):
                logger.debug(f"[EXEC_CMD] Sending command in enable mode: {command}")
                shell.send(f"{command}\n")
                time.sleep(0.5)

                # Read output until we get the prompt back with output limiting
                output_limiter = OutputLimiter()
                output = ""
                start_time = time.time()

                while time.time() - start_time < timeout:
                    if shell.recv_ready():
                        chunk = shell.recv(4096).decode('utf-8', errors='ignore')

                        # Apply output limiting
                        limited_chunk, should_continue = output_limiter.add_chunk(chunk)
                        output += limited_chunk
                        logger.debug(f"[EXEC_CMD] Received chunk ({len(chunk)} bytes)")

                        if not should_continue:
                            logger.warning(f"Output size limit exceeded for command: {command}")
                            break

                        # Check for prompt (ends with # or >)
                        if output.strip() and (output.strip().endswith('#') or output.strip().endswith('>')):
                            # Wait a bit more to ensure all output is received
                            time.sleep(0.5)
                            if shell.recv_ready():
                                more_chunk = shell.recv(4096).decode('utf-8', errors='ignore')
                                limited_more, _ = output_limiter.add_chunk(more_chunk)
                                output += limited_more
                                logger.debug(f"[EXEC_CMD] Received additional chunk ({len(more_chunk)} bytes)")
                            break
                    else:
                        time.sleep(0.1)
                else:
                    # Timeout occurred
                    logger.warning(f"Command timed out after {timeout} seconds: {command}")
                    return output, f"Command timed out after {timeout} seconds", 124

                # Clean up the output - remove command echo and prompt
                lines = output.split('\n')
                if len(lines) > 1:
                    # Remove command echo and final prompt
                    cleaned_lines = []
                    for line in lines[1:]:  # Skip command echo
                        line = line.strip()
                        if not (line.endswith(('#', '>')) or not line):  # Skip prompt and empty lines
                            cleaned_lines.append(line)
                    output = '\n'.join(cleaned_lines).strip()

                return output, "", 0
            else:
                return "", "Not in enable mode", 1

        except Exception as e:
            error_msg = f"Error executing command in enable mode: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return "", error_msg, 1
        finally:
            if shell:
                try:
                    shell.close()
                except Exception as e:
                    logger.error(f"Error closing shell: {str(e)}", exc_info=True)

    def _get_or_create_shell(self, session_key: str, client: paramiko.SSHClient) -> Any:
        """Get or create a persistent shell for stateful command execution."""
        if session_key in self._session_shells:
            shell = self._session_shells[session_key]
            try:
                # Check if shell is still active
                if shell.closed or not shell.get_transport() or not shell.get_transport().is_active():
                    del self._session_shells[session_key]
                else:
                    return shell
            except:
                if session_key in self._session_shells:
                    del self._session_shells[session_key]
        
        # Create new shell
        shell = client.invoke_shell()
        time.sleep(0.5)
        # Clear initial output
        if shell.recv_ready():
            shell.recv(4096)
        self._session_shells[session_key] = shell
        return shell

    def _execute_standard_command_internal(self, client: paramiko.SSHClient, command: str,
                                           timeout: int, session_key: str) -> tuple[str, str, int]:
        """Internal method to execute a standard SSH command using persistent shell."""
        logger = self.logger.getChild('standard_command')

        try:
            shell = self._get_or_create_shell(session_key, client)
            shell.settimeout(timeout)

            # Send command
            shell.send(command + '\n')
            time.sleep(0.3)

            # Read output with size limiting
            output_limiter = OutputLimiter()
            output = ""
            start_time = time.time()

            while time.time() - start_time < timeout:
                if shell.recv_ready():
                    chunk = shell.recv(4096).decode('utf-8', errors='ignore')
                    limited_chunk, should_continue = output_limiter.add_chunk(chunk)
                    output += limited_chunk
                    
                    if not should_continue:
                        logger.warning(f"Output size limit exceeded")
                        break
                    
                    # Check for prompt (command completed)
                    lines = output.split('\n')
                    if len(lines) > 1 and lines[-1].strip().endswith(('$', '#', '>', '%')):
                        time.sleep(0.2)
                        if shell.recv_ready():
                            more = shell.recv(4096).decode('utf-8', errors='ignore')
                            limited_more, _ = output_limiter.add_chunk(more)
                            output += limited_more
                        break
                else:
                    time.sleep(0.1)
            else:
                return output, f"Command timed out after {timeout} seconds", 124

            # Clean output - remove command echo and prompt
            lines = output.split('\n')
            if len(lines) > 1:
                cleaned = []
                for line in lines[1:-1]:  # Skip first (echo) and last (prompt)
                    cleaned.append(line)
                output = '\n'.join(cleaned).strip()

            return output, "", 0

        except Exception as e:
            logger.error(f"Error executing command: {str(e)}", exc_info=True)
            # Clean up broken shell
            if session_key in self._session_shells:
                try:
                    self._session_shells[session_key].close()
                except:
                    pass
                del self._session_shells[session_key]
            return "", f"Error: {str(e)}", 1

    def read_file(self, host: str, remote_path: str, username: Optional[str] = None,
                  password: Optional[str] = None, key_filename: Optional[str] = None,
                  port: Optional[int] = None, encoding: str = "utf-8",
                  errors: str = "replace", max_bytes: Optional[int] = None,
                  sudo_password: Optional[str] = None, use_sudo: bool = False) -> tuple[str, str, int]:
        """Read a remote file over SSH using SFTP, with optional sudo fallback.
        
        Args:
            sudo_password: Password for sudo (optional, not needed if NOPASSWD configured)
            use_sudo: If True, use sudo for reading (tries passwordless first if no sudo_password)
        """
        logger = self.logger.getChild('read_file')
        logger.info(f"Reading remote file on {host}: {remote_path}")

        if not remote_path:
            return "", "Remote path must be provided", 1

        _, _, _, _, session_key = self._resolve_connection(host, username, port)
        client = self.get_or_create_session(host, username, password, key_filename, port)

        byte_limit = self.MAX_FILE_TRANSFER_SIZE
        if max_bytes is not None:
            byte_limit = min(max_bytes, self.MAX_FILE_TRANSFER_SIZE)

        used_encoding = encoding or "utf-8"
        used_errors = errors or "replace"

        # Try SFTP first
        sftp = None
        permission_denied = False
        try:
            sftp = client.open_sftp()
            attrs = sftp.stat(remote_path)
            if stat.S_ISDIR(attrs.st_mode):
                return "", f"Remote path is a directory: {remote_path}", 1

            with sftp.file(remote_path, "rb") as remote_file:
                data = remote_file.read(byte_limit + 1)

            truncated = len(data) > byte_limit
            if truncated:
                data = data[:byte_limit]

            try:
                content = data.decode(used_encoding, used_errors)
            except UnicodeDecodeError as e:
                logger.error(f"Decode error reading file {remote_path} on {session_key}: {str(e)}")
                return "", f"Failed to decode file using encoding '{used_encoding}': {str(e)}", 1

            stderr_msg = ""
            if truncated:
                stderr_msg = (
                    f"Content truncated to {byte_limit} bytes. Increase max_bytes to retrieve full file."
                )
                content += f"\n\n[CONTENT TRUNCATED after {byte_limit} bytes]"

            return content, stderr_msg, 0
        except FileNotFoundError:
            return "", f"Remote file not found: {remote_path}", 1
        except PermissionError:
            permission_denied = True
        except Exception as e:
            if 'permission denied' in str(e).lower():
                permission_denied = True
            else:
                logger.error(f"Error reading file {remote_path} on {session_key}: {str(e)}", exc_info=True)
                return "", f"Error reading remote file: {str(e)}", 1
        finally:
            if sftp:
                try:
                    sftp.close()
                except Exception:
                    pass

        # Fallback to sudo if permission denied and use_sudo or sudo_password provided
        if permission_denied and (use_sudo or sudo_password):
            logger.info(f"SFTP permission denied, falling back to sudo cat for {remote_path}")
            # Use head to limit output size
            cmd = f"sudo cat {shlex.quote(remote_path)} | head -c {byte_limit}"
            
            if sudo_password:
                stdout, stderr, exit_code = self._execute_sudo_command(client, cmd, sudo_password, timeout=30)
            else:
                # Try passwordless sudo
                stdout, stderr, exit_code = self._execute_standard_command_internal(client, cmd, 30, session_key)
            
            if exit_code != 0:
                return "", f"Permission denied and sudo failed: {stderr}", exit_code
            
            # Check if output was truncated
            truncated = len(stdout.encode('utf-8')) >= byte_limit
            if truncated:
                stdout += f"\n\n[CONTENT TRUNCATED after {byte_limit} bytes]"
                stderr_msg = f"Content truncated to {byte_limit} bytes. Increase max_bytes to retrieve full file."
            else:
                stderr_msg = ""
            
            return stdout, stderr_msg, 0
        elif permission_denied:
            return "", "Permission denied reading file. Set use_sudo=True or provide sudo_password to retry with sudo.", 1
        
        return "", "Unexpected error in read_file", 1

    def write_file(self, host: str, remote_path: str, content: str,
                   username: Optional[str] = None, password: Optional[str] = None,
                   key_filename: Optional[str] = None, port: Optional[int] = None,
                   encoding: str = "utf-8", errors: str = "strict",
                   append: bool = False, make_dirs: bool = False,
                   permissions: Optional[int] = None,
                   max_bytes: Optional[int] = None,
                   sudo_password: Optional[str] = None, use_sudo: bool = False) -> tuple[str, str, int]:
        """Write content to a remote file over SSH using SFTP, with optional sudo fallback.
        
        Args:
            sudo_password: Password for sudo (optional, not needed if NOPASSWD configured)
            use_sudo: If True, use sudo for writing (tries passwordless first if no sudo_password)
        """
        logger = self.logger.getChild('write_file')
        logger.info(f"Writing remote file on {host}: {remote_path} (append={append})")

        if not remote_path:
            return "", "Remote path must be provided", 1

        used_encoding = encoding or "utf-8"
        used_errors = errors or "strict"

        try:
            data = content.encode(used_encoding, used_errors)
        except Exception as e:
            return "", f"Failed to encode content using encoding '{used_encoding}': {str(e)}", 1

        byte_limit = self.MAX_FILE_TRANSFER_SIZE
        if max_bytes is not None:
            byte_limit = min(max_bytes, self.MAX_FILE_TRANSFER_SIZE)

        if len(data) > byte_limit:
            return "", (
                f"Content size {len(data)} bytes exceeds maximum allowed {byte_limit} bytes. "
                "Split the write into smaller chunks."
            ), 1

        _, _, _, _, session_key = self._resolve_connection(host, username, port)
        client = self.get_or_create_session(host, username, password, key_filename, port)

        # Try SFTP first if not explicitly using sudo
        if not use_sudo and not sudo_password:
            sftp = None
            try:
                sftp = client.open_sftp()

                if make_dirs:
                    directory = posixpath.dirname(remote_path)
                    self._ensure_remote_dirs(sftp, directory)

                mode = "ab" if append else "wb"
                with sftp.file(remote_path, mode) as remote_file:
                    remote_file.write(data)
                    remote_file.flush()

                if permissions is not None:
                    sftp.chmod(remote_path, permissions)

                message = f"Wrote {len(data)} bytes to {remote_path}"
                if append:
                    message += " (append)"
                return message, "", 0
            except FileNotFoundError:
                return "", f"Remote path not found: {remote_path}", 1
            except PermissionError:
                return "", "Permission denied writing file. Set use_sudo=True or provide sudo_password to retry with sudo.", 1
            except Exception as e:
                if 'permission denied' in str(e).lower():
                    return "", "Permission denied writing file. Set use_sudo=True or provide sudo_password to retry with sudo.", 1
                logger.error(f"Error writing file {remote_path} on {session_key}: {str(e)}", exc_info=True)
                return "", f"Error writing remote file: {str(e)}", 1
            finally:
                if sftp:
                    try:
                        sftp.close()
                    except Exception:
                        pass
        
        # Use sudo shell commands
        logger.info(f"Using sudo to write {remote_path}")
        
        # Helper to execute with or without password
        def exec_sudo(cmd: str) -> tuple[str, str, int]:
            if sudo_password:
                return self._execute_sudo_command(client, cmd, sudo_password, timeout=30)
            else:
                return self._execute_standard_command_internal(client, cmd, 30, session_key)
        
        # Create parent directories if needed
        if make_dirs:
            directory = posixpath.dirname(remote_path)
            if directory and directory != '/':
                mkdir_cmd = f"sudo mkdir -p {shlex.quote(directory)}"
                _, stderr, exit_code = exec_sudo(mkdir_cmd)
                if exit_code != 0:
                    return "", f"Failed to create directories: {stderr}", exit_code
        
        # Write content using tee (supports both write and append)
        escaped_content = content.replace('\\', '\\\\').replace('"', '\\"').replace('$', '\\$').replace('`', '\\`')
        
        if append:
            cmd = f'echo -n "{escaped_content}" | sudo tee -a {shlex.quote(remote_path)} > /dev/null'
        else:
            cmd = f'echo -n "{escaped_content}" | sudo tee {shlex.quote(remote_path)} > /dev/null'
        
        stdout, stderr, exit_code = exec_sudo(cmd)
        
        if exit_code != 0:
            return "", f"Failed to write file with sudo: {stderr}", exit_code
        
        # Set permissions if specified
        if permissions is not None:
            chmod_cmd = f"sudo chmod {oct(permissions)[2:]} {shlex.quote(remote_path)}"
            _, stderr, exit_code = exec_sudo(chmod_cmd)
            if exit_code != 0:
                logger.warning(f"Failed to set permissions: {stderr}")
        
        message = f"Wrote {len(data)} bytes to {remote_path} using sudo"
        if append:
            message += " (append)"
        if not sudo_password:
            message += " (passwordless)"
        return message, "", 0

    def execute_command(self, host: str, username: Optional[str] = None,
                       command: str = "", password: Optional[str] = None,
                       key_filename: Optional[str] = None,
                       port: Optional[int] = None,
                       enable_password: Optional[str] = None,
                       enable_command: str = "enable",
                       sudo_password: Optional[str] = None,
                       timeout: int = 30) -> tuple[str, str, int]:
        """Execute a command on a host using persistent session.

        Args:
            host: Hostname or SSH config alias
            username: SSH username (optional, will use config if available)
            command: Command to execute
            password: Password (optional)
            key_filename: Path to SSH key file (optional, will use config if available)
            port: SSH port (optional, will use config if available)
            enable_password: Password for enable mode on network devices (optional)
            enable_command: Command to enter enable mode (default: "enable")
            sudo_password: Password for sudo commands on Unix/Linux hosts (optional)
            timeout: Timeout in seconds for command execution (default: 30)
        """
        logger = self.logger.getChild('execute_command')
        logger.info(f"Executing command on {host}: {command}")

        # Validate command for safety
        is_valid, error_msg = self._command_validator.validate_command(command)
        if not is_valid:
            logger.warning(f"Command validation failed: {error_msg}")
            return "", error_msg, 1

        # Enforce timeout limits
        timeout = min(timeout, self.MAX_COMMAND_TIMEOUT)
        logger.debug(f"Using timeout: {timeout} seconds")
        # Get SSH config for this host
        _, resolved_host, resolved_username, resolved_port, session_key = self._resolve_connection(
            host, username, port
        )

        client = self.get_or_create_session(host, username, password, key_filename, port)

        # Handle sudo commands for Unix/Linux hosts
        if sudo_password:
            return self._execute_sudo_command(client, command, sudo_password, timeout)

        # Handle enable mode for network devices
        if enable_password:
            return self._execute_with_thread_timeout(
                self._execute_enable_mode_command_internal,
                timeout,
                client, session_key, command, enable_password, enable_command, timeout
            )
        else:
            # Standard exec_command for regular SSH hosts
            return self._execute_with_thread_timeout(
                self._execute_standard_command_internal,
                timeout,
                client, command, timeout, session_key
            )
