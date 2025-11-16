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
import uuid
from dataclasses import dataclass
from enum import Enum
from datetime import datetime


class CommandValidator:
    """Validates commands for safety before execution."""

    # Maximum output size in bytes (10MB)
    MAX_OUTPUT_SIZE = 10 * 1024 * 1024

    # Patterns that indicate streaming/indefinite commands
    STREAMING_PATTERNS = []

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


class CommandStatus(Enum):
    RUNNING = "running"
    COMPLETED = "completed"
    INTERRUPTED = "interrupted"
    FAILED = "failed"


@dataclass
class RunningCommand:
    command_id: str
    session_key: str
    command: str
    shell: Any
    future: Any
    status: CommandStatus
    stdout: str
    stderr: str
    exit_code: Optional[int]
    start_time: datetime
    end_time: Optional[datetime]


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
        self._active_commands: Dict[str, Any] = {} # Track active command shells
        self._commands: Dict[str, RunningCommand] = {}  # Command history (running + completed)
        self._lock = threading.Lock()
        self._ssh_config = self._load_ssh_config()
        self._command_validator = CommandValidator()
        self._executor = ThreadPoolExecutor(max_workers=self.MAX_WORKERS, thread_name_prefix="ssh_cmd")
        self._active_channels: Dict[str, Any] = {}  # Track active channels for cleanup
        self._max_completed_commands = 100  # Keep last 100 completed commands

        # Setup logging
        log_dir = Path('/tmp/mcp_ssh_session_logs')
        log_dir.mkdir(exist_ok=True, parents=True)
        log_file = log_dir / 'mcp_ssh_session.log'

        # Configure logger - only log to file, not to stdout (which would send MCP notifications)
        self.logger = logging.getLogger('ssh_session')
        self.logger.setLevel(logging.DEBUG)
        self.logger.propagate = False  # Don't propagate to root logger

        # Only add file handler (no StreamHandler to avoid MCP notifications)
        file_handler = logging.FileHandler(str(log_file))
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s - [%(threadName)s] - %(name)s - %(levelname)s - %(message)s'
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
        logger = self.logger.getChild('get_session')
        logger.debug(f"Request for session to {host} for user {username}")

        # Get SSH config for this host
        host_config, resolved_host, resolved_username, resolved_port, session_key = self._resolve_connection(
            host, username, port
        )
        resolved_key = key_filename or host_config.get('identityfile', [None])[0]
        logger.debug(f"Resolved session key: {session_key}")

        with self._lock:
            if session_key in self._sessions:
                client = self._sessions[session_key]
                # Check if connection is still alive
                try:
                    transport = client.get_transport()
                    if transport and transport.is_active():
                        logger.debug(f"Reusing active session: {session_key}")
                        return client
                    else:
                        logger.warning(f"Found dead session, will recreate: {session_key}")
                except Exception as e:
                    logger.warning(f"Error checking session, will recreate: {session_key} - {e}")

                # Connection is dead, remove it
                self._close_session(session_key)

            # Create new session
            logger.info(f"Creating new session: {session_key}")
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            connect_kwargs = {
                'hostname': resolved_host,
                'port': resolved_port,
                'username': resolved_username,
            }
            logger.debug(f"Connection parameters: {connect_kwargs}")

            if password:
                connect_kwargs['password'] = password
                logger.debug("Connecting with password")
            elif resolved_key:
                # Expand ~ in key path
                expanded_key = os.path.expanduser(resolved_key)
                connect_kwargs['key_filename'] = expanded_key
                logger.debug(f"Connecting with key: {expanded_key}")
            else:
                logger.debug("Connecting without password or key (agent or no auth)")

            try:
                client.connect(**connect_kwargs)
                self._sessions[session_key] = client
                logger.info(f"Successfully created new session: {session_key}")
                return client
            except Exception as e:
                logger.error(f"Failed to connect to {session_key}: {e}", exc_info=True)
                raise e

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
                    if re.search(r'[Pp]assword:|password.*:', output) or '#' in output:
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
        logger = self.logger.getChild('close_session')
        _, _, _, _, session_key = self._resolve_connection(host, username, port)
        logger.info(f"Request to close session: {session_key}")
        with self._lock:
            self._close_session(session_key)

    def _close_session(self, session_key: str):
        """Internal method to close a session (not thread-safe)."""
        logger = self.logger.getChild('internal_close')
        logger.debug(f"Closing session resources for {session_key}")

        # Close persistent shell if exists
        if session_key in self._session_shells:
            logger.debug(f"Closing persistent shell for {session_key}")
            try:
                self._session_shells[session_key].close()
            except Exception as e:
                logger.warning(f"Error closing shell for {session_key}: {e}")
            del self._session_shells[session_key]

        if session_key in self._sessions:
            logger.debug(f"Closing SSH client for {session_key}")
            try:
                self._sessions[session_key].close()
            except Exception as e:
                logger.warning(f"Error closing client for {session_key}: {e}")
            del self._sessions[session_key]

        # Clean up enable mode tracking
        if session_key in self._enable_mode:
            logger.debug(f"Cleaning up enable mode tracking for {session_key}")
            del self._enable_mode[session_key]
        
        logger.info(f"Session closed: {session_key}")

    def close_all_sessions(self):
        """Close all sessions and cleanup resources."""
        logger = self.logger.getChild('close_all')
        logger.info("Closing all active sessions and resources.")
        with self._lock:
            # Close all persistent shells
            logger.debug(f"Closing {len(self._session_shells)} persistent shells.")
            for key, shell in self._session_shells.items():
                try:
                    shell.close()
                except Exception as e:
                    logger.warning(f"Error closing shell for {key}: {e}")
            self._session_shells.clear()

            # Close all active channels
            logger.debug(f"Closing {len(self._active_channels)} active channels.")
            for channel_id in list(self._active_channels.keys()):
                try:
                    self._force_close_channel(channel_id)
                except Exception as e:
                    logger.warning(f"Error force-closing channel {channel_id}: {e}")

            # Close all SSH sessions
            logger.debug(f"Closing {len(self._sessions)} SSH clients.")
            for key, client in self._sessions.items():
                try:
                    client.close()
                except Exception as e:
                    logger.warning(f"Error closing client for {key}: {e}")
            self._sessions.clear()
            self._enable_mode.clear()
        
        logger.info("All sessions closed.")

        # Shutdown the executor
        logger.info("Shutting down thread pool executor.")
        try:
            self._executor.shutdown(wait=False, cancel_futures=True)
            logger.debug("Executor shutdown successfully.")
        except Exception as e:
            logger.error(f"Error shutting down executor: {e}", exc_info=True)

    def __del__(self):
        """Cleanup when the session manager is destroyed."""
        logger = self.logger.getChild('destructor')
        logger.info("SSHSessionManager instance being destroyed, ensuring cleanup.")
        try:
            self.close_all_sessions()
        except Exception as e:
            logger.error(f"Error during __del__ cleanup: {e}", exc_info=True)

    def list_sessions(self) -> list[str]:
        """List all active session keys."""
        logger = self.logger.getChild('list_sessions')
        with self._lock:
            sessions = list(self._sessions.keys())
            logger.info(f"Listing {len(sessions)} active sessions.")
            logger.debug(f"Active sessions: {sessions}")
            return sessions

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
        logger = self.logger.getChild('ensure_dirs')
        if not remote_dir or remote_dir in (".", "/"):
            return

        logger.debug(f"Ensuring remote directory exists: {remote_dir}")
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
                    logger.error(f"Remote path exists and is not a directory: {directory}")
                    raise IOError(f"Remote path exists and is not a directory: {directory}")
            except FileNotFoundError:
                logger.info(f"Creating remote directory: {directory}")
                sftp.mkdir(directory)

    def _execute_with_thread_timeout(self, func, timeout: int, *args, **kwargs) -> Tuple[str, str, int]:
        """DEPRECATED - kept for compatibility but not used."""
        logger = self.logger.getChild('thread_timeout')
        logger.debug(f"[DEPRECATED] _execute_with_thread_timeout called")
        try:
            return func(*args, **kwargs)
        except Exception as e:
            logger.error(f"Error: {str(e)}", exc_info=True)
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
            logger.debug(f"Executing sudo command with timeout {timeout}s: {command[:100]}...")

            # Ensure command starts with sudo
            if not command.strip().startswith('sudo'):
                command = f"sudo {command}"
                logger.debug(f"Prepended sudo to command.")

            shell = client.invoke_shell()
            shell.settimeout(timeout)
            time.sleep(0.5)

            # Clear any initial output
            if shell.recv_ready():
                initial_output = shell.recv(4096).decode('utf-8', errors='ignore')
                logger.debug(f"Cleared initial shell output: {initial_output!r}")

            # Send command
            logger.debug("Sending command to shell.")
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
                    logger.debug(f"Received chunk of size {len(chunk)}")

                    # Apply output limiting
                    limited_chunk, should_continue = output_limiter.add_chunk(chunk)
                    output += limited_chunk

                    if not should_continue:
                        logger.warning(f"Output size limit exceeded for sudo command")
                        break

                    # Look for sudo password prompt
                    if not password_sent and re.search(r'\[sudo\].*password|password.*:', output, re.IGNORECASE):
                        logger.info("Sudo password prompt detected. Sending password.")
                        shell.send(sudo_password + '\n')
                        password_sent = True
                        time.sleep(0.3)
                        continue

                    # Check if command completed (got prompt back)
                    lines = output.split('\n')
                    if len(lines) > 1 and lines[-1].strip().endswith(('$', '#', '>')):
                        logger.debug("Command prompt detected, assuming command finished.")
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
            logger.debug(f"Sudo command finished. Output size: {len(output)}")

            # Check for sudo errors
            if 'Sorry, try again' in output or 'incorrect password' in output.lower():
                logger.error("Sudo incorrect password.")
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
        logger = self.logger.getChild('sudo_wrapper')
        logger.debug(f"Executing sudo command via deprecated thread timeout wrapper: {command[:100]}...")
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
        logger.debug(f"Executing in enable mode on {session_key}: {command[:100]}...")

        # Check if we need to enter enable mode
        shell = None
        if not self._enable_mode.get(session_key, False):
            logger.info(f"Not in enable mode, attempting to enter for {session_key}")
            success, result = self._enter_enable_mode(session_key, client, enable_password, enable_command)
            if not success:
                logger.error(f"Failed to enter enable mode for {session_key}: {result}")
                return "", f"Failed to enter enable mode: {result}", 1
            # We got the shell from _enter_enable_mode
            shell, output = result
            logger.info(f"Successfully entered enable mode for {session_key}")
        else:
            # We're already in enable mode, get a new shell
            logger.debug(f"Already in enable mode for {session_key}, getting new shell.")
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
                            logger.debug("Enable mode prompt detected, assuming command finished.")
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
                
                logger.debug(f"Enable mode command finished. Output size: {len(output)}")
                return output, "", 0
            else:
                logger.error("Internal logic error: should be in enable mode but flag is false.")
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
        logger = self.logger.getChild('shell')

        if session_key in self._session_shells:
            shell = self._session_shells[session_key]
            try:
                if shell.closed or not shell.get_transport() or not shell.get_transport().is_active():
                    logger.warning(f"[SHELL_DEAD] Shell for {session_key} is dead. Recreating.")
                    del self._session_shells[session_key]
                else:
                    logger.debug(f"[SHELL_REUSE] Reusing existing shell for {session_key}")
                    return shell
            except Exception as e:
                logger.warning(f"[SHELL_ERROR] Error checking shell for {session_key}: {e}. Recreating.")
                if session_key in self._session_shells:
                    del self._session_shells[session_key]

        logger.info(f"[SHELL_CREATE] Creating new persistent shell for {session_key}")
        shell = client.invoke_shell()
        time.sleep(0.5)
        if shell.recv_ready():
            initial_output = shell.recv(4096).decode('utf-8', errors='ignore')
            logger.debug(f"[SHELL_CREATE] Initial shell output: {initial_output!r}")
        self._session_shells[session_key] = shell
        logger.info(f"[SHELL_READY] New shell for {session_key} is ready.")
        return shell

    def _execute_standard_command_internal(self, client: paramiko.SSHClient, command: str,
                                           timeout: int, session_key: str) -> tuple[str, str, int]:
        """Internal method to execute a standard SSH command using persistent shell."""
        logger = self.logger.getChild('standard_command')
        logger.debug(f"[CMD_START] Executing on {session_key}: {command[:100]}...")
        shell = None
        try:
            shell = self._get_or_create_shell(session_key, client)
            shell.settimeout(timeout)

            with self._lock:
                self._active_commands[session_key] = shell

            logger.debug(f"[CMD_SEND] Sending command to shell.")
            shell.send(command + '\n')
            time.sleep(0.3)
            logger.debug(f"[CMD_READ] Reading output from shell.")

            # Read output with size limiting
            output_limiter = OutputLimiter()
            output = ""
            start_time = time.time()

            last_recv_time = start_time
            idle_timeout = 2.0  # If no data for 2s after receiving some, assume done

            while time.time() - start_time < timeout:
                if shell.recv_ready():
                    chunk = shell.recv(4096).decode('utf-8', errors='ignore')
                    logger.debug(f"[CMD_CHUNK] Received {len(chunk)} bytes")
                    last_recv_time = time.time()
                    limited_chunk, should_continue = output_limiter.add_chunk(chunk)
                    output += limited_chunk

                    if not should_continue:
                        logger.warning(f"[CMD_LIMIT] Output size limit exceeded")
                        break

                    # Check for prompt (command completed)
                    lines = output.split('\n')
                    if len(lines) > 1 and lines[-1].strip().endswith(('$', '#', '>', '%')):
                        logger.debug(f"[CMD_PROMPT] Detected prompt, assuming command finished.")
                        time.sleep(0.2)
                        if shell.recv_ready():
                            more = shell.recv(4096).decode('utf-8', errors='ignore')
                            limited_more, _ = output_limiter.add_chunk(more)
                            output += limited_more
                        break
                else:
                    # No data ready - check if we've been idle too long after receiving data
                    if output and (time.time() - last_recv_time) > idle_timeout:
                        logger.debug(f"[CMD_IDLE] No data for {idle_timeout}s, assuming complete")
                        break
                    time.sleep(0.1)
            else:
                logger.warning(f"[CMD_TIMEOUT] Timed out after {timeout}s")
                return output, f"Command timed out after {timeout} seconds", 124

            # Clean output - remove command echo and prompt
            lines = output.split('\n')
            if len(lines) > 1:
                cleaned = []
                for line in lines[1:-1]:  # Skip first (echo) and last (prompt)
                    cleaned.append(line)
                output = '\n'.join(cleaned).strip()

            logger.debug(f"[CMD_SUCCESS] Command finished. Output size: {len(output)} bytes")
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
        finally:
            with self._lock:
                if session_key in self._active_commands:
                    del self._active_commands[session_key]


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
            logger.error("Remote path must be provided.")
            return "", "Remote path must be provided", 1

        _, _, _, _, session_key = self._resolve_connection(host, username, port)
        client = self.get_or_create_session(host, username, password, key_filename, port)

        byte_limit = self.MAX_FILE_TRANSFER_SIZE
        if max_bytes is not None:
            byte_limit = min(max_bytes, self.MAX_FILE_TRANSFER_SIZE)
        logger.debug(f"Byte limit set to {byte_limit}")

        used_encoding = encoding or "utf-8"
        used_errors = errors or "replace"

        # Try SFTP first
        sftp = None
        permission_denied = False
        try:
            logger.debug("Attempting to read file via SFTP.")
            sftp = client.open_sftp()
            attrs = sftp.stat(remote_path)
            if stat.S_ISDIR(attrs.st_mode):
                logger.error(f"Remote path is a directory: {remote_path}")
                return "", f"Remote path is a directory: {remote_path}", 1

            with sftp.file(remote_path, "rb") as remote_file:
                data = remote_file.read(byte_limit + 1)
            logger.debug(f"Read {len(data)} bytes via SFTP.")

            truncated = len(data) > byte_limit
            if truncated:
                data = data[:byte_limit]
                logger.warning(f"File content truncated to {byte_limit} bytes.")

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

            logger.info(f"Successfully read file {remote_path} via SFTP.")
            return content, stderr_msg, 0
        except FileNotFoundError:
            logger.error(f"Remote file not found: {remote_path}")
            return "", f"Remote file not found: {remote_path}", 1
        except PermissionError:
            logger.warning(f"SFTP permission denied for {remote_path}.")
            permission_denied = True
        except Exception as e:
            if 'permission denied' in str(e).lower():
                logger.warning(f"SFTP permission denied for {remote_path}.")
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
            logger.debug(f"Sudo fallback command: {cmd}")

            if sudo_password:
                stdout, stderr, exit_code = self._execute_sudo_command(client, cmd, sudo_password, timeout=30)
            else:
                # Try passwordless sudo
                stdout, stderr, exit_code = self._execute_standard_command_internal(client, cmd, 30, session_key)

            if exit_code != 0:
                logger.error(f"Sudo fallback failed for {remote_path}: {stderr}")
                return "", f"Permission denied and sudo failed: {stderr}", exit_code

            # Check if output was truncated
            truncated = len(stdout.encode('utf-8')) >= byte_limit
            if truncated:
                stdout += f"\n\n[CONTENT TRUNCATED after {byte_limit} bytes]"
                stderr_msg = f"Content truncated to {byte_limit} bytes. Increase max_bytes to retrieve full file."
            else:
                stderr_msg = ""
            
            logger.info(f"Successfully read file {remote_path} via sudo fallback.")
            return stdout, stderr_msg, 0
        elif permission_denied:
            logger.error(f"Permission denied reading {remote_path} and no sudo fallback specified.")
            return "", "Permission denied reading file. Set use_sudo=True or provide sudo_password to retry with sudo.", 1

        logger.error("Unexpected error in read_file logic.")
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
            logger.error("Remote path must be provided.")
            return "", "Remote path must be provided", 1

        used_encoding = encoding or "utf-8"
        used_errors = errors or "strict"

        try:
            data = content.encode(used_encoding, used_errors)
        except Exception as e:
            logger.error(f"Failed to encode content using encoding '{used_encoding}': {e}")
            return "", f"Failed to encode content using encoding '{used_encoding}': {str(e)}", 1

        byte_limit = self.MAX_FILE_TRANSFER_SIZE
        if max_bytes is not None:
            byte_limit = min(max_bytes, self.MAX_FILE_TRANSFER_SIZE)
        logger.debug(f"Byte limit set to {byte_limit}")

        if len(data) > byte_limit:
            logger.error(f"Content size {len(data)} exceeds limit {byte_limit}.")
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
                logger.debug("Attempting to write file via SFTP.")
                sftp = client.open_sftp()

                if make_dirs:
                    directory = posixpath.dirname(remote_path)
                    self._ensure_remote_dirs(sftp, directory)

                mode = "ab" if append else "wb"
                logger.debug(f"Opening remote file in mode '{mode}'.")
                with sftp.file(remote_path, mode) as remote_file:
                    remote_file.write(data)
                    remote_file.flush()

                if permissions is not None:
                    logger.debug(f"Setting permissions to {oct(permissions)}.")
                    sftp.chmod(remote_path, permissions)

                message = f"Wrote {len(data)} bytes to {remote_path}"
                if append:
                    message += " (append)"
                logger.info(f"Successfully wrote file via SFTP: {message}")
                return message, "", 0
            except FileNotFoundError:
                logger.error(f"Remote path not found: {remote_path}")
                return "", f"Remote path not found: {remote_path}", 1
            except PermissionError:
                logger.warning(f"SFTP permission denied for {remote_path}. Will try sudo if configured.")
                return "", "Permission denied writing file. Set use_sudo=True or provide sudo_password to retry with sudo.", 1
            except Exception as e:
                if 'permission denied' in str(e).lower():
                    logger.warning(f"SFTP permission denied for {remote_path}. Will try sudo if configured.")
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
                logger.debug(f"Executing mkdir command: {mkdir_cmd}")
                _, stderr, exit_code = exec_sudo(mkdir_cmd)
                if exit_code != 0:
                    logger.error(f"Failed to create directories with sudo: {stderr}")
                    return "", f"Failed to create directories: {stderr}", exit_code

        # Write content using tee (supports both write and append)
        escaped_content = content.replace('\\', '\\\\').replace('"', '\"').replace('$', r'\$').replace('`', r'\`')

        if append:
            cmd = f'echo -n "{escaped_content}" | sudo tee -a {shlex.quote(remote_path)} > /dev/null'
        else:
            cmd = f'echo -n "{escaped_content}" | sudo tee {shlex.quote(remote_path)} > /dev/null'
        logger.debug(f"Executing write command: {cmd[:100]}...")

        stdout, stderr, exit_code = exec_sudo(cmd)

        if exit_code != 0:
            logger.error(f"Failed to write file with sudo: {stderr}")
            return "", f"Failed to write file with sudo: {stderr}", exit_code

        # Set permissions if specified
        if permissions is not None:
            chmod_cmd = f"sudo chmod {oct(permissions)[2:]} {shlex.quote(remote_path)}"
            logger.debug(f"Executing chmod command: {chmod_cmd}")
            _, stderr, exit_code = exec_sudo(chmod_cmd)
            if exit_code != 0:
                logger.warning(f"Failed to set permissions: {stderr}")

        message = f"Wrote {len(data)} bytes to {remote_path} using sudo"
        if append:
            message += " (append)"
        if not sudo_password:
            message += " (passwordless)"
        logger.info(f"Successfully wrote file via sudo: {message}")
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

        All commands execute async internally. This polls until completion or timeout.

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

        Returns:
            Tuple of (stdout, stderr, exit_code)
            If timeout reached, returns ("", "ASYNC:command_id", 124)
        """
        logger = self.logger.getChild('execute_command')
        logger.info(f"[EXEC_REQ] host={host}, cmd={command[:100]}..., timeout={timeout}")

        # Validate command
        is_valid, error_msg = self._command_validator.validate_command(command)
        if not is_valid:
            logger.warning(f"[EXEC_INVALID] {error_msg}")
            return "", error_msg, 1

        # Start async
        logger.debug(f"[EXEC_ASYNC_START] Starting async execution")
        command_id = self.execute_command_async(
            host, username, command, password, key_filename, port,
            sudo_password, enable_password, enable_command, timeout
        )
        logger.debug(f"[EXEC_ASYNC_ID] command_id={command_id}")

        # Poll until done or timeout
        start = time.time()
        poll_count = 0
        while time.time() - start < timeout:
            status = self.get_command_status(command_id)
            poll_count += 1
            if poll_count % 10 == 0:
                logger.debug(f"[EXEC_POLL] count={poll_count}, status={status.get('status')}")

            if 'error' in status:
                logger.error(f"[EXEC_ERROR] {status['error']}")
                return "", status['error'], 1
            if status['status'] != 'running':
                logger.info(f"[EXEC_DONE] status={status['status']}, polls={poll_count}, duration={time.time() - start:.2f}s")
                return status['stdout'], status['stderr'], status['exit_code'] or 0
            time.sleep(0.1)

        # Timeout - return command ID
        logger.warning(f"[EXEC_TIMEOUT] Returning async command_id after {timeout}s")
        return "", f"ASYNC:{command_id}", 124



    def _execute_command_async_worker(self, command_id: str, client: paramiko.SSHClient,
                                       command: str, timeout: int, session_key: str,
                                       sudo_password: Optional[str] = None,
                                       enable_password: Optional[str] = None,
                                       enable_command: str = "enable"):
        """Execute command in background thread and update running command state."""
        logger = self.logger.getChild('async_worker')
        logger.debug(f"[WORKER_START] command_id={command_id}")

        try:
            with self._lock:
                if command_id not in self._commands:
                    logger.error(f"[WORKER_NOTFOUND] command_id={command_id} no longer in registry.")
                    return
                running_cmd = self._commands[command_id]

            logger.debug(f"[WORKER_EXEC] Executing command for {command_id}")

            if sudo_password:
                logger.debug(f"Executing as sudo for {command_id}")
                stdout, stderr, exit_code = self._execute_sudo_command_internal(
                    client, command, sudo_password, timeout
                )
            elif enable_password:
                logger.debug(f"Executing in enable mode for {command_id}")
                stdout, stderr, exit_code = self._execute_enable_mode_command_internal(
                    client, session_key, command, enable_password, enable_command, timeout
                )
            else:
                logger.debug(f"Executing as standard command for {command_id}")
                stdout, stderr, exit_code = self._execute_standard_command_internal(
                    client, command, timeout, session_key
                )

            logger.debug(f"[WORKER_DONE] command_id={command_id}, exit_code={exit_code}")
            with self._lock:
                if command_id in self._commands:
                    running_cmd.stdout = stdout
                    running_cmd.stderr = stderr
                    running_cmd.exit_code = exit_code
                    running_cmd.status = CommandStatus.COMPLETED
                    running_cmd.end_time = datetime.now()
                    logger.info(f"Command {command_id} completed.")
        except Exception as e:
            logger.error(f"[WORKER_ERROR] command_id={command_id}, error={e}", exc_info=True)
            with self._lock:
                if command_id in self._commands:
                    running_cmd = self._commands[command_id]
                    running_cmd.stderr = str(e)
                    running_cmd.exit_code = 1
                    running_cmd.status = CommandStatus.FAILED
                    running_cmd.end_time = datetime.now()
        finally:
            # Cleanup old commands
            self._cleanup_old_commands()

    def execute_command_async(self, host: str, username: Optional[str] = None,
                             command: str = "", password: Optional[str] = None,
                             key_filename: Optional[str] = None,
                             port: Optional[int] = None,
                             sudo_password: Optional[str] = None,
                             enable_password: Optional[str] = None,
                             enable_command: str = "enable",
                             timeout: int = 300) -> str:
        """Execute a command asynchronously without blocking.

        Returns a command ID that can be used to check status and retrieve output.
        """
        logger = self.logger.getChild('execute_async')
        logger.info(f"[ASYNC_START] host={host}, cmd={command[:100]}...")

        _, resolved_host, resolved_username, resolved_port, session_key = self._resolve_connection(
            host, username, port
        )

        # Check if a command is already running for this session
        with self._lock:
            for cmd in self._commands.values():
                if cmd.session_key == session_key and cmd.status == CommandStatus.RUNNING:
                    error_msg = (
                        f"A command is already running in this session ({session_key}).\n"
                        f"Running Command ID: {cmd.command_id}\n"
                        f"Running Command Status: {cmd.status.value}"
                    )
                    logger.error(error_msg)
                    raise Exception(error_msg)

        client = self.get_or_create_session(host, username, password, key_filename, port)
        shell = self._get_or_create_shell(session_key, client)

        command_id = str(uuid.uuid4())
        logger.debug(f"Generated command_id: {command_id}")

        running_cmd = RunningCommand(
            command_id=command_id,
            session_key=session_key,
            command=command,
            shell=shell,
            future=None,
            status=CommandStatus.RUNNING,
            stdout="",
            stderr="",
            exit_code=None,
            start_time=datetime.now(),
            end_time=None
        )

        with self._lock:
            self._commands[command_id] = running_cmd
            logger.debug(f"Registered running command {command_id}")

        logger.debug(f"[ASYNC_SUBMIT] Submitting command {command_id} to thread pool")
        future = self._executor.submit(
            self._execute_command_async_worker,
            command_id, client, command, timeout, session_key,
            sudo_password, enable_password, enable_command
        )
        running_cmd.future = future
        logger.info(f"[ASYNC_SUBMITTED] command_id={command_id}")

        return command_id

    def get_command_status(self, command_id: str) -> dict:
        """Get the status and output of an async command."""
        logger = self.logger.getChild('get_status')
        logger.debug(f"Fetching status for command_id: {command_id}")
        with self._lock:
            if command_id not in self._commands:
                logger.error(f"Command ID not found: {command_id}")
                return {"error": "Command ID not found"}

            cmd = self._commands[command_id]
            status_payload = {
                "command_id": cmd.command_id,
                "session_key": cmd.session_key,
                "command": cmd.command,
                "status": cmd.status.value,
                "stdout": cmd.stdout,
                "stderr": cmd.stderr,
                "exit_code": cmd.exit_code,
                "start_time": cmd.start_time.isoformat(),
                "end_time": cmd.end_time.isoformat() if cmd.end_time else None
            }
            logger.debug(f"Status for {command_id}: {status_payload['status']}")
            return status_payload

    def interrupt_command_by_id(self, command_id: str) -> tuple[bool, str]:
        """Interrupt a running async command by its ID."""
        logger = self.logger.getChild('interrupt')
        logger.info(f"Attempting to interrupt command_id: {command_id}")
        with self._lock:
            if command_id not in self._commands:
                logger.error(f"Command ID not found for interrupt: {command_id}")
                return False, f"Command ID {command_id} not found"

            cmd = self._commands[command_id]
            if cmd.status != CommandStatus.RUNNING:
                logger.warning(f"Command {command_id} is not running (status: {cmd.status.value})")
                return False, f"Command {command_id} is not running (status: {cmd.status.value})"

            try:
                logger.debug(f"Sending Ctrl+C to shell for command {command_id}")
                cmd.shell.send('\x03')  # Send Ctrl+C
                cmd.status = CommandStatus.INTERRUPTED
                cmd.end_time = datetime.now()
                logger.info(f"Successfully sent interrupt signal to command {command_id}")
                return True, f"Sent interrupt signal to command {command_id}"
            except Exception as e:
                logger.error(f"Failed to interrupt command {command_id}: {e}", exc_info=True)
                return False, f"Failed to interrupt command {command_id}: {e}"

    def send_input(self, command_id: str, input_text: str) -> tuple[bool, str, str]:
        """Send input to a running command and return any new output.

        Args:
            command_id: The command ID to send input to
            input_text: Text to send (e.g., 'q' to quit pager, 'y' for yes/no prompts)

        Returns:
            Tuple of (success: bool, output: str, error: str)
        """
        logger = self.logger.getChild('send_input')
        logger.info(f"Sending input to command_id: {command_id}")
        with self._lock:
            if command_id not in self._commands:
                logger.error(f"Command ID not found: {command_id}")
                return False, "", "Command ID not found"

            cmd = self._commands[command_id]
            if cmd.status != CommandStatus.RUNNING:
                logger.warning(f"Command is not running (status: {cmd.status.value})")
                return False, "", f"Command is not running (status: {cmd.status.value})"

            try:
                logger.debug(f"Sending text to shell: {input_text!r}")
                cmd.shell.send(input_text)
                time.sleep(0.2)

                # Read any new output
                output = ""
                if cmd.shell.recv_ready():
                    output = cmd.shell.recv(65535).decode('utf-8', errors='replace')
                    cmd.stdout += output
                    logger.debug(f"Received {len(output)} bytes of new output.")

                return True, output, ""
            except Exception as e:
                logger.error(f"Failed to send input: {e}", exc_info=True)
                return False, "", f"Failed to send input: {e}"

    def send_input_by_session(self, host: str, input_text: str, username: Optional[str] = None,
                                port: Optional[int] = None) -> tuple[bool, str, str]:
        """Send input to the active shell for a session.

        Args:
            host: Hostname or SSH config alias
            input_text: Text to send (e.g., 'q\n' to quit pager)
            username: SSH username (optional)
            port: SSH port (optional)

        Returns:
            Tuple of (success: bool, output: str, error: str)
        """
        logger = self.logger.getChild('send_input_session')
        _, _, _, _, session_key = self._resolve_connection(host, username, port)
        logger.info(f"Sending input to session: {session_key}")

        with self._lock:
            if session_key not in self._session_shells:
                logger.error(f"No active shell for session: {session_key}")
                return False, "", "No active shell for this session"

            shell = self._session_shells[session_key]
            try:
                logger.debug(f"Sending text to shell: {input_text!r}")
                shell.send(input_text)
                time.sleep(0.2)

                output = ""
                if shell.recv_ready():
                    output = shell.recv(65535).decode('utf-8', errors='replace')
                    logger.debug(f"Received {len(output)} bytes of new output.")

                return True, output, ""
            except Exception as e:
                logger.error(f"Failed to send input to session {session_key}: {e}", exc_info=True)
                return False, "", f"Failed to send input: {e}"

    def list_running_commands(self) -> list[dict]:
        """List all running async commands."""
        logger = self.logger.getChild('list_running')
        with self._lock:
            running_list = [
                {
                    "command_id": cmd.command_id,
                    "session_key": cmd.session_key,
                    "command": cmd.command,
                    "status": cmd.status.value,
                    "start_time": cmd.start_time.isoformat()
                }
                for cmd in self._commands.values()
                if cmd.status == CommandStatus.RUNNING
            ]
            logger.info(f"Found {len(running_list)} running commands.")
            return running_list

    def list_command_history(self, limit: int = 50) -> list[dict]:
        """List recent command history (completed, failed, interrupted)."""
        logger = self.logger.getChild('list_history')
        with self._lock:
            completed = [
                {
                    "command_id": cmd.command_id,
                    "session_key": cmd.session_key,
                    "command": cmd.command,
                    "status": cmd.status.value,
                    "exit_code": cmd.exit_code,
                    "start_time": cmd.start_time.isoformat(),
                    "end_time": cmd.end_time.isoformat() if cmd.end_time else None
                }
                for cmd in self._commands.values()
                if cmd.status != CommandStatus.RUNNING
            ]
            # Sort by end time, most recent first
            completed.sort(key=lambda x: x['end_time'] or '', reverse=True)
            result = completed[:limit]
            logger.info(f"Returning {len(result)} commands from history (limit: {limit}).")
            return result

    def _cleanup_old_commands(self):
        """Remove old completed commands, keeping only recent ones."""
        logger = self.logger.getChild('cleanup')
        with self._lock:
            completed = [
                (cmd_id, cmd) for cmd_id, cmd in self._commands.items()
                if cmd.status in [CommandStatus.COMPLETED, CommandStatus.FAILED, CommandStatus.INTERRUPTED]
            ]
            if len(completed) > self._max_completed_commands:
                logger.info(f"Found {len(completed)} completed commands, exceeding limit of {self._max_completed_commands}. Cleaning up.")
                # Sort by end time, remove oldest
                completed.sort(key=lambda x: x[1].end_time or datetime.min)
                to_remove = completed[:-self._max_completed_commands]
                logger.debug(f"Removing {len(to_remove)} old commands.")
                for cmd_id, _ in to_remove:
                    del self._commands[cmd_id]
            else:
                logger.debug(f"Cleanup check: {len(completed)} completed commands within limit of {self._max_completed_commands}.")