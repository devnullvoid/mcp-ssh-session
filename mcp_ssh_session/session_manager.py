"""SSH session manager using Paramiko."""
import logging
import os
import re
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import paramiko

from .command_executor import CommandExecutor
from .datastructures import CommandStatus
from .file_manager import FileManager
from .validation import CommandValidator, OutputLimiter


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
        self._active_commands: Dict[str, Any] = {}
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

        self.command_executor = CommandExecutor(self)
        self.file_manager = FileManager(self)


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
                           timeout: int = ENABLE_MODE_TIMEOUT) -> tuple[bool, str]:
        """Enter enable mode on a network device."""
        logger = self.logger.getChild('enable_mode')
        logger.info(f"Starting enable mode workflow for {session_key}")

        shell = None
        try:
            shell = client.invoke_shell()
            time.sleep(1)

            shell.send("terminal length 0\n")
            time.sleep(0.5)

            output = ""
            if shell.recv_ready():
                output = shell.recv(4096).decode('utf-8', errors='ignore')
                logger.debug(f"Initial enable output: {output!r}")

            shell.send(f"{enable_command}\n")
            time.sleep(0.5)

            start_time = time.time()
            password_sent = False
            while time.time() - start_time < timeout:
                if shell.recv_ready():
                    chunk = shell.recv(4096).decode('utf-8', errors='ignore')
                    output += chunk
                    logger.debug(f"Enable chunk: {chunk!r}")

                    if '#' in output:
                        logger.debug("Already in enable mode")
                        self._enable_mode[session_key] = True
                        return True, (shell, output.strip())

                    if re.search(r'[Pp]assword:|password.*:', output):
                        shell.send(f"{enable_password}\n")
                        time.sleep(0.5)
                        password_sent = True
                        break
                time.sleep(0.1)

            if not password_sent:
                error_msg = f"Timeout waiting for enable password prompt. Output: {output}"
                logger.error(error_msg)
                shell.close()
                return False, error_msg

            output = ""
            start_time = time.time()
            while time.time() - start_time < timeout:
                if shell.recv_ready():
                    chunk = shell.recv(4096).decode('utf-8', errors='ignore')
                    output += chunk
                    if '#' in output:
                        self._enable_mode[session_key] = True
                        return True, (shell, output.strip())
                time.sleep(0.1)

            error_msg = f"Timeout waiting for enable prompt. Output: {output}"
            logger.error(error_msg)
            shell.close()
            return False, error_msg

        except Exception as exc:
            error_msg = f"Failed to enter enable mode: {exc}"
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

        # Shutdown the executor managed by CommandExecutor
        logger.info("Shutting down command executor pool.")
        try:
            self.command_executor.shutdown()
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





    def _get_or_create_shell(self, session_key: str, client: paramiko.SSHClient) -> Any:
        """Get or create (or recreate) a persistent shell for a session."""
        logger = self.logger.getChild('shell')

        if session_key in self._session_shells:
            shell = self._session_shells[session_key]
            try:
                transport = shell.get_transport() if hasattr(shell, 'get_transport') else None
                if shell.closed or not transport or not transport.is_active():
                    logger.warning(f"[SHELL_DEAD] Shell for {session_key} is dead. Recreating.")
                    del self._session_shells[session_key]
                else:
                    logger.debug(f"[SHELL_REUSE] Reusing existing shell for {session_key}")
                    return shell
            except Exception as exc:
                logger.warning(f"[SHELL_ERROR] Error checking shell for {session_key}: {exc}. Recreating.")
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

    def _execute_with_thread_timeout(self, func, timeout: int, *args, **kwargs) -> Tuple[str, str, int]:
        """Legacy wrapper retained for compatibility (no additional timeout logic)."""
        try:
            return func(*args, **kwargs)
        except Exception as exc:
            logger = self.logger.getChild('thread_timeout')
            logger.error(f"Error during execution: {exc}", exc_info=True)
            return "", f"Error: {exc}", 1

    def _execute_sudo_command_internal(self, client: paramiko.SSHClient, command: str,
                                       sudo_password: str, timeout: int = 30) -> tuple[str, str, int]:
        """Execute a sudo command, handling password prompts and output limiting."""
        logger = self.logger.getChild('sudo_command')
        shell = None

        try:
            timeout = min(timeout, self.MAX_COMMAND_TIMEOUT)
            if not command.strip().startswith('sudo'):
                command = f"sudo {command}"

            shell = client.invoke_shell()
            shell.settimeout(timeout)
            time.sleep(0.5)

            if shell.recv_ready():
                _ = shell.recv(4096)

            shell.send(command + '\n')
            time.sleep(0.5)

            output_limiter = OutputLimiter()
            output = ""
            password_sent = False
            start_time = time.time()

            while time.time() - start_time < timeout:
                if shell.recv_ready():
                    chunk = shell.recv(4096).decode('utf-8', errors='ignore')
                    limited_chunk, should_continue = output_limiter.add_chunk(chunk)
                    output += limited_chunk

                    if not password_sent and re.search(r'password', chunk, re.IGNORECASE):
                        shell.send(f"{sudo_password}\n")
                        password_sent = True
                        time.sleep(0.3)
                        continue

                    if not should_continue:
                        return output, f"Output truncated at {output_limiter.max_size} bytes", 124

                    if password_sent and ('#' in chunk or '$' in chunk):
                        time.sleep(0.3)
                        break
                else:
                    time.sleep(0.1)
            else:
                return output, f"Command timed out after {timeout} seconds", 124

            return output.strip(), "", 0

        except paramiko.SSHException as exc:
            logger.error(f"SSH error during sudo command: {exc}")
            return "", f"SSH error: {exc}", 1
        except Exception as exc:
            logger.error(f"Error executing sudo command: {exc}", exc_info=True)
            return "", f"Error executing sudo command: {exc}", 1
        finally:
            if shell:
                try:
                    shell.close()
                except Exception:
                    pass

    def _execute_sudo_command(self, client: paramiko.SSHClient, command: str,
                               sudo_password: str, timeout: int = 30) -> tuple[str, str, int]:
        """Compatibility wrapper around the sudo execution helper."""
        return self._execute_with_thread_timeout(
            self._execute_sudo_command_internal,
            timeout,
            client, command, sudo_password, timeout
        )

    def _execute_standard_command_internal(self, client: paramiko.SSHClient, command: str,
                                           timeout: int, session_key: str) -> tuple[str, str, int]:
        """Execute a standard SSH command using the persistent session shell."""
        logger = self.logger.getChild('standard_command')
        shell = None
        try:
            shell = self._get_or_create_shell(session_key, client)
            shell.settimeout(timeout)

            with self._lock:
                self._active_commands[session_key] = shell

            shell.send(command + '\n')
            time.sleep(0.3)

            output_limiter = OutputLimiter()
            output = ""
            start_time = time.time()
            last_recv_time = start_time
            idle_timeout = 2.0

            while time.time() - start_time < timeout:
                if shell.recv_ready():
                    chunk = shell.recv(4096).decode('utf-8', errors='ignore')
                    limited_chunk, should_continue = output_limiter.add_chunk(chunk)
                    output += limited_chunk
                    last_recv_time = time.time()

                    if not should_continue:
                        logger.warning("Output size limit exceeded")
                        break

                    lines = output.split('\n')
                    if len(lines) > 1 and lines[-1].strip().endswith(('$', '#', '>', '%')):
                        time.sleep(0.2)
                        if shell.recv_ready():
                            more = shell.recv(4096).decode('utf-8', errors='ignore')
                            limited_more, _ = output_limiter.add_chunk(more)
                            output += limited_more
                        break
                else:
                    if output and (time.time() - last_recv_time) > idle_timeout:
                        break
                    time.sleep(0.1)
            else:
                return output, f"Command timed out after {timeout} seconds", 124

            lines = output.split('\n')
            if len(lines) > 1:
                output = '\n'.join(lines[1:-1]).strip()

            return output, "", 0

        except Exception as exc:
            logger.error(f"Error executing command: {exc}", exc_info=True)
            if session_key in self._session_shells:
                try:
                    self._session_shells[session_key].close()
                except Exception:
                    pass
                del self._session_shells[session_key]
            return "", f"Error: {exc}", 1
        finally:
            with self._lock:
                self._active_commands.pop(session_key, None)

    def _execute_enable_mode_command_internal(self, client: paramiko.SSHClient, session_key: str,
                                              command: str, enable_password: str,
                                              enable_command: str, timeout: int) -> tuple[str, str, int]:
        """Execute a command while the session is in enable mode."""
        logger = self.logger.getChild('enable_mode_command')

        shell = None
        if not self._enable_mode.get(session_key, False):
            success, result = self._enter_enable_mode(session_key, client, enable_password, enable_command)
            if not success:
                return "", f"Failed to enter enable mode: {result}", 1
            shell, _ = result
        else:
            shell = client.invoke_shell()
            time.sleep(0.5)
            if shell.recv_ready():
                shell.recv(4096)

        try:
            shell.settimeout(timeout)
            shell.send(f"{command}\n")
            time.sleep(0.5)

            output_limiter = OutputLimiter()
            output = ""
            start_time = time.time()

            while time.time() - start_time < timeout:
                if shell.recv_ready():
                    chunk = shell.recv(4096).decode('utf-8', errors='ignore')
                    limited_chunk, should_continue = output_limiter.add_chunk(chunk)
                    output += limited_chunk

                    if not should_continue:
                        break

                    if output.strip().endswith(('#', '>')):
                        time.sleep(0.5)
                        if shell.recv_ready():
                            more_chunk = shell.recv(4096).decode('utf-8', errors='ignore')
                            limited_more, _ = output_limiter.add_chunk(more_chunk)
                            output += limited_more
                        break
                else:
                    time.sleep(0.1)
            else:
                return output, f"Command timed out after {timeout} seconds", 124

            lines = output.split('\n')
            if len(lines) > 1:
                cleaned_lines = []
                for line in lines[1:]:
                    stripped = line.strip()
                    if stripped and not stripped.endswith(('#', '>')):
                        cleaned_lines.append(stripped)
                output = '\n'.join(cleaned_lines).strip()

            return output, "", 0

        except Exception as exc:
            logger.error(f"Enable mode command error: {exc}", exc_info=True)
            return "", f"Error executing enable mode command: {exc}", 1
        finally:
            try:
                if shell:
                    shell.close()
            except Exception:
                pass

    def send_input_by_session(self, host: str, input_text: str, username: Optional[str] = None,
                              port: Optional[int] = None) -> tuple[bool, str, str]:
        """Send input to the active shell for a session."""
        logger = self.logger.getChild('send_input_session')
        _, _, _, _, session_key = self._resolve_connection(host, username, port)
        logger.info(f"Sending input to session: {session_key}")

        with self._lock:
            shell = self._session_shells.get(session_key)

        if not shell:
            logger.error(f"No active shell for session: {session_key}")
            return False, "", "No active shell for this session"

        try:
            logger.debug(f"Sending text to shell: {input_text!r}")
            shell.send(input_text)
            time.sleep(0.2)

            output = ""
            if getattr(shell, 'recv_ready', lambda: False)():
                output = shell.recv(65535).decode('utf-8', errors='replace')
                logger.debug(f"Received {len(output)} bytes of new output.")

            return True, output, ""
        except Exception as exc:
            logger.error(f"Failed to send input to session {session_key}: {exc}", exc_info=True)
            return False, "", f"Failed to send input: {exc}"


    def read_file(self, host: str, remote_path: str, username: Optional[str] = None,
                  password: Optional[str] = None, key_filename: Optional[str] = None,
                  port: Optional[int] = None, encoding: str = "utf-8",
                  errors: str = "replace", max_bytes: Optional[int] = None,
                  sudo_password: Optional[str] = None, use_sudo: bool = False) -> tuple[str, str, int]:
        """Delegate remote file reads to the FileManager helper."""
        return self.file_manager.read_file(
            host=host,
            remote_path=remote_path,
            username=username,
            password=password,
            key_filename=key_filename,
            port=port,
            encoding=encoding,
            errors=errors,
            max_bytes=max_bytes,
            sudo_password=sudo_password,
            use_sudo=use_sudo,
        )

    def write_file(self, host: str, remote_path: str, content: str,
                   username: Optional[str] = None, password: Optional[str] = None,
                   key_filename: Optional[str] = None, port: Optional[int] = None,
                   encoding: str = "utf-8", errors: str = "strict",
                   append: bool = False, make_dirs: bool = False,
                   permissions: Optional[int] = None,
                   max_bytes: Optional[int] = None,
                   sudo_password: Optional[str] = None, use_sudo: bool = False) -> tuple[str, str, int]:
        """Delegate remote file writes to the FileManager helper."""
        return self.file_manager.write_file(
            host=host,
            remote_path=remote_path,
            content=content,
            username=username,
            password=password,
            key_filename=key_filename,
            port=port,
            encoding=encoding,
            errors=errors,
            append=append,
            make_dirs=make_dirs,
            permissions=permissions,
            max_bytes=max_bytes,
            sudo_password=sudo_password,
            use_sudo=use_sudo,
        )


    def execute_command(self, host: str, username: Optional[str] = None,
                       command: str = "", password: Optional[str] = None,
                       key_filename: Optional[str] = None,
                       port: Optional[int] = None,
                       enable_password: Optional[str] = None,
                       enable_command: str = "enable",
                       sudo_password: Optional[str] = None,
                       timeout: int = 30) -> tuple[str, str, int]:
        """Execute a command on a host using persistent session."""
        return self.command_executor.execute_command(
            host, username, command, password, key_filename, port,
            enable_password, enable_command, sudo_password, timeout
        )

    def execute_command_async(self, host: str, username: Optional[str] = None,
                             command: str = "", password: Optional[str] = None,
                             key_filename: Optional[str] = None,
                             port: Optional[int] = None,
                             sudo_password: Optional[str] = None,
                             enable_password: Optional[str] = None,
                             enable_command: str = "enable",
                             timeout: int = 300) -> str:
        """Execute a command asynchronously without blocking."""
        return self.command_executor.execute_command_async(
            host, username, command, password, key_filename, port,
            sudo_password, enable_password, enable_command, timeout
        )

    def get_command_status(self, command_id: str) -> dict:
        """Get the status and output of an async command."""
        return self.command_executor.get_command_status(command_id)

    def interrupt_command_by_id(self, command_id: str) -> tuple[bool, str]:
        """Interrupt a running async command by its ID."""
        return self.command_executor.interrupt_command_by_id(command_id)

    def send_input(self, command_id: str, input_text: str) -> tuple[bool, str, str]:
        """Send input to a running command and return any new output."""
        return self.command_executor.send_input(command_id, input_text)

    def list_running_commands(self) -> list[dict]:
        """List all running async commands."""
        return self.command_executor.list_running_commands()

    def list_command_history(self, limit: int = 50) -> list[dict]:
        """List recent command history (completed, failed, interrupted)."""
        return self.command_executor.list_command_history(limit)



    def _cleanup_old_commands(self):
        """Remove old completed commands, keeping only recent ones."""
        logger = self.logger.getChild('cleanup')
        executor = self.command_executor
        with executor._lock:
            completed = [
                (cmd_id, cmd) for cmd_id, cmd in executor._commands.items()
                if cmd.status in (CommandStatus.COMPLETED, CommandStatus.FAILED, CommandStatus.INTERRUPTED)
            ]
            if len(completed) > self._max_completed_commands:
                logger.info(
                    f"Found {len(completed)} completed commands, exceeding limit of {self._max_completed_commands}. Cleaning up."
                )
                completed.sort(key=lambda x: x[1].end_time or datetime.min)
                to_remove = completed[:-self._max_completed_commands]
                for cmd_id, _ in to_remove:
                    del executor._commands[cmd_id]
            else:
                logger.debug(
                    f"Cleanup check: {len(completed)} completed commands within limit of {self._max_completed_commands}."
                )
