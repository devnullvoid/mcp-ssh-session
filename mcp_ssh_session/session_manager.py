"""SSH session manager using Paramiko."""
import paramiko
from typing import Dict, Optional
import threading
import os
from pathlib import Path
import time
import re


import logging
from pathlib import Path

class SSHSessionManager:
    """Manages persistent SSH sessions."""

    def __init__(self):
        self._sessions: Dict[str, paramiko.SSHClient] = {}
        self._enable_mode: Dict[str, bool] = {}  # Track which sessions are in enable mode
        self._lock = threading.Lock()
        self._ssh_config = self._load_ssh_config()

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
        host_config = self._ssh_config.lookup(host)

        # Resolve connection parameters with config precedence
        resolved_host = host_config.get('hostname', host)
        resolved_username = username or host_config.get('user', os.getenv('USER', 'root'))
        resolved_port = port or int(host_config.get('port', 22))
        resolved_key = key_filename or host_config.get('identityfile', [None])[0]

        session_key = f"{resolved_username}@{resolved_host}:{resolved_port}"

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
        # Get SSH config for this host
        host_config = self._ssh_config.lookup(host)

        # Resolve connection parameters with config precedence
        resolved_host = host_config.get('hostname', host)
        resolved_username = username or host_config.get('user', os.getenv('USER', 'root'))
        resolved_port = port or int(host_config.get('port', 22))

        session_key = f"{resolved_username}@{resolved_host}:{resolved_port}"
        with self._lock:
            self._close_session(session_key)

    def _close_session(self, session_key: str):
        """Internal method to close a session (not thread-safe)."""
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
        """Close all sessions."""
        with self._lock:
            for client in self._sessions.values():
                try:
                    client.close()
                except:
                    pass
            self._sessions.clear()

    def list_sessions(self) -> list[str]:
        """List all active session keys."""
        with self._lock:
            return list(self._sessions.keys())

    def _execute_sudo_command(self, client: paramiko.SSHClient, command: str,
                             sudo_password: str, timeout: int = 30) -> tuple[str, str, int]:
        """Execute a command with sudo, handling password prompt.

        Args:
            client: SSH client connection
            command: Command to execute
            sudo_password: Password for sudo
            timeout: Timeout in seconds for command execution

        Returns:
            Tuple of (stdout: str, stderr: str, exit_status: int)
        """
        try:
            # Ensure command starts with sudo
            if not command.strip().startswith('sudo'):
                command = f"sudo {command}"

            shell = client.invoke_shell()
            time.sleep(0.5)

            # Clear any initial output
            if shell.recv_ready():
                shell.recv(4096).decode('utf-8', errors='ignore')

            # Send command
            shell.send(command + '\n')
            time.sleep(0.5)

            # Wait for password prompt or command output
            output = ""
            password_sent = False
            start_time = time.time()

            while time.time() - start_time < timeout:
                if shell.recv_ready():
                    chunk = shell.recv(4096).decode('utf-8', errors='ignore')
                    output += chunk

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
                            output += shell.recv(4096).decode('utf-8', errors='ignore')
                        break
                else:
                    time.sleep(0.1)

            shell.close()

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

        except Exception as e:
            return "", f"Error executing sudo command: {str(e)}", 1

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
        logger.debug(f"Executing command on {host}: {command}")
        # Get SSH config for this host
        host_config = self._ssh_config.lookup(host)
        resolved_host = host_config.get('hostname', host)
        resolved_username = username or host_config.get('user', os.getenv('USER', 'root'))
        resolved_port = port or int(host_config.get('port', 22))
        session_key = f"{resolved_username}@{resolved_host}:{resolved_port}"

        client = self.get_or_create_session(host, username, password, key_filename, port)

        # Handle sudo commands for Unix/Linux hosts
        if sudo_password:
            return self._execute_sudo_command(client, command, sudo_password, timeout)

        # Handle enable mode for network devices
        if enable_password:
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
                # If we're in enable mode, we need to be in config terminal
                if self._enable_mode.get(session_key, False):
                    # For EdgeSwitch, we need to enter config terminal first for some commands
                    if any(cmd in command.lower() for cmd in ['show run', 'show config', 'show interface', 'show vlan']):
                        # Send command with proper newline handling
                        logger.debug(f"[EXEC_CMD] Sending command in enable mode: {command}")
                        shell.send(f"{command}\n")
                        time.sleep(0.5)

                        # Read output until we get the prompt back
                        output = ""
                        start_time = time.time()
                        while time.time() - start_time < timeout:
                            if shell.recv_ready():
                                chunk = shell.recv(4096).decode('utf-8', errors='ignore')
                                output += chunk
                                logger.debug(f"[EXEC_CMD] Received chunk: {chunk!r}")

                                # Check for prompt (ends with # or >)
                                if output.strip() and (output.strip().endswith('#') or output.strip().endswith('>')):
                                    # Wait a bit more to ensure all output is received
                                    time.sleep(0.5)
                                    if shell.recv_ready():
                                        more_chunk = shell.recv(4096).decode('utf-8', errors='ignore')
                                        output += more_chunk
                                        logger.debug(f"[EXEC_CMD] Received additional chunk: {more_chunk!r}")
                                    break
                            else:
                                time.sleep(0.1)

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
                        # For other commands, use the existing shell
                        logger.debug(f"[EXEC_CMD] Sending command in enable mode: {command}")
                        shell.send(f"{command}\n")
                        time.sleep(0.5)

                        # Read output until we get the prompt back
                        output = ""
                        start_time = time.time()
                        while time.time() - start_time < timeout:
                            if shell.recv_ready():
                                chunk = shell.recv(4096).decode('utf-8', errors='ignore')
                                output += chunk
                                logger.debug(f"[EXEC_CMD] Received chunk: {chunk!r}")

                                # Check for prompt (ends with # or >)
                                if output.strip() and (output.strip().endswith('#') or output.strip().endswith('>')):
                                    # Wait a bit more to ensure all output is received
                                    time.sleep(0.5)
                                    if shell.recv_ready():
                                        more_chunk = shell.recv(4096).decode('utf-8', errors='ignore')
                                        output += more_chunk
                                        logger.debug(f"[EXEC_CMD] Received additional chunk: {more_chunk!r}")
                                    break
                            else:
                                time.sleep(0.1)

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
        else:
            # Standard exec_command for regular SSH hosts
            stdin, stdout, stderr = client.exec_command(command)
            exit_status = stdout.channel.recv_exit_status()

            return (
                stdout.read().decode('utf-8'),
                stderr.read().decode('utf-8'),
                exit_status
            )
