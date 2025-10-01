"""SSH session manager using Paramiko."""
import paramiko
from typing import Dict, Optional
import threading
import os
from pathlib import Path


class SSHSessionManager:
    """Manages persistent SSH sessions."""

    def __init__(self):
        self._sessions: Dict[str, paramiko.SSHClient] = {}
        self._lock = threading.Lock()
        self._ssh_config = self._load_ssh_config()

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

    def execute_command(self, host: str, username: Optional[str] = None,
                       command: str = "", password: Optional[str] = None,
                       key_filename: Optional[str] = None,
                       port: Optional[int] = None) -> tuple[str, str, int]:
        """Execute a command on a host using persistent session.

        Args:
            host: Hostname or SSH config alias
            username: SSH username (optional, will use config if available)
            command: Command to execute
            password: Password (optional)
            key_filename: Path to SSH key file (optional, will use config if available)
            port: SSH port (optional, will use config if available)
        """
        client = self.get_or_create_session(host, username, password, key_filename, port)

        stdin, stdout, stderr = client.exec_command(command)
        exit_status = stdout.channel.recv_exit_status()

        return (
            stdout.read().decode('utf-8'),
            stderr.read().decode('utf-8'),
            exit_status
        )
