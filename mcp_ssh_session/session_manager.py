"""SSH session manager using Paramiko."""
import paramiko
from typing import Dict, Optional
import threading


class SSHSessionManager:
    """Manages persistent SSH sessions."""

    def __init__(self):
        self._sessions: Dict[str, paramiko.SSHClient] = {}
        self._lock = threading.Lock()

    def get_or_create_session(self, host: str, username: str,
                              password: Optional[str] = None,
                              key_filename: Optional[str] = None,
                              port: int = 22) -> paramiko.SSHClient:
        """Get existing session or create a new one."""
        session_key = f"{username}@{host}:{port}"

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
                'hostname': host,
                'port': port,
                'username': username,
            }

            if password:
                connect_kwargs['password'] = password
            elif key_filename:
                connect_kwargs['key_filename'] = key_filename

            client.connect(**connect_kwargs)
            self._sessions[session_key] = client
            return client

    def close_session(self, host: str, username: str, port: int = 22):
        """Close a specific session."""
        session_key = f"{username}@{host}:{port}"
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

    def execute_command(self, host: str, username: str, command: str,
                       password: Optional[str] = None,
                       key_filename: Optional[str] = None,
                       port: int = 22) -> tuple[str, str, int]:
        """Execute a command on a host using persistent session."""
        client = self.get_or_create_session(host, username, password, key_filename, port)

        stdin, stdout, stderr = client.exec_command(command)
        exit_status = stdout.channel.recv_exit_status()

        return (
            stdout.read().decode('utf-8'),
            stderr.read().decode('utf-8'),
            exit_status
        )
