import time
import pytest
from unittest.mock import MagicMock, patch
from mcp_ssh_session.session_manager import SSHSessionManager

class MockShell:
    def __init__(self):
        self.output_queue = []
        self.input_buffer = ""
        self.closed = False
        self._recv_ready = False

    def settimeout(self, timeout):
        pass

    def resize_pty(self, width, height):
        pass

    def send(self, data):
        self.input_buffer += data
        # Handle 'q' for pager
        if data == 'q':
            # Simulating quitting pager
            # Mikrotik might clear line or just show prompt
            # We simulate prompt appearing after q
            self.output_queue.append("\r\n[jon@core-rtr-01] > ")
            self._recv_ready = True
        elif data.strip() == "/interface bridge port print":
            # Simulate command output with pager
            response = "Flags: I - INACTIVE\r\n" \
                       "Columns: INTERFACE, BRIDGE, HW, HORIZON, TRUSTED\r\n" \
                       "#   INTERFACE  BRIDGE  HW   HORIZON  TR\r\n" \
                       "0 I ether2     bridge  yes  none     no\r\n" \
                       "-- [Q quit|D dump|right]"
            self.output_queue.append(response)
            self._recv_ready = True
        elif data == '\n':
            # Initial prompt check or just enter
            self.output_queue.append("\r\n[jon@core-rtr-01] > ")
            self._recv_ready = True

    def recv_ready(self):
        return self._recv_ready and len(self.output_queue) > 0

    def recv(self, n):
        if not self.output_queue:
            self._recv_ready = False
            return b""
        data = self.output_queue.pop(0)
        if not self.output_queue:
            self._recv_ready = False
        return data.encode('utf-8')

    def close(self):
        self.closed = True

@pytest.fixture
def mock_ssh_client():
    client = MagicMock()
    shell = MockShell()
    client.invoke_shell.return_value = shell
    client.get_transport.return_value.is_active.return_value = True
    return client

def test_mikrotik_pager_handling(mock_ssh_client):
    manager = SSHSessionManager()

    # Mock _sessions to return our client
    manager._sessions["jon@192.168.88.1:22"] = mock_ssh_client
    manager._session_shell_types["jon@192.168.88.1:22"] = "mikrotik"

    # Mock resolving connection to bypass config lookup
    with patch.object(manager, '_resolve_connection', return_value=({}, "192.168.88.1", "jon", 22, "jon@192.168.88.1:22")):
        # Pre-seed prompt to avoid prompt detection phase which might complicate test
        manager._session_prompts["jon@192.168.88.1:22"] = "[jon@core-rtr-01] >"

        # Execute command that triggers pager
        stdout, stderr, exit_code = manager.execute_command(
            host="192.168.88.1",
            command="/interface bridge port print",
            timeout=15
        )

        # Verify exit code is 0 (success)
        assert exit_code == 0

        # Verify pager prompt is NOT in the output
        # If it IS in the output, this assertion will fail, confirming the issue
        assert "-- [Q quit|D dump|right]" not in stdout
