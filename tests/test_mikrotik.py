import os
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
        print(f"[MOCK SHELL] Received data: {repr(data)}")

        # Handle 'q' for pager
        if data == "q":
            print("[MOCK SHELL] Sending 'q' to quit pager")
            # Simulating quitting pager
            # Mikrotik might clear line or just show prompt
            # We simulate prompt appearing after q
            self.output_queue.append("\r\n[jon@core-rtr-01] > ")
            self._recv_ready = True
        elif data.strip() == "/interface bridge port print":
            print("[MOCK SHELL] Executing Mikrotik command that triggers pager")
            # Simulate command output with pager
            response = (
                "Flags: I - INACTIVE\r\n"
                "Columns: INTERFACE, BRIDGE, HW, HORIZON, TRUSTED\r\n"
                "#   INTERFACE  BRIDGE  HW   HORIZON  TR\r\n"
                "0 I ether2     bridge  yes  none     no\r\n"
                "-- [Q quit|D dump|right]"
            )
            self.output_queue.append(response)
            self._recv_ready = True
        elif data == "\n":
            print("[MOCK SHELL] Sending newline/prompt")
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
        return data.encode("utf-8")

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
    # Get test parameters from environment variables
    host = os.getenv("SSH_TEST_HOST", "192.168.88.1")
    user = os.getenv("SSH_TEST_USER", "jon")
    port = int(os.getenv("SSH_TEST_PORT", "22"))

    print(f"\n=== MIKROTIK PAGER TEST ===")
    print(f"Host: {host}")
    print(f"User: {user}")
    print(f"Port: {port}")

    manager = SSHSessionManager()

    # Create session key
    session_key = f"{user}@{host}:{port}"

    # Mock _sessions to return our client
    manager._sessions[session_key] = mock_ssh_client
    manager._session_shell_types[session_key] = "mikrotik"

    # Mock resolving connection to bypass config lookup
    with patch.object(
        manager, "_resolve_connection", return_value=({}, host, user, port, session_key)
    ):
        # Pre-seed prompt to avoid prompt detection phase which might complicate test
        manager._session_prompts[session_key] = "[jon@core-rtr-01] >"

        # Execute command that triggers pager
        command = "/interface bridge port print"
        print(f"\n=== Testing Mikrotik command: {command} ===")
        stdout, stderr, exit_code = manager.execute_command(
            host=host, command=command, timeout=15
        )
        print(f"Command output length: {len(stdout)} characters")
        print(f"Exit code: {exit_code}")

        # Verify exit code is 0 (success)
        assert exit_code == 0

        # Verify pager prompt is NOT in the output
        # If it IS in the output, this assertion will fail, confirming the issue
        pager_prompt = "-- [Q quit|D dump|right]"
        if pager_prompt in stdout:
            print(f"❌ FAIL: Pager prompt found in output: {pager_prompt}")
        else:
            print(f"✅ PASS: Pager prompt correctly handled and removed from output")
        assert pager_prompt not in stdout
