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
            self.output_queue.append("\r\n[jon@MikroTik] > ")
            self._recv_ready = True
        elif data.strip() == "/interface bridge port print":
            print("[MOCK SHELL] Executing Mikrotik command that triggers pager")
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
            self.output_queue.append("\r\n[jon@MikroTik] > ")
            self._recv_ready = True
        elif "echo \"__MCP_PROMPT_MARKER_" in data:
            marker = data.split("\"")[1]
            print(f"[MOCK SHELL] Handling marker echo: {marker}")
            # Echo the command back and then the marker and prompt
            self.output_queue.append(f"{data}{marker}\r\n[jon@MikroTik] > ")
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


@pytest.fixture(scope="module")
def live_manager():
    """Shared manager for live tests to avoid redundant connections."""
    manager = SSHSessionManager()
    yield manager
    manager.close_all_sessions()


@pytest.fixture
def streaming_manager(mock_ssh_client):
    manager = SSHSessionManager()
    host = os.getenv("SSH_TEST_HOST", "192.168.88.1")
    user = os.getenv("SSH_TEST_USER", "jon")
    port = int(os.getenv("SSH_TEST_PORT", "22"))
    session_key = f"{user}@{host}:{port}"
    manager._session_shell_types[session_key] = "mikrotik"
    manager._session_prompts[session_key] = "[jon@MikroTik] >"
    shell = mock_ssh_client.invoke_shell.return_value

    def fake_streaming_execute(client, command, timeout, skey):
        return f"[streaming start] {command}\n", "", 124, None

    with patch.object(
        manager, "_resolve_connection", return_value=({}, host, user, port, session_key)
    ), patch.object(
        manager, "get_or_create_session", return_value=mock_ssh_client
    ), patch.object(
        manager, "_get_or_create_shell", return_value=shell
    ), patch.object(
        manager, "_execute_standard_command_internal", side_effect=fake_streaming_execute
    ), patch.object(
        manager.command_executor,
        "_continue_monitoring_timeout_background",
        return_value=None,
    ):
        yield manager
    manager.close_all_sessions()


def test_mikrotik_pager_handling_mock(mock_ssh_client):
    host = os.getenv("SSH_TEST_HOST", "192.168.88.1")
    user = os.getenv("SSH_TEST_USER", "jon")
    port = int(os.getenv("SSH_TEST_PORT", "22"))
    manager = SSHSessionManager()
    session_key = f"{user}@{host}:{port}"
    manager._sessions[session_key] = mock_ssh_client
    manager._session_shell_types[session_key] = "mikrotik"

    with patch.object(
        manager, "_resolve_connection", return_value=({}, host, user, port, session_key)
    ):
        manager._session_prompts[session_key] = "[jon@MikroTik] >"
        command = "/interface bridge port print"
        stdout, stderr, exit_code = manager.execute_command(
            host=host, command=command, timeout=15
        )
        assert exit_code == 0
        assert "-- [Q quit|D dump|right]" not in stdout


@pytest.mark.parametrize(
    "streaming_command",
    [
        "/interface/monitor-traffc bridge",
        "/ping 1.1.1.1",
        "/tool/torch bridge",
        "/tool/sniffer quick",
    ],
)
def test_streaming_commands_go_async_mock(streaming_manager, streaming_command):
    stdout, stderr, exit_code = streaming_manager.execute_command(
        host=os.getenv("SSH_TEST_HOST", "192.168.88.1"),
        username=os.getenv("SSH_TEST_USER", "jon"),
        command=streaming_command,
        timeout=1,
    )
    assert exit_code == 124
    assert stderr.startswith("ASYNC:")
    command_id = stderr.split(":", 1)[1]
    status = streaming_manager.get_command_status(command_id)
    assert status["status"] == "running"
    assert "[streaming start]" in stdout


@pytest.mark.skipif(
    not (os.environ.get("MIKROTIK_HOST") or os.environ.get("SSH_TEST_HOST")),
    reason="Set MIKROTIK_HOST or SSH_TEST_HOST to run live MikroTik streaming tests",
)
@pytest.mark.parametrize(
    "streaming_command",
    [
        "/interface/monitor-traffic bridge",
        "/ping 1.1.1.1",
        "/tool/torch bridge",
        "/tool/sniffer quick",
    ],
)
def test_streaming_commands_live(live_manager, streaming_command):
    host = os.environ.get("MIKROTIK_HOST") or os.environ.get("SSH_TEST_HOST")
    user = os.environ.get("MIKROTIK_USER") or os.environ.get("SSH_TEST_USER")

    if host and host.lower().startswith("host="):
        host = host.split("=", 1)[1]
    if user and user.lower().startswith("user="):
        user = user.split("=", 1)[1]
    if not user:
        user = None

    timeout = int(os.environ.get("MIKROTIK_TIMEOUT") or os.environ.get("SSH_TEST_TIMEOUT") or "5")

    # For the first command, give it extra time to clear banner
    stdout, stderr, exit_code = live_manager.execute_command(
        host=host,
        username=user,
        command=streaming_command,
        timeout=timeout,
    )

    # Note: If it returns 0 immediately, it might be due to stale prompt detection
    # during initial banner dump. We'll retry once if output is suspiciously empty.
    if exit_code == 0 and not stdout.strip():
        time.sleep(2)
        stdout, stderr, exit_code = live_manager.execute_command(
            host=host,
            username=user,
            command=streaming_command,
            timeout=timeout,
        )

    assert exit_code == 124, f"expected sync timeout handing to async, got {exit_code}: {stderr!r}. STDOUT: {stdout!r}"
    assert stderr.startswith("ASYNC:")
    command_id = stderr.split(":", 1)[1]
    status = live_manager.get_command_status(command_id)
    assert status["status"] == "running"
    live_manager.command_executor.interrupt_command_by_id(command_id)