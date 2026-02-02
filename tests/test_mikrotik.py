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


@pytest.fixture
def streaming_manager(mock_ssh_client):
    """Session manager wired to treat certain Mikrotik commands as streaming.

    We stub the standard execution path to immediately time out (exit_code 124)
    so the command executor keeps the command running asynchronously. This lets
    us verify that long-running/streaming Mikrotik commands are surfaced to the
    agent as async tasks it can monitor or interrupt.
    """

    manager = SSHSessionManager()

    host = os.getenv("SSH_TEST_HOST", "192.168.88.1")
    user = os.getenv("SSH_TEST_USER", "jon")
    port = int(os.getenv("SSH_TEST_PORT", "22"))
    session_key = f"{user}@{host}:{port}"

    # Prime session metadata used by the executor
    manager._session_shell_types[session_key] = "mikrotik"
    manager._session_prompts[session_key] = "[jon@core-rtr-01] >"

    shell = mock_ssh_client.invoke_shell.return_value

    def fake_streaming_execute(client, command, timeout, skey):
        # Mimic a streaming/never-ending command: immediately signal timeout so
        # the executor leaves it running in the background (status=running).
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
    ), patch.object(manager, "_build_device_profile") as mock_profile:
        # Pre-seed prompt to avoid prompt detection phase which might complicate test
        import re
        manager._session_prompts[session_key] = "[jon@core-rtr-01] >"
        # Ensure we have a pattern so it doesn't try to auto-detect and send sentinels
        manager._session_prompt_patterns[session_key] = re.compile(re.escape("[jon@core-rtr-01] >") + r"\s*$")

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
    """Streaming Mikrotik commands should be handed off to async monitoring (mock)."""

    stdout, stderr, exit_code = streaming_manager.execute_command(
        host=os.getenv("SSH_TEST_HOST", "192.168.88.1"),
        username=os.getenv("SSH_TEST_USER", "jon"),
        command=streaming_command,
        timeout=1,
    )

    # Sync wrapper should return quickly and provide async command id
    assert exit_code == 124
    assert stderr.startswith("ASYNC:")

    command_id = stderr.split(":", 1)[1]
    status = streaming_manager.get_command_status(command_id)

    # Command is still running asynchronously so the agent can decide next steps
    assert status["status"] == "running"
    assert status["command"] == streaming_command

    # Initial chunk from fake streaming executor is surfaced
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
def test_streaming_commands_live(streaming_command):
    """Live check: streaming commands should flip into async mode and stay running."""

    host = os.environ.get("MIKROTIK_HOST") or os.environ.get("SSH_TEST_HOST")
    user = os.environ.get("MIKROTIK_USER") or os.environ.get("SSH_TEST_USER")

    # Some shells/launchers leak values like "host=router" or "user=admin"; normalize them.
    if host and host.lower().startswith("host="):
        host = host.split("=", 1)[1]
    if user and user.lower().startswith("user="):
        user = user.split("=", 1)[1]
    if not user:
        user = None

    timeout = int(os.environ.get("MIKROTIK_TIMEOUT") or os.environ.get("SSH_TEST_TIMEOUT") or "5")

    manager = SSHSessionManager()
    try:
        stdout, stderr, exit_code = manager.execute_command(
            host=host,
            username=user,
            command=streaming_command,
            timeout=timeout,
        )

        # For truly streaming commands we expect the sync wrapper to time out and hand back an async id
        assert exit_code == 124, f"expected sync timeout handing to async, got {exit_code}: {stderr!r}"
        assert stderr.startswith("ASYNC:"), f"stderr should contain ASYNC id, got {stderr!r}"

        command_id = stderr.split(":", 1)[1]
        status = manager.get_command_status(command_id)

        assert status["status"] == "running", f"command not running: {status}"
        assert status["command"] == streaming_command

        # Clean up: stop the long-running command
        manager.command_executor.interrupt_command_by_id(command_id)
    finally:
        manager.close_all_sessions()
