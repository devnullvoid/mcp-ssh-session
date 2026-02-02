
import unittest
import time
import threading
import logging
from unittest.mock import MagicMock, patch
from mcp_ssh_session.session_manager import SSHSessionManager
from mcp_ssh_session.datastructures import CommandStatus
import os
import re

# Configure logging
# logging.basicConfig(level=logging.DEBUG)

class MockTransport:
    def is_active(self):
        return True

class MockShell:
    def __init__(self):
        self.output_queue = []
        self._recv_ready = False
        self.closed = False
        self.sent_data = []
        self.transport = MockTransport()

    def send(self, data):
        self.sent_data.append(data)

    def recv_ready(self):
        ready = len(self.output_queue) > 0
        return ready

    def recv(self, n):
        if not self.output_queue:
            return b""
        data = self.output_queue.pop(0)
        return data.encode("utf-8")

    def settimeout(self, t):
        pass

    def resize_pty(self, width=80, height=24):
        pass

    def close(self):
        self.closed = True

    def get_transport(self):
        return self.transport

class TestBugs(unittest.TestCase):
    def setUp(self):
        # Patch the logger to avoid TypeError on exc_info
        patcher = patch('mcp_ssh_session.logging_manager.RateLimitedLogger.error')
        self.mock_logger_error = patcher.start()
        self.addCleanup(patcher.stop)

        self.manager = SSHSessionManager()
        self.mock_client = MagicMock()
        self.shell = MockShell()
        self.mock_client.invoke_shell.return_value = self.shell
        self.mock_client.get_transport.return_value.is_active.return_value = True

        # Setup session
        self.session_key = "user@localhost:22"
        self.manager._sessions[self.session_key] = self.mock_client
        self.manager._session_shells[self.session_key] = self.shell
        self.manager._session_shell_types[self.session_key] = "unix_shell"

        # Simulate generic prompt fallback which is prone to false positives
        self.manager._session_prompt_patterns[self.session_key] = re.compile(r"[>#\$]\s*$")
        self.manager._session_prompts[self.session_key] = "$"

    def test_bug1_false_positive_completion_prevention(self):
        """Test that output ending with a prompt character NO LONGER triggers completion (timeout expected)."""
        print("\n--- Testing Bug 1: False Positive Prevention ---")

        def inject():
            time.sleep(0.5)
            self.shell.output_queue.append("some_command\n")
            self.shell.output_queue.append("Doing some work...\n")
            self.shell.output_queue.append("Cost is 10$")

        t = threading.Thread(target=inject)
        t.start()

        with patch.object(self.manager, '_resolve_connection', return_value=({}, "localhost", "user", 22, self.session_key)):
             stdout, stderr, exit_code, _ = self.manager._execute_standard_command_internal(
                 self.mock_client, "some_command", timeout=2, session_key=self.session_key
             )

        t.join()

        # Expect timeout because sentinel is missing
        self.assertEqual(exit_code, 124)
        print("Success: Command correctly waited (timed out) instead of false completion.")

    def test_sentinel_success(self):
        """Test that sentinel correctly detects completion and exit code."""
        print("\n--- Testing Sentinel Success ---")

        marker_event = threading.Event()
        marker_container = []
        original_build = self.manager._build_sentinel_command

        def side_effect_build(marker, path):
            marker_container.append(marker)
            marker_event.set()
            return original_build(marker, path)

        with patch.object(self.manager, '_build_sentinel_command', side_effect=side_effect_build):
            def inject_response():
                # Wait for marker
                if not marker_event.wait(timeout=5):
                    print("Timeout waiting for marker capture")
                    return

                marker = marker_container[0]
                # Ensure we inject AFTER the send has happened.
                time.sleep(0.2)

                # Inject echoed command (with marker) + Output + Sentinel + Prompt
                self.shell.output_queue.append(f"some_command; ... {marker} ...\n")
                self.shell.output_queue.append("Command Output\n")
                self.shell.output_queue.append(f"\n{marker}0\n")
                self.shell.output_queue.append("$ ")

            t = threading.Thread(target=inject_response)
            t.start()

            with patch.object(self.manager, '_resolve_connection', return_value=({}, "localhost", "user", 22, self.session_key)):
                 stdout, stderr, exit_code, _ = self.manager._execute_standard_command_internal(
                     self.mock_client, "some_command", timeout=5, session_key=self.session_key
                 )

            t.join()

            self.assertEqual(exit_code, 0)
            self.assertIn("Command Output", stdout)

    def test_network_device_fallback(self):
        """Test that network devices still use prompt detection."""
        print("\n--- Testing Network Device Fallback ---")

        # Change shell type to network device
        self.manager._session_shell_types[self.session_key] = "cisco"
        self.manager._session_prompts[self.session_key] = "Router#"

        def inject():
            time.sleep(0.5)
            self.shell.output_queue.append("show ver\n")
            self.shell.output_queue.append("Cisco IOS Software...\n")
            self.shell.output_queue.append("Router#")

        t = threading.Thread(target=inject)
        t.start()

        with patch.object(self.manager, '_resolve_connection', return_value=({}, "localhost", "user", 22, self.session_key)):
             stdout, stderr, exit_code, _ = self.manager._execute_standard_command_internal(
                 self.mock_client, "show ver", timeout=5, session_key=self.session_key
             )

        t.join()

        # Verify no sentinel was sent
        sent_str = "".join(self.shell.sent_data)
        self.assertNotIn("__MCP_CMD_", sent_str)

        # Should succeed with 0 via prompt detection
        self.assertEqual(exit_code, 0)
        self.assertIn("Cisco IOS Software", stdout)

    def test_bug2_excessive_output(self):
        """Test that get_command_status returns limited output when requested."""
        print("\n--- Testing Bug 2: Excessive Output Limiting ---")

        # Manually register a command in the executor
        cmd_id = "test-cmd-limit"
        from mcp_ssh_session.datastructures import RunningCommand
        from datetime import datetime

        # Create a huge output (2000 lines)
        huge_output = "\n".join([f"Line {i}" for i in range(2000)])

        cmd = RunningCommand(
            command_id=cmd_id,
            session_key=self.session_key,
            command="long_output_cmd",
            shell=self.shell,
            future=None,
            status=CommandStatus.RUNNING,
            stdout=huge_output,
            stderr="",
            exit_code=None,
            start_time=datetime.now(),
            end_time=None
        )

        self.manager.command_executor._commands[cmd_id] = cmd

        # 1. Test without limit (should return all)
        status = self.manager.get_command_status(cmd_id)
        self.assertEqual(len(status['stdout']), len(huge_output))
        self.assertTrue(len(status['stdout']) > 10000)

        # 2. Test with limit (e.g. 50 lines)
        limit = 50
        status_limited = self.manager.get_command_status(cmd_id, last_n_lines=limit)
        limited_out = status_limited['stdout']

        # Check truncation message
        self.assertIn("... (output truncated to last 50 lines) ...", limited_out)

        # Check line count (excluding truncation message line)
        lines = limited_out.splitlines()
        # Should be limit + 1 (message) lines
        self.assertEqual(len(lines), limit + 1)

        # Check content (should be last lines)
        self.assertIn("Line 1999", limited_out)
        self.assertNotIn("Line 0", limited_out)

        print(f"Limited output length: {len(limited_out)}")
        print("Success: Output correctly limited.")

if __name__ == '__main__':
    unittest.main()
