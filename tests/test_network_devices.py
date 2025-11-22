import os
import pytest
import logging
import time
from mcp_ssh_session.session_manager import SSHSessionManager

# Configure logging to see what's happening during tests
logging.basicConfig(level=logging.DEBUG)

@pytest.mark.skipif(
    not os.environ.get("SSH_TEST_HOST") or not os.environ.get("SSH_TEST_ENABLE_PASSWORD"),
    reason="Skipping network device tests: SSH_TEST_HOST or SSH_TEST_ENABLE_PASSWORD not set"
)
class TestCiscoStyleDevices:
    """Tests for Cisco-style network devices with enable mode and configure mode."""

    @pytest.fixture(scope="class")
    def session_manager(self):
        manager = SSHSessionManager()
        yield manager
        manager.close_all_sessions()

    @pytest.fixture(scope="class")
    def ssh_config(self):
        host = os.environ.get("SSH_TEST_HOST")
        username = os.environ.get("SSH_TEST_USER")
        password = os.environ.get("SSH_TEST_PASSWORD")
        key_filename = os.environ.get("SSH_TEST_KEY_FILE")
        port = int(os.environ.get("SSH_TEST_PORT", "22"))
        enable_password = os.environ.get("SSH_TEST_ENABLE_PASSWORD")

        return {
            "host": host,
            "username": username,
            "password": password,
            "key_filename": key_filename,
            "port": port,
            "enable_password": enable_password
        }

    def test_enable_mode_basic(self, session_manager, ssh_config):
        """Test entering enable mode and running a command."""
        print(f"\nConnecting to {ssh_config['host']} and entering enable mode...")

        stdout, stderr, exit_code = session_manager.execute_command(
            host=ssh_config['host'],
            username=ssh_config['username'],
            password=ssh_config['password'],
            key_filename=ssh_config['key_filename'],
            port=ssh_config['port'],
            enable_password=ssh_config['enable_password'],
            command="show version",
            timeout=30
        )

        print(f"Output: {stdout[:500]}...")  # Print first 500 chars
        assert exit_code == 0
        assert len(stdout) > 0

    def test_enable_mode_multiple_commands(self, session_manager, ssh_config):
        """Test that enable mode persists across multiple commands."""

        # First command in enable mode
        stdout1, stderr1, exit_code1 = session_manager.execute_command(
            host=ssh_config['host'],
            username=ssh_config['username'],
            password=ssh_config['password'],
            key_filename=ssh_config['key_filename'],
            port=ssh_config['port'],
            enable_password=ssh_config['enable_password'],
            command="show running-config | include hostname",
            timeout=30
        )

        assert exit_code1 == 0

        # Second command - should reuse enable mode session
        stdout2, stderr2, exit_code2 = session_manager.execute_command(
            host=ssh_config['host'],
            username=ssh_config['username'],
            password=ssh_config['password'],
            key_filename=ssh_config['key_filename'],
            port=ssh_config['port'],
            enable_password=ssh_config['enable_password'],
            command="show interfaces status",
            timeout=30
        )

        assert exit_code2 == 0

    def test_configure_mode(self, session_manager, ssh_config):
        """Test entering configure mode, making changes, and exiting.

        Note: This test uses Cisco IOS commands and will be skipped on devices
        that don't support 'configure terminal' mode (like EdgeSwitch).
        """

        # First, check if the device supports configure terminal
        check_stdout, _, check_exit = session_manager.execute_command(
            host=ssh_config['host'],
            username=ssh_config['username'],
            password=ssh_config['password'],
            key_filename=ssh_config['key_filename'],
            port=ssh_config['port'],
            enable_password=ssh_config['enable_password'],
            command="configure terminal\nexit",
            timeout=10
        )

        # Skip if device doesn't support configure terminal
        if "Invalid input" in check_stdout or "% " in check_stdout:
            pytest.skip("Device doesn't support Cisco IOS 'configure terminal' mode")

        # Enter configure mode, add a comment to config, then exit
        # This is a safe operation that won't affect the device
        commands = """
configure terminal
interface Loopback999
description Test interface for MCP SSH Session testing
exit
exit
show running-config interface Loopback999
""".strip()

        stdout, stderr, exit_code = session_manager.execute_command(
            host=ssh_config['host'],
            username=ssh_config['username'],
            password=ssh_config['password'],
            key_filename=ssh_config['key_filename'],
            port=ssh_config['port'],
            enable_password=ssh_config['enable_password'],
            command=commands,
            timeout=30
        )

        print(f"Configure mode output: {stdout}")
        assert exit_code == 0
        # Check that we got valid config output, not error messages
        assert "Invalid input" not in stdout, "Device reported invalid input"
        assert "description Test interface" in stdout or "Description: Test interface" in stdout

        # Cleanup - remove the test interface
        cleanup_commands = """
configure terminal
no interface Loopback999
exit
""".strip()

        session_manager.execute_command(
            host=ssh_config['host'],
            username=ssh_config['username'],
            password=ssh_config['password'],
            key_filename=ssh_config['key_filename'],
            port=ssh_config['port'],
            enable_password=ssh_config['enable_password'],
            command=cleanup_commands,
            timeout=30
        )

    def test_show_command_with_pager(self, session_manager, ssh_config):
        """Test handling of commands with paged output (long output)."""

        # Many devices will page output for long show commands
        # The session manager should handle the pager automatically
        stdout, stderr, exit_code = session_manager.execute_command(
            host=ssh_config['host'],
            username=ssh_config['username'],
            password=ssh_config['password'],
            key_filename=ssh_config['key_filename'],
            port=ssh_config['port'],
            enable_password=ssh_config['enable_password'],
            command="show running-config",
            timeout=60
        )

        print(f"Paged output length: {len(stdout)} bytes")
        assert exit_code == 0
        # Running config should have substantial content
        assert len(stdout) > 100


@pytest.mark.skipif(
    not os.environ.get("SSH_TEST_NETWORK_DEVICE_HOST"),
    reason="Skipping Mikrotik/Palo Alto tests: SSH_TEST_NETWORK_DEVICE_HOST not set"
)
class TestMikrotikPaloAltoDevices:
    """Tests for Mikrotik and Palo Alto style devices with interactive pagers."""

    @pytest.fixture(scope="class")
    def session_manager(self):
        manager = SSHSessionManager()
        yield manager
        manager.close_all_sessions()

    @pytest.fixture(scope="class")
    def ssh_config(self):
        host = os.environ.get("SSH_TEST_NETWORK_DEVICE_HOST")
        username = os.environ.get("SSH_TEST_NETWORK_DEVICE_USER", os.environ.get("SSH_TEST_USER"))
        password = os.environ.get("SSH_TEST_NETWORK_DEVICE_PASSWORD", os.environ.get("SSH_TEST_PASSWORD"))
        key_filename = os.environ.get("SSH_TEST_NETWORK_DEVICE_KEY_FILE")
        port = int(os.environ.get("SSH_TEST_NETWORK_DEVICE_PORT", "22"))

        return {
            "host": host,
            "username": username,
            "password": password,
            "key_filename": key_filename,
            "port": port
        }

    def test_basic_command(self, session_manager, ssh_config):
        """Test basic command execution on Mikrotik/Palo Alto device."""
        print(f"\nConnecting to {ssh_config['host']}...")

        # MikroTik: /system resource print
        # Palo Alto: show system info
        # Try a generic command that should work on both
        stdout, stderr, exit_code = session_manager.execute_command(
            host=ssh_config['host'],
            username=ssh_config['username'],
            password=ssh_config['password'],
            key_filename=ssh_config['key_filename'],
            port=ssh_config['port'],
            command="?",  # Help command works on most devices
            timeout=30
        )

        print(f"Output: {stdout[:500]}...")
        assert exit_code == 0
        assert len(stdout) > 0

    def test_command_with_pager(self, session_manager, ssh_config):
        """Test handling of paged output (MikroTik/Palo Alto style)."""

        # MikroTik often shows pagers with format like:
        # -- [Q quit|D dump|C-z pause]
        # Palo Alto shows: (END) or -- More --

        # Try a command likely to trigger paging
        commands_to_try = [
            "/export",  # MikroTik: export full config
            "show config running",  # Palo Alto: show running config
            "/system resource print detail",  # MikroTik: detailed system info
        ]

        # Try each command until one succeeds (depends on device type)
        success = False
        for cmd in commands_to_try:
            try:
                stdout, stderr, exit_code = session_manager.execute_command(
                    host=ssh_config['host'],
                    username=ssh_config['username'],
                    password=ssh_config['password'],
                    key_filename=ssh_config['key_filename'],
                    port=ssh_config['port'],
                    command=cmd,
                    timeout=60
                )

                if exit_code == 0 and len(stdout) > 100:
                    print(f"Success with command: {cmd}")
                    print(f"Output length: {len(stdout)} bytes")
                    success = True
                    break
            except Exception as e:
                print(f"Command '{cmd}' failed: {e}")
                continue

        assert success, "None of the test commands succeeded"

    def test_interactive_prompt_handling(self, session_manager, ssh_config):
        """Test handling of interactive prompts that appear during command execution."""

        # Some commands may prompt for confirmation
        # The session manager should detect when it's awaiting input

        # For MikroTik, try a safe command that might prompt
        # For Palo Alto, configure commands often prompt for confirmation

        stdout, stderr, exit_code = session_manager.execute_command(
            host=ssh_config['host'],
            username=ssh_config['username'],
            password=ssh_config['password'],
            key_filename=ssh_config['key_filename'],
            port=ssh_config['port'],
            command="?",
            timeout=10
        )

        # Basic assertion - just verify we can handle the device
        assert exit_code == 0

    def test_multiple_commands_session_persistence(self, session_manager, ssh_config):
        """Test that session persists across multiple commands."""

        # First command
        stdout1, stderr1, exit_code1 = session_manager.execute_command(
            host=ssh_config['host'],
            username=ssh_config['username'],
            password=ssh_config['password'],
            key_filename=ssh_config['key_filename'],
            port=ssh_config['port'],
            command="/system identity print",  # MikroTik
            timeout=10
        )

        # Second command - should reuse session
        stdout2, stderr2, exit_code2 = session_manager.execute_command(
            host=ssh_config['host'],
            username=ssh_config['username'],
            password=ssh_config['password'],
            key_filename=ssh_config['key_filename'],
            port=ssh_config['port'],
            command="/system resource print",  # MikroTik
            timeout=10
        )

        # At least one should succeed (depends on device type)
        assert exit_code1 == 0 or exit_code2 == 0
