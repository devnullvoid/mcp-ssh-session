import os
import pytest
import logging
import time
from mcp_ssh_session.session_manager import SSHSessionManager

# Configure logging to see what's happening during tests
logging.basicConfig(level=logging.DEBUG)

@pytest.mark.skipif(
    not os.environ.get("SSH_TEST_HOST"),
    reason="Skipping integration tests: SSH_TEST_HOST not set"
)
class TestSSHIntegration:
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
        
        return {
            "host": host,
            "username": username,
            "password": password,
            "key_filename": key_filename,
            "port": port
        }

    def _execute_and_wait(self, session_manager, ssh_config, command, timeout=10, expected_input=None):
        """
        Helper to execute a command and handle ASYNC or AWAITING_INPUT responses.
        Returns final stdout, stderr, exit_code.
        """
        stdout, stderr, exit_code = session_manager.execute_command(
            host=ssh_config['host'],
            username=ssh_config['username'],
            password=ssh_config['password'],
            key_filename=ssh_config['key_filename'],
            port=ssh_config['port'],
            command=command,
            timeout=timeout
        )

        if exit_code == 124:
            if stderr.startswith("ASYNC:"):
                command_id = stderr.split(":", 1)[1]
                print(f"Command went async. Polling command ID: {command_id}")
                # Poll until completion or timeout
                start_time = time.time()
                while time.time() - start_time < timeout + 5: # Give a little extra time for async completion
                    status_response = session_manager.get_command_status(command_id)
                    if "error" in status_response:
                        return "", status_response["error"], 1
                    if status_response["status"] != "running":
                        return status_response["stdout"], status_response["stderr"], status_response["exit_code"] or 0
                    time.sleep(0.5)
                return "", "ASYNC command timed out during polling", 124
            elif stderr.startswith("AWAITING_INPUT:"):
                parts = stderr.split(":", 2)
                command_id = parts[1]
                reason = parts[2] if len(parts) > 2 else "unknown"
                print(f"Command {command_id} awaiting input: {reason}. Providing input...")
                if expected_input:
                    input_success, input_output, input_error = session_manager.send_input(command_id, expected_input)
                    if not input_success:
                        return "", f"Failed to send input: {input_error}", 1
                    # After sending input, it should transition back to running. Poll for completion.
                    start_time = time.time()
                    while time.time() - start_time < timeout + 5:
                        status_response = session_manager.get_command_status(command_id)
                        if "error" in status_response:
                            return "", status_response["error"], 1
                        if status_response["status"] != "running":
                            return status_response["stdout"], status_response["stderr"], status_response["exit_code"] or 0
                        time.sleep(0.5)
                    return "", "AWAITING_INPUT command timed out after providing input", 124
                else:
                    return stdout, f"Command awaiting input ({reason}) but no expected_input provided.", 124
        
        return stdout, stderr, exit_code

    def test_connection_and_simple_command(self, session_manager, ssh_config):
        """Test basic connection and simple echo command."""
        print(f"\nConnecting to {ssh_config['host']}...")
        
        stdout, stderr, exit_code = self._execute_and_wait(
            session_manager, ssh_config, command="echo 'Hello World'", timeout=10
        )
        
        assert exit_code == 0
        assert "Hello World" in stdout
        assert stderr == ""

    def test_multiple_commands_same_session(self, session_manager, ssh_config):
        """Test that multiple commands reuse the session and maintain state."""
        
        self._execute_and_wait(
            session_manager, ssh_config, command="export MY_VAR='test_value'", timeout=5
        )
        
        stdout, _, exit_code = self._execute_and_wait(
            session_manager, ssh_config, command="echo $MY_VAR", timeout=5
        )
        
        assert exit_code == 0
        assert "test_value" in stdout

    def test_command_with_delay(self, session_manager, ssh_config):
        """Test a command that takes some time to complete."""
        
        stdout, _, exit_code = self._execute_and_wait(
            session_manager, ssh_config, command="sleep 2 && echo 'Finished'", timeout=5
        )
        
        assert exit_code == 0
        assert "Finished" in stdout

    def test_large_output(self, session_manager, ssh_config):
        """Test handling of larger output."""
        stdout, _, exit_code = self._execute_and_wait(
            session_manager, ssh_config, command="for i in {1..50}; do echo \"Line $i\"; done", timeout=10
        )
        
        assert exit_code == 0
        assert "Line 1" in stdout
        assert "Line 50" in stdout
        assert len(stdout.splitlines()) >= 50

    def test_stderr_output(self, session_manager, ssh_config):
        """Test command that produces stderr."""
        stdout, stderr, exit_code = self._execute_and_wait(
            session_manager, ssh_config, command="echo 'error message' >&2", timeout=5
        )
        
        assert "error message" in stdout or "error message" in stderr # Depending on shell, stderr can be merged to stdout
        assert exit_code == 0

    def test_directory_persistence(self, session_manager, ssh_config):
        """Test that changing directory persists."""
        
        self._execute_and_wait(
            session_manager, ssh_config, command="mkdir -p /tmp/mcp_test_dir", timeout=5
        )
        
        self._execute_and_wait(
            session_manager, ssh_config, command="cd /tmp/mcp_test_dir", timeout=5
        )
        
        stdout, _, exit_code = self._execute_and_wait(
            session_manager, ssh_config, command="pwd", timeout=5
        )
        
        assert "/tmp/mcp_test_dir" in stdout
        assert exit_code == 0
        
        # Cleanup
        self._execute_and_wait(
            session_manager, ssh_config, command="cd ~", timeout=5
        )
        self._execute_and_wait(
            session_manager, ssh_config, command="rm -rf /tmp/mcp_test_dir", timeout=5
        )

    def test_interactive_input(self, session_manager, ssh_config):
        """Test handling of an interactive command using the AWAITING_INPUT mechanism."""
        # "Please enter value: " should match the regex 'enter [a-z\s]+[:\s]*$'
        command = 'read -p "Please enter value: " my_var && echo "You said: $my_var"'
        
        # Use _execute_and_wait which handles the AWAITING_INPUT response by sending 'expected_input'
        stdout, stderr, exit_code = self._execute_and_wait(
            session_manager, ssh_config, 
            command=command, 
            timeout=5, 
            expected_input="magic_word\n"
        )
        
        assert exit_code == 0
        assert "You said: magic_word" in stdout

    def test_streaming_async_output(self, session_manager, ssh_config):
        """Test that we can see intermediate output from a running async command."""
        command = "for i in {1..3}; do echo \"Step $i\"; sleep 1; done"

        # Start async command
        command_id = session_manager.execute_command_async(
            host=ssh_config['host'],
            command=command,
            timeout=10
        )

        print(f"Started async command {command_id}")

        # Poll a few times to check for streaming output
        full_output = ""
        completed = False
        start_time = time.time()

        while time.time() - start_time < 10:
            status = session_manager.get_command_status(command_id)

            if status['stdout']:
                print(f"Current stdout: {status['stdout'].strip()}")
                full_output = status['stdout']

            if "Step 1" in full_output and not completed:
                # We saw the first step while it might still be running (or just finished)
                pass

            if status['status'] != 'running':
                completed = True
                break

            time.sleep(0.5)

        assert completed
        assert "Step 1" in full_output
        assert "Step 2" in full_output
        assert "Step 3" in full_output
        assert status['exit_code'] == 0

    @pytest.mark.skipif(
        not os.environ.get("SSH_TEST_SUDO_PASSWORD"),
        reason="Skipping sudo test: SSH_TEST_SUDO_PASSWORD not set"
    )
    def test_sudo_with_password(self, session_manager, ssh_config):
        """Test sudo command with automatic password handling."""
        sudo_password = os.environ.get("SSH_TEST_SUDO_PASSWORD")

        # Create a test file that requires sudo to write
        stdout, stderr, exit_code = session_manager.execute_command(
            host=ssh_config['host'],
            username=ssh_config['username'],
            password=ssh_config['password'],
            key_filename=ssh_config['key_filename'],
            port=ssh_config['port'],
            sudo_password=sudo_password,
            command="whoami",
            timeout=10
        )

        print(f"Sudo whoami output: {stdout}")
        assert exit_code == 0
        assert "root" in stdout.lower()

        # Test writing to a protected location
        test_file = "/tmp/mcp_test_sudo_file.txt"
        test_content = "sudo test content"

        stdout, stderr, exit_code = session_manager.execute_command(
            host=ssh_config['host'],
            username=ssh_config['username'],
            password=ssh_config['password'],
            key_filename=ssh_config['key_filename'],
            port=ssh_config['port'],
            sudo_password=sudo_password,
            command=f"echo '{test_content}' | sudo tee {test_file}",
            timeout=10
        )

        assert exit_code == 0

        # Verify the file was created
        stdout, stderr, exit_code = session_manager.execute_command(
            host=ssh_config['host'],
            username=ssh_config['username'],
            password=ssh_config['password'],
            key_filename=ssh_config['key_filename'],
            port=ssh_config['port'],
            sudo_password=sudo_password,
            command=f"sudo cat {test_file}",
            timeout=10
        )

        assert exit_code == 0
        assert test_content in stdout

        # Cleanup
        session_manager.execute_command(
            host=ssh_config['host'],
            username=ssh_config['username'],
            password=ssh_config['password'],
            key_filename=ssh_config['key_filename'],
            port=ssh_config['port'],
            sudo_password=sudo_password,
            command=f"sudo rm {test_file}",
            timeout=10
        )