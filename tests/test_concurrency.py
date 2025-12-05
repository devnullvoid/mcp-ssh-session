import os
import pytest
import time
from mcp_ssh_session.session_manager import SSHSessionManager

@pytest.mark.skipif(
    not os.environ.get("SSH_TEST_HOST"),
    reason="Skipping integration tests: SSH_TEST_HOST not set"
)
class TestConcurrency:
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
        
        # Handle "empty" values from justfile
        if password == "<not set>":
            password = None

        return {
            "host": host,
            "username": username,
            "password": password,
            "key_filename": key_filename,
            "port": port
        }

    def test_concurrent_command_rejection(self, session_manager, ssh_config):
        """Test that a new command is rejected while an async command is running."""
        print(f"\nConnecting to {ssh_config['host']}...")
        
        # 1. Start a long-running command (sleep 5)
        cmd_async = "sleep 5"
        print(f"Starting async command: {cmd_async}")
        command_id = session_manager.execute_command_async(
            host=ssh_config['host'],
            username=ssh_config['username'],
            password=ssh_config['password'],
            key_filename=ssh_config['key_filename'],
            port=ssh_config['port'],
            command=cmd_async,
            timeout=10
        )
        
        print(f"Async command started with ID: {command_id}")
        
        # Verify it is running
        status = session_manager.get_command_status(command_id)
        assert status['status'] == 'running'
        
        # 2. Try to execute another command immediately (sync)
        print("Attempting to run second command immediately...")
        stdout, stderr, exit_code = session_manager.execute_command(
            host=ssh_config['host'],
            username=ssh_config['username'],
            password=ssh_config['password'],
            key_filename=ssh_config['key_filename'],
            port=ssh_config['port'],
            command="echo 'Should fail'",
            timeout=5
        )
        
        # Expectation: It fails cleanly with exit code 1 and error message
        print(f"Second command result: code={exit_code}, stderr={stderr}")
        assert exit_code == 1
        assert "A command is already running" in stderr

        # 3. Try write_file with use_sudo=True (forces shell usage)
        print("Attempting to write file with sudo immediately (should fail)...")
        msg, stderr, exit_code = session_manager.write_file(
            host=ssh_config['host'],
            username=ssh_config['username'],
            password=ssh_config['password'],
            key_filename=ssh_config['key_filename'],
            port=ssh_config['port'],
            remote_path="/tmp/mcp_test_concurrent.txt",
            content="test",
            use_sudo=True, # Forces shell usage
            sudo_password="placeholder" 
        )
        
        print(f"Write result: code={exit_code}, stderr={stderr}")
        assert exit_code == 1
        assert "A command is already running" in stderr

        # 4. Wait for async command to finish
        print("Waiting for async command to finish...")
        while True:
            status = session_manager.get_command_status(command_id)
            if status['status'] != 'running':
                break
            time.sleep(1)
            
        print("Async command finished.")
        
        # 5. Now verify we can run commands again
        print("Attempting command after finish...")
        stdout, stderr, exit_code = session_manager.execute_command(
            host=ssh_config['host'],
            username=ssh_config['username'],
            password=ssh_config['password'],
            key_filename=ssh_config['key_filename'],
            port=ssh_config['port'],
            command="echo 'Success'",
            timeout=5
        )
        assert exit_code == 0
        assert "Success" in stdout
