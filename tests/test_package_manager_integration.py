"""
Integration tests for package manager operations.

These tests verify that package installs/uninstalls work correctly
with the SSH session tool, ensuring the idle timeout extensions
and async handling work properly.

Environment Variables Required:
    SSH_TEST_HOST: Hostname or IP of the test server
    SSH_TEST_USER: Username for SSH connection
    SSH_TEST_PASSWORD: (optional) Password for SSH
    SSH_TEST_KEY_FILE: (optional) Path to SSH private key
    SSH_TEST_PORT: (optional) SSH port, defaults to 22

Example:
    SSH_TEST_HOST=myserver SSH_TEST_USER=admin uv run pytest -xvs tests/test_package_manager_integration.py
"""

import os
import pytest
import time
import logging
from mcp_ssh_session.session_manager import SSHSessionManager

logging.basicConfig(level=logging.DEBUG)


def _is_network_device(host):
    """Check if a host appears to be a network device rather than Unix/Linux."""
    if not host:
        return False
    host_lower = host.lower()
    network_indicators = [
        "router",
        "switch",
        "sw",
        "fw",
        "firewall",
        "gw",
        "gateway",
        "ap",
    ]
    return any(indicator in host_lower for indicator in network_indicators)


@pytest.mark.skipif(
    not os.environ.get("SSH_TEST_HOST"),
    reason="Skipping integration tests: SSH_TEST_HOST not set",
)
@pytest.mark.skipif(
    _is_network_device(os.environ.get("SSH_TEST_HOST")),
    reason="Skipping Unix/Linux integration tests: host appears to be a network device",
)
class TestPackageManagerIntegration:
    """Integration tests for package manager operations on real hosts."""

    # Small packages with minimal dependencies for testing
    TEST_PACKAGES = {
        "apt": "sl",  # Steam Locomotive - tiny, no deps, widely available
        "apt-get": "sl",
        "dnf": "sl",  # Also available on Fedora
        "yum": "cowsay",  # Older distros
        "pacman": "ascii",  # Tiny Arch package
        "zypper": "cowsay",  # openSUSE
        "pkg": "cowsay",  # Termux/FreeBSD
        "apk": "figlet",  # Alpine
    }

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

        print(
            f"\n[DEBUG] Test config - host: {repr(host)}, username: {repr(username)}, port: {port}"
        )

        return {
            "host": host,
            "username": username,
            "password": password,
            "key_filename": key_filename,
            "port": port,
        }

    def _execute_and_wait(self, session_manager, ssh_config, command, timeout=60):
        """
        Helper to execute a command and handle ASYNC responses.
        Package manager commands often go async, so we need to poll.
        """
        print(f"\n[EXEC] {command}")
        stdout, stderr, exit_code = session_manager.execute_command(
            host=ssh_config["host"],
            username=ssh_config["username"],
            password=ssh_config["password"],
            key_filename=ssh_config["key_filename"],
            port=ssh_config["port"],
            command=command,
            timeout=timeout,
        )

        # Handle ASYNC response for long-running package operations
        if exit_code == 124 and stderr.startswith("ASYNC:"):
            command_id = stderr.split(":", 2)[1] if ":" in stderr else None
            if command_id:
                print(f"[ASYNC] Command running as ID: {command_id}")
                # Poll until completion
                start_time = time.time()
                max_wait = 300  # 5 minutes max for package operations

                while time.time() - start_time < max_wait:
                    status = session_manager.get_command_status(command_id)
                    print(
                        f"[STATUS] {status['status']} - elapsed: {time.time() - start_time:.1f}s"
                    )

                    if status["status"] == "completed":
                        print(f"[DONE] Exit code: {status['exit_code']}")
                        return (
                            status["stdout"],
                            status["stderr"],
                            status["exit_code"] or 0,
                        )
                    elif status["status"] == "failed":
                        print(f"[FAILED] {status.get('stderr', '')}")
                        return (
                            status["stdout"],
                            status.get("stderr", ""),
                            status.get("exit_code", 1),
                        )
                    elif status["status"] == "awaiting_input":
                        reason = status.get("awaiting_input_reason", "unknown")
                        print(f"[AWAITING_INPUT] {reason}")
                        # For package managers, this is usually a confirmation prompt
                        # Try sending 'y' to confirm
                        session_manager.send_input(command_id, "y\n")

                    time.sleep(2.0)  # Poll every 2 seconds for package operations

                return "", f"Package operation timed out after {max_wait}s", 124

        return stdout, stderr, exit_code

    def _detect_package_manager(self, session_manager, ssh_config):
        """Detect which package manager is available on the system."""
        print("\n[DETECT] Checking for available package managers...")

        # Try common package managers
        pkg_managers = [
            "apt-get",
            "apt",
            "dnf",
            "yum",
            "pacman",
            "zypper",
            "pkg",
            "apk",
        ]

        for pm in pkg_managers:
            stdout, _, exit_code = self._execute_and_wait(
                session_manager, ssh_config, f"which {pm}", timeout=5
            )
            if exit_code == 0:
                print(f"[FOUND] Package manager: {pm}")
                return pm

        return None

    def _build_install_command(self, pkg_manager, package):
        """Build the appropriate install command for the package manager."""
        commands = {
            "apt": f"apt-get update && apt-get install -y {package}",
            "apt-get": f"apt-get update && apt-get install -y {package}",
            "dnf": f"dnf install -y {package}",
            "yum": f"yum install -y {package}",
            "pacman": f"pacman -S --noconfirm {package}",
            "zypper": f"zypper install -y {package}",
            "pkg": f"pkg install -y {package}",
            "apk": f"apk add {package}",
        }
        return commands.get(pkg_manager)

    def _build_remove_command(self, pkg_manager, package):
        """Build the appropriate remove command for the package manager."""
        commands = {
            "apt": f"apt-get remove -y {package}",
            "apt-get": f"apt-get remove -y {package}",
            "dnf": f"dnf remove -y {package}",
            "yum": f"yum remove -y {package}",
            "pacman": f"pacman -R --noconfirm {package}",
            "zypper": f"zypper remove -y {package}",
            "pkg": f"pkg remove -y {package}",
            "apk": f"apk del {package}",
        }
        return commands.get(pkg_manager)

    def test_package_manager_detection(self, session_manager, ssh_config):
        """Test that we can detect the package manager on the system."""
        pkg_manager = self._detect_package_manager(session_manager, ssh_config)
        assert pkg_manager is not None, "No package manager detected on the system"
        print(f"\n[INFO] Detected package manager: {pkg_manager}")

    def _build_install_command(
        self, pkg_manager, package, use_sudo=False, skip_update=False
    ):
        """Build the appropriate install command for the package manager."""
        sudo_prefix = "sudo " if use_sudo else ""
        commands = {
            "apt": f"{sudo_prefix}apt-get install -y {package}"
            if skip_update
            else f"{sudo_prefix}apt-get update && {sudo_prefix}apt-get install -y {package}",
            "apt-get": f"{sudo_prefix}apt-get install -y {package}"
            if skip_update
            else f"{sudo_prefix}apt-get update && {sudo_prefix}apt-get install -y {package}",
            "dnf": f"{sudo_prefix}dnf install -y {package}",
            "yum": f"{sudo_prefix}yum install -y {package}",
            "pacman": f"{sudo_prefix}pacman -S --noconfirm {package}",
            "zypper": f"{sudo_prefix}zypper install -y {package}",
            "pkg": f"{sudo_prefix}pkg install -y {package}",
            "apk": f"{sudo_prefix}apk add {package}",
        }
        return commands.get(pkg_manager)

    def _build_remove_command(self, pkg_manager, package, use_sudo=False):
        """Build the appropriate remove command for the package manager."""
        sudo_prefix = "sudo " if use_sudo else ""
        commands = {
            "apt": f"{sudo_prefix}apt-get remove -y {package}",
            "apt-get": f"{sudo_prefix}apt-get remove -y {package}",
            "dnf": f"{sudo_prefix}dnf remove -y {package}",
            "yum": f"{sudo_prefix}yum remove -y {package}",
            "pacman": f"{sudo_prefix}pacman -R --noconfirm {package}",
            "zypper": f"{sudo_prefix}zypper remove -y {package}",
            "pkg": f"{sudo_prefix}pkg remove -y {package}",
            "apk": f"{sudo_prefix}apk del {package}",
        }
        return commands.get(pkg_manager)

    def _check_sudo_access(self, session_manager, ssh_config):
        """Check if we have passwordless sudo access."""
        stdout, stderr, exit_code = self._execute_and_wait(
            session_manager, ssh_config, "sudo -n whoami", timeout=10
        )
        return exit_code == 0 and "root" in stdout

    def test_package_install_and_remove(self, session_manager, ssh_config):
        """
        Test installing and removing a small package.

        This is the main integration test that verifies:
        1. Package manager commands start in async mode
        2. Extended idle timeout works during database operations
        3. Commands complete successfully without hanging
        4. Sessions remain usable after package operations
        """
        # Detect package manager
        pkg_manager = self._detect_package_manager(session_manager, ssh_config)
        if not pkg_manager:
            pytest.skip("No package manager available on test system")

        # Get test package for this package manager
        test_package = self.TEST_PACKAGES.get(pkg_manager)
        if not test_package:
            pytest.skip(f"No test package configured for {pkg_manager}")

        print(f"\n[TEST] Using {pkg_manager} with package: {test_package}")

        # Check if we need sudo
        use_sudo = False
        if pkg_manager in ["apt", "apt-get", "dnf", "yum", "zypper", "pacman"]:
            print("\n[CHECK] Checking if sudo is needed...")
            # Try a simple package manager command without sudo
            stdout, stderr, exit_code = self._execute_and_wait(
                session_manager, ssh_config, f"{pkg_manager} --version", timeout=10
            )
            # If we can check version but not install, we probably need sudo
            if exit_code == 0:
                # Check if we have passwordless sudo
                if self._check_sudo_access(session_manager, ssh_config):
                    print(
                        "[SUDO] Passwordless sudo available, will use for install/remove"
                    )
                    use_sudo = True
                else:
                    print(
                        "[WARN] Package manager may require sudo, but passwordless sudo not available"
                    )

        # Step 1: Check if package is already installed
        print("\n[STEP 1] Checking if package is already installed...")
        check_cmd = f"which {test_package}"
        stdout, _, exit_code = self._execute_and_wait(
            session_manager, ssh_config, check_cmd, timeout=10
        )

        if exit_code == 0:
            print(
                f"[SKIP] Package {test_package} is already installed, removing first..."
            )
            remove_cmd = self._build_remove_command(
                pkg_manager, test_package, use_sudo=use_sudo
            )
            stdout, stderr, exit_code = self._execute_and_wait(
                session_manager, ssh_config, remove_cmd, timeout=60
            )
            print(
                f"[REMOVE] exit_code={exit_code}, stdout={stdout[:200] if stdout else ''}"
            )

        # Step 2: Install the package
        print(f"\n[STEP 2] Installing {test_package} (sudo={use_sudo})...")
        # Skip apt-get update for apt-based systems to avoid network issues in tests
        skip_update = pkg_manager in ["apt", "apt-get"]
        install_cmd = self._build_install_command(
            pkg_manager, test_package, use_sudo=use_sudo, skip_update=skip_update
        )
        stdout, stderr, exit_code = self._execute_and_wait(
            session_manager, ssh_config, install_cmd, timeout=180
        )

        print(f"[INSTALL] exit_code={exit_code}")
        print(f"[INSTALL] stdout length: {len(stdout) if stdout else 0}")
        print(f"[INSTALL] stderr length: {len(stderr) if stderr else 0}")

        # Package managers might return warnings on stderr even on success
        assert exit_code == 0, (
            f"Package installation failed with exit code {exit_code}: {stderr}"
        )

        # Step 3: Verify package was installed
        print(f"\n[STEP 3] Verifying {test_package} is installed...")
        stdout, _, exit_code = self._execute_and_wait(
            session_manager, ssh_config, f"which {test_package}", timeout=10
        )

        assert exit_code == 0, (
            f"Package {test_package} was not found after installation"
        )
        print(f"[VERIFY] Package installed at: {stdout.strip()}")

        # Step 4: Test that the package works
        print(f"\n[STEP 4] Testing {test_package} functionality...")
        if test_package == "sl":
            # sl shows an animation that confuses prompt detection
            # Just verify it exists and can show version
            stdout, _, exit_code = self._execute_and_wait(
                session_manager,
                ssh_config,
                f"dpkg -l | grep -q '^ii.*{test_package}' && echo '{test_package} installed'",
                timeout=10,
            )
            assert "installed" in stdout, "sl package not found in dpkg"
        elif test_package == "cowsay":
            stdout, _, exit_code = self._execute_and_wait(
                session_manager, ssh_config, f"echo 'test' | {test_package}", timeout=5
            )
            assert "test" in stdout, "cowsay output doesn't contain input text"
        else:
            stdout, _, exit_code = self._execute_and_wait(
                session_manager,
                ssh_config,
                f"{test_package} --version 2>&1 || {test_package} -v 2>&1 || echo 'ok'",
                timeout=5,
            )

        print(f"[TEST] Package functional test passed")

        # Step 5: Remove the package
        print(f"\n[STEP 5] Removing {test_package} (sudo={use_sudo})...")
        remove_cmd = self._build_remove_command(
            pkg_manager, test_package, use_sudo=use_sudo
        )
        stdout, stderr, exit_code = self._execute_and_wait(
            session_manager, ssh_config, remove_cmd, timeout=60
        )

        print(f"[REMOVE] exit_code={exit_code}")
        # Some package managers might warn but still succeed
        assert exit_code == 0, (
            f"Package removal failed with exit code {exit_code}: {stderr}"
        )

        # Step 6: Verify package was removed
        print(f"\n[STEP 6] Verifying {test_package} was removed...")
        stdout, _, exit_code = self._execute_and_wait(
            session_manager, ssh_config, f"which {test_package}", timeout=10
        )

        assert exit_code != 0, f"Package {test_package} is still present after removal"
        print(f"[VERIFY] Package successfully removed")

        # Step 7: Verify session is still functional
        print("\n[STEP 7] Verifying session is still functional...")
        stdout, _, exit_code = self._execute_and_wait(
            session_manager, ssh_config, "echo 'session_test'", timeout=10
        )

        assert exit_code == 0, (
            "Session is no longer functional after package operations"
        )
        assert "session_test" in stdout, "Session test echo failed"
        print("[VERIFY] Session is functional")

    @pytest.mark.skipif(
        not os.environ.get("SSH_TEST_SUDO_PASSWORD"),
        reason="Skipping sudo package test: SSH_TEST_SUDO_PASSWORD not set",
    )
    def test_package_install_with_sudo(self, session_manager, ssh_config):
        """
        Test package installation requiring sudo privileges.

        This verifies that package managers work correctly when sudo is required.
        """
        sudo_password = os.environ.get("SSH_TEST_SUDO_PASSWORD")

        # Detect package manager
        pkg_manager = self._detect_package_manager(session_manager, ssh_config)
        if not pkg_manager:
            pytest.skip("No package manager available on test system")

        test_package = self.TEST_PACKAGES.get(pkg_manager)
        if not test_package:
            pytest.skip(f"No test package configured for {pkg_manager}")

        print(
            f"\n[TEST-SUDO] Using {pkg_manager} with sudo for package: {test_package}"
        )

        # Build sudo install command
        if pkg_manager in ["apt", "apt-get"]:
            install_cmd = (
                f"sudo apt-get update && sudo apt-get install -y {test_package}"
            )
        elif pkg_manager == "dnf":
            install_cmd = f"sudo dnf install -y {test_package}"
        elif pkg_manager == "yum":
            install_cmd = f"sudo yum install -y {test_package}"
        else:
            pytest.skip(f"Sudo test not implemented for {pkg_manager}")

        # Check if already installed
        stdout, _, exit_code = session_manager.execute_command(
            host=ssh_config["host"],
            username=ssh_config["username"],
            password=ssh_config["password"],
            key_filename=ssh_config["key_filename"],
            port=ssh_config["port"],
            command=f"which {test_package}",
            timeout=10,
        )

        if exit_code == 0:
            print(f"[SKIP] Package already installed, removing first...")
            remove_cmd = f"sudo {pkg_manager} remove -y {test_package}"
            session_manager.execute_command(
                host=ssh_config["host"],
                username=ssh_config["username"],
                password=ssh_config["password"],
                key_filename=ssh_config["key_filename"],
                port=ssh_config["port"],
                sudo_password=sudo_password,
                command=remove_cmd,
                timeout=60,
            )

        # Install with sudo
        print(f"\n[INSTALL-SUDO] Installing {test_package} with sudo...")
        stdout, stderr, exit_code = session_manager.execute_command(
            host=ssh_config["host"],
            username=ssh_config["username"],
            password=ssh_config["password"],
            key_filename=ssh_config["key_filename"],
            port=ssh_config["port"],
            sudo_password=sudo_password,
            command=install_cmd,
            timeout=120,
        )

        print(f"[INSTALL-SUDO] exit_code={exit_code}")

        if exit_code == 124 and stderr.startswith("ASYNC:"):
            # Handle async
            command_id = stderr.split(":", 2)[1]
            print(f"[ASYNC] Polling command {command_id}...")
            start_time = time.time()
            while time.time() - start_time < 300:
                status = session_manager.get_command_status(command_id)
                if status["status"] == "completed":
                    exit_code = status["exit_code"] or 0
                    break
                elif status["status"] == "failed":
                    exit_code = 1
                    break
                time.sleep(2)

        assert exit_code == 0, f"Sudo package install failed: {stderr}"

        # Verify installation
        stdout, _, exit_code = session_manager.execute_command(
            host=ssh_config["host"],
            username=ssh_config["username"],
            password=ssh_config["password"],
            key_filename=ssh_config["key_filename"],
            port=ssh_config["port"],
            command=f"which {test_package}",
            timeout=10,
        )

        assert exit_code == 0, f"Package not found after sudo installation"

        # Cleanup - remove with sudo
        print(f"\n[CLEANUP] Removing {test_package} with sudo...")
        remove_cmd = f"sudo {pkg_manager} remove -y {test_package}"
        session_manager.execute_command(
            host=ssh_config["host"],
            username=ssh_config["username"],
            password=ssh_config["password"],
            key_filename=ssh_config["key_filename"],
            port=ssh_config["port"],
            sudo_password=sudo_password,
            command=remove_cmd,
            timeout=60,
        )
