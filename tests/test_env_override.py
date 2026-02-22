"""Tests for environment variable override system."""

import os
import pytest
from unittest.mock import patch, MagicMock

from mcp_ssh_session.session_manager import SSHSessionManager


class TestEnvOverrideSystem:
    """Test environment variable override system for credential hiding."""

    def setup_method(self):
        """Set up test fixtures."""
        self.manager = SSHSessionManager()
        # Clear any existing env vars that might interfere
        for key in list(os.environ.keys()):
            if key.startswith("OVRD_"):
                del os.environ[key]

    def teardown_method(self):
        """Clean up after tests."""
        # Clear test env vars
        for key in list(os.environ.keys()):
            if key.startswith("OVRD_"):
                del os.environ[key]

    def test_resolve_connection_no_override(self):
        """Test connection resolution without env overrides."""
        host_config, resolved_host, resolved_username, resolved_port, session_key = (
            self.manager._resolve_connection("example.com", "testuser", 2222)
        )

        assert resolved_host == "example.com"
        assert resolved_username == "testuser"
        assert resolved_port == 2222
        assert session_key == "testuser@example.com:2222"

    def test_resolve_connection_host_override(self):
        """Test host override via environment variable."""
        os.environ["OVRD_myserver_HOST"] = "192.168.1.100"

        host_config, resolved_host, resolved_username, resolved_port, session_key = (
            self.manager._resolve_connection("myserver", "testuser", 22)
        )

        assert resolved_host == "192.168.1.100"
        assert resolved_username == "testuser"
        assert session_key == "testuser@192.168.1.100:22"

    def test_resolve_connection_user_override(self):
        """Test user override via environment variable."""
        os.environ["OVRD_myserver_USER"] = "admin"

        host_config, resolved_host, resolved_username, resolved_port, session_key = (
            self.manager._resolve_connection("myserver", "testuser", 22)
        )

        assert resolved_host == "myserver"
        assert resolved_username == "admin"

    def test_resolve_connection_port_override(self):
        """Test port override via environment variable."""
        os.environ["OVRD_myserver_PORT"] = "2222"

        host_config, resolved_host, resolved_username, resolved_port, session_key = (
            self.manager._resolve_connection("myserver", "testuser", 22)
        )

        assert resolved_port == 2222
        assert session_key == "testuser@myserver:2222"

    def test_resolve_connection_invalid_port_override(self):
        """Test invalid port override is handled gracefully."""
        os.environ["OVRD_myserver_PORT"] = "invalid"

        host_config, resolved_host, resolved_username, resolved_port, session_key = (
            self.manager._resolve_connection("myserver", "testuser", 22)
        )

        # Should fall back to provided port when invalid
        assert resolved_port == 22

    def test_resolve_connection_all_overrides(self):
        """Test all connection parameters can be overridden."""
        os.environ["OVRD_prod_db_HOST"] = "10.0.0.50"
        os.environ["OVRD_prod_db_USER"] = "dbadmin"
        os.environ["OVRD_prod_db_PORT"] = "2222"

        host_config, resolved_host, resolved_username, resolved_port, session_key = (
            self.manager._resolve_connection("prod_db", "user", 22)
        )

        assert resolved_host == "10.0.0.50"
        assert resolved_username == "dbadmin"
        assert resolved_port == 2222
        assert session_key == "dbadmin@10.0.0.50:2222"

    def test_get_env_override_helper(self):
        """Test the _get_env_override helper method."""
        os.environ["OVRD_test_PASS"] = "secret123"
        os.environ["OVRD_test_KEY"] = "/path/to/key"

        assert self.manager._get_env_override("test", "PASS") == "secret123"
        assert self.manager._get_env_override("test", "KEY") == "/path/to/key"
        assert self.manager._get_env_override("test", "NONEXISTENT") is None
        assert self.manager._get_env_override("test", "NONEXISTENT", "default") == "default"

    def test_get_env_override_different_hosts(self):
        """Test that overrides are host-specific."""
        os.environ["OVRD_host1_PASS"] = "pass1"
        os.environ["OVRD_host2_PASS"] = "pass2"

        assert self.manager._get_env_override("host1", "PASS") == "pass1"
        assert self.manager._get_env_override("host2", "PASS") == "pass2"

    def test_backward_compatibility_no_env_vars(self):
        """Test that system works normally when no env vars are set."""
        host_config, resolved_host, resolved_username, resolved_port, session_key = (
            self.manager._resolve_connection("example.com", "user", 22)
        )

        assert resolved_host == "example.com"
        assert resolved_username == "user"
        assert resolved_port == 22

    def test_env_var_prefix_format(self):
        """Test that env var prefix is correctly formatted."""
        # Test with various host names
        test_cases = [
            ("myserver", "OVRD_myserver_"),
            ("prod-db", "OVRD_prod-db_"),
            ("web_server", "OVRD_web_server_"),
            ("192.168.1.1", "OVRD_192.168.1.1_"),
        ]

        for host, expected_prefix in test_cases:
            os.environ[f"{expected_prefix}TEST"] = "value"
            result = self.manager._get_env_override(host, "TEST")
            assert result == "value", f"Failed for host: {host}"
            del os.environ[f"{expected_prefix}TEST"]
