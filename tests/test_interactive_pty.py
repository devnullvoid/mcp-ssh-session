"""Tests for interactive PTY mode functionality."""

import os
import pytest
from mcp_ssh_session.session_manager import SSHSessionManager


class TestInteractivePTY:
    """Test interactive PTY mode features."""

    def test_interactive_mode_enabled_by_default(self):
        """Test that interactive mode is enabled by default (v0.2.0+)."""
        # Ensure env var is not set (should default to enabled)
        os.environ.pop("MCP_SSH_INTERACTIVE_MODE", None)
        
        manager = SSHSessionManager()
        assert manager._interactive_mode
        assert len(manager._session_emulators) == 0

    def test_interactive_mode_can_be_disabled(self):
        """Test that interactive mode can be explicitly disabled."""
        os.environ["MCP_SSH_INTERACTIVE_MODE"] = "0"

        manager = SSHSessionManager()
        assert not manager._interactive_mode
        assert len(manager._session_emulators) == 0

        # Cleanup
        os.environ.pop("MCP_SSH_INTERACTIVE_MODE", None)

    def test_interactive_mode_enabled_with_flag(self):
        """Test that interactive mode can be enabled."""
        os.environ["MCP_SSH_INTERACTIVE_MODE"] = "1"
        
        manager = SSHSessionManager()
        assert manager._interactive_mode
        
        # Cleanup
        os.environ.pop("MCP_SSH_INTERACTIVE_MODE", None)

    @pytest.mark.skipif(
        not os.environ.get("SSH_TEST_HOST"),
        reason="SSH_TEST_HOST not set"
    )
    def test_emulator_created_for_session(self):
        """Test that emulator is created when session is established."""
        os.environ["MCP_SSH_INTERACTIVE_MODE"] = "1"
        
        manager = SSHSessionManager()
        
        try:
            # Execute a simple command
            stdout, stderr, exit_code = manager.execute_command(
                host=os.environ["SSH_TEST_HOST"],
                username=os.environ.get("SSH_TEST_USER"),
                password=os.environ.get("SSH_TEST_PASSWORD"),
                key_filename=os.environ.get("SSH_TEST_KEY_FILE"),
                command="echo 'test'"
            )
            
            assert exit_code == 0
            
            # Check emulator was created
            sessions = manager.list_sessions()
            assert len(sessions) > 0
            
            session_key = sessions[0]
            assert session_key in manager._session_emulators
            
            screen, stream = manager._session_emulators[session_key]
            assert screen is not None
            assert stream is not None
            
        finally:
            manager.close_all_sessions()
            os.environ.pop("MCP_SSH_INTERACTIVE_MODE", None)

    @pytest.mark.skipif(
        not os.environ.get("SSH_TEST_HOST"),
        reason="SSH_TEST_HOST not set"
    )
    def test_screen_snapshot_basic(self):
        """Test basic screen snapshot functionality."""
        os.environ["MCP_SSH_INTERACTIVE_MODE"] = "1"
        
        manager = SSHSessionManager()
        
        try:
            # Execute command
            stdout, stderr, exit_code = manager.execute_command(
                host=os.environ["SSH_TEST_HOST"],
                username=os.environ.get("SSH_TEST_USER"),
                password=os.environ.get("SSH_TEST_PASSWORD"),
                key_filename=os.environ.get("SSH_TEST_KEY_FILE"),
                command="echo 'Hello PTY'"
            )
            
            assert exit_code == 0
            
            # Get screen snapshot
            sessions = manager.list_sessions()
            session_key = sessions[0]
            
            snapshot = manager._get_screen_snapshot(session_key)
            
            # Verify snapshot structure
            assert "lines" in snapshot
            assert "cursor_x" in snapshot
            assert "cursor_y" in snapshot
            assert "width" in snapshot
            assert "height" in snapshot
            
            # Verify dimensions
            assert snapshot["width"] == 100
            assert snapshot["height"] == 24
            
            # Verify lines is a list
            assert isinstance(snapshot["lines"], list)
            assert len(snapshot["lines"]) <= 24
            
        finally:
            manager.close_all_sessions()
            os.environ.pop("MCP_SSH_INTERACTIVE_MODE", None)

    @pytest.mark.skipif(
        not os.environ.get("SSH_TEST_HOST"),
        reason="SSH_TEST_HOST not set"
    )
    def test_screen_captures_output(self):
        """Test that screen captures command output."""
        os.environ["MCP_SSH_INTERACTIVE_MODE"] = "1"
        
        manager = SSHSessionManager()
        
        try:
            # Execute command with known output
            test_string = "UNIQUE_TEST_STRING_12345"
            stdout, stderr, exit_code = manager.execute_command(
                host=os.environ["SSH_TEST_HOST"],
                username=os.environ.get("SSH_TEST_USER"),
                password=os.environ.get("SSH_TEST_PASSWORD"),
                key_filename=os.environ.get("SSH_TEST_KEY_FILE"),
                command=f"echo '{test_string}'"
            )
            
            assert exit_code == 0
            assert test_string in stdout
            
            # Note: Screen may have scrolled, so we don't assert the string
            # is still visible. The important thing is the emulator was fed.
            sessions = manager.list_sessions()
            session_key = sessions[0]
            
            snapshot = manager._get_screen_snapshot(session_key)
            assert len(snapshot["lines"]) > 0
            
        finally:
            manager.close_all_sessions()
            os.environ.pop("MCP_SSH_INTERACTIVE_MODE", None)

    @pytest.mark.skipif(
        not os.environ.get("SSH_TEST_HOST"),
        reason="SSH_TEST_HOST not set"
    )
    def test_send_input_by_session(self):
        """Test sending input to a session."""
        os.environ["MCP_SSH_INTERACTIVE_MODE"] = "1"
        
        manager = SSHSessionManager()
        
        try:
            # Establish session
            stdout, stderr, exit_code = manager.execute_command(
                host=os.environ["SSH_TEST_HOST"],
                username=os.environ.get("SSH_TEST_USER"),
                password=os.environ.get("SSH_TEST_PASSWORD"),
                key_filename=os.environ.get("SSH_TEST_KEY_FILE"),
                command="echo 'initial'"
            )
            
            assert exit_code == 0
            
            # Send input
            success, out, err = manager.send_input_by_session(
                host=os.environ["SSH_TEST_HOST"],
                username=os.environ.get("SSH_TEST_USER"),
                input_text="echo 'sent input'\n"
            )
            
            assert success
            
        finally:
            manager.close_all_sessions()
            os.environ.pop("MCP_SSH_INTERACTIVE_MODE", None)

    @pytest.mark.skipif(
        not os.environ.get("SSH_TEST_HOST"),
        reason="SSH_TEST_HOST not set"
    )
    def test_multiple_commands_with_emulator(self):
        """Test that emulator persists across multiple commands."""
        os.environ["MCP_SSH_INTERACTIVE_MODE"] = "1"
        
        manager = SSHSessionManager()
        
        try:
            host = os.environ["SSH_TEST_HOST"]
            user = os.environ.get("SSH_TEST_USER")
            password = os.environ.get("SSH_TEST_PASSWORD")
            keyfile = os.environ.get("SSH_TEST_KEY_FILE")
            
            # First command
            stdout1, stderr1, exit1 = manager.execute_command(
                host=host, username=user, password=password,
                key_filename=keyfile, command="echo 'first'"
            )
            assert exit1 == 0
            
            sessions = manager.list_sessions()
            session_key = sessions[0]
            
            # Verify emulator exists
            assert session_key in manager._session_emulators
            emulator1 = manager._session_emulators[session_key]
            
            # Second command
            stdout2, stderr2, exit2 = manager.execute_command(
                host=host, username=user, password=password,
                key_filename=keyfile, command="echo 'second'"
            )
            assert exit2 == 0
            
            # Verify same emulator is used
            emulator2 = manager._session_emulators[session_key]
            assert emulator1 is emulator2
            
            # Get snapshot
            snapshot = manager._get_screen_snapshot(session_key)
            assert snapshot["width"] == 100
            assert snapshot["height"] == 24
            
        finally:
            manager.close_all_sessions()
            os.environ.pop("MCP_SSH_INTERACTIVE_MODE", None)

    def test_screen_snapshot_without_interactive_mode(self):
        """Test that screen snapshot returns error when interactive mode is off."""
        os.environ.pop("MCP_SSH_INTERACTIVE_MODE", None)
        
        manager = SSHSessionManager()
        
        # Try to get snapshot without interactive mode
        snapshot = manager._get_screen_snapshot("fake_session")
        
        assert "error" in snapshot
        assert snapshot["lines"] == []
        assert snapshot["width"] == 0
        assert snapshot["height"] == 0


class TestModeInference:
    """Test mode inference from screen content."""

    def test_mode_inference_vim_insert(self):
        """Test detection of vim in insert mode."""
        os.environ["MCP_SSH_INTERACTIVE_MODE"] = "1"
        
        manager = SSHSessionManager()
        
        # Create a fake session with emulator
        session_key = "test@localhost:22"
        import pyte
        screen = pyte.Screen(100, 24)
        stream = pyte.Stream(screen)
        manager._session_emulators[session_key] = (screen, stream)
        
        # Simulate vim insert mode output
        vim_output = "\n" * 20 + "-- INSERT --\n"
        stream.feed(vim_output)
        
        # Infer mode
        mode = manager._infer_mode_from_screen(session_key)
        
        assert mode == 'editor'
        assert manager._session_modes[session_key] == 'editor'
        
        os.environ.pop("MCP_SSH_INTERACTIVE_MODE", None)

    def test_mode_inference_vim_tildes(self):
        """Test detection of vim by tilde markers."""
        os.environ["MCP_SSH_INTERACTIVE_MODE"] = "1"
        
        manager = SSHSessionManager()
        
        session_key = "test@localhost:22"
        import pyte
        screen = pyte.Screen(100, 24)
        stream = pyte.Stream(screen)
        manager._session_emulators[session_key] = (screen, stream)
        
        # Simulate vim with many tildes
        vim_output = "~\n" * 10
        stream.feed(vim_output)
        
        mode = manager._infer_mode_from_screen(session_key)
        
        assert mode == 'editor'
        
        os.environ.pop("MCP_SSH_INTERACTIVE_MODE", None)

    def test_mode_inference_nano(self):
        """Test detection of nano editor."""
        os.environ["MCP_SSH_INTERACTIVE_MODE"] = "1"
        
        manager = SSHSessionManager()
        
        session_key = "test@localhost:22"
        import pyte
        screen = pyte.Screen(100, 24)
        stream = pyte.Stream(screen)
        manager._session_emulators[session_key] = (screen, stream)
        
        # Simulate nano output
        nano_output = "  GNU nano 6.2\n\n^G Get Help  ^O Write Out\n"
        stream.feed(nano_output)
        
        mode = manager._infer_mode_from_screen(session_key)
        
        assert mode == 'editor'
        
        os.environ.pop("MCP_SSH_INTERACTIVE_MODE", None)

    def test_mode_inference_less_pager(self):
        """Test detection of less pager."""
        os.environ["MCP_SSH_INTERACTIVE_MODE"] = "1"
        
        manager = SSHSessionManager()
        
        session_key = "test@localhost:22"
        import pyte
        screen = pyte.Screen(100, 24)
        stream = pyte.Stream(screen)
        manager._session_emulators[session_key] = (screen, stream)
        
        # Simulate less pager at end
        pager_output = "Line 1\nLine 2\nLine 3\n(END)"
        stream.feed(pager_output)
        
        mode = manager._infer_mode_from_screen(session_key)
        
        assert mode == 'pager'
        
        os.environ.pop("MCP_SSH_INTERACTIVE_MODE", None)

    def test_mode_inference_less_colon(self):
        """Test detection of less pager with colon prompt."""
        os.environ["MCP_SSH_INTERACTIVE_MODE"] = "1"
        
        manager = SSHSessionManager()
        
        session_key = "test@localhost:22"
        import pyte
        screen = pyte.Screen(100, 24)
        stream = pyte.Stream(screen)
        manager._session_emulators[session_key] = (screen, stream)
        
        # Simulate less pager with : prompt
        pager_output = "Line 1\nLine 2\n:"
        stream.feed(pager_output)
        
        mode = manager._infer_mode_from_screen(session_key)
        
        assert mode == 'pager'
        
        os.environ.pop("MCP_SSH_INTERACTIVE_MODE", None)

    def test_mode_inference_password_prompt(self):
        """Test detection of password prompt."""
        os.environ["MCP_SSH_INTERACTIVE_MODE"] = "1"
        
        manager = SSHSessionManager()
        
        session_key = "test@localhost:22"
        import pyte
        screen = pyte.Screen(100, 24)
        stream = pyte.Stream(screen)
        manager._session_emulators[session_key] = (screen, stream)
        
        # Simulate password prompt
        prompt_output = "[sudo] password for user:"
        stream.feed(prompt_output)
        
        mode = manager._infer_mode_from_screen(session_key)
        
        assert mode == 'password_prompt'
        
        os.environ.pop("MCP_SSH_INTERACTIVE_MODE", None)

    def test_mode_aware_awaiting_input_editor(self):
        """Test that awaiting_input is skipped in editor mode."""
        os.environ["MCP_SSH_INTERACTIVE_MODE"] = "1"
        
        manager = SSHSessionManager()
        
        session_key = "test@localhost:22"
        manager._session_modes[session_key] = 'editor'
        
        # Try to detect awaiting input (should return None for editor)
        result = manager._detect_awaiting_input("some output", session_key)
        
        assert result is None
        
        os.environ.pop("MCP_SSH_INTERACTIVE_MODE", None)

    def test_mode_aware_awaiting_input_pager(self):
        """Test that awaiting_input works for pager mode."""
        os.environ["MCP_SSH_INTERACTIVE_MODE"] = "1"
        
        manager = SSHSessionManager()
        
        session_key = "test@localhost:22"
        manager._session_modes[session_key] = 'pager'
        
        # Try to detect pager prompt
        result = manager._detect_awaiting_input("some output\n(END)", session_key)
        
        assert result == 'pager'
        
        os.environ.pop("MCP_SSH_INTERACTIVE_MODE", None)
