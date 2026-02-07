"""Tests for enhanced SSH session features."""

import pytest
from mcp_ssh_session.datastructures import ErrorInfo, ErrorCategory, SessionDiagnostics
from mcp_ssh_session.error_handler import ErrorHandler, ProgressReporter
from mcp_ssh_session.logging_manager import get_logger, get_context_logger
from mcp_ssh_session.session_diagnostics import (
    SessionDiagnostics as SessionDiagnosticsImpl,
)
from mcp_ssh_session.enhanced_executor import EnhancedCommandExecutor


class TestEnhancedFeatures:
    """Test enhanced SSH session features."""

    def test_error_handler(self):
        """Test enhanced error handling."""
        # Test network error
        network_error = ErrorHandler.categorize_error("Connection refused")
        assert network_error.category == ErrorCategory.NETWORK
        assert network_error.message is not None

        # Test authentication error
        auth_error = ErrorHandler.categorize_error("Authentication failed")
        assert auth_error.category == ErrorCategory.AUTHENTICATION
        assert auth_error.message is not None

        # Format for AI
        formatted = ErrorHandler.format_error_for_ai(network_error)
        assert isinstance(formatted, str)
        assert len(formatted) > 0

    def test_progress_reporter(self):
        """Test progress reporting."""
        # Test progress format
        progress = ProgressReporter.format_progress(
            50, 100, "File Transfer", "backup.tar.gz"
        )
        assert isinstance(progress, str)
        assert "50.0%" in progress
        assert "File Transfer" in progress

        # Test streaming output
        streaming = ProgressReporter.format_streaming_output(
            "test output", "cmd-123", 1024
        )
        assert isinstance(streaming, str)
        assert "cmd-123" in streaming
        assert "test output" in streaming

    def test_enhanced_logging(self):
        """Test enhanced logging system."""
        logger = get_logger("test_enhanced")
        context_logger = get_context_logger("test_enhanced")

        # Test rate limiting (should not raise exceptions)
        for i in range(5):
            logger.info(f"Repeated message {i}", "test_key")

        # Test context logging
        context_logger.log_operation_start("test_operation", "details")
        context_logger.log_operation_end("test_operation", True)

        # Test performance logging
        logger.performance("test_operation", 1.5, {"iterations": 10})

        # Get stats
        stats = logger.get_stats()
        assert isinstance(stats, dict)
        assert "log_counts" in stats
        assert "uptime_seconds" in stats

    def test_data_structures(self):
        """Test enhanced data structures."""
        # Test SessionDiagnostics
        diagnostics = SessionDiagnostics(
            session_key="test@example.com:22",
            shell_type="bash",
            connection_health="healthy",
            prompt_detection_confidence=95.0,
        )
        assert diagnostics.session_key == "test@example.com:22"
        assert diagnostics.shell_type == "bash"
        assert diagnostics.connection_health == "healthy"
        assert diagnostics.prompt_detection_confidence == 95.0

        # Test ErrorInfo with all fields
        error_info = ErrorInfo(
            category=ErrorCategory.NETWORK,
            message="Connection failed",
            troubleshooting_hint="Check network connectivity",
            suggest_action="Verify hostname",
        )
        assert error_info.category == ErrorCategory.NETWORK
        assert error_info.message == "Connection failed"
        assert error_info.troubleshooting_hint == "Check network connectivity"
        assert error_info.suggest_action == "Verify hostname"

    def test_integration(self):
        """Test basic integration."""
        # Test import and basic instantiation
        from mcp_ssh_session.session_manager import SSHSessionManager

        session_manager = SSHSessionManager()

        # Test that enhanced components are initialized
        assert hasattr(session_manager, "enhanced_executor")
        assert hasattr(session_manager, "session_diagnostics")
        assert hasattr(session_manager, "connection_profiles")

        # Test enhanced methods exist
        assert hasattr(session_manager, "execute_command_enhanced")
        assert hasattr(session_manager, "get_session_diagnostics")
        assert hasattr(session_manager, "reset_session_prompt")

    def test_enhanced_executor_initialization(self):
        """Test EnhancedCommandExecutor initialization."""
        from mcp_ssh_session.session_manager import SSHSessionManager

        session_manager = SSHSessionManager()
        executor = EnhancedCommandExecutor(session_manager)

        assert hasattr(executor, "logger")
        assert hasattr(executor, "context_logger")
        assert hasattr(executor, "session_manager")
        assert hasattr(executor, "_commands")

    def test_session_diagnostics_initialization(self):
        """Test SessionDiagnostics initialization."""
        from mcp_ssh_session.session_manager import SSHSessionManager

        session_manager = SSHSessionManager()
        diagnostics_impl = SessionDiagnosticsImpl(session_manager)

        assert hasattr(diagnostics_impl, "session_manager")
        assert diagnostics_impl.session_manager == session_manager
        assert hasattr(diagnostics_impl, "get_session_diagnostics")
        assert hasattr(diagnostics_impl, "logger")
