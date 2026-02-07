"""Optimized logging with rate limiting and performance monitoring."""

import logging
import time
import threading
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, Set
from enum import Enum


class LogLevel(Enum):
    """Log levels with performance considerations."""

    CRITICAL = "CRITICAL"
    ERROR = "ERROR"
    WARNING = "WARNING"
    INFO = "INFO"
    PERFORMANCE = "PERF"
    DEBUG = "DEBUG"


class RateLimitedLogger:
    """Logger with intelligent rate limiting and performance monitoring."""

    def __init__(self, name: str, log_dir: Optional[Path] = None):
        self.name = name
        self.logger = logging.getLogger(name)

        # Rate limiting configuration
        self.log_intervals = {
            LogLevel.DEBUG: 5.0,  # Every 5 seconds
            LogLevel.INFO: 2.0,  # Every 2 seconds
            LogLevel.WARNING: 1.0,  # Every 1 second
            LogLevel.ERROR: 0.5,  # Every 0.5 seconds
            LogLevel.CRITICAL: 0.1,  # No limit for critical
            LogLevel.PERFORMANCE: 10.0,  # Every 10 seconds
        }

        # Rate limiting state
        self._last_log_time: Dict[str, float] = {}
        self._log_counts: Dict[str, int] = {}
        self._lock = threading.Lock()

        # Performance monitoring
        self._performance_metrics: Dict[str, Dict] = {}
        self._start_time = time.time()

        # Setup file logging only (no stdout to avoid MCP notifications)
        self._setup_file_logging(log_dir)

    def _setup_file_logging(self, log_dir: Optional[Path] = None):
        """Setup file logging with rotation."""
        global _file_handler_setup

        if log_dir is None:
            log_dir = Path("/tmp/mcp_ssh_session_logs")

        log_dir.mkdir(exist_ok=True, parents=True)
        # Use a single log file for all loggers
        log_file = log_dir / "mcp_ssh_session.log"

        # Clear existing handlers
        if self.logger.handlers:
            self.logger.handlers.clear()

        # Setup file handler only once globally
        with _file_handler_lock:
            if not _file_handler_setup:
                # Create a shared file handler for all loggers
                shared_handler = logging.FileHandler(str(log_file))
                formatter = logging.Formatter(
                    "%(asctime)s - [%(threadName)s] - %(name)s - %(levelname)s - %(message)s"
                )
                shared_handler.setFormatter(formatter)

                # Store the shared handler for reuse
                if not hasattr(self.__class__, "_shared_handler"):
                    self.__class__._shared_handler = shared_handler

                _file_handler_setup = True

        # Use the shared handler
        if hasattr(self.__class__, "_shared_handler"):
            self.logger.addHandler(self.__class__._shared_handler)

        self.logger.setLevel(logging.DEBUG)
        self.logger.propagate = False

    def _should_log(self, level: LogLevel, key: str) -> bool:
        """Check if message should be logged based on rate limiting."""
        current_time = time.time()

        with self._lock:
            last_time = self._last_log_time.get(key, 0)
            interval = self.log_intervals.get(level, 1.0)

            if current_time - last_time >= interval:
                self._last_log_time[key] = current_time
                self._log_counts[key] = self._log_counts.get(key, 0) + 1
                return True

            return False

    def debug(self, message: str, key: Optional[str] = None):
        """Log debug message with rate limiting."""
        log_key = f"{key}_debug" if key else "debug"
        if self._should_log(LogLevel.DEBUG, log_key):
            self.logger.debug(message)

    def info(self, message: str, key: Optional[str] = None):
        """Log info message with rate limiting."""
        log_key = f"{key}_info" if key else "info"
        if self._should_log(LogLevel.INFO, log_key):
            self.logger.info(message)

    def warning(self, message: str, key: Optional[str] = None):
        """Log warning message with rate limiting."""
        log_key = f"{key}_warning" if key else "warning"
        if self._should_log(LogLevel.WARNING, log_key):
            self.logger.warning(message)

    def error(self, message: str, key: Optional[str] = None):
        """Log error message with rate limiting."""
        log_key = f"{key}_error" if key else "error"
        if self._should_log(LogLevel.ERROR, log_key):
            self.logger.error(message)

    def critical(self, message: str, key: Optional[str] = None):
        """Log critical message without rate limiting."""
        self.logger.critical(message)

    def performance(
        self, operation: str, duration: float, details: Optional[Dict] = None
    ):
        """Log performance metrics."""
        perf_key = f"{operation}_perf"

        if self._should_log(LogLevel.PERFORMANCE, perf_key):
            msg = f"PERF: {operation} took {duration:.3f}s"
            if details:
                msg += f" - {details}"
            self.logger.info(msg)

        # Track metrics
        with self._lock:
            if operation not in self._performance_metrics:
                self._performance_metrics[operation] = {
                    "count": 0,
                    "total_time": 0.0,
                    "min_time": float("inf"),
                    "max_time": 0.0,
                }

            metrics = self._performance_metrics[operation]
            metrics["count"] += 1
            metrics["total_time"] += duration
            metrics["min_time"] = min(metrics["min_time"], duration)
            metrics["max_time"] = max(metrics["max_time"], duration)

    def get_performance_report(self) -> Dict[str, Dict]:
        """Get performance metrics report."""
        report = {}

        with self._lock:
            for operation, metrics in self._performance_metrics.items():
                if metrics["count"] > 0:
                    report[operation] = {
                        "count": metrics["count"],
                        "avg_time": metrics["total_time"] / metrics["count"],
                        "min_time": metrics["min_time"],
                        "max_time": metrics["max_time"],
                        "total_time": metrics["total_time"],
                    }

        return report

    def reset_rate_limits(self):
        """Reset rate limiting counters (useful for debugging)."""
        with self._lock:
            self._last_log_time.clear()
            self._log_counts.clear()

    def getChild(self, suffix: str) -> "RateLimitedLogger":
        """Get a child logger."""
        return RateLimitedLogger(f"{self.name}.{suffix}")

    def get_stats(self) -> Dict[str, any]:
        """Get logging statistics."""
        with self._lock:
            return {
                "log_counts": dict(self._log_counts),
                "last_log_times": dict(self._last_log_time),
                "uptime_seconds": time.time() - self._start_time,
                "performance_metrics": dict(self._performance_metrics),
            }


class ContextLogger:
    """Context-aware logger that adapts based on operation type."""

    def __init__(self, rate_limited_logger: RateLimitedLogger):
        self.base_logger = rate_limited_logger
        self.operation_context: Dict[str, str] = {}
        self._lock = threading.Lock()

    def set_context(self, operation: str, context: str):
        """Set operation context for smarter logging."""
        with self._lock:
            self.operation_context[operation] = context

    def log_operation_start(self, operation: str, details: Optional[str] = None):
        """Log operation start with timing."""
        start_time = time.time()

        # Store timing for later
        context_key = f"{operation}_start"
        with self._lock:
            self.operation_context[context_key] = start_time

        msg = f"Starting {operation}"
        if details:
            msg += f" - {details}"

        self.base_logger.info(msg, f"{operation}_start")

    def log_operation_end(
        self, operation: str, success: bool = True, details: Optional[str] = None
    ):
        """Log operation end with duration and performance tracking."""
        end_time = time.time()

        # Get start time
        context_key = f"{operation}_start"
        with self._lock:
            start_time = self.operation_context.pop(context_key, end_time)

        duration = end_time - start_time
        status = "✓" if success else "✗"

        # Performance logging
        self.base_logger.performance(
            operation, duration, {"success": success, "details": details}
        )

        # Standard logging
        msg = f"{status} {operation} in {duration:.3f}s"
        if details:
            msg += f" - {details}"

        level = LogLevel.INFO if success else LogLevel.WARNING
        if success:
            self.base_logger.info(msg, f"{operation}_end")
        else:
            self.base_logger.warning(msg, f"{operation}_end")

    def log_with_context(self, level: LogLevel, operation: str, message: str):
        """Log message with operation context."""
        context_key = f"{operation}_context"
        with self._lock:
            context = self.operation_context.get(context_key, "general")

        contextual_message = f"[{context}] {message}"

        if level == LogLevel.DEBUG:
            self.base_logger.debug(contextual_message, f"{operation}_context")
        elif level == LogLevel.INFO:
            self.base_logger.info(contextual_message, f"{operation}_context")
        elif level == LogLevel.WARNING:
            self.base_logger.warning(contextual_message, f"{operation}_context")
        elif level == LogLevel.ERROR:
            self.base_logger.error(contextual_message, f"{operation}_context")
        elif level == LogLevel.CRITICAL:
            self.base_logger.critical(contextual_message)


# Global logger instances
_loggers: Dict[str, RateLimitedLogger] = {}
_logger_lock = threading.Lock()
_file_handler_lock = threading.Lock()
_file_handler_setup = False


def get_logger(name: str) -> RateLimitedLogger:
    """Get or create a rate-limited logger instance."""
    with _logger_lock:
        if name not in _loggers:
            _loggers[name] = RateLimitedLogger(f"ssh_session.{name}")
        return _loggers[name]


def get_context_logger(name: str) -> ContextLogger:
    """Get or create a context-aware logger instance."""
    return ContextLogger(get_logger(name))
