"""Data structures for SSH session management."""
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional, List, Dict
from datetime import datetime
import threading


class CommandStatus(Enum):
    RUNNING = "running"
    AWAITING_INPUT = "awaiting_input"  # Waiting for user input (password, prompt, etc.)
    COMPLETED = "completed"
    INTERRUPTED = "interrupted"
    FAILED = "failed"
    STREAMING = "streaming"  # New: For long-running commands with streaming output


class ErrorCategory(Enum):
    """Categories of errors for better user understanding."""
    NETWORK = "network"
    AUTHENTICATION = "authentication" 
    TIMEOUT = "timeout"
    COMMAND = "command"
    PROTOCOL = "protocol"
    PERMISSION = "permission"
    UNKNOWN = "unknown"


@dataclass
class ErrorInfo:
    """Structured error information with troubleshooting hints."""
    category: ErrorCategory
    message: str
    original_error: Optional[str] = None
    troubleshooting_hint: Optional[str] = None
    suggest_action: Optional[str] = None


@dataclass
class SessionDiagnostics:
    """Diagnostic information about an SSH session."""
    session_key: str
    shell_type: Optional[str] = None
    captured_prompt: Optional[str] = None
    generalized_prompt: Optional[str] = None
    prompt_pattern: Optional[str] = None
    last_activity: Optional[datetime] = None
    command_history: List[str] = field(default_factory=list)
    prompt_detection_confidence: float = 0.0
    shell_state: Dict[str, Any] = field(default_factory=dict)
    connection_health: str = "unknown"  # "healthy", "degraded", "dead"


@dataclass
class RunningCommand:
    command_id: str
    session_key: str
    command: str
    shell: Any
    future: Any
    status: CommandStatus
    stdout: str
    stderr: str
    exit_code: Optional[int]
    start_time: datetime
    end_time: Optional[datetime]
    awaiting_input_reason: Optional[str] = None  # What is the command waiting for? (e.g., "password", "user_input")
    monitoring_cancelled: threading.Event = field(default_factory=threading.Event)
    sentinel: Optional[str] = None  # Sentinel marker used for Unix command completion
    
    # New fields for enhanced UX
    auto_extend_timeout: bool = False
    max_timeout: int = 300  # Maximum timeout if auto-extending
    progress_callback: Optional[str] = None  # MCP tool name for progress callbacks
    streaming_mode: bool = False
    last_output_time: Optional[datetime] = None
    output_chunks: List[str] = field(default_factory=list)  # For streaming mode


@dataclass
class ConnectionProfile:
    """Cached SSH connection profile for performance."""
    hostname: str
    username: str
    port: int
    key_filename: Optional[str]
    config_host: Optional[str]  # Original SSH config alias
    resolved_at: datetime = field(default_factory=datetime.now)
    
    # Performance metrics
    connect_count: int = 0
    last_connect: Optional[datetime] = None
    avg_connect_time: float = 0.0
    connection_health: str = "unknown"  # "healthy", "degraded", "dead"