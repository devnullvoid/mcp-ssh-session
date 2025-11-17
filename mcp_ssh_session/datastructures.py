"""Data structures for SSH session management."""
from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional
from datetime import datetime


class CommandStatus(Enum):
    RUNNING = "running"
    AWAITING_INPUT = "awaiting_input"  # Waiting for user input (password, prompt, etc.)
    COMPLETED = "completed"
    INTERRUPTED = "interrupted"
    FAILED = "failed"


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
