"""Data structures for SSH session management."""
from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional
from datetime import datetime


class CommandStatus(Enum):
    RUNNING = "running"
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
