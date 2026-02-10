"""Command validation and output limiting for SSH sessions."""
import re
import shlex
from typing import Optional, Tuple


class CommandValidator:
    """Validates commands for safety before execution."""

    # Maximum output size in bytes (10MB)
    MAX_OUTPUT_SIZE = 10 * 1024 * 1024

    # Patterns that indicate streaming/indefinite commands
    STREAMING_PATTERNS = []

    # Patterns for background processes
    BACKGROUND_PATTERNS = [
        r'&\s*$',  # Command ending with &
        r'\bnohup\b',
        r'\bdisown\b',
    ]

    # Potentially dangerous commands (optional - can be enabled/disabled)
    DANGEROUS_PATTERNS = [
        r'\brm\s+.*-rf\s+/(?!home|tmp)',  # rm -rf on root paths
        r'\bdd\s+.*of=/dev/',  # dd to device files
        r'\b:\(\)\{.*:\|:.*\};:',  # fork bomb
        r'\bmkfs\b',
        r'\bformat\b',
    ]

    @classmethod
    def validate_command(
        cls, command: str, check_dangerous: bool = False, pty_aware: bool = False
    ) -> Tuple[bool, Optional[str]]:
        """
        Validate a command for safety.

        Args:
            command: The command to validate
            check_dangerous: Whether to check for dangerous patterns

        Returns:
            Tuple of (is_valid: bool, error_message: Optional[str])
        """
        command_lower = command.lower().strip()

        # Check for streaming patterns
        for pattern in cls.STREAMING_PATTERNS:
            if re.search(pattern, command, re.IGNORECASE):
                return False, f"Streaming/interactive command blocked: Matches pattern '{pattern}'. Use finite operations (e.g., 'tail -n 100' instead of 'tail -f')."

        # Check for background processes
        for pattern in cls.BACKGROUND_PATTERNS:
            if re.search(pattern, command, re.IGNORECASE):
                return False, f"Background process blocked: Matches pattern '{pattern}'. Background processes are not allowed."
        if cls._contains_blocked_tmux_invocation(command, pty_aware=pty_aware):
            return False, (
                "Background/interactive tmux invocation blocked. "
                "Use non-interactive file/inspection commands instead."
            )
        if cls._contains_blocked_screen_invocation(command, pty_aware=pty_aware):
            return False, (
                "Background/interactive screen invocation blocked. "
                "Use non-interactive file/inspection commands instead."
            )

        # Check for dangerous commands (optional)
        if check_dangerous:
            for pattern in cls.DANGEROUS_PATTERNS:
                if re.search(pattern, command, re.IGNORECASE):
                    return False, f"Dangerous command blocked: Matches pattern '{pattern}'. This operation is not allowed for safety."

        return True, None

    @classmethod
    def _contains_blocked_tmux_invocation(
        cls, command: str, pty_aware: bool = False
    ) -> bool:
        """Block only actual tmux invocations that start/attach interactive sessions.

        This intentionally avoids false positives for file paths such as ~/.tmux.conf.
        """
        for segment in re.split(r"(?:&&|\|\||;|\|)", command):
            tokens = cls._safe_split(segment)
            if not tokens:
                continue

            cmd_idx = cls._find_invoked_command_index(tokens)
            if cmd_idx is None:
                continue

            executable = tokens[cmd_idx].rsplit("/", 1)[-1].lower()
            if executable != "tmux":
                continue

            args = [t.lower() for t in tokens[cmd_idx + 1 :]]
            if cls._is_blocked_tmux_usage(args, strict=not pty_aware):
                return True

        return False

    @classmethod
    def _contains_blocked_screen_invocation(
        cls, command: str, pty_aware: bool = False
    ) -> bool:
        for segment in re.split(r"(?:&&|\|\||;|\|)", command):
            tokens = cls._safe_split(segment)
            if not tokens:
                continue

            cmd_idx = cls._find_invoked_command_index(tokens)
            if cmd_idx is None:
                continue

            executable = tokens[cmd_idx].rsplit("/", 1)[-1].lower()
            if executable != "screen":
                continue

            args = [t.lower() for t in tokens[cmd_idx + 1 :]]
            if cls._is_blocked_screen_usage(args, strict=not pty_aware):
                return True

        return False

    @staticmethod
    def _safe_split(command: str) -> list[str]:
        try:
            return shlex.split(command.strip())
        except ValueError:
            return command.strip().split()

    @staticmethod
    def _find_invoked_command_index(tokens: list[str]) -> Optional[int]:
        wrappers = {"sudo", "command", "env", "builtin", "exec", "nohup"}
        i = 0
        while i < len(tokens):
            token = tokens[i]
            if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", token):
                i += 1
                continue
            if token in wrappers:
                i += 1
                while i < len(tokens) and tokens[i].startswith("-"):
                    i += 1
                continue
            return i
        return None

    @staticmethod
    def _is_blocked_tmux_usage(args: list[str], strict: bool) -> bool:
        if strict:
            return True

        # Bare tmux starts an interactive session.
        if not args:
            return True

        subcommand = None
        for arg in args:
            if not arg.startswith("-"):
                subcommand = arg
                break

        if subcommand in {"attach", "attach-session", "a"}:
            return True

        if subcommand in {"new", "new-session", "n"}:
            return True

        return False

    @staticmethod
    def _is_blocked_screen_usage(args: list[str], strict: bool) -> bool:
        if strict:
            return True

        # Bare screen opens an interactive terminal multiplexer.
        if not args:
            return True

        safe_flags = {"-ls", "-list", "-wipe", "-v", "--version", "-version"}

        # PTY-aware mode allows read-only discovery commands only.
        if all(arg in safe_flags for arg in args):
            return False

        return True


class OutputLimiter:
    """Limits output size to prevent memory issues."""

    def __init__(self, max_size: int = CommandValidator.MAX_OUTPUT_SIZE):
        self.max_size = max_size
        self.current_size = 0
        self.truncated = False

    def add_chunk(self, chunk: str) -> Tuple[str, bool]:
        """
        Add a chunk of output, enforcing size limits.

        Args:
            chunk: The chunk of output to add

        Returns:
            Tuple of (chunk_to_add: str, should_continue: bool)
        """
        chunk_size = len(chunk.encode('utf-8'))

        if self.current_size + chunk_size > self.max_size:
            # Calculate how much we can still add
            remaining = self.max_size - self.current_size
            if remaining > 0:
                # Truncate the chunk
                truncated_chunk = chunk.encode('utf-8')[:remaining].decode('utf-8', errors='ignore')
                self.current_size = self.max_size
                self.truncated = True
                truncation_msg = f"\n\n[OUTPUT TRUNCATED: Maximum output size of {self.max_size} bytes exceeded]"
                return truncated_chunk + truncation_msg, False
            else:
                return "", False

        self.current_size += chunk_size
        return chunk, True
