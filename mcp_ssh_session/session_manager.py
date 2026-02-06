"""SSH session manager using Paramiko."""

import os
import re
import threading
import time
import uuid
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import paramiko
try:
    NoValidConnectionsError = paramiko.NoValidConnectionsError  # Paramiko <4.0
except AttributeError:  # Paramiko 4.x moved it
    from paramiko.ssh_exception import NoValidConnectionsError  # type: ignore

import pyte

from .command_executor import CommandExecutor
from .datastructures import CommandStatus
from .file_manager import FileManager
from .validation import CommandValidator, OutputLimiter
from .logging_manager import get_logger, get_context_logger, RateLimitedLogger
from .error_handler import ErrorHandler, ProgressReporter
from .session_diagnostics import SessionDiagnostics, ConnectionProfileManager
from .enhanced_executor import EnhancedCommandExecutor
from .datastructures import ErrorInfo, ErrorCategory


class SSHSessionManager:
    """Manages persistent SSH sessions with safety protections."""

    # Default timeouts
    DEFAULT_COMMAND_TIMEOUT = 30
    MAX_COMMAND_TIMEOUT = 300  # 5 minutes maximum

    # Enable mode timeout
    ENABLE_MODE_TIMEOUT = 10

    # Thread pool for timeout enforcement
    MAX_WORKERS = 10

    # Time (seconds) to wait for new output before switching sync commands to async
    SYNC_IDLE_TO_ASYNC = 2.0

    # Maximum bytes allowed for file read/write operations (2MB)
    MAX_FILE_TRANSFER_SIZE = 2 * 1024 * 1024

    def __init__(self):
        self._sessions: Dict[str, paramiko.SSHClient] = {}
        self._enable_mode: Dict[
            str, bool
        ] = {}  # Track which sessions are in enable mode
        self._session_shells: Dict[
            str, Any
        ] = {}  # Track persistent shells for stateful sessions
        self._session_shell_types: Dict[str, str] = {}
        self._session_prompt_patterns: Dict[str, re.Pattern] = {}
        self._session_prompts: Dict[str, str] = {}  # Store literal captured prompts
        self._prompt_miss_count: Dict[
            str, int
        ] = {}  # Track failed prompt matches for regeneration
        self._lock = threading.Lock()
        self._ssh_config = self._load_ssh_config()
        self._command_validator = CommandValidator()
        self._active_commands: Dict[str, Any] = {}
        self._max_completed_commands = 100  # Keep last 100 completed commands
        self._log_rate_limits: Dict[
            str, float
        ] = {}  # Track last log time for rate limiting

        # Terminal emulator support (enabled by default in v0.2.0+)
        self._interactive_mode = os.environ.get("MCP_SSH_INTERACTIVE_MODE", "1") == "1"
        self._session_emulators: Dict[str, Tuple[pyte.Screen, pyte.Stream]] = {}
        self._session_modes: Dict[str, str] = {}  # Track mode: editor, pager, shell, password_prompt, unknown

        # Setup optimized logging
        self.logger = get_logger("ssh_session")
        self.context_logger = get_context_logger("ssh_session")
        self.logger.info("SSHSessionManager initialized with enhanced logging")

        # Initialize enhanced components
        self.enhanced_executor = EnhancedCommandExecutor(self)
        self.session_diagnostics = SessionDiagnostics(self)
        self.connection_profiles = ConnectionProfileManager(self)

        if self._interactive_mode:
            self.logger.info("Interactive PTY mode enabled")
        self.logger.info("SSHSessionManager initialized")

        self.command_executor = CommandExecutor(self)
        self.file_manager = FileManager(self)

    def _feed_emulator(self, session_key: str, data: str) -> None:
        """Feed data to terminal emulator if interactive mode is enabled."""
        if self._interactive_mode and session_key in self._session_emulators:
            _, stream = self._session_emulators[session_key]
            stream.feed(data)
            # Update mode after feeding
            self._infer_mode_from_screen(session_key)

    def _infer_mode_from_screen(self, session_key: str) -> str:
        """Infer the current mode from screen content.
        
        Returns:
            Mode string: 'editor', 'pager', 'password_prompt', 'shell', or 'unknown'
        """
        if not self._interactive_mode or session_key not in self._session_emulators:
            return 'unknown'
        
        screen, _ = self._session_emulators[session_key]
        
        # Get screen content
        lines = []
        for y in range(screen.lines):
            line = screen.display[y].rstrip()
            if line:
                lines.append(line)
        
        if not lines:
            mode = 'unknown'
        else:
            last_line = lines[-1] if lines else ""
            screen_text = '\n'.join(lines)
            
            # Check for editor (vim, nano)
            # Vim: status line with -- INSERT --, -- VISUAL --, or many ~ lines
            if any(marker in screen_text for marker in ['-- INSERT --', '-- VISUAL --', '-- REPLACE --']):
                mode = 'editor'
            elif screen_text.count('~') > 5 and any('~' in line for line in lines[-10:]):
                # Many tildes in last 10 lines suggests vim
                mode = 'editor'
            elif 'GNU nano' in screen_text or '^G Get Help' in screen_text:
                mode = 'editor'
            # Check for pager (less, more)
            elif '(END)' in last_line or last_line.strip() == ':':
                mode = 'pager'
            elif '--More--' in last_line or '-- [Q quit|D dump' in last_line:
                mode = 'pager'
            # Check for password prompt
            elif re.search(r'password[^:=\n"\']*:?\s*$', last_line, re.IGNORECASE):
                mode = 'password_prompt'
            elif re.search(r'passphrase[^:=\n"\']*:?\s*$', last_line, re.IGNORECASE):
                mode = 'password_prompt'
            # Check for shell prompt (has prompt pattern)
            elif session_key in self._session_prompts:
                prompt = self._session_prompts[session_key]
                # Handle wildcard prompts
                if '*' in prompt or '[' in prompt:
                    # Convert wildcard to regex
                    pattern_str = re.escape(prompt).replace(r'\*', '.*?')
                    pattern_str = pattern_str.replace(r'\[>#\]', '[>#]').replace(r'\[\$#\]', '[$#]')
                    if re.search(pattern_str + r'\s*$', last_line):
                        mode = 'shell'
                    else:
                        mode = 'unknown'
                elif last_line.endswith(prompt.rstrip()):
                    mode = 'shell'
                else:
                    mode = 'unknown'
            else:
                mode = 'unknown'
        
        # Store the mode
        self._session_modes[session_key] = mode
        return mode

    def _get_screen_snapshot(self, session_key: str, max_lines: int = 24) -> dict:
        """Get a snapshot of the terminal screen state.
        
        Returns:
            dict with keys: lines (list of strings), cursor_x, cursor_y, width, height
        """
        if not self._interactive_mode or session_key not in self._session_emulators:
            return {
                "error": "Interactive mode not enabled or session not found",
                "lines": [],
                "cursor_x": 0,
                "cursor_y": 0,
                "width": 0,
                "height": 0
            }
        
        screen, _ = self._session_emulators[session_key]
        
        # Get screen lines (pyte stores them as a dict keyed by line number)
        lines = []
        for y in range(min(max_lines, screen.lines)):
            line = screen.display[y]
            lines.append(line.rstrip())
        
        return {
            "lines": lines,
            "cursor_x": screen.cursor.x,
            "cursor_y": screen.cursor.y,
            "width": screen.columns,
            "height": screen.lines
        }

    def _log_debug_rate_limited(
        self, logger: logging.Logger, key: str, msg: str, interval: float = 5.0
    ):
        """Log a debug message only if enough time has passed since last log with this key."""
        now = time.time()
        last_time = self._log_rate_limits.get(key, 0.0)
        if now - last_time >= interval:
            self._log_rate_limits[key] = now
            logger.debug(msg)

    def _resolve_connection(
        self, host: str, username: Optional[str], port: Optional[int]
    ) -> tuple[Dict[str, Any], str, str, int, str]:
        """Resolve SSH connection parameters using config precedence."""
        host_config = self._ssh_config.lookup(host)
        resolved_host = host_config.get("hostname", host)
        resolved_username = username or host_config.get(
            "user", os.getenv("USER", "root")
        )
        resolved_port = port or int(host_config.get("port", 22))
        session_key = f"{resolved_username}@{resolved_host}:{resolved_port}"
        return host_config, resolved_host, resolved_username, resolved_port, session_key

    def _load_ssh_config(self) -> paramiko.SSHConfig:
        """Load SSH config from default locations."""
        ssh_config = paramiko.SSHConfig()
        config_path = Path.home() / ".ssh" / "config"

        if config_path.exists():
            with open(config_path) as f:
                ssh_config.parse(f)

        return ssh_config

    def get_or_create_session(
        self,
        host: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        key_filename: Optional[str] = None,
        port: Optional[int] = None,
    ) -> paramiko.SSHClient:
        """Get existing session or create a new one.

        Args:
            host: Hostname or SSH config alias
            username: SSH username (optional, will use config if available)
            password: Password (optional)
            key_filename: Path to SSH key file (optional, will use config if available)
            port: SSH port (optional, will use config if available, default 22)
        """
        logger = self.logger.getChild("get_session")

        # Get SSH config for this host
        host_config, resolved_host, resolved_username, resolved_port, session_key = (
            self._resolve_connection(host, username, port)
        )
        resolved_key = key_filename or host_config.get("identityfile", [None])[0]

        with self._lock:
            if session_key in self._sessions:
                client = self._sessions[session_key]
                # Check if connection is still alive
                try:
                    transport = client.get_transport()
                    if transport and transport.is_active():
                        logger.debug(f"Reusing active session: {session_key}")
                        self._ensure_shell_type(session_key, client)
                        return client
                    else:
                        logger.warning(
                            f"Found dead session, will recreate: {session_key}"
                        )
                except Exception as e:
                    logger.warning(
                        f"Error checking session, will recreate: {session_key} - {e}"
                    )

                # Connection is dead, remove it
                self._close_session(session_key)

            # Create new session
            logger.info(f"Creating new session: {session_key}")
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            connect_kwargs = {
                "hostname": resolved_host,
                "port": resolved_port,
                "username": resolved_username,
            }

            if password:
                connect_kwargs["password"] = password
            elif resolved_key:
                # Expand ~ in key path
                expanded_key = os.path.expanduser(resolved_key)
                connect_kwargs["key_filename"] = expanded_key

            try:
                # Add connection timeout to prevent hangs
                connect_kwargs["timeout"] = 30  # 30 second connection timeout
                connect_kwargs["banner_timeout"] = 30  # 30 second banner timeout
                connect_kwargs["auth_timeout"] = 30  # 30 second auth timeout

                client.connect(**connect_kwargs)

                self._sessions[session_key] = client
                logger.info(f"Successfully created new session: {session_key}")
                return client
            except (
                paramiko.AuthenticationException,
                paramiko.SSHException,
                NoValidConnectionsError,
                OSError,
                TimeoutError,
            ) as e:
                logger.error(
                    f"Connection failed to {session_key}: {type(e).__name__}: {e}"
                )
                try:
                    client.close()
                except:
                    pass
                raise ConnectionError(
                    f"Unable to connect to {resolved_host}:{resolved_port} - {e}"
                )
            except Exception as e:
                logger.error(
                    f"Unexpected error connecting to {session_key}: {type(e).__name__}: {e}",
                    exc_info=True,
                )
                try:
                    client.close()
                except:
                    pass
                raise ConnectionError(f"Connection failed: {e}")

    def _enter_enable_mode(
        self,
        session_key: str,
        client: paramiko.SSHClient,
        enable_password: str,
        enable_command: str = "enable",
        timeout: int = ENABLE_MODE_TIMEOUT,
    ) -> tuple[bool, str]:
        """Enter enable mode on a network device using the persistent shell."""
        logger = self.logger.getChild("enable_mode")
        logger.info(f"Starting enable mode workflow for {session_key}")

        try:
            # Get the persistent shell for this session
            shell = self._get_or_create_shell(session_key, client)
            shell.settimeout(timeout)

            # Disable paging on network devices
            shell.send("terminal length 0\n")
            time.sleep(0.5)

            # Clear any output from the paging command
            output = ""
            if shell.recv_ready():
                output = shell.recv(4096).decode("utf-8", errors="ignore")

            # Send the enable command
            shell.send(f"{enable_command}\n")
            time.sleep(0.5)

            # Wait for password prompt or enable prompt
            start_time = time.time()
            password_sent = False
            while time.time() - start_time < timeout:
                if shell.recv_ready():
                    chunk = shell.recv(4096).decode("utf-8", errors="ignore")
                    output += chunk

                    # Check if already in enable mode (prompt ends with #)
                    if "#" in output and output.strip().endswith("#"):
                        logger.info("Already in enable mode")
                        self._enable_mode[session_key] = True
                        # Update the session prompt to use # for enable mode
                        # And make it flexible to match mode changes like (Config)# and mode drops to >
                        if session_key in self._session_prompts:
                            old_prompt = self._session_prompts[session_key]
                            # Use regex pattern to match both > and # with mode variations
                            # e.g., (SW1) > becomes (SW1)*[>#] to match (SW1) #, (SW1) >, (SW1) (Config)#, etc.
                            base_prompt = old_prompt.replace(">", "")  # Remove the >
                            enable_prompt = (
                                base_prompt + "*[>#]"
                            )  # Add wildcard and character class for > or #
                            self._session_prompts[session_key] = enable_prompt
                            logger.info(
                                f"Updated prompt from '{old_prompt}' to '{enable_prompt}' (with wildcard for mode variations and > or #)"
                            )
                        return True, "Already in enable mode"

                    # Check for password prompt
                    if re.search(r"[Pp]assword:|password.*:", output):
                        logger.info("Sending enable password")
                        shell.send(f"{enable_password}\n")
                        time.sleep(0.5)
                        password_sent = True
                        break
                time.sleep(0.1)

            if not password_sent:
                error_msg = (
                    f"Timeout waiting for enable password prompt. Output: {output}"
                )
                logger.error(error_msg)
                return False, error_msg

            # Wait for enable prompt after sending password
            output = ""
            start_time = time.time()
            while time.time() - start_time < timeout:
                if shell.recv_ready():
                    chunk = shell.recv(4096).decode("utf-8", errors="ignore")
                    output += chunk
                    # Check if we now have the enable prompt (#)
                    if "#" in output and output.strip().endswith("#"):
                        logger.info("Successfully entered enable mode")
                        self._enable_mode[session_key] = True
                        # Update the session prompt to use # for enable mode
                        # And make it flexible to match mode changes like (Config)# and mode drops to >
                        if session_key in self._session_prompts:
                            old_prompt = self._session_prompts[session_key]
                            # Use regex pattern to match both > and # with mode variations
                            # e.g., (SW1) > becomes (SW1)*[>#] to match (SW1) #, (SW1) >, (SW1) (Config)#, etc.
                            base_prompt = old_prompt.replace(">", "")  # Remove the >
                            enable_prompt = (
                                base_prompt + "*[>#]"
                            )  # Add wildcard and character class for > or #
                            self._session_prompts[session_key] = enable_prompt
                            logger.info(
                                f"Updated prompt from '{old_prompt}' to '{enable_prompt}' (with wildcard for mode variations and > or #)"
                            )
                        return True, "Entered enable mode successfully"
                time.sleep(0.1)

            error_msg = f"Timeout waiting for enable prompt. Output: {output}"
            logger.error(error_msg)
            return False, error_msg

        except Exception as exc:
            error_msg = f"Failed to enter enable mode: {exc}"
            logger.error(error_msg, exc_info=True)
            return False, error_msg

    def close_session(
        self, host: str, username: Optional[str] = None, port: Optional[int] = None
    ):
        """Close a specific session.

        Args:
            host: Hostname or SSH config alias
            username: SSH username (optional, will use config if available)
            port: SSH port (optional, will use config if available)
        """
        logger = self.logger.getChild("close_session")
        _, _, _, _, session_key = self._resolve_connection(host, username, port)
        logger.info(f"Request to close session: {session_key}")
        with self._lock:
            self._close_session(session_key)

    def _close_session(self, session_key: str):
        """Internal method to close a session (not thread-safe)."""
        logger = self.logger.getChild("internal_close")
        logger.debug(f"Closing session resources for {session_key}")

        # Clear any commands for this session first
        logger.debug(f"Clearing commands for {session_key}")
        self.command_executor.clear_session_commands(session_key)

        # Close persistent shell if exists
        if session_key in self._session_shells:
            logger.debug(f"Closing persistent shell for {session_key}")
            try:
                self._session_shells[session_key].close()
            except Exception as e:
                logger.warning(f"Error closing shell for {session_key}: {e}")
            del self._session_shells[session_key]

        if session_key in self._sessions:
            logger.debug(f"Closing SSH client for {session_key}")
            try:
                self._sessions[session_key].close()
            except Exception as e:
                logger.warning(f"Error closing client for {session_key}: {e}")
            del self._sessions[session_key]
        self._session_shell_types.pop(session_key, None)
        self._session_prompt_patterns.pop(session_key, None)
        self._session_prompts.pop(session_key, None)

        # Clean up rate limits
        keys_to_remove = [
            k
            for k in list(self._log_rate_limits.keys())
            if k.startswith(f"{session_key}_")
        ]
        for k in keys_to_remove:
            del self._log_rate_limits[k]

        if session_key in self._session_shell_types:
            del self._session_shell_types[session_key]

        # Clean up enable mode tracking
        if session_key in self._enable_mode:
            logger.debug(f"Cleaning up enable mode tracking for {session_key}")
            del self._enable_mode[session_key]

        logger.info(f"Session closed: {session_key}")

    def close_all_sessions(self):
        """Close all sessions and cleanup resources."""
        logger = self.logger.getChild("close_all")
        logger.info("Closing all active sessions and resources.")
        with self._lock:
            # Clear all commands first
            logger.debug("Clearing all commands")
            self.command_executor.clear_all_commands()

            # Close all persistent shells
            logger.debug(f"Closing {len(self._session_shells)} persistent shells.")
            for key, shell in self._session_shells.items():
                try:
                    shell.close()
                except Exception as e:
                    logger.warning(f"Error closing shell for {key}: {e}")
            self._session_shells.clear()

            # Close all SSH sessions
            logger.debug(f"Closing {len(self._sessions)} SSH clients.")
            for key, client in self._sessions.items():
                try:
                    client.close()
                except Exception as e:
                    logger.warning(f"Error closing client for {key}: {e}")
            self._sessions.clear()
            self._enable_mode.clear()
            self._session_shell_types.clear()
            self._session_prompt_patterns.clear()
            self._session_prompts.clear()
            self._session_shell_types.clear()

        logger.info("All sessions closed.")

    def __del__(self):
        """Cleanup when the session manager is destroyed."""
        logger = self.logger.getChild("destructor")
        logger.info("SSHSessionManager instance being destroyed, ensuring cleanup.")
        try:
            self.close_all_sessions()
        except Exception as e:
            logger.error(f"Error during __del__ cleanup: {e}", exc_info=True)

        # Shutdown the executor when manager is destroyed
        try:
            self.command_executor.shutdown()
        except Exception as e:
            logger.error(f"Error shutting down executor: {e}", exc_info=True)

    def list_sessions(self) -> list[str]:
        """List all active session keys."""
        logger = self.logger.getChild("list_sessions")
        with self._lock:
            sessions = list(self._sessions.keys())
            logger.info(f"Listing {len(sessions)} active sessions.")
            logger.debug(f"Active sessions: {sessions}")
            return sessions

    def _get_or_create_shell(self, session_key: str, client: paramiko.SSHClient) -> Any:
        """Get or create (or recreate) a persistent shell for a session."""
        logger = self.logger.getChild("shell")

        if session_key in self._session_shells:
            shell = self._session_shells[session_key]
            try:
                transport = (
                    shell.get_transport() if hasattr(shell, "get_transport") else None
                )
                if shell.closed or not transport or not transport.is_active():
                    logger.info(f"Shell for {session_key} is dead, recreating")
                    del self._session_shells[session_key]
                else:
                    client_ref = self._sessions.get(session_key)
                    if client_ref:
                        self._ensure_shell_type(session_key, client_ref)
                        # Recapture prompt if not available
                        if session_key not in self._session_prompts:
                            self._capture_prompt(session_key, shell)
                    return shell
            except Exception as exc:
                logger.warning(
                    f"Error checking shell for {session_key}: {exc}. Recreating."
                )
                if session_key in self._session_shells:
                    del self._session_shells[session_key]

        logger.info(f"Creating new persistent shell for {session_key}")
        shell = client.invoke_shell()
        shell.resize_pty(width=100, height=24)

        # Create terminal emulator if interactive mode is enabled
        if self._interactive_mode:
            screen = pyte.Screen(100, 24)
            stream = pyte.Stream(screen)
            self._session_emulators[session_key] = (screen, stream)
            logger.debug(f"Created terminal emulator for {session_key}")

        time.sleep(2)  # Give shell time to initialize
        initial_output = ""
        # Wait up to 5 seconds for initial output/banner (some routers are slow)
        start_wait = time.time()
        while time.time() - start_wait < 5.0:
            if shell.recv_ready():
                chunk = shell.recv(4096).decode("utf-8", errors="ignore")
                logger.debug(f"Initial shell output chunk: {repr(chunk)}")
                initial_output += chunk
                # Feed to emulator if enabled
                if self._interactive_mode and session_key in self._session_emulators:
                    _, stream = self._session_emulators[session_key]
                    stream.feed(chunk)
            elif initial_output and (time.time() - start_wait > 1.0):
                # We got some output and it's quiet, maybe it's done
                break
            time.sleep(0.2)

        self._session_shells[session_key] = shell

        # Build device profile from shell output instead of exec_command
        self._build_device_profile(session_key, initial_output)

        # Capture the actual prompt for this session
        self._capture_prompt(session_key, shell)

        # For non-POSIX Unix shells, start bash to avoid compatibility issues
        # We do this AFTER capturing the initial prompt to ensure the shell is responsive
        device_type = self._session_shell_types.get(session_key, "unknown")
        if device_type == "unix_shell":
            # Detect non-POSIX shells (fish, nushell, elvish, etc.)
            is_non_posix = any(
                indicator in initial_output.lower()
                for indicator in ["fish", "nushell", "elvish", "xonsh"]
            )

            # If not detected from banner, specifically probe for fish shell
            if not is_non_posix:
                logger.debug(f"Probing for fish shell on {session_key}")
                # Use a probe that works in both bash and fish but produces different output
                # In fish, $FISH_VERSION is set. In bash, it's usually not.
                shell.send('echo "FISH_CHECK:$FISH_VERSION"\n')

                probe_output = ""
                start_time = time.time()
                while time.time() - start_time < 2.0:
                    if shell.recv_ready():
                        probe_output += shell.recv(4096).decode(
                            "utf-8", errors="ignore"
                        )
                        if "FISH_CHECK:" in probe_output and "\n" in probe_output:
                            break
                    time.sleep(0.1)

                logger.debug(f"Probe output: {repr(probe_output)}")

                # Look for version number pattern after FISH_CHECK:
                # Fish: FISH_CHECK:3.6.1
                # Bash: FISH_CHECK:
                if re.search(r"FISH_CHECK:\d+\.", probe_output):
                    logger.info(
                        f"Detected fish shell via probe, starting bash for {session_key}"
                    )
                    is_non_posix = True

            if is_non_posix:
                logger.info(
                    f"Starting bash for {session_key} (non-POSIX shell detected)"
                )
                shell.send("bash\n")
                time.sleep(0.5)
                if shell.recv_ready():
                    shell.recv(4096)  # Clear bash startup output

                # Recapture prompt for the new bash shell
                logger.info(f"Recapturing prompt for bash shell on {session_key}")
                self._capture_prompt(session_key, shell)

        logger.info(f"New shell for {session_key} is ready")
        return shell

    def _build_device_profile(self, session_key: str, initial_output: str):
        """Build device profile incrementally from shell output."""
        logger = self.logger.getChild("device_profile")

        # Detect device type from initial output
        device_type = "unknown"
        if initial_output:
            output_lower = initial_output.lower()

            # Network device vendors
            if "mikrotik" in output_lower or "routeros" in output_lower:
                device_type = "mikrotik"
            elif "edgeswitch" in output_lower or "ubiquiti" in output_lower:
                device_type = "edgeswitch"
            elif "cisco" in output_lower or "ios" in output_lower:
                device_type = "cisco"
            elif "juniper" in output_lower or "junos" in output_lower:
                device_type = "juniper"
            elif (
                "fortinet" in output_lower
                or "fortigate" in output_lower
                or "fortios" in output_lower
            ):
                device_type = "fortinet"
            elif "arista" in output_lower or "eos" in output_lower:
                device_type = "arista"
            elif "palo alto" in output_lower or "pan-os" in output_lower:
                device_type = "paloalto"
            elif "checkpoint" in output_lower or "gaia" in output_lower:
                device_type = "checkpoint"
            elif "vyos" in output_lower or "vyatta" in output_lower:
                device_type = "vyos"
            elif "openwrt" in output_lower or "lede" in output_lower:
                device_type = "openwrt"
            # Unix/Linux shells - check for shell indicators or prompt characters
            elif any(
                indicator in output_lower
                for indicator in [
                    "fish",
                    "bash",
                    "zsh",
                    "ubuntu",
                    "debian",
                    "centos",
                    "redhat",
                    "fedora",
                    "linux",
                    "bsd",
                ]
            ) or any(prompt in initial_output for prompt in ["$", "#", "❯"]):
                device_type = "unix_shell"
            # Generic network device fallback
            elif any(
                keyword in output_lower
                for keyword in ["switch", "router", "firewall", "gateway"]
            ):
                device_type = "network_device"
            else:
                device_type = "unknown"

        self._session_shell_types[session_key] = device_type

        # Set up prompt pattern based on device type and actual output
        self._ensure_prompt_pattern(session_key, None, initial_output)

    def _capture_prompt(self, session_key: str, shell: Any) -> Optional[str]:
        """Capture the actual prompt string for this session by sending a marker command.

        This provides the most reliable prompt detection by capturing the exact prompt
        that appears after a known marker, regardless of custom themes or ANSI codes.

        Handles different device types:
        - Unix/Linux shells: Uses echo command with marker
        - Network devices: Sends newline and captures response
        - Generalizes prompts to handle directory changes

        Args:
            session_key: Session identifier
            shell: Interactive shell to capture prompt from

        Returns:
            Captured prompt string (ANSI-stripped), or None if capture failed
        """
        logger = self.logger.getChild("capture_prompt")

        try:
            device_type = self._session_shell_types.get(session_key, "unknown")
            output = ""
            marker = None

            # Strategy depends on device type
            if device_type in (
                "cisco",
                "juniper",
                "fortinet",
                "arista",
                "paloalto",
                "checkpoint",
                "mikrotik",
                "edgeswitch",
                "vyos",
                "openwrt",
                "network_device",
            ):
                # Network devices: just send newline and capture what comes back
                shell.send("\n")
                time.sleep(0.3)

                if shell.recv_ready():
                    output = shell.recv(4096).decode("utf-8", errors="ignore")
                    logger.debug(f"Capture prompt received: {repr(output)}")
            else:
                # Unix/Linux shells: try echo with marker
                marker = f"__MCP_PROMPT_MARKER_{uuid.uuid4().hex[:8]}__"
                shell.send(f'echo "{marker}"\n')
                time.sleep(0.5)

                # Collect output
                start_time = time.time()
                timeout = 10.0

                while time.time() - start_time < timeout:
                    if shell.recv_ready():
                        chunk = shell.recv(4096).decode("utf-8", errors="ignore")
                        logger.debug(f"Capture prompt received chunk: {repr(chunk)}")
                        output += chunk

                        # Check if we've received the marker and subsequent prompt
                        if marker in output:
                            # Give a bit more time for the prompt to appear
                            time.sleep(0.3)
                            if shell.recv_ready():
                                final_chunk = shell.recv(4096).decode(
                                    "utf-8", errors="ignore"
                                )
                                output += final_chunk
                            break
                    time.sleep(0.1)

                # If marker not found, fall back to newline method
                if marker and marker not in output:
                    logger.warning(
                        f"Marker not found, trying newline method for {session_key}"
                    )
                    # Try simple newline approach
                    shell.send("\n")
                    time.sleep(0.5)
                    if shell.recv_ready():
                        fallback_output = shell.recv(4096).decode("utf-8", errors="ignore")
                        logger.debug(f"Capture prompt fallback received: {repr(fallback_output)}")
                        output += fallback_output
                        marker = None  # Disable marker processing

                    # Check if we can identify the device type from the accumulated output
                    output_lower = output.lower()
                    if (
                        "mikrotik" in output_lower
                        or "routeros" in output_lower
                        or re.search(r"\[.+@.+\]\s*>", output)
                    ):
                        logger.info(
                            f"Detected MikroTik device from fallback output for {session_key}"
                        )
                        self._session_shell_types[session_key] = "mikrotik"
                    elif "edgeswitch" in output_lower or "ubiquiti" in output_lower:
                        self._session_shell_types[session_key] = "edgeswitch"
                    elif any(c in output_lower for c in ["cisco", "ios", ">", "#"]):
                        # Very basic check for other network devices
                        if not any(s in output_lower for s in ["bash", "zsh", "fish"]):
                             logger.info(f"Suspect network device for {session_key} based on prompt/output")
                             # Don't set to mikrotik, but maybe generic network_device
                             if device_type == "unknown":
                                 self._session_shell_types[session_key] = "network_device"

            if not output:
                logger.warning(f"No output received for {session_key}")
                return None

            # Extract the prompt
            prompt = None
            if marker and marker in output:
                # Extract prompt after marker
                parts = output.split(marker)
                if len(parts) >= 2:
                    after_marker = parts[-1]
                    clean_after = self._strip_ansi(after_marker)
                    lines = [line for line in clean_after.split("\n") if line.strip()]
                    if lines:
                        prompt = lines[-1].strip()
            else:
                # Extract prompt from simple output (no marker)
                clean_output = self._strip_ansi(output)
                lines = [line for line in clean_output.split("\n") if line.strip()]
                if lines:
                    # Last line is typically the prompt
                    prompt = lines[-1].strip()

            if not prompt:
                logger.warning(f"Empty prompt extracted for {session_key}")
                return None

            # Generalize the prompt to handle context changes (directory, etc.)
            generalized_prompt = self._generalize_prompt(prompt, logger)

            logger.info(f"Captured prompt for {session_key}: {repr(prompt)}")
            if generalized_prompt != prompt:
                logger.debug(f"Generalized to: {repr(generalized_prompt)}")

            self._session_prompts[session_key] = generalized_prompt
            return generalized_prompt

        except Exception as exc:
            logger.error(
                f"Failed to capture prompt for {session_key}: {exc}", exc_info=True
            )
            return None

    def _generalize_prompt(self, prompt: str, logger) -> str:
        """Generalize a captured prompt to handle context changes.

        Makes prompts flexible for:
        - Directory changes: [user@host ~/dir]$ -> [user@host *]$
        - Path changes: user@host:/path$ -> user@host:*$

        Args:
            prompt: The literal captured prompt
            logger: Logger instance

        Returns:
            Generalized prompt pattern (still a literal string with wildcards)
        """
        original = prompt

        # Pattern 1: [user@host directory]$ or [user@host directory]#
        # Generalize: [user@host *]$ or [user@host *]#
        if "[" in prompt and "]" in prompt and ("@" in prompt or " " in prompt):
            # Replace content between last space/@ and ] with *
            # Match [anything] followed by prompt char
            match = re.search(r"(\[[^\]]*[@\s][^\]]*)\]([>#\$%])", prompt)
            if match:
                # Find the last space or path separator in the bracket
                bracket_content = match.group(1)
                prompt_char = match.group(2)
                # Replace everything after last space with *
                if " " in bracket_content:
                    parts = bracket_content.rsplit(" ", 1)
                    generalized = parts[0] + " *]" + prompt_char
                    return generalized

        # Pattern 2: user@host:/path$ or user@host:~$ or user@host:~/path$
        # Generalize: user@host:*$ or user@host:*#
        if ":" in prompt and "@" in prompt:
            # Replace path after : with *
            parts = prompt.rsplit(":", 1)
            if len(parts) == 2:
                # Keep the prompt char at the end
                prompt_char_match = re.search(r"([>#\$%]\s*)$", parts[1])
                if prompt_char_match:
                    prompt_char = prompt_char_match.group(1)
                    generalized = parts[0] + ":*" + prompt_char
                    return generalized
                # If no prompt char found but there's content after colon, still generalize
                elif parts[1].strip():
                    # Assume last character is prompt char
                    content = parts[1].rstrip()
                    if content and content[-1] in ">#$%":
                        prompt_char = content[-1]
                        generalized = parts[0] + ":*" + prompt_char
                        return generalized

        # Pattern 3: user@host directory$ or user@host directory#
        # Generalize: user@host *$ or user@host *#
        if "@" in prompt and " " in prompt:
            match = re.search(r"(@[^\s]+\s+)(.+)([>#\$%]\s*)$", prompt)
            if match:
                prefix = match.group(1)
                prompt_char = match.group(3)
                # Extract user part
                user_part = prompt.split("@")[0]
                generalized = user_part + prefix + "*" + prompt_char
                return generalized

        # Pattern 4: Simple prompts with just directory before prompt char
        # ~/dir$ -> *$ or /path$ -> *$
        # DISABLED: Too dangerous, matches any output ending in prompt char
        # if not '@' in prompt and re.search(r'[~/][^\s]*([>#\$%]\s*)$', prompt):
        #     match = re.search(r'^(.*/)?[^/\s]+([>#\$%]\s*)$', prompt)
        #     if match:
        #         prompt_char = match.group(2)
        #         generalized = '*' + prompt_char
        #         return generalized

        # No generalization needed
        return prompt

    def _ensure_shell_type(self, session_key: str, client: paramiko.SSHClient) -> str:
        """Legacy method - now handled by _build_device_profile."""
        if session_key in self._session_shell_types:
            return self._session_shell_types[session_key]

        # Fallback for cases where profile wasn't built
        self._session_shell_types[session_key] = "unknown"
        return "unknown"

    def _ensure_prompt_pattern(
        self,
        session_key: str,
        client: paramiko.SSHClient,
        initial_output: Optional[str] = None,
        shell: Optional[Any] = None,
    ) -> re.Pattern:
        """Detect and cache shell prompt pattern for reliable command completion detection.

        Args:
            session_key: Session identifier
            client: SSH client (used for exec_command fallback)
            initial_output: Initial shell output to analyze
            shell: Interactive shell (preferred for reading PS1)
        """
        if session_key in self._session_prompt_patterns:
            return self._session_prompt_patterns[session_key]

        logger = self.logger.getChild("detect_prompt")
        pattern: Optional[re.Pattern] = None

        # Try to detect shell type
        shell_type = self._session_shell_types.get(session_key, "unknown").lower()

        # For Fish shell, use a more specific pattern to avoid false positives
        if "fish" in shell_type:
            # Fish prompts typically have context before the prompt character
            pattern = re.compile(r"(\S+\s+)?[>#\$]\s*$")
            logger.debug("Using Fish shell prompt pattern")
        elif shell_type in (
            "cisco",
            "juniper",
            "fortinet",
            "arista",
            "paloalto",
            "checkpoint",
            "mikrotik",
            "edgeswitch",
            "vyos",
            "openwrt",
            "network_device",
        ):
            logger.debug(f"Skipping PS1 check for network device type: {shell_type}")
        else:
            # Try to read $PS1 from interactive shell (preferred) or exec_command (fallback)
            if shell:
                try:
                    # Use markers to extract PS1 from shell output
                    shell.send('echo "___PS1_START___$PS1___PS1_END___"\n')
                    time.sleep(0.5)

                    output = ""
                    start_time = time.time()
                    while time.time() - start_time < 3:
                        if shell.recv_ready():
                            chunk = shell.recv(4096).decode("utf-8", errors="ignore")
                            output += chunk
                            if "___PS1_END___" in output:
                                break
                        time.sleep(0.1)

                    # Extract PS1 between markers
                    match = re.search(
                        r"___PS1_START___(.+?)___PS1_END___", output, re.DOTALL
                    )
                    if match:
                        prompt = match.group(1).strip()
                        if prompt and prompt != "$PS1":
                            pattern = self._convert_ps1_to_pattern(prompt, logger)
                except Exception as exc:
                    logger.warning(
                        f"Failed to read PS1 from shell for {session_key}: {exc}"
                    )

            # Fallback to exec_command if shell method didn't work
            if pattern is None and client:
                try:
                    stdin, stdout, stderr = client.exec_command("echo $PS1", timeout=10)
                    prompt = stdout.read().decode("utf-8").strip()
                    if prompt and prompt != "$PS1":
                        pattern = self._convert_ps1_to_pattern(prompt, logger)
                except Exception as exc:
                    logger.warning(f"Failed to read $PS1 for {session_key}: {exc}")

        # Fallback: extract from initial output
        if pattern is None and initial_output:
            fallback = self._extract_prompt_from_output(initial_output)
            if fallback:
                # Make extracted prompt flexible for directory changes
                if "[" in fallback and "]" in fallback:
                    # Support both [user@host dir]$ and [host]$ patterns
                    flexible_pattern = r"\[[^@\]]+(@[^\]]+)?\][$#]\s*$"
                    pattern = re.compile(flexible_pattern)
                else:
                    escaped = re.escape(fallback)
                    pattern = re.compile(rf"{escaped}\s*$")

        # Enhanced fallback: try common prompt patterns with scoring
        if pattern is None:
            common_patterns = [
                # Network device prompts (more specific first)
                r"\([^)]+\)\s*[>#]\s*$",  # (hostname)> or (hostname)#
                r"[^@\s]+[>#]\s*$",  # hostname> or hostname#
                r"\[[^@]+@[^\]]+\]\s*[>#$]\s*$",  # [user@host]>
                # Unix shell prompts
                r"\[[^@]+@[^\\s\]]+\s+[^\]]*\][$#]\s*$",  # [user@host dir]$ or [user@host dir]#
                r"[^@]+@[^:]+:[^$#]*[$#]\s*$",  # user@host:path$
                r"[^@]+@[^\s]+\s+[^$#]*[$#]\s*$",  # user@host path$
                # Generic prompts (least specific last)
                r"[>#\$%]\s*$",  # Generic prompt chars
            ]

            # Test patterns against initial output if available
            if initial_output:
                clean_output = self._strip_ansi(initial_output)

                # Score patterns by specificity (longer match = more specific)
                pattern_scores = []
                for i, p in enumerate(common_patterns):
                    test_pattern = re.compile(p)
                    match = test_pattern.search(clean_output)
                    if match:
                        # Score based on matched text length (more specific = higher score)
                        score = len(match.group(0))
                        pattern_scores.append((score, i, test_pattern, p))

                if pattern_scores:
                    # Use most specific (highest score) pattern
                    score, best_idx, pattern, pattern_str = max(pattern_scores)

            # Final fallback if no pattern matched
            if pattern is None:
                pattern = re.compile(r"[>#\$]\s*$")

        self._session_prompt_patterns[session_key] = pattern
        self._prompt_miss_count[session_key] = 0  # Reset miss count
        return pattern

    def _convert_ps1_to_pattern(self, prompt: str, logger) -> re.Pattern:
        """Convert PS1 prompt string to regex pattern."""
        # Convert PS1 variables to flexible regex patterns
        pattern_str = prompt
        pattern_str = pattern_str.replace("\\u", "[^@\\s]+")  # username
        pattern_str = pattern_str.replace("\\h", "[^\\s\\]]+")  # hostname
        pattern_str = pattern_str.replace("\\H", "[^\\s\\]]+")  # full hostname
        pattern_str = pattern_str.replace("\\W", "[^\\]\\s]*")  # working dir basename
        pattern_str = pattern_str.replace("\\w", "[^\\]\\s]*")  # full working dir
        pattern_str = pattern_str.replace("\\$", "[$#]")  # $ or #

        # Now escape special regex chars, but preserve our bracket patterns
        # First mark our patterns to protect them
        pattern_str = pattern_str.replace("[^@\\s]+", "___USERNAME___")
        pattern_str = pattern_str.replace("[^\\s\\]]+", "___HOSTNAME___")
        pattern_str = pattern_str.replace("[^\\]\\s]*", "___DIRNAME___")
        pattern_str = pattern_str.replace("[$#]", "___PROMPT___")

        # Escape everything else
        pattern_str = re.escape(pattern_str)

        # Restore our patterns
        pattern_str = pattern_str.replace("___USERNAME___", "[^@\\s]+")
        pattern_str = pattern_str.replace("___HOSTNAME___", "[^\\s\\]]+")
        pattern_str = pattern_str.replace("___DIRNAME___", "[^\\]\\s]*")
        pattern_str = pattern_str.replace("___PROMPT___", "[$#]")

        pattern = re.compile(rf"{pattern_str}\s*$")
        return pattern

    @staticmethod
    def _strip_ansi(text: str) -> str:
        """Strip all ANSI escape sequences including CSI, OSC, and other types."""
        # Remove CSI sequences: \x1b[...
        text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
        # Remove OSC sequences: \x1b]...(\x07|\x1b\\)
        text = re.sub(r"\x1b\][^\x07]*\x07", "", text)
        text = re.sub(r"\x1b\][^\x1b]*\x1b\\", "", text)
        # Remove other escape sequences
        text = re.sub(r"\x1b[PX^_][^\x1b]*\x1b\\", "", text)
        # Remove terminal UI noise like <N> (fish iTerm integration)
        text = re.sub(r"<\d+>", "", text)
        # Remove special characters that appear in terminal output (␤, ⏎, etc.)
        text = re.sub(
            r"[\r\x00\u240c\u23ce]", "", text
        )  # CR, NUL, form feed symbol, return symbol
        # Remove any remaining single control characters
        text = re.sub(r"[\x01-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)
        return text

    @staticmethod
    def _extract_prompt_from_output(output: str) -> Optional[str]:
        """Extract prompt from shell output by finding last line ending with prompt character.

        Uses comprehensive ANSI stripping to handle all escape sequence types.
        """
        lines = [line.rstrip() for line in output.splitlines() if line.strip()]
        for line in reversed(lines):
            # Use comprehensive ANSI stripping instead of basic CSI-only pattern
            stripped = SSHSessionManager._strip_ansi(line)
            if stripped and stripped[-1] in ("$", "#", ">", "%"):
                return stripped.strip()
        return None

    def _build_sentinel_command(self, marker: str, shell_path: str) -> str:
        lower = shell_path.lower()
        if "fish" in lower:
            return (
                "set -l __mcp_status $status; "
                f"printf '\\n{marker}%d\\n' $__mcp_status\n"
            )
        if lower.endswith("csh") or "tcsh" in lower:
            return f'set __mcp_status=$status; echo "{marker}$__mcp_status"\n'
        return (
            "__mcp_status=$?; "
            f'printf \'\\n{marker}%d\\n\' "$__mcp_status" 2>/dev/null || echo "{marker}$__mcp_status"\n'
        )

    def _execute_with_thread_timeout(
        self, func, timeout: int, *args, **kwargs
    ) -> Tuple[str, str, int]:
        """Legacy wrapper retained for compatibility (no additional timeout logic)."""
        try:
            return func(*args, **kwargs)
        except Exception as exc:
            logger = self.logger.getChild("thread_timeout")
            logger.error(f"Error during execution: {exc}", exc_info=True)
            return "", f"Error: {exc}", 1

    def _execute_sudo_command_internal(
        self,
        client: paramiko.SSHClient,
        command: str,
        sudo_password: str,
        timeout: int = 30,
    ) -> tuple[str, str, int]:
        """Execute a sudo command using the persistent shell, handling password prompts.

        Uses the persistent shell from the session to maintain state and benefit from
        prompt detection.
        """
        logger = self.logger.getChild("sudo_command")

        # Get session key for this client
        # We need to derive the session key from the client
        # Find the session key that matches this client
        session_key = None
        with self._lock:
            for key, sess_client in self._sessions.items():
                if sess_client == client:
                    session_key = key
                    break

        if not session_key:
            logger.error("Could not find session key for client")
            return "", "Could not find session for sudo command", 1

        try:
            timeout = min(timeout, self.MAX_COMMAND_TIMEOUT)

            # Ensure command starts with sudo
            if not command.strip().startswith("sudo"):
                command = f"sudo {command}"

            # Get the persistent shell
            shell = self._get_or_create_shell(session_key, client)
            shell.settimeout(timeout)

            # Send the command
            shell.send(command + "\n")
            time.sleep(0.5)

            output_limiter = OutputLimiter()
            raw_output = ""
            password_sent = False
            start_time = time.time()
            last_recv_time = start_time
            idle_timeout = 2.0
            max_idle_checks = 50  # Max 5 seconds of idle checking (50 * 0.1s)
            idle_check_count = 0

            while time.time() - start_time < timeout:
                if shell.recv_ready():
                    chunk = shell.recv(4096).decode("utf-8", errors="ignore")
                    logger.logger.debug(f"Received chunk: {repr(chunk)}")
                    self._feed_emulator(session_key, chunk)
                    last_recv_time = time.time()
                    idle_check_count = 0  # Reset idle check counter on new data
                    limited_chunk, should_continue = output_limiter.add_chunk(chunk)
                    raw_output += limited_chunk

                    # Check for password prompt
                    if not password_sent and re.search(
                        r"\[sudo\] password|password for", raw_output, re.IGNORECASE
                    ):
                        logger.debug("Detected sudo password prompt, sending password")
                        shell.send(f"{sudo_password}\n")
                        password_sent = True
                        time.sleep(0.3)
                        # Clear output buffer to avoid re-detecting the prompt
                        raw_output = ""
                        continue

                    if not should_continue:
                        return (
                            raw_output,
                            f"Output truncated at {output_limiter.max_size} bytes",
                            124,
                        )

                    # Check for interactive prompts (SSH host key, etc.) BEFORE checking completion
                    awaiting = self._detect_awaiting_input(raw_output, session_key)
                    if awaiting:
                        logger.info(f"Sudo command waiting for input: {awaiting}")
                        return raw_output, f"Command requires input: {awaiting}", 1

                    # Check for command completion using prompt detection
                    clean_output = self._strip_ansi(raw_output)
                    is_complete, cleaned_output = self._check_prompt_completion(
                        session_key, raw_output, clean_output
                    )

                    if is_complete:
                        logger.debug("Sudo command completed (prompt detected)")
                        return cleaned_output, "", 0
                else:
                    # Check idle timeout
                    if raw_output and (time.time() - last_recv_time) > idle_timeout:
                        idle_check_count += 1

                        # If we've been idle-checking too long without finding a prompt, break
                        if idle_check_count > max_idle_checks:
                            logger.warning(
                                f"Sudo command exceeded max idle checks ({max_idle_checks}), assuming still running"
                            )
                            break

                        # Check for interactive prompts during idle
                        awaiting = self._detect_awaiting_input(raw_output, session_key)
                        if awaiting:
                            logger.info(
                                f"Sudo command waiting for input (idle): {awaiting}"
                            )
                            return raw_output, f"Command requires input: {awaiting}", 1

                        logger.debug("Sudo command idle timeout, checking completion")
                        clean_output = self._strip_ansi(raw_output)
                        is_complete, cleaned_output = self._check_prompt_completion(
                            session_key, raw_output, clean_output
                        )
                        if is_complete:
                            logger.debug("Sudo command completed (idle timeout)")
                            return cleaned_output, "", 0
                        # If not complete but idle, wait a bit more

                    time.sleep(0.1)

            # Timeout reached
            logger.warning(f"Sudo command timed out after {timeout}s")
            return raw_output.strip(), f"Command timed out after {timeout} seconds", 124

        except paramiko.SSHException as exc:
            logger.error(f"SSH error during sudo command: {exc}")
            return "", f"SSH error: {exc}", 1
        except Exception as exc:
            logger.error(f"Error executing sudo command: {exc}", exc_info=True)
            return "", f"Error executing sudo command: {exc}", 1

    def _execute_sudo_command(
        self,
        client: paramiko.SSHClient,
        command: str,
        sudo_password: str,
        timeout: int = 30,
    ) -> tuple[str, str, int]:
        """Compatibility wrapper around the sudo execution helper."""
        return self._execute_with_thread_timeout(
            self._execute_sudo_command_internal,
            timeout,
            client,
            command,
            sudo_password,
            timeout,
        )

    def _check_prompt_completion(
        self, session_key: str, raw_output: str, clean_output: str
    ) -> tuple[bool, str]:
        """Check if output indicates command completion by detecting the prompt.

        Args:
            session_key: Session identifier
            raw_output: Raw output with ANSI codes
            clean_output: ANSI-stripped output

        Returns:
            Tuple of (is_complete, cleaned_output_without_prompt)
        """
        logger = self.logger.getChild("prompt_check")

        # Strategy 1: Check for captured literal/generalized prompt (most reliable)
        if session_key in self._session_prompts:
            literal_prompt = self._session_prompts[session_key]

            # Check if prompt contains wildcards or character classes (generalized)
            if "*" in literal_prompt or "[" in literal_prompt:
                # Convert to pattern for wildcard matching
                # Escape special regex chars except * and []
                pattern_str = re.escape(literal_prompt).replace(r"\*", ".*?")
                # Un-escape specific character classes we use (like [>#] from enable mode)
                # Do NOT unescape all brackets as that breaks literal brackets in prompts
                pattern_str = pattern_str.replace(r"\[>#\]", "[>#]").replace(
                    r"\[\$#\]", "[$#]"
                )
                # Ensure it matches at end of output
                pattern = re.compile(re.escape("").join([pattern_str, r"\s*$"]))

                # Debug: show what we're matching against
                last_100 = (
                    clean_output.rstrip()[-100:]
                    if len(clean_output) > 100
                    else clean_output.rstrip()
                )
                self._log_debug_rate_limited(
                    logger,
                    f"{session_key}_prompt_check",
                    f"Checking wildcard pattern '{literal_prompt}' (regex: '{pattern.pattern}') against last 100 chars: {repr(last_100)}",
                )

                match = pattern.search(clean_output.rstrip())
                if match:
                    # Remove the matched prompt from output
                    output = clean_output[: match.start()].rstrip()
                    logger.debug(
                        f"Wildcard pattern matched! Matched text: {repr(match.group())}"
                    )
                    return True, output
                else:
                    self._log_debug_rate_limited(
                        logger,
                        f"{session_key}_prompt_nomatch",
                        "Wildcard pattern did not match",
                    )
            else:
                # Exact literal match
                if clean_output.rstrip().endswith(literal_prompt):
                    # Remove the prompt from output
                    output = clean_output.rstrip()
                    if output.endswith(literal_prompt):
                        output = output[: -len(literal_prompt)].rstrip()
                    return True, output

        # Strategy 2: Fall back to pattern matching
        if session_key in self._session_prompt_patterns:
            prompt_pattern = self._session_prompt_patterns[session_key]

            if prompt_pattern.search(clean_output):
                output = prompt_pattern.sub("", clean_output).rstrip()
                return True, output

        return False, clean_output

    def _detect_awaiting_input(
        self, output: str, session_key: str = "global"
    ) -> Optional[str]:
        """Detect if command is waiting for user input.

        Returns string describing what input is needed, or None if not awaiting input.
        """
        logger = self.logger.getChild("awaiting_input")
        
        # Mode-aware gating (only when interactive mode is enabled)
        if self._interactive_mode and session_key in self._session_modes:
            mode = self._session_modes.get(session_key, 'unknown')
            
            # If in editor mode, don't flag as awaiting input
            # Editors handle their own input and shouldn't be interrupted
            if mode == 'editor':
                logger.debug(f"In editor mode, skipping awaiting_input detection")
                return None
            
            # For pager mode, allow pager detection to proceed
            # For shell/password_prompt/unknown, use normal detection
        
        last_100 = output[-100:] if len(output) > 100 else output
        self._log_debug_rate_limited(
            logger,
            f"{session_key}_awaiting_input",
            f"Checking for awaiting input, last 100 chars: {repr(last_100)}",
        )

        clean_output = self._strip_ansi(output)
        lines = [line for line in clean_output.splitlines() if line.strip()]
        last_line = lines[-1].strip() if lines else ""

        # Common password prompts - match various formats like "password:", "password for user:", etc.
        # Note: We do NOT use re.MULTILINE so $ matches only the end of the string
        # We also exclude newlines, =, ", and ' from the wildcard to prevent matching
        # across lines, URL parameters, or JSON keys
        if re.search(r'password[^:=\n"\']*:?\s*$', last_line, re.IGNORECASE):
            logger.debug("Detected password prompt")
            return "password"
        if re.search(r'passphrase[^:=\n"\']*:?\s*$', last_line, re.IGNORECASE):
            logger.debug("Detected passphrase prompt")
            return "passphrase"

        # Pager prompts (less, more, MikroTik)
        # Match (END) with optional line numbers before it, or : on the last line
        # Strip ANSI codes from the end to properly detect pager prompts
        if re.search(r"(?:^|[\r\n]).*?\(END\)\s*$", clean_output):
            logger.debug("Detected pager (END) prompt")
            return "pager"
        if last_line == ":":
            # Common pager prompt when less/most waits for input
            logger.debug("Detected pager ':' prompt")
            return "pager"

        # MikroTik pager prompt
        if re.search(r"--\s*\[Q quit\|D dump\|.*?\]\s*$", output):
            return "pager"

        # SSH host key confirmation
        if re.search(
            r"Are you sure you want to continue connecting.*\(yes/no",
            output,
            re.IGNORECASE,
        ):
            return "ssh_host_key"

        # Yes/no prompts
        if re.search(
            r"\(y/n\)[:\s]*$|\(yes/no\)[:\s]*$|\[y/N\][:\s]*$|\[Y/n\][:\s]*$",
            last_line,
            re.IGNORECASE,
        ):
            return "yes_no"

        # Press any key / continue
        if re.search(
            r"(?:press any key|press enter|to continue)[:\.]*\s*$",
            last_line,
            re.IGNORECASE,
        ):
            return "press_key"

        # Generic prompt at end (anything ending with ? or prompt-like)
        if last_line.endswith("?") and len(last_line) <= 80 and "|" not in last_line:
            if not re.search(r"https?://|\bselect\b|\bfrom\b", last_line, re.IGNORECASE):
                return "user_input"
        if re.search(r"\benter\b[^:]{0,80}:\s*$", last_line, re.IGNORECASE):
            return "user_input"

        return None

    def _is_context_changing_command(self, command: str) -> bool:
        """Detect if a command is likely to change the shell context/prompt.

        Commands that change the shell context include:
        - sudo -i, sudo -s, sudo su (root shell)
        - su, su - (switch user)
        - ssh (nested SSH)
        - docker exec -it, kubectl exec -it (container shells)
        - screen, tmux (terminal multiplexers)
        - bash, sh, zsh, fish (spawning new shell)

        Args:
            command: The command to check

        Returns:
            True if command likely changes shell context
        """
        # Extract base command (first word)
        cmd_lower = command.strip().lower()
        base_cmd = cmd_lower.split()[0] if cmd_lower else ""

        # Check for context-changing patterns
        context_changers = [
            r"^sudo\s+(-i|su|-s)",  # sudo -i, sudo su, sudo -s
            r"^su\b",  # su, su -, su user
            r"^ssh\b",  # ssh to another host
            r"^docker\s+exec.*-it",  # docker exec -it
            r"^kubectl\s+exec.*-it",  # kubectl exec -it
            r"^podman\s+exec.*-it",  # podman exec -it
            r"^screen\b",  # screen
            r"^tmux\b",  # tmux
            r"^(bash|sh|zsh|fish|ksh|csh|tcsh)\s*$",  # spawning new shell
        ]

        for pattern in context_changers:
            if re.search(pattern, cmd_lower):
                return True

        return False

    def _execute_standard_command_internal(
        self, client: paramiko.SSHClient, command: str, timeout: int, session_key: str
    ) -> tuple[str, str, int, Optional[str]]:
        """Execute command with natural completion detection and interactive prompt detection.

        Returns: (stdout, stderr, exit_code, awaiting_input_reason)
        - awaiting_input_reason is None if complete, or a string describing what input is needed
        """
        logger = self.logger.getChild("standard_command")

        # Check if this command will change the shell context
        context_changing = self._is_context_changing_command(command)
        if context_changing:
            logger.info(f"Detected context-changing command: {command}")

        try:
            shell = self._get_or_create_shell(session_key, client)
            shell.settimeout(timeout)

            with self._lock:
                self._active_commands[session_key] = shell

            # Clear any pending output to avoid matching stale prompts
            if shell.recv_ready():
                try:
                    while shell.recv_ready():
                        shell.recv(4096)
                except Exception:
                    pass

            # Check shell type to decide on sentinel usage
            shell_type = self._session_shell_types.get(session_key, "unknown")
            logger.debug(f"Shell type for {session_key}: {shell_type}")
            is_unix = shell_type == "unix_shell"

            # Use sentinel only for Unix-like shells
            sentinel = None
            command_to_send = command
            if is_unix:
                marker = f"__MCP_CMD_{uuid.uuid4().hex[:8]}__"
                command_to_send = self._build_sentinel_command(marker, "")
                # Inject user command before sentinel
                # The _build_sentinel_command creates:
                # __mcp_status=$?; printf '\n{marker}%d\n' "$__mcp_status" ...
                # We need to prepend the actual command
                command_to_send = f"{command}; {command_to_send}"
                sentinel = marker
                logger.debug(f"Using sentinel marker: {sentinel}")

            logger.info(f"Executing command on {session_key}: {command}")
            shell.send(command_to_send + "\n")
            time.sleep(0.3)

            output_limiter = OutputLimiter()
            raw_output = ""
            start_time = time.time()
            last_recv_time = start_time
            idle_timeout = 2.0
            seen_command_echo = False
            echo_end_pos: Optional[int] = None
            # Ensure prompt pattern exists as fallback
            self._ensure_prompt_pattern(session_key, client, shell=shell)
            consecutive_misses = 0  # Track consecutive prompt detection failures

            while time.time() - start_time < timeout:
                if shell.recv_ready():
                    chunk = shell.recv(4096).decode("utf-8", errors="ignore")
                    logger.logger.debug(f"Received chunk: {repr(chunk)}")
                    self._feed_emulator(session_key, chunk)
                    last_recv_time = time.time()
                    limited_chunk, should_continue = output_limiter.add_chunk(chunk)
                    raw_output += limited_chunk

                    if not seen_command_echo and "\n" in raw_output:
                        seen_command_echo = True
                        # Record end of echo line so prompt detection only looks after it
                        clean_snapshot = self._strip_ansi(raw_output)
                        newline_idx = clean_snapshot.find("\n")
                        if newline_idx != -1:
                            echo_end_pos = newline_idx + 1

                    if not should_continue:
                        logger.warning("Output limit reached")
                        return raw_output, "Output limit exceeded", 124, None

                    # Check for interactive prompts BEFORE checking for completion
                    awaiting = self._detect_awaiting_input(raw_output, session_key)
                    if awaiting:
                        # Only treat as awaiting input after a brief idle and if prompt isn't present
                        # Exception: Pagers should be handled immediately to keep stream flowing
                        if awaiting == "pager" or (time.time() - last_recv_time) > 0.2:
                            clean_output = self._strip_ansi(raw_output)
                            tail_start = echo_end_pos or 0
                            tail_clean = clean_output[tail_start:]
                            is_complete, _ = self._check_prompt_completion(
                                session_key, raw_output, tail_clean
                            )
                            if not is_complete:
                                logger.info(f"Detected interactive prompt: {awaiting}")
                                # Automatically handle pagers by sending 'q' to quit
                                if awaiting == "pager":
                                    logger.info(
                                        "Automatically handling pager - sending 'q' to quit"
                                    )

                                    # Strip MikroTik pager prompt from output to avoid agent confusion
                                    # Match raw output as detection does
                                    raw_output = re.sub(
                                        r"--\s*\[Q quit\|D dump\|.*?\]\s*$", "", raw_output
                                    )

                                    shell.send("q")
                                    # Wait for pager to exit and shell prompt to appear
                                    # Don't just continue - actively wait for the prompt
                                    pager_exit_start = time.time()
                                    pager_exit_timeout = 3.0
                                    while time.time() - pager_exit_start < pager_exit_timeout:
                                        time.sleep(0.1)
                                        if shell.recv_ready():
                                            chunk = shell.recv(4096).decode("utf-8", errors="ignore")
                                            logger.logger.debug(f"Received chunk (pager): {repr(chunk)}")
                                            self._feed_emulator(session_key, chunk)
                                            limited_chunk, should_continue = output_limiter.add_chunk(chunk)
                                            raw_output += limited_chunk
                                            if not should_continue:
                                                return raw_output, "Output limit exceeded", 124, None
                                            # Check if we now have the shell prompt
                                            clean_output = self._strip_ansi(raw_output)
                                            tail_start = echo_end_pos or 0
                                            tail_clean = clean_output[tail_start:]
                                            is_complete, cleaned_output = self._check_prompt_completion(
                                                session_key, raw_output, tail_clean
                                            )
                                            if is_complete:
                                                logger.debug("Shell prompt detected after quitting pager")
                                                return cleaned_output, "", 0, None
                                    # If we didn't get prompt, continue normal loop
                                    logger.debug("Pager quit, continuing to wait for shell prompt")
                                    continue
                                # For other types of input (password, etc.), return and let agent handle
                                return raw_output, "", 0, awaiting

                    # Check for sentinel (Unix shells)
                    if sentinel and sentinel in raw_output:
                        logger.debug("Sentinel detected")
                        # Extract exit code and clean output
                        clean_output = self._strip_ansi(raw_output)

                        # Find sentinel and exit code
                        # Pattern: marker + digits
                        sentinel_pattern = re.compile(re.escape(sentinel) + r"(\d+)")
                        match = sentinel_pattern.search(clean_output)
                        if match:
                            exit_code = int(match.group(1))

                            # Clean up output: remove everything from sentinel onwards using the match position
                            # This avoids truncating at the command echo which also contains the sentinel string

                            # We use clean_output for truncation to ensure accurate regex index matching
                            # match.start() is the index of the sentinel in clean_output
                            final_output = clean_output[:match.start()]

                            # We should return the clean output directly
                            return final_output.strip(), "", exit_code, None

                    # Check for command completion using captured prompt or pattern
                    # Only check after brief idle to avoid false positives from command echo
                    # AND make sure we've seen the command echo (newline)
                    if seen_command_echo and (time.time() - last_recv_time) > 0.2:
                        clean_output = self._strip_ansi(raw_output)
                        tail_start = echo_end_pos or 0
                        tail_clean = clean_output[tail_start:]

                        is_complete, cleaned_output = self._check_prompt_completion(
                            session_key, raw_output, tail_clean
                        )

                        # If sentinel mode is on, we ignore simple prompt matching unless
                        # we are really sure or it's been a long time?
                        # Actually, the bug is "Cost is 10$" triggers prompt match.
                        # If we have a sentinel, "Cost is 10$" will appear, but sentinel won't.
                        # So we should IGNORE is_complete if sentinel is active and sentinel not found.
                        if sentinel and is_complete:
                             # Logic: If sentinel is used, we trust sentinel.
                             # We DO NOT return on prompt detection alone to fix the bug.
                             is_complete = False
                    else:
                        is_complete = False
                        cleaned_output = ""

                    if is_complete:
                        # Reset miss count on successful match
                        self._prompt_miss_count[session_key] = 0
                        consecutive_misses = 0

                        # If this was a context-changing command, recapture the prompt
                        if context_changing:
                            logger.info(
                                f"Recapturing prompt after context-changing command"
                            )
                            with self._lock:
                                self._session_prompts.pop(session_key, None)
                            self._capture_prompt(session_key, shell)

                        return cleaned_output, "", 0, None
                    else:
                        consecutive_misses += 1

                        # If we've had too many consecutive misses, try recapturing the prompt
                        if consecutive_misses > 10:
                            miss_count = self._prompt_miss_count.get(session_key, 0) + 1
                            self._prompt_miss_count[session_key] = miss_count

                            if miss_count > 3:
                                logger.warning(
                                    f"Prompt detection failing repeatedly ({miss_count} times), recapturing for {session_key}"
                                )
                                with self._lock:
                                    self._session_prompts.pop(session_key, None)
                                    self._session_prompt_patterns.pop(session_key, None)

                                # Try to clear any stuck state with Ctrl+C
                                logger.info(f"Sending Ctrl+C to clear stuck state for {session_key}")
                                try:
                                    shell.send('\x03')
                                    time.sleep(0.5)
                                    # Clear any output from Ctrl+C
                                    if shell.recv_ready():
                                        shell.recv(4096)
                                except Exception as e:
                                    logger.warning(f"Error sending Ctrl+C: {e}")

                                # Try to recapture prompt
                                self._capture_prompt(session_key, shell)
                                self._ensure_prompt_pattern(
                                    session_key, client, raw_output, shell
                                )
                                consecutive_misses = 0
                                logger.info(
                                    f"Recaptured prompt and regenerated pattern"
                                )

                            # Nuclear option: if we've tried many times, reset the shell
                            if miss_count > 5:
                                logger.error(
                                    f"Prompt detection failed {miss_count} times for {session_key}. "
                                    f"Shell state may be corrupted. Consider closing and recreating the session."
                                )
                                # Mark the shell as needing reset by closing it
                                # The next command will create a new shell
                                try:
                                    shell.close()
                                except:
                                    pass
                                if session_key in self._session_shells:
                                    del self._session_shells[session_key]
                                # Return error indicating session needs reset
                                return raw_output, "Session state corrupted. The session has been reset. Please retry your command.", 1, None
                else:
                    # No data available - check if we should timeout from inactivity
                    if raw_output and (time.time() - last_recv_time) > idle_timeout:
                        clean_output = self._strip_ansi(raw_output)

                        # Check for interactive prompts BEFORE checking for completion
                        awaiting = self._detect_awaiting_input(raw_output, session_key)
                        if awaiting:
                            logger.info(
                                f"Detected interactive prompt during idle timeout: {awaiting}"
                            )
                            # Automatically handle pagers by sending 'q' to quit
                            if awaiting == "pager":
                                logger.info(
                                    "Automatically handling pager during idle timeout - sending 'q' to quit"
                                )

                                # Strip MikroTik pager prompt from output to avoid agent confusion
                                raw_output = re.sub(
                                    r"--\s*\[Q quit\|D dump\|.*?\]\s*$", "", raw_output
                                )

                                shell.send("q")
                                # Wait for pager to exit and shell prompt to appear
                                pager_exit_start = time.time()
                                pager_exit_timeout = 3.0
                                while time.time() - pager_exit_start < pager_exit_timeout:
                                    time.sleep(0.1)
                                    if shell.recv_ready():
                                        chunk = shell.recv(4096).decode("utf-8", errors="ignore")
                                        logger.logger.debug(f"Received chunk (idle-pager): {repr(chunk)}")
                                        self._feed_emulator(session_key, chunk)
                                        limited_chunk, should_continue = output_limiter.add_chunk(chunk)
                                        raw_output += limited_chunk
                                        if not should_continue:
                                            return raw_output, "Output limit exceeded", 124, None
                                        # Check if we now have the shell prompt
                                        clean_output = self._strip_ansi(raw_output)
                                        tail_start = echo_end_pos or 0
                                        tail_clean = clean_output[tail_start:]
                                        is_complete, cleaned_output = self._check_prompt_completion(
                                            session_key, raw_output, tail_clean
                                        )
                                        if is_complete:
                                            logger.debug("Shell prompt detected after quitting pager (idle)")
                                            return cleaned_output, "", 0, None
                                # Reset idle timer and continue collecting
                                last_recv_time = time.time()
                                logger.debug("Pager quit during idle, continuing to wait for shell prompt")
                                continue
                            # For other types of input (password, etc.), return and let agent handle
                            # Only return awaiting input if prompt isn't already visible
                            tail_start = echo_end_pos or 0
                            tail_clean = clean_output[tail_start:]
                            is_complete, _ = self._check_prompt_completion(
                                session_key, raw_output, tail_clean
                            )
                            if not is_complete:
                                return raw_output, "", 0, awaiting

                        # Only complete on idle timeout if we detect a prompt
                        tail_start = echo_end_pos or 0
                        tail_clean = clean_output[tail_start:]
                        is_complete, cleaned_output = self._check_prompt_completion(
                            session_key, raw_output, tail_clean
                        )
                        if is_complete:
                            logger.debug(
                                "Prompt found in cleaned output during idle timeout"
                            )

                            # If sentinel is active, verify sentinel presence even on idle timeout
                            if sentinel:
                                if sentinel in raw_output:
                                     # Sentinel found, we can proceed
                                     # Logic handled in main loop, but here we are in idle block
                                     # Let main loop handle it in next iteration (idle doesn't break loop unless we return)
                                     pass
                                else:
                                     # Sentinel NOT found, but prompt found.
                                     # This is the ambiguous case.
                                     # If we return here, we risk the bug.
                                     # If we don't, we risk hanging if sentinel is lost.
                                     # Given the bug report, we MUST prioritize avoiding false positives.
                                     # So we ignore the prompt if sentinel is missing.
                                     logger.debug("Sentinel active but not found - ignoring prompt detection on idle")
                                     is_complete = False

                        if is_complete:
                            # If this was a context-changing command, recapture the prompt
                            if context_changing:
                                logger.info(
                                    f"Recapturing prompt after context-changing command (idle timeout)"
                                )
                                with self._lock:
                                    self._session_prompts.pop(session_key, None)
                                self._capture_prompt(session_key, shell)

                            return cleaned_output, "", 0, None
                    time.sleep(0.1)

            logger.warning(f"Command timed out after {timeout}s")
            return (
                raw_output.strip(),
                f"Command timed out after {timeout} seconds",
                124,
                None,
            )

        except Exception as exc:
            logger.error(f"Error executing command: {exc}", exc_info=True)
            if session_key in self._session_shells:
                try:
                    self._session_shells[session_key].close()
                except Exception:
                    pass
                del self._session_shells[session_key]
            return "", f"Error: {exc}", 1, None
        finally:
            with self._lock:
                self._active_commands.pop(session_key, None)

    def _execute_enable_mode_command_internal(
        self,
        client: paramiko.SSHClient,
        session_key: str,
        command: str,
        enable_password: str,
        enable_command: str,
        timeout: int,
    ) -> tuple[str, str, int]:
        """Execute a command while the session is in enable mode using the persistent shell."""
        logger = self.logger.getChild("enable_mode_command")

        try:
            # Get the persistent shell for this session
            shell = self._get_or_create_shell(session_key, client)
            shell.settimeout(timeout)

            # Validate enable mode state if we think we are enabled
            if self._enable_mode.get(session_key, False):
                # Clear pending output first
                if shell.recv_ready():
                    shell.recv(4096)

                # Check prompt
                shell.send("\n")
                time.sleep(0.5)

                if shell.recv_ready():
                    output = shell.recv(4096).decode("utf-8", errors="ignore")
                    clean = self._strip_ansi(output).strip()
                    # Check if prompt ends with # (standard enable mode indicator)
                    # We also check if it contains '>' which usually indicates user mode
                    if (
                        clean
                        and not clean.endswith("#")
                        and (clean.endswith(">") or ">" in clean.splitlines()[-1])
                    ):
                        logger.warning(
                            f"Enable mode validation failed. Prompt '{clean}' does not appear to be enable mode. Re-entering enable mode."
                        )
                        self._enable_mode[session_key] = False

            # Enter enable mode if not already in it
            if not self._enable_mode.get(session_key, False):
                success, message = self._enter_enable_mode(
                    session_key, client, enable_password, enable_command
                )
                if not success:
                    return "", f"Failed to enter enable mode: {message}", 1

            # Clear any pending output
            if shell.recv_ready():
                shell.recv(4096)

            # Send the command
            shell.send(f"{command}\n")
            time.sleep(0.5)

            output_limiter = OutputLimiter()
            raw_output = ""
            start_time = time.time()
            last_output_time = time.time()
            idle_timeout = 2.0  # Consider command complete after 2 seconds of no output

            while time.time() - start_time < timeout:
                if shell.recv_ready():
                    chunk = shell.recv(4096).decode("utf-8", errors="ignore")
                    logger.logger.debug(f"Received chunk: {repr(chunk)}")
                    self._feed_emulator(session_key, chunk)
                    limited_chunk, should_continue = output_limiter.add_chunk(chunk)
                    raw_output += limited_chunk
                    last_output_time = time.time()

                    if not should_continue:
                        break

                    # Use proper prompt detection instead of naive character checking
                    clean_output = re.sub(r"\x1b\[[0-9;]*[mGKHF]", "", raw_output)
                    is_complete, _ = self._check_prompt_completion(
                        session_key, raw_output, clean_output
                    )
                    if is_complete:
                        logger.debug("Prompt detected - command complete")
                        break
                else:
                    # No data available - check if we've been idle long enough
                    if time.time() - last_output_time >= idle_timeout and raw_output:
                        logger.debug(
                            f"Idle timeout reached after {idle_timeout}s - command appears complete"
                        )
                        break
                    time.sleep(0.1)
            else:
                return raw_output, f"Command timed out after {timeout} seconds", 124

            # Clean up the output using proper prompt detection
            clean_output = re.sub(r"\x1b\[[0-9;]*[mGKHF]", "", raw_output)
            is_complete, cleaned_output = self._check_prompt_completion(
                session_key, raw_output, clean_output
            )

            # Remove the command echo (first line)
            lines = cleaned_output.split("\n")
            if len(lines) > 1 and lines[0].strip() in command:
                # First line is command echo, skip it
                output = "\n".join(lines[1:]).strip()
            else:
                output = cleaned_output.strip()

            return output, "", 0

        except Exception as exc:
            logger.error(f"Enable mode command error: {exc}", exc_info=True)
            return "", f"Error executing enable mode command: {exc}", 1

    def send_input_by_session(
        self,
        host: str,
        input_text: str,
        username: Optional[str] = None,
        port: Optional[int] = None,
    ) -> tuple[bool, str, str]:
        """Send input to the active shell for a session."""
        logger = self.logger.getChild("send_input_session")
        _, _, _, _, session_key = self._resolve_connection(host, username, port)
        logger.info(f"Sending input to session: {session_key}")

        with self._lock:
            shell = self._session_shells.get(session_key)

        if not shell:
            logger.error(f"No active shell for session: {session_key}")
            return False, "", "No active shell for this session"

        try:
            logger.debug(f"Sending text to shell: {input_text!r}")
            shell.send(input_text)
            time.sleep(0.2)

            output = ""
            if getattr(shell, "recv_ready", lambda: False)():
                output = shell.recv(65535).decode("utf-8", errors="replace")
                logger.debug(f"Received {len(output)} bytes of new output.")

            return True, output, ""
        except Exception as exc:
            logger.error(
                f"Failed to send input to session {session_key}: {exc}", exc_info=True
            )
            return False, "", f"Failed to send input: {exc}"

    def read_file(
        self,
        host: str,
        remote_path: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        key_filename: Optional[str] = None,
        port: Optional[int] = None,
        encoding: str = "utf-8",
        errors: str = "replace",
        max_bytes: Optional[int] = None,
        sudo_password: Optional[str] = None,
        use_sudo: bool = False,
    ) -> tuple[str, str, int]:
        """Delegate remote file reads to the FileManager helper."""
        return self.file_manager.read_file(
            host=host,
            remote_path=remote_path,
            username=username,
            password=password,
            key_filename=key_filename,
            port=port,
            encoding=encoding,
            errors=errors,
            max_bytes=max_bytes,
            sudo_password=sudo_password,
            use_sudo=use_sudo,
        )

    def write_file(
        self,
        host: str,
        remote_path: str,
        content: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        key_filename: Optional[str] = None,
        port: Optional[int] = None,
        encoding: str = "utf-8",
        errors: str = "strict",
        append: bool = False,
        make_dirs: bool = False,
        permissions: Optional[int] = None,
        max_bytes: Optional[int] = None,
        sudo_password: Optional[str] = None,
        use_sudo: bool = False,
    ) -> tuple[str, str, int]:
        """Delegate remote file writes to the FileManager helper."""
        return self.file_manager.write_file(
            host=host,
            remote_path=remote_path,
            content=content,
            username=username,
            password=password,
            key_filename=key_filename,
            port=port,
            encoding=encoding,
            errors=errors,
            append=append,
            make_dirs=make_dirs,
            permissions=permissions,
            max_bytes=max_bytes,
            sudo_password=sudo_password,
            use_sudo=use_sudo,
        )

    def execute_command(
        self,
        host: str,
        username: Optional[str] = None,
        command: str = "",
        password: Optional[str] = None,
        key_filename: Optional[str] = None,
        port: Optional[int] = None,
        enable_password: Optional[str] = None,
        enable_command: str = "enable",
        sudo_password: Optional[str] = None,
        timeout: int = 30,
    ) -> tuple[str, str, int]:
        """Execute a command on a host using persistent session."""
        return self.command_executor.execute_command(
            host,
            username,
            command,
            password,
            key_filename,
            port,
            enable_password,
            enable_command,
            sudo_password,
            timeout,
        )

    def execute_command_enhanced(
        self,
        host: str,
        username: Optional[str] = None,
        command: str = "",
        password: Optional[str] = None,
        key_filename: Optional[str] = None,
        port: Optional[int] = None,
        enable_password: Optional[str] = None,
        enable_command: str = "enable",
        sudo_password: Optional[str] = None,
        timeout: int = 30,
        auto_extend_timeout: bool = True,
        max_timeout: int = 600,
        streaming_mode: bool = False,
        progress_callback: Optional[str] = None,
    ) -> str:
        """Execute command with enhanced features."""
        return self.enhanced_executor.execute_command_enhanced(
            host,
            username,
            command,
            password,
            key_filename,
            port,
            enable_password,
            enable_command,
            sudo_password,
            timeout,
            auto_extend_timeout,
            max_timeout,
            streaming_mode,
            progress_callback,
        )

    def get_session_diagnostics(
        self, host: str, username: Optional[str] = None, port: Optional[int] = None
    ):
        """Get session diagnostics."""
        return self.session_diagnostics.get_session_diagnostics(host, username, port)

    def reset_session_prompt(
        self, host: str, username: Optional[str] = None, port: Optional[int] = None
    ) -> bool:
        """Reset session prompt detection."""
        return self.session_diagnostics.reset_session_prompt_detection(
            host, username, port
        )

    def get_connection_health_report(self):
        """Get connection health report."""
        return self.session_diagnostics.get_connection_health_report()

    def get_performance_metrics(self):
        """Get performance metrics from logging."""
        return self.logger.get_performance_report()

    def execute_command_async(
        self,
        host: str,
        username: Optional[str] = None,
        command: str = "",
        password: Optional[str] = None,
        key_filename: Optional[str] = None,
        port: Optional[int] = None,
        sudo_password: Optional[str] = None,
        enable_password: Optional[str] = None,
        enable_command: str = "enable",
        timeout: int = 300,
    ) -> str:
        """Execute a command asynchronously without blocking."""
        return self.command_executor.execute_command_async(
            host,
            username,
            command,
            password,
            key_filename,
            port,
            sudo_password,
            enable_password,
            enable_command,
            timeout,
        )

    def get_command_status(self, command_id: str) -> dict:
        """Get the status and output of an async command."""
        return self.command_executor.get_command_status(command_id)

    def interrupt_command_by_id(self, command_id: str) -> tuple[bool, str]:
        """Interrupt a running async command by its ID."""
        return self.command_executor.interrupt_command_by_id(command_id)

    def send_input(self, command_id: str, input_text: str) -> tuple[bool, str, str]:
        """Send input to a running command and return any new output."""
        return self.command_executor.send_input(command_id, input_text)

    def list_running_commands(self) -> list[dict]:
        """List all running async commands."""
        return self.command_executor.list_running_commands()

    def list_command_history(self, limit: int = 50) -> list[dict]:
        """List recent command history (completed, failed, interrupted)."""
        return self.command_executor.list_command_history(limit)

    def _cleanup_old_commands(self):
        """Remove old completed commands, keeping only recent ones."""
        logger = self.logger.getChild("cleanup")
        executor = self.command_executor
        with executor._lock:
            completed = [
                (cmd_id, cmd)
                for cmd_id, cmd in executor._commands.items()
                if cmd.status
                in (
                    CommandStatus.COMPLETED,
                    CommandStatus.FAILED,
                    CommandStatus.INTERRUPTED,
                )
            ]
            if len(completed) > self._max_completed_commands:
                logger.info(
                    f"Found {len(completed)} completed commands, exceeding limit of {self._max_completed_commands}. Cleaning up."
                )
                completed.sort(key=lambda x: x[1].end_time or datetime.min)
                to_remove = completed[: -self._max_completed_commands]
                for cmd_id, _ in to_remove:
                    del executor._commands[cmd_id]
            else:
                logger.debug(
                    f"Cleanup check: {len(completed)} completed commands within limit of {self._max_completed_commands}."
                )
