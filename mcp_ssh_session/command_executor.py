"""Command execution for SSH sessions."""
import atexit
import paramiko
from typing import Dict, Optional, Tuple, Any
import threading
import time
import re
import logging
from concurrent.futures import ThreadPoolExecutor
import uuid
from datetime import datetime

from .datastructures import CommandStatus, RunningCommand
from .validation import OutputLimiter


class CommandExecutor:
    """Executes commands on SSH sessions."""

    def __init__(self, session_manager):
        self._session_manager = session_manager
        self.logger = logging.getLogger('ssh_session.command_executor')
        self._commands: Dict[str, RunningCommand] = {}
        self._executor = ThreadPoolExecutor(max_workers=self._session_manager.MAX_WORKERS, thread_name_prefix="ssh_cmd")
        self._lock = threading.Lock()
        self._interpreter_exiting = False

        # Mark when the interpreter is shutting down so we can skip late submissions
        atexit.register(self._mark_interpreter_exit)

    def _mark_interpreter_exit(self):
        self._interpreter_exiting = True

    def execute_command(self, host: str, username: Optional[str] = None,
                       command: str = "", password: Optional[str] = None,
                       key_filename: Optional[str] = None,
                       port: Optional[int] = None,
                       enable_password: Optional[str] = None,
                       enable_command: str = "enable",
                       sudo_password: Optional[str] = None,
                       timeout: int = 30) -> tuple[str, str, int]:
        """Execute a command on a host using persistent session."""
        logger = self.logger.getChild('execute_command')
        logger.info(f"[EXEC_REQ] host={host}, cmd={command[:100]}..., timeout={timeout}")

        # Validate command
        is_valid, error_msg = self._session_manager._command_validator.validate_command(command)
        if not is_valid:
            logger.warning(f"[EXEC_INVALID] {error_msg}")
            return "", error_msg, 1

        # Start async
        logger.debug(f"[EXEC_ASYNC_START] Starting async execution")
        try:
            command_id = self.execute_command_async(
                host, username, command, password, key_filename, port,
                sudo_password, enable_password, enable_command, timeout
            )
        except Exception as e:
            return "", str(e), 1
            
        logger.debug(f"[EXEC_ASYNC_ID] command_id={command_id}")

        # Poll until done or timeout
        start = time.time()
        poll_count = 0
        idle_threshold = getattr(self._session_manager, 'SYNC_IDLE_TO_ASYNC', 0)
        last_activity = start
        last_stdout = ""
        last_stderr = ""
        while time.time() - start < timeout:
            status = self.get_command_status(command_id)
            poll_count += 1

            if 'error' in status:
                logger.error(f"[EXEC_ERROR] {status['error']}")
                return "", status['error'], 1
            
            if status['status'] == 'awaiting_input':
                reason = status.get('awaiting_input_reason', 'unknown')
                logger.info(f"[EXEC_AWAIT] Command {command_id} waiting for input: {reason}")
                # Return immediately for awaiting input, let the tool handle it.
                return "", f"AWAITING_INPUT:{command_id}:{reason}", 124
                
            if status['status'] != 'running':
                logger.info(f"[EXEC_DONE] status={status['status']}, polls={poll_count}, duration={time.time() - start:.2f}s")
                return status['stdout'], status['stderr'], status['exit_code'] or 0

            # If the command is running but has been idle for SYNC_IDLE_TO_ASYNC, it means it *should* transition to async
            # and we should continue polling until the full timeout for this sync execute_command call.
            # The `_execute_standard_command_internal` function will return `ASYNC:{command_id}` if it hits its idle timeout.
            # The outer `execute_command` (sync tool) should then continue to poll this async ID.
            # This block is for when the *internal* async transition happens, but the outer sync call should keep waiting.
            # If we reached here, it means the internal worker is still 'running' but might be idle or waiting internally.

            time.sleep(0.1)

        # If we reach here, the command genuinely timed out based on the outer `timeout` parameter.
        logger.warning(f"[EXEC_TIMEOUT] Command {command_id} timed out after {timeout}s")
        status_on_timeout = self.get_command_status(command_id)
        return status_on_timeout.get('stdout', ''), f"ASYNC:{command_id}", 124

    def execute_command_async(self, host: str, username: Optional[str] = None,
                             command: str = "", password: Optional[str] = None,
                             key_filename: Optional[str] = None,
                             port: Optional[int] = None,
                             sudo_password: Optional[str] = None,
                             enable_password: Optional[str] = None,
                             enable_command: str = "enable",
                             timeout: int = 300) -> str:
        """Execute a command asynchronously without blocking."""
        logger = self.logger.getChild('execute_async')
        logger.info(f"[ASYNC_START] host={host}, cmd={command[:100]}...")

        _, _, _, _, session_key = self._session_manager._resolve_connection(
            host, username, port
        )

        # Prepare session and shell first (outside lock to avoid blocking)
        # Note: This avoids race conditions where two threads check for running commands
        # simultaneously before either registers one.
        client = self._session_manager.get_or_create_session(host, username, password, key_filename, port)
        shell = self._session_manager._get_or_create_shell(session_key, client)

        command_id = str(uuid.uuid4())
        logger.debug(f"Generated command_id: {command_id}")

        running_cmd = RunningCommand(
            command_id=command_id,
            session_key=session_key,
            command=command,
            shell=shell,
            future=None,
            status=CommandStatus.RUNNING,
            stdout="",
            stderr="",
            exit_code=None,
            start_time=datetime.now(),
            end_time=None
        )

        # Atomic check and registration
        with self._lock:
            for cmd in self._commands.values():
                if cmd.session_key == session_key and cmd.status in (CommandStatus.RUNNING, CommandStatus.AWAITING_INPUT):
                    error_msg = (
                        f"A command is already running or awaiting input in this session ({session_key}).\n"
                        f"Running Command ID: {cmd.command_id}\n"
                        f"Running Command Status: {cmd.status.value}"
                    )
                    logger.error(error_msg)
                    raise Exception(error_msg)

            self._commands[command_id] = running_cmd
            logger.debug(f"Registered running command {command_id}")

        logger.debug(f"[ASYNC_SUBMIT] Submitting command {command_id} to thread pool")
        future = self._executor.submit(
            self._execute_command_async_worker,
            command_id, client, command, timeout, session_key,
            sudo_password, enable_password, enable_command
        )
        running_cmd.future = future
        logger.info(f"[ASYNC_SUBMITTED] command_id={command_id}")

        return command_id

    def _execute_command_async_worker(self, command_id: str, client: paramiko.SSHClient,
                                       command: str, timeout: int, session_key: str,
                                       sudo_password: Optional[str] = None,
                                       enable_password: Optional[str] = None,
                                       enable_command: str = "enable"):
        """Execute command in background thread and update running command state."""
        logger = self.logger.getChild('async_worker')
        logger.debug(f"[WORKER_START] command_id={command_id}")

        try:
            with self._lock:
                if command_id not in self._commands:
                    logger.error(f"[WORKER_NOTFOUND] command_id={command_id} no longer in registry.")
                    return
                running_cmd = self._commands[command_id]

            logger.debug(f"[WORKER_EXEC] Executing command for {command_id}")

            if sudo_password:
                logger.debug(f"Executing as sudo for {command_id}")
                stdout, stderr, exit_code = self._execute_sudo_command_internal(
                    client, command, sudo_password, timeout
                )
                # Parse awaiting_input from stderr if present
                if exit_code == 1 and stderr.startswith("Command requires input: "):
                    awaiting_input_reason = stderr.replace("Command requires input: ", "")
                else:
                    awaiting_input_reason = None
            elif enable_password:
                logger.debug(f"Executing in enable mode for {command_id}")
                stdout, stderr, exit_code = self._execute_enable_mode_command_internal(
                    client, session_key, command, enable_password, enable_command, timeout
                )
                awaiting_input_reason = None
            else:
                logger.debug(f"Executing as standard command for {command_id}")
                stdout, stderr, exit_code, awaiting_input_reason = self._execute_standard_command_internal(
                    client, command, timeout, session_key
                )

            logger.debug(f"[WORKER_DONE] command_id={command_id}, exit_code={exit_code}, awaiting_input={awaiting_input_reason}")

            # Handle timeout case - command is still running on remote shell
            if exit_code == 124 and not awaiting_input_reason:
                logger.warning(f"Command {command_id} timed out after {timeout}s, continuing to monitor in background")
                with self._lock:
                    if command_id in self._commands:
                        running_cmd.stdout = stdout
                        running_cmd.stderr = f"Command exceeded {timeout}s timeout, still running..."
                        running_cmd.exit_code = None  # Clear exit code since it's still running
                        # Keep status as RUNNING
                        logger.info(f"Command {command_id} still running after timeout, submitting background monitor")

                # Continue monitoring in background
                try:
                    # Guard against interpreter shutdown or executor shutdown during teardown
                    if self._interpreter_exiting or getattr(self._executor, "_shutdown", False):
                        logger.warning(f"Executor shutting down; skip background monitor for {command_id}")
                        return

                    self._executor.submit(
                        self._continue_monitoring_timeout_background,
                        command_id, running_cmd, session_key, timeout_occurred_at=time.time()
                    )
                except RuntimeError as submit_err:
                    logger.debug(
                        f"Skip background monitor for {command_id}: {submit_err}"
                    )
                return

            # Normal completion or awaiting input
            with self._lock:
                if command_id in self._commands:
                    running_cmd.stdout = stdout
                    running_cmd.stderr = stderr
                    running_cmd.exit_code = exit_code
                    running_cmd.awaiting_input_reason = awaiting_input_reason
                    if awaiting_input_reason:
                        running_cmd.status = CommandStatus.AWAITING_INPUT
                        logger.info(f"Command {command_id} awaiting input: {awaiting_input_reason}")
                    else:
                        running_cmd.status = CommandStatus.COMPLETED
                        running_cmd.end_time = datetime.now()
                        logger.info(f"Command {command_id} completed.")
        except Exception as e:
            logger.error(f"[WORKER_ERROR] command_id={command_id}, error={e}", exc_info=True)
            with self._lock:
                if command_id in self._commands:
                    running_cmd = self._commands[command_id]
                    running_cmd.stderr = str(e)
                    running_cmd.exit_code = 1
                    running_cmd.status = CommandStatus.FAILED
                    running_cmd.end_time = datetime.now()
        finally:
            # Cleanup old commands
            self._session_manager._cleanup_old_commands()

    def get_command_status(self, command_id: str) -> dict:
        """Get the status and output of an async command."""
        logger = self.logger.getChild('get_status')
        with self._lock:
            if command_id not in self._commands:
                logger.error(f"Command ID not found: {command_id}")
                return {"error": "Command ID not found"}

            cmd = self._commands[command_id]
            status_payload = {
                "command_id": cmd.command_id,
                "session_key": cmd.session_key,
                "command": cmd.command,
                "status": cmd.status.value,
                "stdout": cmd.stdout,
                "stderr": cmd.stderr,
                "exit_code": cmd.exit_code,
                "start_time": cmd.start_time.isoformat(),
                "end_time": cmd.end_time.isoformat() if cmd.end_time else None,
                "awaiting_input_reason": cmd.awaiting_input_reason
            }
            return status_payload

    def interrupt_command_by_id(self, command_id: str) -> tuple[bool, str]:
        """Interrupt a running async command by its ID."""
        logger = self.logger.getChild('interrupt')
        logger.info(f"Attempting to interrupt command_id: {command_id}")
        with self._lock:
            if command_id not in self._commands:
                logger.error(f"Command ID not found for interrupt: {command_id}")
                return False, f"Command ID {command_id} not found"

            cmd = self._commands[command_id]
            if cmd.status != CommandStatus.RUNNING:
                logger.warning(f"Command {command_id} is not running (status: {cmd.status.value})")
                return False, f"Command {command_id} is not running (status: {cmd.status.value})"

            try:
                logger.debug(f"Sending Ctrl+C to shell for command {command_id}")
                cmd.shell.send('\x03')  # Send Ctrl+C
                cmd.status = CommandStatus.INTERRUPTED
                cmd.end_time = datetime.now()
                logger.info(f"Successfully sent interrupt signal to command {command_id}")
                return True, f"Sent interrupt signal to command {command_id}"
            except Exception as e:
                logger.error(f"Failed to interrupt command {command_id}: {e}", exc_info=True)
                return False, f"Failed to interrupt command {command_id}: {e}"

    def send_input(self, command_id: str, input_text: str) -> tuple[bool, str, str]:
        """Send input to a running command and return any new output."""
        logger = self.logger.getChild('send_input')
        logger.info(f"Sending input to command_id: {command_id}")
        with self._lock:
            if command_id not in self._commands:
                logger.error(f"Command ID not found: {command_id}")
                return False, "", "Command ID not found"

            cmd = self._commands[command_id]
            # Allow sending input to commands that are RUNNING or AWAITING_INPUT
            if cmd.status not in (CommandStatus.RUNNING, CommandStatus.AWAITING_INPUT):
                logger.warning(f"Command is not active (status: {cmd.status.value})")
                return False, "", f"Command is not active (status: {cmd.status.value})"

            try:
                # Handle escaped newlines - convert literal \n to actual newlines
                # This handles cases where the client sends 'password\n' as literal characters
                processed_input = input_text.replace('\\n', '\n').replace('\\r', '\r')
                logger.debug(f"Original input: {input_text!r}")
                logger.debug(f"Processed input: {processed_input!r}")
                logger.debug(f"Input length: {len(processed_input)}, ends with newline: {processed_input.endswith(chr(10))}")
                bytes_sent = cmd.shell.send(processed_input)
                logger.debug(f"Sent {bytes_sent} bytes to shell")
                time.sleep(0.2)

                # If command was awaiting input, transition back to RUNNING and continue monitoring
                if cmd.status == CommandStatus.AWAITING_INPUT:
                    cmd.status = CommandStatus.RUNNING
                    cmd.awaiting_input_reason = None  # Clear the awaiting input reason
                    logger.info(f"Command {command_id} transitioned from AWAITING_INPUT to RUNNING after input sent")

                    # Submit a background task to continue monitoring for command completion
                    # We don't wait for it - that would block the MCP server
                    logger.debug(f"Submitting background monitoring task for {command_id}")
                    future = self._executor.submit(
                        self._continue_monitoring_shell_background,
                        command_id, cmd
                    )
                    logger.debug(f"Background monitoring submitted for {command_id}")
                    return True, "", ""

                # Read any new output (for commands that were already RUNNING)
                output = ""
                if cmd.shell.recv_ready():
                    output = cmd.shell.recv(65535).decode('utf-8', errors='replace')
                    cmd.stdout += output
                    logger.debug(f"Received {len(output)} bytes of new output.")

                return True, output, ""
            except Exception as e:
                logger.error(f"Failed to send input: {e}", exc_info=True)
                return False, "", f"Failed to send input: {e}"

    def _retrieve_exit_code(self, shell: Any, session_key: str) -> int:
        """Attempt to retrieve the exit code of the last command executed in the shell."""
        logger = self.logger.getChild('retrieve_exit_code')
        try:
            # Determine correct syntax for exit code check
            shell_type = self._session_manager._session_shell_types.get(session_key, 'unknown').lower()
            if 'fish' in shell_type:
                cmd = "echo $status\n"
            elif 'csh' in shell_type or 'tcsh' in shell_type:
                cmd = "echo $status\n"
            else:
                cmd = "echo $?\n"

            # Send command
            shell.send(cmd)
            time.sleep(0.2)

            # Read output
            output = ""
            start_time = time.time()
            # Wait up to 2 seconds for response
            while time.time() - start_time < 2.0:
                if shell.recv_ready():
                    chunk = shell.recv(4096).decode('utf-8', errors='ignore')
                    output += chunk
                    if '\n' in output.strip():
                        break
                time.sleep(0.1)

            # Parse output
            # Output will contain the command echo (maybe) and the result number
            clean_output = self._session_manager._strip_ansi(output)

            # Look for the last number in the output
            matches = re.findall(r'\b(\d+)\b', clean_output)
            if matches:
                # The last number is likely the exit code
                # But we need to be careful about the command echo "echo 0"
                # If we send "echo $?", we might get:
                # echo $?
                # 0
                # prompt

                # If we have multiple numbers, the last one before the prompt (if any) or just the last line number
                # A safer bet is searching for a line that is just digits
                lines = [line.strip() for line in clean_output.splitlines() if line.strip()]
                for line in reversed(lines):
                    if line.isdigit():
                        code = int(line)
                        logger.debug(f"Retrieved exit code: {code}")
                        return code

            logger.warning(f"Could not parse exit code from output: {repr(output)}")
            return 0  # Default to 0 if we can't determine

        except Exception as e:
            logger.error(f"Error retrieving exit code: {e}")
            return 0

    def _continue_monitoring_timeout_background(self, command_id: str, cmd: Any,
                                                session_key: str, timeout_occurred_at: float) -> None:
        """Background task to monitor shell output after a timeout occurred.

        Continues monitoring the shell until command actually completes.
        This prevents premature completion when commands take longer than the timeout.
        """
        logger = self.logger.getChild('timeout_monitor_bg')
        logger.info(f"[TIMEOUT_MONITOR_START] command_id={command_id}")

        idle_timeout = 2.0
        last_recv_time = time.time()
        start_time = time.time()
        max_additional_timeout = 300  # Max 5 minutes additional after initial timeout

        # Initialize output limiter
        output_limiter = OutputLimiter()
        # Estimate current size
        output_limiter.current_size = len(cmd.stdout.encode('utf-8'))

        last_log_time = 0.0

        try:
            while time.time() - start_time < max_additional_timeout:
                # Check cancellation signal
                if cmd.monitoring_cancelled.is_set():
                    logger.info(f"[TIMEOUT_MONITOR_CANCELLED] Monitoring cancelled for {command_id}")
                    return

                try:
                    # Check if command was interrupted/cancelled
                    with self._lock:
                        if command_id not in self._commands:
                            logger.info(f"[TIMEOUT_MONITOR_CANCELLED] Command {command_id} removed from registry")
                            return
                        if cmd.status == CommandStatus.INTERRUPTED:
                            logger.info(f"[TIMEOUT_MONITOR_INTERRUPTED] Command {command_id} was interrupted")
                            return

                    if cmd.shell.recv_ready():
                        chunk = cmd.shell.recv(65535).decode('utf-8', errors='replace')
                        if chunk:
                            # Apply output limiting
                            chunk_to_add, should_continue = output_limiter.add_chunk(chunk)
                            
                            with self._lock:
                                if command_id in self._commands:
                                    cmd.stdout += chunk_to_add
                            
                            if not should_continue:
                                logger.warning(f"[TIMEOUT_MONITOR_LIMIT] Output limit reached for {command_id}")
                                with self._lock:
                                    if command_id in self._commands:
                                        cmd.status = CommandStatus.FAILED
                                        cmd.stderr += f"\nOutput limit of {output_limiter.max_size} bytes exceeded."
                                        cmd.end_time = datetime.now()
                                return

                            last_recv_time = time.time()

                            # Rate limit logging (max once per second unless large chunk)
                            if len(chunk) > 1000 or (time.time() - last_log_time) > 1.0:
                                logger.debug(f"[TIMEOUT_MONITOR_RECV] Received {len(chunk)} bytes")
                                last_log_time = time.time()

                            # Check for interactive prompts
                            awaiting = self._session_manager._detect_awaiting_input(cmd.stdout, session_key)
                            if awaiting:
                                logger.info(f"[TIMEOUT_MONITOR_AWAITING] Command awaiting input: {awaiting}")
                                with self._lock:
                                    if command_id in self._commands:
                                        cmd.status = CommandStatus.AWAITING_INPUT
                                        cmd.awaiting_input_reason = awaiting
                                return

                            # Check for prompt completion
                            clean_output = self._session_manager._strip_ansi(cmd.stdout)
                            is_complete, cleaned_output = self._session_manager._check_prompt_completion(
                                session_key, cmd.stdout, clean_output
                            )
                            if is_complete:
                                logger.info(f"[TIMEOUT_MONITOR_COMPLETE] Prompt detected - command complete")

                                # Try to retrieve actual exit code
                                exit_code = self._retrieve_exit_code(cmd.shell, session_key)

                                with self._lock:
                                    if command_id in self._commands:
                                        cmd.stdout = cleaned_output
                                        cmd.status = CommandStatus.COMPLETED
                                        cmd.exit_code = exit_code
                                        cmd.end_time = datetime.now()
                                return
                    else:
                        # No data available - check if we've been idle long enough
                        elapsed_idle = time.time() - last_recv_time
                        if elapsed_idle > idle_timeout and cmd.stdout:
                            # Check one more time for prompt
                            clean_output = self._session_manager._strip_ansi(cmd.stdout)
                            is_complete, cleaned_output = self._session_manager._check_prompt_completion(
                                session_key, cmd.stdout, clean_output
                            )
                            if is_complete:
                                logger.info(f"[TIMEOUT_MONITOR_IDLE_COMPLETE] Idle timeout with prompt - command complete")

                                # Try to retrieve actual exit code
                                exit_code = self._retrieve_exit_code(cmd.shell, session_key)

                                with self._lock:
                                    if command_id in self._commands:
                                        cmd.stdout = cleaned_output
                                        cmd.status = CommandStatus.COMPLETED
                                        cmd.exit_code = exit_code
                                        cmd.end_time = datetime.now()
                                return

                        time.sleep(0.1)
                except Exception as recv_error:
                    logger.error(f"[TIMEOUT_MONITOR_RECV_ERROR] Error receiving data: {recv_error}")
                    break
        except Exception as e:
            logger.error(f"[TIMEOUT_MONITOR_ERROR] Error in timeout monitoring: {e}", exc_info=True)
            with self._lock:
                if command_id in self._commands:
                    cmd.status = CommandStatus.FAILED
                    cmd.stderr = f"Error during background monitoring: {e}"
                    cmd.end_time = datetime.now()

        # If we reached max timeout, mark as completed with what we have
        logger.warning(f"[TIMEOUT_MONITOR_MAX] Command {command_id} reached max monitoring time")
        with self._lock:
            if command_id in self._commands and cmd.status == CommandStatus.RUNNING:
                cmd.status = CommandStatus.COMPLETED
                cmd.exit_code = 124
                cmd.stderr = f"Command exceeded maximum monitoring time ({max_additional_timeout}s after initial timeout)"
                cmd.end_time = datetime.now()

    def _continue_monitoring_shell_background(self, command_id: str, cmd: Any) -> None:
        """Background task to monitor shell output after input has been sent.

        Updates command status when completion is detected.
        Runs in background thread pool, does not block caller.
        """
        logger = self.logger.getChild('continue_monitoring_bg')
        logger.info(f"[BG_MONITOR_START] command_id={command_id}")

        idle_timeout = 2.0
        last_recv_time = time.time()
        start_time = time.time()
        max_timeout = 60  # Max 60 seconds to wait for completion

        # Initialize output limiter
        output_limiter = OutputLimiter()
        # Estimate current size
        output_limiter.current_size = len(cmd.stdout.encode('utf-8'))

        last_log_time = 0.0

        try:
            while time.time() - start_time < max_timeout:
                # Check cancellation signal
                if cmd.monitoring_cancelled.is_set():
                    logger.info(f"[BG_MONITOR_CANCELLED] Monitoring cancelled for {command_id}")
                    return

                try:
                    if cmd.shell.recv_ready():
                        chunk = cmd.shell.recv(65535).decode('utf-8', errors='replace')
                        if chunk:
                            # Apply output limiting
                            chunk_to_add, should_continue = output_limiter.add_chunk(chunk)

                            with self._lock:
                                if command_id in self._commands:
                                    cmd.stdout += chunk_to_add
                            
                            if not should_continue:
                                logger.warning(f"[BG_MONITOR_LIMIT] Output limit reached for {command_id}")
                                with self._lock:
                                    if command_id in self._commands:
                                        cmd.status = CommandStatus.FAILED
                                        cmd.stderr += f"\nOutput limit of {output_limiter.max_size} bytes exceeded."
                                        cmd.end_time = datetime.now()
                                return

                            last_recv_time = time.time()

                            # Rate limit logging (max once per second unless large chunk)
                            if len(chunk) > 1000 or (time.time() - last_log_time) > 1.0:
                                logger.debug(f"[BG_MONITOR_RECV] Received {len(chunk)} bytes: {repr(chunk[:100])}")
                                last_log_time = time.time()
                        else:
                            # Rate limit empty chunk logging significantly (every 5 seconds)
                            if (time.time() - last_log_time) > 5.0:
                                logger.debug(f"[BG_MONITOR_EMPTY] recv() returned empty chunk")
                                last_log_time = time.time()
                    else:
                        # No data available - check if we've timed out from inactivity
                        elapsed_idle = time.time() - last_recv_time
                        if elapsed_idle > idle_timeout:
                            logger.info(f"[BG_MONITOR_COMPLETE] Idle timeout ({elapsed_idle:.1f}s) - command complete")

                            # Update command status to completed
                            with self._lock:
                                if command_id in self._commands:
                                    cmd.status = CommandStatus.COMPLETED
                                    cmd.end_time = datetime.now()
                                    logger.info(f"[BG_MONITOR_FINAL] Command {command_id} completed after input")
                            break

                        time.sleep(0.1)
                except Exception as recv_error:
                    logger.error(f"[BG_MONITOR_RECV_ERROR] Error receiving data: {recv_error}")
                    break
        except Exception as e:
            logger.error(f"[BG_MONITOR_ERROR] Error in background monitoring: {e}", exc_info=True)
            with self._lock:
                if command_id in self._commands:
                    cmd.status = CommandStatus.FAILED
                    cmd.stderr = str(e)
                    cmd.end_time = datetime.now()

    def list_running_commands(self) -> list[dict]:
        """List all running async commands."""
        logger = self.logger.getChild('list_running')
        with self._lock:
            running_list = [
                {
                    "command_id": cmd.command_id,
                    "session_key": cmd.session_key,
                    "command": cmd.command,
                    "status": cmd.status.value,
                    "start_time": cmd.start_time.isoformat()
                }
                for cmd in self._commands.values()
                if cmd.status == CommandStatus.RUNNING
            ]
            logger.info(f"Found {len(running_list)} running commands.")
            return running_list

    def list_command_history(self, limit: int = 50) -> list[dict]:
        """List recent command history (completed, failed, interrupted)."""
        logger = self.logger.getChild('list_history')
        with self._lock:
            completed = [
                {
                    "command_id": cmd.command_id,
                    "session_key": cmd.session_key,
                    "command": cmd.command,
                    "status": cmd.status.value,
                    "exit_code": cmd.exit_code,
                    "start_time": cmd.start_time.isoformat(),
                    "end_time": cmd.end_time.isoformat() if cmd.end_time else None
                }
                for cmd in self._commands.values()
                if cmd.status != CommandStatus.RUNNING
            ]
            # Sort by end time, most recent first
            completed.sort(key=lambda x: x['end_time'] or '', reverse=True)
            result = completed[:limit]
            logger.info(f"Returning {len(result)} commands from history (limit: {limit}).")
            return result

    def clear_session_commands(self, session_key: str):
        """Clear all commands for a specific session.

        Args:
            session_key: Session identifier (e.g., "user@host:22")
        """
        logger = self.logger.getChild('clear_session_commands')
        with self._lock:
            commands_to_remove = [
                cmd_id for cmd_id, cmd in self._commands.items()
                if cmd.session_key == session_key
            ]

            if commands_to_remove:
                logger.info(f"Clearing {len(commands_to_remove)} commands for session {session_key}")
                for cmd_id in commands_to_remove:
                    cmd = self._commands[cmd_id]
                    # Signal cancellation to background threads
                    cmd.monitoring_cancelled.set()

                    # Mark as interrupted if still running/awaiting
                    if cmd.status in (CommandStatus.RUNNING, CommandStatus.AWAITING_INPUT):
                        cmd.status = CommandStatus.INTERRUPTED
                        cmd.end_time = datetime.now()
                        logger.debug(f"Marked command {cmd_id} as interrupted")
                    del self._commands[cmd_id]
                logger.info(f"Cleared {len(commands_to_remove)} commands for session {session_key}")
            else:
                logger.debug(f"No commands found for session {session_key}")

    def clear_all_commands(self):
        """Clear all commands from all sessions."""
        logger = self.logger.getChild('clear_all_commands')
        with self._lock:
            count = len(self._commands)
            if count > 0:
                logger.info(f"Clearing {count} commands from all sessions")
                for cmd in self._commands.values():
                    # Signal cancellation
                    cmd.monitoring_cancelled.set()

                    if cmd.status in (CommandStatus.RUNNING, CommandStatus.AWAITING_INPUT):
                        cmd.status = CommandStatus.INTERRUPTED
                        cmd.end_time = datetime.now()
                self._commands.clear()
                logger.info(f"Cleared {count} commands")
            else:
                logger.debug("No commands to clear")

    def shutdown(self):
        """Shut down the underlying thread pool executor and clear running commands."""
        logger = self.logger.getChild('shutdown')
        logger.info("Shutting down command executor pool")
        self._executor.shutdown(wait=False, cancel_futures=True)

        with self._lock:
            running_count = sum(1 for cmd in self._commands.values() if cmd.status in (CommandStatus.RUNNING, CommandStatus.AWAITING_INPUT))
            if running_count > 0:
                logger.info(f"Clearing {running_count} active commands from the registry due to shutdown.")
            
            # Signal cancellation to all commands
            for cmd in self._commands.values():
                cmd.monitoring_cancelled.set()
                
            self._commands.clear()

    def _execute_standard_command_internal(self, client: paramiko.SSHClient, command: str,
                                           timeout: int, session_key: str) -> tuple[str, str, int]:
        """Internal method to execute a standard SSH command using persistent shell."""
        return self._session_manager._execute_standard_command_internal(client, command, timeout, session_key)

    def _execute_sudo_command_internal(self, client: paramiko.SSHClient, command: str,
                                      sudo_password: str, timeout: int = 30) -> tuple[str, str, int]:
        """Internal method to execute a command with sudo, handling password prompt."""
        return self._session_manager._execute_sudo_command_internal(client, command, sudo_password, timeout)

    def _execute_enable_mode_command_internal(self, client: paramiko.SSHClient, session_key: str,
                                              command: str, enable_password: str,
                                              enable_command: str, timeout: int) -> tuple[str, str, int]:
        """Internal method to execute command in enable mode on network device."""
        return self._session_manager._execute_enable_mode_command_internal(client, session_key, command, enable_password, enable_command, timeout)
