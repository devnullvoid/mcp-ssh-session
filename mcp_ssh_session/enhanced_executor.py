"""Enhanced command execution with streaming and auto-timeout features."""
import time
import threading
import uuid
from datetime import datetime
from typing import Optional, Dict, Any, List, Callable

from .datastructures import CommandStatus, RunningCommand, ErrorInfo, ErrorCategory
from .logging_manager import RateLimitedLogger, get_logger, get_context_logger, LogLevel
from .error_handler import ErrorHandler, ProgressReporter


class EnhancedCommandExecutor:
    """Enhanced command executor with streaming and intelligent timeout handling."""
    
    def __init__(self, session_manager):
        self.session_manager = session_manager
        self.logger = get_logger('enhanced_executor')
        self.context_logger = get_context_logger('enhanced_executor')
        self._commands: Dict[str, RunningCommand] = {}
        self._lock = threading.Lock()
    
    def execute_command_enhanced(self, host: str, username: Optional[str] = None,
                               command: str = "", password: Optional[str] = None,
                               key_filename: Optional[str] = None, port: Optional[int] = None,
                               enable_password: Optional[str] = None,
                               enable_command: str = "enable", sudo_password: Optional[str] = None,
                               timeout: int = 30, auto_extend_timeout: bool = True,
                               max_timeout: int = 600, streaming_mode: bool = False,
                               progress_callback: Optional[str] = None) -> str:
        """Execute command with enhanced features.
        
        Args:
            auto_extend_timeout: Automatically extend timeout for long-running commands
            max_timeout: Maximum timeout when auto-extending
            streaming_mode: Return output as it streams (for long operations)
            progress_callback: MCP tool name for progress callbacks
        """
        self.context_logger.log_operation_start("execute_enhanced", 
            f"cmd={command[:50]}..., auto_extend={auto_extend_timeout}, streaming={streaming_mode}")
        
        try:
            # Validate command
            is_valid, error_msg = self.session_manager._command_validator.validate_command(
                command,
                pty_aware=(
                    self.session_manager._interactive_mode
                    and self.session_manager._pty_aware_validation
                ),
            )
            if not is_valid:
                self.context_logger.log_operation_end("execute_enhanced", success=False,
                                                details=f"Invalid command: {error_msg}")
                return f"❌ Command validation failed: {error_msg}"
            
            # Get session
            client = self.session_manager.get_or_create_session(host, username, password, 
                                                        key_filename, port)
            _, _, _, _, session_key = self.session_manager._resolve_connection(
                host, username, port
            )
            
            # Create enhanced command record
            command_id = str(uuid.uuid4())
            shell = self.session_manager._get_or_create_shell(session_key, client)
            
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
                end_time=None,
                auto_extend_timeout=auto_extend_timeout,
                max_timeout=max_timeout,
                progress_callback=progress_callback,
                streaming_mode=streaming_mode,
                last_output_time=datetime.now(),
                output_chunks=[]
            )
            
            # Register command
            with self._lock:
                self._commands[command_id] = running_cmd
            
            # Start execution
            if streaming_mode:
                return self._execute_streaming_command(command_id, running_cmd, 
                                                 timeout, session_key)
            else:
                return self._execute_enhanced_sync_command(command_id, running_cmd,
                                                      timeout, session_key)
        
        except Exception as e:
            error_info = ErrorHandler.categorize_error(str(e), e)
            self.context_logger.log_operation_end("execute_enhanced", success=False,
                                            details=f"Exception: {error_info.message}")
            return ErrorHandler.format_error_for_ai(error_info)
    
    def _execute_streaming_command(self, command_id: str, running_cmd: RunningCommand,
                                 timeout: int, session_key: str) -> str:
        """Execute command in streaming mode."""
        self.context_logger.set_context("streaming", command_id)
        self.context_logger.log_operation_start("streaming_execution",
                                          f"timeout={timeout}")
        
        try:
            shell = running_cmd.shell
            shell.settimeout(timeout)
            
            # Send command
            shell.send(running_cmd.command + '\n')
            time.sleep(0.3)
            
            # Stream output
            start_time = datetime.now()
            last_progress_time = start_time
            current_timeout = timeout
            
            while True:
                # Check for interruption
                if running_cmd.monitoring_cancelled.is_set():
                    self._interrupt_command_internal(command_id)
                    break
                
                # Read available data
                if shell.recv_ready():
                    chunk = shell.recv(4096).decode('utf-8', errors='ignore')
                    running_cmd.output_chunks.append(chunk)
                    running_cmd.stdout += chunk
                    running_cmd.last_output_time = datetime.now()
                    
                    # Update status periodically for streaming
                    if running_cmd.progress_callback:
                        now = datetime.now()
                        if (now - last_progress_time).total_seconds() > 5.0:  # Every 5 seconds
                            self._send_progress_update(command_id, running_cmd)
                            last_progress_time = now
                
                # Check for completion
                if running_cmd.stdout:
                    clean_output = self.session_manager._strip_ansi(running_cmd.stdout)
                    is_complete, _ = self.session_manager._check_prompt_completion(
                        session_key, running_cmd.stdout, clean_output
                    )
                    
                    if is_complete:
                        running_cmd.status = CommandStatus.COMPLETED
                        running_cmd.end_time = datetime.now()
                        duration = (running_cmd.end_time - start_time).total_seconds()
                        
                        self.context_logger.log_operation_end("streaming_execution",
                                                        success=True,
                                                        details=f"completed in {duration:.1f}s")
                        
                        return ProgressReporter.format_streaming_output(
                            running_cmd.stdout, command_id, len(running_cmd.stdout)
                        )
                
                # Check for timeouts and auto-extend
                now = datetime.now()
                elapsed = (now - start_time).total_seconds()
                
                if elapsed > current_timeout:
                    if running_cmd.auto_extend_timeout and current_timeout < running_cmd.max_timeout:
                        # Auto-extend timeout
                        new_timeout = min(current_timeout * 1.5, running_cmd.max_timeout)
                        self.context_logger.log_with_context(LogLevel.INFO, "streaming",
                            f"Auto-extending timeout from {current_timeout}s to {new_timeout}s")
                        current_timeout = new_timeout
                    else:
                        # Final timeout
                        running_cmd.status = CommandStatus.FAILED
                        running_cmd.end_time = now
                        
                        error_msg = f"Command timed out after {elapsed:.1f}s (max timeout: {current_timeout}s)"
                        self.context_logger.log_operation_end("streaming_execution",
                                                        success=False, details=error_msg)
                        
                        return f"⏰ {error_msg}\n\n{ProgressReporter.format_streaming_output(running_cmd.stdout, command_id)}"
                
                time.sleep(0.1)
        
        except Exception as e:
            error_info = ErrorHandler.categorize_error(str(e), e)
            running_cmd.status = CommandStatus.FAILED
            running_cmd.end_time = datetime.now()
            
            self.context_logger.log_operation_end("streaming_execution", success=False,
                                            details=error_info.message)
            return ErrorHandler.format_error_for_ai(error_info)
        
        finally:
            with self._lock:
                running_cmd.status = CommandStatus.COMPLETED
    
    def _execute_enhanced_sync_command(self, command_id: str, running_cmd: RunningCommand,
                                     timeout: int, session_key: str) -> str:
        """Execute command with enhanced sync features."""
        self.context_logger.set_context("enhanced_sync", command_id)
        self.context_logger.log_operation_start("enhanced_sync_execution",
                                          f"timeout={timeout}, auto_extend={running_cmd.auto_extend_timeout}")
        
        try:
            # Use existing standard execution but with enhancements
            if running_cmd.auto_extend_timeout:
                return self._execute_with_auto_extend(command_id, running_cmd, 
                                                timeout, session_key)
            else:
                return self._execute_standard_with_monitoring(command_id, running_cmd,
                                                        timeout, session_key)
        
        except Exception as e:
            error_info = ErrorHandler.categorize_error(str(e), e)
            running_cmd.status = CommandStatus.FAILED
            running_cmd.end_time = datetime.now()
            
            self.context_logger.log_operation_end("enhanced_sync_execution", success=False,
                                            details=error_info.message)
            return ErrorHandler.format_error_for_ai(error_info)
        
        finally:
            with self._lock:
                if running_cmd.status == CommandStatus.RUNNING:
                    running_cmd.status = CommandStatus.COMPLETED
                    running_cmd.end_time = datetime.now()
    
    def _execute_with_auto_extend(self, command_id: str, running_cmd: RunningCommand,
                                 initial_timeout: int, session_key: str) -> str:
        """Execute command with automatic timeout extension."""
        start_time = datetime.now()
        current_timeout = initial_timeout
        shell = running_cmd.shell
        
        # Send command
        shell.send(running_cmd.command + '\n')
        time.sleep(0.3)
        
        self.context_logger.log_with_context(LogLevel.INFO, "auto_extend",
            f"Starting with timeout {current_timeout}s, max {running_cmd.max_timeout}s")
        
        while True:
            if running_cmd.monitoring_cancelled.is_set():
                self._interrupt_command_internal(command_id)
                break
            
            # Check completion
            if running_cmd.stdout:
                clean_output = self.session_manager._strip_ansi(running_cmd.stdout)
                is_complete, cleaned = self.session_manager._check_prompt_completion(
                    session_key, running_cmd.stdout, clean_output
                )
                
                if is_complete:
                    running_cmd.status = CommandStatus.COMPLETED
                    running_cmd.end_time = datetime.now()
                    duration = (running_cmd.end_time - start_time).total_seconds()
                    
                    self.context_logger.log_with_context(LogLevel.INFO, "auto_extend",
                        f"Command completed in {duration:.1f}s (timeout: {current_timeout}s)")
                    
                    return cleaned
            
            # Check timeout
            now = datetime.now()
            elapsed = (now - start_time).total_seconds()
            
            if elapsed > current_timeout:
                if current_timeout < running_cmd.max_timeout:
                    # Auto-extend
                    old_timeout = current_timeout
                    current_timeout = min(current_timeout * 1.5, running_cmd.max_timeout)
                    
                    self.context_logger.log_with_context(LogLevel.INFO, "auto_extend",
                        f"Extending timeout: {old_timeout}s -> {current_timeout}s")
                    
                    # Send progress if callback available
                    if running_cmd.progress_callback:
                        self._send_progress_update(command_id, running_cmd)
                else:
                    # Max timeout reached
                    running_cmd.status = CommandStatus.FAILED
                    running_cmd.end_time = now
                    
                    error_msg = f"Command timed out after {elapsed:.1f}s (max timeout: {running_cmd.max_timeout}s)"
                    self.context_logger.log_operation_end("auto_extend_execution", success=False,
                                                    details=error_msg)
                    
                    error_info = ErrorInfo(
                        category=ErrorCategory.TIMEOUT,
                        message=error_msg,
                        troubleshooting_hint="Use streaming_mode for very long operations or increase max_timeout",
                        suggest_action="Consider using streaming_mode for long-running commands"
                    )
                    return ErrorHandler.format_error_for_ai(error_info)
            
            # Brief sleep to avoid CPU spinning
            time.sleep(0.1)
        
        return ""
    
    def _execute_standard_with_monitoring(self, command_id: str, running_cmd: RunningCommand,
                                         timeout: int, session_key: str) -> str:
        """Execute standard command with enhanced monitoring."""
        # Use existing session manager execution with monitoring
        client = self.session_manager._sessions.get(session_key)
        
        if running_cmd.progress_callback:
            # Start monitoring thread for progress updates
            monitoring_thread = threading.Thread(
                target=self._monitor_command_progress,
                args=(command_id, running_cmd),
                daemon=True
            )
            monitoring_thread.start()
        
        # Execute using existing method
        stdout, stderr, exit_code, awaiting_input = self.session_manager._execute_standard_command_internal(
            client, running_cmd.command, timeout, session_key
        )
        
        # Handle awaiting input
        if awaiting_input:
            running_cmd.status = CommandStatus.AWAITING_INPUT
            running_cmd.awaiting_input_reason = awaiting_input
            self.context_logger.log_with_context(LogLevel.INFO, "enhanced_sync",
                f"Command awaiting input: {awaiting_input}")
            return f"Command paused waiting for input: {awaiting_input}"
        
        running_cmd.stdout = stdout
        running_cmd.stderr = stderr
        running_cmd.exit_code = exit_code
        running_cmd.end_time = datetime.now()
        
        if exit_code == 0:
            running_cmd.status = CommandStatus.COMPLETED
        else:
            running_cmd.status = CommandStatus.FAILED
        
        return stdout if exit_code == 0 else stderr or f"Command failed with exit code {exit_code}"
    
    def _monitor_command_progress(self, command_id: str, running_cmd: RunningCommand):
        """Monitor command progress and send updates."""
        last_update = datetime.now()
        
        while (running_cmd.status == CommandStatus.RUNNING and 
               not running_cmd.monitoring_cancelled.is_set()):
            
            now = datetime.now()
            if (now - last_update).total_seconds() > 10.0:  # Every 10 seconds
                self._send_progress_update(command_id, running_cmd)
                last_update = now
            
            time.sleep(1.0)
    
    def _send_progress_update(self, command_id: str, running_cmd: RunningCommand):
        """Send progress update via callback if available."""
        if not running_cmd.progress_callback:
            return
        
        try:
            duration = (datetime.now() - running_cmd.start_time).total_seconds()
            output_size = len(running_cmd.stdout)
            
            progress_msg = ProgressReporter.format_progress(
                int(duration), running_cmd.max_timeout or 300,
                f"Command execution", f"{output_size} bytes output"
            )
            
            self.context_logger.log_with_context(LogLevel.INFO, "progress",
                f"Update for {command_id}: {duration:.1f}s, {output_size} bytes")
            
            # Note: In real implementation, this would call the actual MCP tool
            # For now, we just log it
            self.logger.info(f"PROGRESS_UPDATE: {progress_msg}")
            
        except Exception as e:
            self.context_logger.log_with_context(LogLevel.WARNING, "progress",
                f"Failed to send progress update: {e}")
    
    def _interrupt_command_internal(self, command_id: str):
        """Internal command interruption."""
        with self._lock:
            if command_id in self._commands:
                running_cmd = self._commands[command_id]
                running_cmd.monitoring_cancelled.set()
                running_cmd.status = CommandStatus.INTERRUPTED
                running_cmd.end_time = datetime.now()
                
                # Send Ctrl+C
                try:
                    running_cmd.shell.send('\x03')  # Ctrl+C
                    time.sleep(0.5)
                except Exception as e:
                    self.context_logger.log_with_context(LogLevel.WARNING, "interrupt",
                        f"Failed to send interrupt: {e}")
    
    def get_command_status_enhanced(self, command_id: str) -> Dict[str, Any]:
        """Get enhanced status of a command."""
        with self._lock:
            if command_id not in self._commands:
                return {
                    'command_id': command_id,
                    'status': 'not_found',
                    'message': 'Command not found'
                }
            
            running_cmd = self._commands[command_id]
            
            status_data = {
                'command_id': command_id,
                'status': running_cmd.status.value,
                'start_time': running_cmd.start_time.isoformat(),
                'stdout_size': len(running_cmd.stdout),
                'stderr_size': len(running_cmd.stderr),
                'auto_extend_timeout': running_cmd.auto_extend_timeout,
                'max_timeout': running_cmd.max_timeout,
                'streaming_mode': running_cmd.streaming_mode,
                'has_progress_callback': bool(running_cmd.progress_callback)
            }
            
            if running_cmd.end_time:
                status_data['end_time'] = running_cmd.end_time.isoformat()
                status_data['duration_seconds'] = (running_cmd.end_time - running_cmd.start_time).total_seconds()
            
            if running_cmd.exit_code is not None:
                status_data['exit_code'] = running_cmd.exit_code
            
            if running_cmd.awaiting_input_reason:
                status_data['awaiting_input_reason'] = running_cmd.awaiting_input_reason
            
            # Add preview for long output
            if len(running_cmd.stdout) > 1000:
                status_data['output_preview'] = running_cmd.stdout[-200:]
                status_data['output_size_display'] = f"{len(running_cmd.stdout):,} bytes"
            else:
                status_data['output_preview'] = running_cmd.stdout
                status_data['output_size_display'] = f"{len(running_cmd.stdout)} bytes"
            
            return status_data
