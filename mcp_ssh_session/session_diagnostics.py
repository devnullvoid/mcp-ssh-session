"""Session diagnostics and health monitoring."""
import re
import time
from datetime import datetime
from typing import Dict, Optional, List, Any
from .datastructures import SessionDiagnostics, ConnectionProfile


class SessionDiagnostics:
    """Provides diagnostic information about SSH sessions."""
    
    def __init__(self, session_manager):
        self.session_manager = session_manager
        self.logger = session_manager.logger.getChild('diagnostics')
    
    def get_session_diagnostics(self, host: str, username: Optional[str] = None,
                           port: Optional[int] = None) -> SessionDiagnostics:
        """Get comprehensive diagnostics for a session."""
        logger = self.logger.getChild('get_diagnostics')
        
        # Resolve connection
        _, resolved_host, resolved_username, resolved_port, session_key = \
            self.session_manager._resolve_connection(host, username, port)
        
        logger.info(f"Generating diagnostics for session: {session_key}")
        
        diagnostics = SessionDiagnostics(session_key=session_key)
        
        with self.session_manager._lock:
            # Basic session info
            client = self.session_manager._sessions.get(session_key)
            shell = self.session_manager._session_shells.get(session_key)
            
            if not client:
                diagnostics.connection_health = "dead"
                return diagnostics
            
            # Check connection health
            try:
                transport = client.get_transport()
                if transport and transport.is_active():
                    diagnostics.connection_health = "healthy"
                else:
                    diagnostics.connection_health = "degraded"
            except Exception as e:
                logger.warning(f"Error checking connection health: {e}")
                diagnostics.connection_health = "dead"
            
            # Shell type and prompt info
            diagnostics.shell_type = self.session_manager._session_shell_types.get(session_key)
            diagnostics.captured_prompt = self.session_manager._session_prompts.get(session_key)
            
            # Prompt pattern info
            prompt_pattern = self.session_manager._session_prompt_patterns.get(session_key)
            if prompt_pattern:
                diagnostics.prompt_pattern = prompt_pattern.pattern
                # Calculate confidence based on recent prompt detection success
                miss_count = self.session_manager._prompt_miss_count.get(session_key, 0)
                diagnostics.prompt_detection_confidence = max(0.0, 100.0 - (miss_count * 10.0))
            
            # Last activity
            active_cmd = self.session_manager._active_commands.get(session_key)
            if active_cmd and hasattr(active_cmd, 'last_output_time'):
                diagnostics.last_activity = active_cmd.last_output_time
            else:
                diagnostics.last_activity = datetime.now()
            
            # Shell state
            diagnostics.shell_state = self._get_shell_state(session_key, shell)
            
            # Command history (recent commands)
            diagnostics.command_history = self._get_recent_commands(session_key, limit=10)
        
        return diagnostics
    
    def _get_shell_state(self, session_key: str, shell: Any) -> Dict[str, Any]:
        """Get detailed shell state information."""
        state = {}
        
        try:
            # Check if shell exists and is responsive
            if shell:
                state['shell_exists'] = True
                state['shell_closed'] = getattr(shell, 'closed', True)
                
                # Try to get transport info
                transport = getattr(shell, 'get_transport', lambda: None)()
                if transport:
                    state['transport_active'] = transport.is_active()
                    state['transport_version'] = getattr(transport, 'version', 'unknown')
                else:
                    state['transport_active'] = False
            else:
                state['shell_exists'] = False
            
            # Enable mode state
            state['enable_mode'] = self.session_manager._enable_mode.get(session_key, False)
            
            # Prompt detection state
            state['prompt_captured'] = session_key in self.session_manager._session_prompts
            state['prompt_pattern_available'] = session_key in self.session_manager._session_prompt_patterns
            state['prompt_miss_count'] = self.session_manager._prompt_miss_count.get(session_key, 0)
            
        except Exception as e:
            state['error'] = str(e)
        
        return state
    
    def _get_recent_commands(self, session_key: str, limit: int = 10) -> List[str]:
        """Get recent commands executed on this session."""
        try:
            history = self.session_manager.command_executor.list_command_history(limit=50)
            
            # Filter commands for this session
            session_commands = [
                cmd['command'] for cmd in history 
                if cmd.get('session_key') == session_key and cmd.get('command')
            ]
            
            return session_commands[-limit:] if session_commands else []
        except Exception as e:
            self.logger.warning(f"Error getting command history: {e}")
            return []
    
    def reset_session_prompt_detection(self, host: str, username: Optional[str] = None,
                                  port: Optional[int] = None) -> bool:
        """Reset and recapture prompt detection for a session."""
        logger = self.logger.getChild('reset_prompt')
        
        _, _, _, _, session_key = self.session_manager._resolve_connection(host, username, port)
        logger.info(f"Resetting prompt detection for session: {session_key}")
        
        with self.session_manager._lock:
            shell = self.session_manager._session_shells.get(session_key)
            if not shell:
                logger.error(f"No shell found for session: {session_key}")
                return False
            
            try:
                # Clear existing prompt data
                self.session_manager._session_prompts.pop(session_key, None)
                self.session_manager._session_prompt_patterns.pop(session_key, None)
                self.session_manager._prompt_miss_count[session_key] = 0
                
                # Recapture prompt
                self.session_manager._capture_prompt(session_key, shell)
                logger.info("Successfully reset and recaptured prompt")
                return True
                
            except Exception as e:
                logger.error(f"Error resetting prompt detection: {e}")
                return False
    
    def get_connection_health_report(self) -> Dict[str, Any]:
        """Get health report for all active connections."""
        logger = self.logger.getChild('health_report')
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'total_sessions': len(self.session_manager._sessions),
            'healthy_sessions': 0,
            'degraded_sessions': 0,
            'dead_sessions': 0,
            'session_details': {}
        }
        
        for session_key in list(self.session_manager._sessions.keys()):
            try:
                client = self.session_manager._sessions[session_key]
                transport = client.get_transport()
                
                if transport and transport.is_active():
                    health = "healthy"
                    report['healthy_sessions'] += 1
                else:
                    health = "dead"
                    report['dead_sessions'] += 1
                
                # Get additional session info
                shell_type = self.session_manager._session_shell_types.get(session_key, 'unknown')
                last_cmd = self.session_manager._active_commands.get(session_key)
                
                report['session_details'][session_key] = {
                    'health': health,
                    'shell_type': shell_type,
                    'has_active_command': last_cmd is not None,
                    'enable_mode': self.session_manager._enable_mode.get(session_key, False)
                }
                
            except Exception as e:
                logger.warning(f"Error checking session {session_key}: {e}")
                report['dead_sessions'] += 1
                report['session_details'][session_key] = {
                    'health': 'error',
                    'error': str(e)
                }
        
        return report
    
    def suggest_session_optimization(self, session_key: str) -> List[str]:
        """Suggest optimizations based on session diagnostics."""
        suggestions = []
        
        try:
            # Check prompt detection confidence
            miss_count = self.session_manager._prompt_miss_count.get(session_key, 0)
            if miss_count > 3:
                suggestions.append("Consider resetting prompt detection - multiple misses detected")
            
            # Check shell type
            shell_type = self.session_manager._session_shell_types.get(session_key, 'unknown')
            if shell_type == 'unknown':
                suggestions.append("Shell type not detected - may affect prompt detection")
            
            # Check for long-running commands
            active_cmd = self.session_manager._active_commands.get(session_key)
            if active_cmd and hasattr(active_cmd, 'start_time'):
                runtime = datetime.now() - active_cmd.start_time
                if runtime.total_seconds() > 300:  # 5 minutes
                    suggestions.append("Command has been running long - consider using streaming mode")
            
            # Check connection issues
            try:
                client = self.session_manager._sessions[session_key]
                transport = client.get_transport()
                if not (transport and transport.is_active()):
                    suggestions.append("Connection appears unhealthy - consider reconnecting")
            except:
                suggestions.append("Session connection may be unstable")
        
        except Exception as e:
            self.logger.warning(f"Error generating suggestions: {e}")
            suggestions.append("Unable to analyze session for optimization suggestions")
        
        return suggestions


class ConnectionProfileManager:
    """Manages connection profiles for performance optimization."""
    
    def __init__(self, session_manager):
        self.session_manager = session_manager
        self._profiles: Dict[str, ConnectionProfile] = {}
        self.logger = session_manager.logger.getChild('connection_profiles')
    
    def get_profile(self, host: str, username: Optional[str] = None,
                   port: Optional[int] = None) -> ConnectionProfile:
        """Get or create connection profile."""
        _, resolved_host, resolved_username, resolved_port, session_key = \
            self.session_manager._resolve_connection(host, username, port)
        
        if session_key not in self._profiles:
            self._profiles[session_key] = ConnectionProfile(
                hostname=resolved_host,
                username=resolved_username,
                port=resolved_port,
                key_filename=None,
                config_host=host if host != resolved_host else None
            )
        
        return self._profiles[session_key]
    
    def update_connection_stats(self, session_key: str, connect_time: float):
        """Update connection statistics."""
        if session_key in self._profiles:
            profile = self._profiles[session_key]
            profile.connect_count += 1
            profile.last_connect = datetime.now()
            
            # Update average connect time
            if profile.connect_count == 1:
                profile.avg_connect_time = connect_time
            else:
                profile.avg_connect_time = (
                    (profile.avg_connect_time * (profile.connect_count - 1) + connect_time) / 
                    profile.connect_count
                )
    
    def get_performance_report(self) -> Dict[str, Any]:
        """Get performance report for connection profiles."""
        report = {
            'total_profiles': len(self._profiles),
            'profiles': {}
        }
        
        for session_key, profile in self._profiles.items():
            report['profiles'][session_key] = {
                'hostname': profile.hostname,
                'username': profile.username,
                'port': profile.port,
                'connect_count': profile.connect_count,
                'avg_connect_time': profile.avg_connect_time,
                'last_connect': profile.last_connect.isoformat() if profile.last_connect else None,
                'connection_health': profile.connection_health
            }
        
        return report