"""Enhanced error handling and user-friendly messaging."""
import re
from typing import Optional, Tuple
from .datastructures import ErrorInfo, ErrorCategory


class ErrorHandler:
    """Handles error categorization and user-friendly messaging."""
    
    # Common error patterns and their categories
    ERROR_PATTERNS = {
        ErrorCategory.NETWORK: [
            r'connection.*refused',
            r'network.*unreachable',
            r'no route to host',
            r'timeout.*connecting',
            r'connection.*timed out',
            r'host.*not found',
            r'name or service.*not known',
            r'ssh_exchange_identification.*remote.*closed'
        ],
        ErrorCategory.AUTHENTICATION: [
            r'authentication.*failed',
            r'permission.*denied',
            r'password.*incorrect',
            r'invalid.*user',
            r'publickey.*denied',
            r'access.*denied',
            r'auth.*failed'
        ],
        ErrorCategory.PERMISSION: [
            r'permission.*denied',
            r'operation.*not permitted',
            r'insufficient.*privileges',
            r'sudo.*password.*required',
            r'must be.*root',
            r'access.*denied'
        ],
        ErrorCategory.TIMEOUT: [
            r'timed out',
            r'timeout.*period',
            r'read.*timeout',
            r'connection.*timeout',
            r'inactivity.*timeout'
        ],
        ErrorCategory.PROTOCOL: [
            r'protocol.*error',
            r'ssh.*protocol',
            r'version.*mismatch',
            r'banner.*exchange.*failed'
        ]
    }
    
    # Troubleshooting hints by category
    TROUBLESHOOTING_HINTS = {
        ErrorCategory.NETWORK: (
            "1. Verify the hostname/IP address is correct\n"
            "2. Check network connectivity (ping the host)\n"
            "3. Ensure SSH service is running on the target\n"
            "4. Check firewall rules on both ends\n"
            "5. Try using a different port if SSH runs on non-standard port"
        ),
        ErrorCategory.AUTHENTICATION: (
            "1. Verify username is correct\n"
            "2. Check password or SSH key\n"
            "3. Ensure the account is not locked\n"
            "4. Try manual SSH to test credentials\n"
            "5. Check if key-based auth is properly configured"
        ),
        ErrorCategory.PERMISSION: (
            "1. Use sudo or run as appropriate user\n"
            "2. Check file/directory permissions\n"
            "3. Verify the user has required privileges\n"
            "4. For system commands, use enable mode on network devices"
        ),
        ErrorCategory.TIMEOUT: (
            "1. Check network latency and stability\n"
            "2. Increase timeout parameter for long operations\n"
            "3. Consider breaking large operations into smaller ones\n"
            "4. Use streaming mode for long-running commands"
        ),
        ErrorCategory.PROTOCOL: (
            "1. Check SSH protocol version compatibility\n"
            "2. Verify target SSH server is properly configured\n"
            "3. Try with different SSH options\n"
            "4. Check for SSH software updates"
        )
    }
    
    # Suggested actions by category
    SUGGESTED_ACTIONS = {
        ErrorCategory.NETWORK: "Check network connectivity and host accessibility",
        ErrorCategory.AUTHENTICATION: "Verify credentials and authentication method",
        ErrorCategory.PERMISSION: "Use appropriate privileges (sudo/enable mode)",
        ErrorCategory.TIMEOUT: "Increase timeout or use streaming mode for long operations",
        ErrorCategory.PROTOCOL: "Check SSH configuration compatibility",
        ErrorCategory.COMMAND: "Verify command syntax and execution context"
    }
    
    @classmethod
    def categorize_error(cls, error_message: str, original_exception: Optional[Exception] = None) -> ErrorInfo:
        """Categorize an error and provide user-friendly information."""
        
        error_lower = error_message.lower()
        
        # Try to match against patterns
        for category, patterns in cls.ERROR_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, error_lower):
                    return cls._create_error_info(
                        category, error_message, original_exception, pattern
                    )
        
        # Fallback categorization
        return cls._fallback_categorize(error_message, original_exception)
    
    @classmethod
    def _create_error_info(cls, category: ErrorCategory, error_message: str,
                         original_exception: Optional[Exception] = None,
                         pattern: Optional[str] = None) -> ErrorInfo:
        """Create structured error info."""
        
        return ErrorInfo(
            category=category,
            message=cls._get_user_friendly_message(category, error_message),
            original_error=str(original_exception) if original_exception else error_message,
            troubleshooting_hint=cls.TROUBLESHOOTING_HINTS.get(category),
            suggest_action=cls.SUGGESTED_ACTIONS.get(category)
        )
    
    @classmethod
    def _fallback_categorize(cls, error_message: str, original_exception: Optional[Exception]) -> ErrorInfo:
        """Fallback categorization when patterns don't match."""
        
        error_lower = error_message.lower()
        
        # Simple keyword fallback
        if any(keyword in error_lower for keyword in ['command', 'not found', 'invalid']):
            category = ErrorCategory.COMMAND
        elif any(keyword in error_lower for keyword in ['ssh', 'protocol', 'banner']):
            category = ErrorCategory.PROTOCOL
        elif any(keyword in error_lower for keyword in ['timeout', 'timed']):
            category = ErrorCategory.TIMEOUT
        elif any(keyword in error_lower for keyword in ['auth', 'login', 'password']):
            category = ErrorCategory.AUTHENTICATION
        else:
            category = ErrorCategory.UNKNOWN
        
        return cls._create_error_info(category, error_message, original_exception)
    
    @classmethod
    def _get_user_friendly_message(cls, category: ErrorCategory, original_message: str) -> str:
        """Convert technical error messages to user-friendly ones."""
        
        if category == ErrorCategory.NETWORK:
            if "connection refused" in original_message.lower():
                return "The SSH connection was refused. The target host is likely running but not accepting SSH connections."
            elif "no route to host" in original_message.lower():
                return "The target host cannot be reached. Check the hostname/IP address and network routing."
            elif "host not found" in original_message.lower():
                return "The hostname could not be resolved. Verify the DNS name or IP address."
            else:
                return "Network connection failed. The target host may be down or unreachable."
        
        elif category == ErrorCategory.AUTHENTICATION:
            if "password" in original_message.lower():
                return "Authentication failed with password. Check the password or try key-based authentication."
            elif "publickey" in original_message.lower():
                return "SSH key authentication failed. Verify the key file and permissions."
            else:
                return "Authentication failed. Verify your credentials and authentication method."
        
        elif category == ErrorCategory.PERMISSION:
            return "Permission denied. Use appropriate privileges (sudo/enable mode)."
        
        elif category == ErrorCategory.TIMEOUT:
            if "read timeout" in original_message.lower():
                return "The connection timed out while waiting for data. Check network stability."
            else:
                return "Operation timed out. Consider increasing the timeout or using streaming mode."
        
        elif category == ErrorCategory.COMMAND:
            return "Command execution failed. Check command syntax and execution context."
        
        elif category == ErrorCategory.PROTOCOL:
            return "SSH protocol error. Check SSH configuration and compatibility."
        
        else:
            return f"An error occurred: {original_message}"
    
    @classmethod
    def format_error_for_ai(cls, error_info: ErrorInfo, include_troubleshooting: bool = True) -> str:
        """Format error information for AI agent consumption."""
        
        response_parts = [
            f"❌ {error_info.message}",
            f"📂 Category: {error_info.category.value}",
            f"🎯 Suggested Action: {error_info.suggest_action}"
        ]
        
        if include_troubleshooting and error_info.troubleshooting_hint:
            response_parts.extend([
                "",
                "🔧 Troubleshooting Steps:",
                error_info.troubleshooting_hint
            ])
        
        if error_info.original_error and error_info.original_error != error_info.message:
            response_parts.extend([
                "",
                f"🐛 Technical Details: {error_info.original_error}"
            ])
        
        return "\n".join(response_parts)


class ProgressReporter:
    """Handles progress reporting for long-running operations."""
    
    @staticmethod
    def format_progress(current: int, total: int, operation: str, 
                        item: Optional[str] = None) -> str:
        """Format a progress message."""
        if total > 0:
            percentage = (current / total) * 100
            bar = "█" * int(percentage // 2) + "░" * (50 - int(percentage // 2))
            
            item_str = f" ({item})" if item else ""
            return f"📊 {operation}: {percentage:.1f}% |{bar}| ({current}/{total}){item_str}"
        else:
            return f"🔄 {operation}: {current} items processed"
    
    @staticmethod 
    def format_streaming_output(output: str, command_id: str, 
                             buffer_size: int = 0) -> str:
        """Format streaming output message."""
        preview = output[-100:] if len(output) > 100 else output
        
        return (
            f"📡 Streaming Output (Command ID: {command_id}):\n"
            f"📄 Preview (last 100 chars): {preview}\n"
            f"💾 Buffer Size: {len(output)} bytes"
        )