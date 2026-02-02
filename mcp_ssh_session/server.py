"""MCP server for SSH session management."""
import json
from typing import Optional
from fastmcp import FastMCP
from .session_manager import SSHSessionManager


# Initialize the MCP server
mcp = FastMCP("ssh-session")
session_manager = SSHSessionManager()


@mcp.tool()
def execute_command(
    host: str,
    command: str,
    username: Optional[str] = None,
    password: Optional[str] = None,
    key_filename: Optional[str] = None,
    port: Optional[int] = None,
    enable_password: Optional[str] = None,
    enable_command: str = "enable",
    sudo_password: Optional[str] = None,
    timeout: int = 30
) -> str:
    """Execute a command on an SSH host using a persistent session.

    Starts synchronously and waits for completion. If the command doesn't complete
    within the timeout, it automatically transitions to async mode and returns a
    command ID for tracking.

    The host parameter can be either a hostname/IP or an SSH config alias.
    If an SSH config alias is provided, configuration will be read from ~/.ssh/config.

    For network devices (routers, switches), use enable_password to automatically
    enter privileged/enable mode before executing commands.

    For Unix/Linux hosts requiring sudo, use sudo_password to automatically handle
    the sudo password prompt. The command will be automatically prefixed with 'sudo'
    if not already present.

    Advanced Features:
    - Automatic timeout handling with async transition
    - Interactive command support with input capability
    - Command interruption (Ctrl+C) for stuck processes
    - Session persistence across multiple commands

    Args:
        host: Hostname, IP address, or SSH config alias (e.g., "myserver")
        command: Command to execute
        username: SSH username (optional, will use SSH config or current user)
        password: Password (optional)
        key_filename: Path to SSH key file (optional, will use SSH config)
        port: SSH port (optional, will use SSH config or default 22)
        enable_password: Enable mode password for network devices (optional)
        enable_command: Command to enter enable mode (default: "enable")
        sudo_password: Password for sudo commands on Unix/Linux hosts (optional)
        timeout: Timeout in seconds for command execution (default: 30)
    """
    logger = session_manager.logger.getChild('tool_execute_command')
    logger.info(f"Executing command on {host}: {command[:100]}...")
    
    try:
        stdout, stderr, exit_status = session_manager.execute_command(
            host=host,
            username=username,
            command=command,
            password=password,
            key_filename=key_filename,
            port=port,
            enable_password=enable_password,
            enable_command=enable_command,
            sudo_password=sudo_password,
            timeout=timeout,
        )
    except ConnectionError as e:
        logger.error(f"Connection error: {e}")
        return f"Connection Error: {e}"
    except Exception as e:
        logger.error(f"Exception during execute_command: {e}", exc_info=True)
        return f"Error: {e}"

    # Check if command transitioned to async mode
    if exit_status == 124:
        if stderr.startswith("ASYNC:"):
            command_id = stderr.split(":", 1)[1]
            response = (
                f"Command exceeded timeout of {timeout}s and is now running in background.\n\n"
                f"Command ID: {command_id}\n\n"
                f"Use get_command_status('{command_id}') to check progress.\n"
                f"Use interrupt_command_by_id('{command_id}') to stop it."
            )
            logger.warning(f"Command timed out, returning async response for command_id {command_id}")
            return response
            
        if stderr.startswith("AWAITING_INPUT:"):
            # Format: AWAITING_INPUT:command_id:reason
            parts = stderr.split(":", 2)
            command_id = parts[1]
            reason = parts[2] if len(parts) > 2 else "unknown"
            
            response = (
                f"Command paused waiting for user input ({reason}).\n\n"
                f"Command ID: {command_id}\n\n"
                f"Use send_input('{command_id}', 'your_input\\n') to provide input.\n"
                f"For example, if it's a password, provide the password followed by \\n."
            )
            logger.info(f"Command awaiting input, returning instructions for command_id {command_id}")
            return response

    result = f"Exit Status: {exit_status}\n\n"
    if stdout:
        result += f"STDOUT:\n{stdout}\n"
    if stderr:
        result += f"STDERR:\n{stderr}\n"

    logger.info(f"Command finished with exit status {exit_status}.")
    logger.debug(f"Returning result:\n{result}")
    return result


@mcp.tool()
def list_sessions() -> str:
    """List all active SSH sessions."""
    logger = session_manager.logger.getChild('tool_list_sessions')
    logger.info("Listing active SSH sessions.")
    sessions = session_manager.list_sessions()
    if sessions:
        response = "Active SSH Sessions:\n" + "\n".join(f"- {s}" for s in sessions)
    else:
        response = "No active SSH sessions"
    logger.debug(f"Response: {response}")
    return response


@mcp.tool()
def close_session(host: str, username: Optional[str] = None, port: Optional[int] = None) -> str:
    """Close a specific SSH session.

    The host parameter can be either a hostname/IP or an SSH config alias.

    Args:
        host: Hostname, IP address, or SSH config alias
        username: SSH username (optional, will use SSH config or current user)
        port: SSH port (optional, will use SSH config or default 22)
    """
    logger = session_manager.logger.getChild('tool_close_session')
    logger.info(f"Closing session for host={host}, user={username}, port={port}")
    session_manager.close_session(host, username, port)

    # Get the resolved values for the response message
    host_config = session_manager._ssh_config.lookup(host)
    resolved_host = host_config.get('hostname', host)
    resolved_username = username or host_config.get('user', 'current user')
    resolved_port = port or int(host_config.get('port', 22))

    response = f"Closed session: {resolved_username}@{resolved_host}:{resolved_port}"
    logger.info(f"Session closed successfully. Response: {response}")
    return response


@mcp.tool()
def close_all_sessions() -> str:
    """Close all active SSH sessions."""
    logger = session_manager.logger.getChild('tool_close_all_sessions')
    logger.info("Closing all active SSH sessions.")
    session_manager.close_all_sessions()
    response = "All SSH sessions closed"
    logger.info(response)
    return response


@mcp.tool()
def read_file(
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
) -> str:
    """Read a remote file over SSH.
    
    Attempts to read using SFTP first. If permission is denied and use_sudo is True
    or sudo_password is provided, falls back to using 'sudo cat' via shell command.
    
    Args:
        host: Hostname, IP address, or SSH config alias
        remote_path: Path to the remote file
        username: SSH username (optional)
        password: SSH password (optional)
        key_filename: Path to SSH key file (optional)
        port: SSH port (optional)
        encoding: Text encoding (default: utf-8)
        errors: Error handling for decoding (default: replace)
        max_bytes: Maximum bytes to read (default: 2MB)
        sudo_password: Password for sudo (optional, not needed if NOPASSWD configured)
        use_sudo: Use sudo for reading (tries passwordless if no sudo_password provided)
    """
    logger = session_manager.logger.getChild('tool_read_file')
    logger.info(f"Reading file {remote_path} from {host}")
    
    content, stderr, exit_status = session_manager.read_file(
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

    result = f"Exit Status: {exit_status}\n\n"
    if content:
        result += f"CONTENT:\n{content}\n"
    if stderr:
        result += f"STDERR:\n{stderr}\n"
        
    logger.info(f"Read file finished with exit status {exit_status}.")
    logger.debug(f"Returning result for read_file:\n{result}")
    return result


@mcp.tool()
def write_file(
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
) -> str:
    """Write content to a remote file over SSH.
    
    If use_sudo is True or sudo_password is provided, uses sudo via shell commands (tee).
    Otherwise, attempts to write using SFTP.
    
    Args:
        host: Hostname, IP address, or SSH config alias
        remote_path: Path to the remote file
        content: Content to write
        username: SSH username (optional)
        password: SSH password (optional)
        key_filename: Path to SSH key file (optional)
        port: SSH port (optional)
        encoding: Text encoding (default: utf-8)
        errors: Error handling for encoding (default: strict)
        append: Append to file instead of overwriting (default: False)
        make_dirs: Create parent directories if they don't exist (default: False)
        permissions: Octal file permissions to set (e.g., 420 for 0644)
        max_bytes: Maximum bytes to write (default: 2MB)
        sudo_password: Password for sudo (optional, not needed if NOPASSWD configured)
        use_sudo: Use sudo for writing (tries passwordless if no sudo_password provided)
    """
    logger = session_manager.logger.getChild('tool_write_file')
    logger.info(f"Writing file {remote_path} to {host}")
    
    message, stderr, exit_status = session_manager.write_file(
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

    result = f"Exit Status: {exit_status}\n\n"
    if message:
        result += f"MESSAGE:\n{message}\n"
    if stderr:
        result += f"STDERR:\n{stderr}\n"
        
    logger.info(f"Write file finished with exit status {exit_status}.")
    logger.debug(f"Returning result for write_file:\n{result}")
    return result


@mcp.tool()
def execute_command_async(
    host: str,
    command: str,
    username: Optional[str] = None,
    password: Optional[str] = None,
    key_filename: Optional[str] = None,
    port: Optional[int] = None,
    timeout: int = 300
) -> str:
    """Execute a command asynchronously without blocking the server.

    Returns a command ID that can be used to check status, retrieve output, or interrupt.
    Useful for long-running commands like 'sleep 60', monitoring tasks, or large operations.

    Use with companion tools:
    - get_command_status(command_id) to check progress and retrieve output
    - interrupt_command_by_id(command_id) to send Ctrl+C and stop execution
    - send_input(command_id, text) to provide input to interactive commands

    Args:
        host: Hostname, IP address, or SSH config alias
        command: Command to execute
        username: SSH username (optional)
        password: SSH password (optional)
        key_filename: Path to SSH key file (optional)
        port: SSH port (optional)
        timeout: Maximum execution time in seconds (default: 300)
    """
    logger = session_manager.logger.getChild('tool_execute_async')
    logger.info(f"Executing async command on {host}: {command[:100]}...")
    
    try:
        command_id = session_manager.execute_command_async(
            host=host,
            command=command,
            username=username,
            password=password,
            key_filename=key_filename,
            port=port,
            timeout=timeout
        )
    except ConnectionError as e:
        logger.error(f"Connection error: {e}")
        return f"Connection Error: {e}"
    except Exception as e:
        logger.error(f"Exception during execute_command_async: {e}", exc_info=True)
        return f"Error: {e}"

    response = f"Command started with ID: {command_id}\n\nUse get_command_status('{command_id}') to check progress."
    logger.info(f"Async command started with ID: {command_id}")
    return response


@mcp.tool()
def get_command_status(command_id: str, last_n_lines: Optional[int] = None) -> str:
    """Get the status and output of an async command.
    
    Args:
        command_id: The command ID returned by execute_command_async
        last_n_lines: Optional limit for stdout lines (from end).
                      Use this for long-running commands to avoid context window overflow.
    """
    logger = session_manager.logger.getChild('tool_get_status')
    logger.info(f"Getting status for command ID: {command_id} (limit={last_n_lines})")
    
    status = session_manager.get_command_status(command_id, last_n_lines=last_n_lines)
    
    if "error" in status:
        logger.error(f"Error getting status for {command_id}: {status['error']}")
        return f"Error: {status['error']}"
    
    result = f"Command ID: {status['command_id']}\n"
    result += f"Session: {status['session_key']}\n"
    result += f"Command: {status['command']}\n"
    result += f"Status: {status['status']}\n"
    result += f"Started: {status['start_time']}\n"
    if status['end_time']:
        result += f"Ended: {status['end_time']}\n"
    if status['exit_code'] is not None:
        result += f"Exit Code: {status['exit_code']}\n"
    if status['awaiting_input_reason']:
        result += f"Awaiting Input: {status['awaiting_input_reason']}\n"
        result += f"  → Use send_input('{status['command_id']}', 'your_input\\n') to provide input\n"

    if status['stdout']:
        result += f"\nSTDOUT:\n{status['stdout']}\n"
    if status['stderr']:
        result += f"\nSTDERR:\n{status['stderr']}\n"
    
    logger.info(f"Status for {command_id}: {status['status']}")
    logger.debug(f"Returning status result for {command_id}:\n{result}")
    return result


@mcp.tool()
def interrupt_command_by_id(command_id: str) -> str:
    """Interrupt a running async command by sending Ctrl+C.
    
    Args:
        command_id: The command ID returned by execute_command_async
    """
    logger = session_manager.logger.getChild('tool_interrupt')
    logger.info(f"Interrupting command ID: {command_id}")
    
    success, message = session_manager.interrupt_command_by_id(command_id)
    
    if success:
        logger.info(f"Interrupt successful for {command_id}: {message}")
    else:
        logger.error(f"Interrupt failed for {command_id}: {message}")
        
    return message


@mcp.tool()
def list_running_commands() -> str:
    """List all currently running async commands."""
    logger = session_manager.logger.getChild('tool_list_running')
    logger.info("Listing running commands.")
    
    commands = session_manager.list_running_commands()
    if not commands:
        logger.info("No running commands found.")
        return "No running commands"
    
    result = "Running Commands:\n"
    for cmd in commands:
        result += f"\n- ID: {cmd['command_id']}\n"
        result += f"  Session: {cmd['session_key']}\n"
        result += f"  Command: {cmd['command']}\n"
        result += f"  Status: {cmd['status']}\n"
        result += f"  Started: {cmd['start_time']}\n"
    
    logger.info(f"Found {len(commands)} running commands.")
    logger.debug(f"Running commands response:\n{result}")
    return result


@mcp.tool()
def list_command_history(limit: int = 50) -> str:
    """List recent command history (completed, failed, interrupted commands).
    
    Args:
        limit: Maximum number of commands to return (default: 50)
    """
    logger = session_manager.logger.getChild('tool_list_history')
    logger.info(f"Listing command history with limit: {limit}")
    
    commands = session_manager.list_command_history(limit)
    if not commands:
        logger.info("No command history found.")
        return "No command history"
    
    result = f"Command History (last {len(commands)}):\n"
    for cmd in commands:
        result += f"\n- ID: {cmd['command_id']}\n"
        result += f"  Session: {cmd['session_key']}\n"
        result += f"  Command: {cmd['command']}\n"
        result += f"  Status: {cmd['status']}\n"
        if cmd['exit_code'] is not None:
            result += f"  Exit Code: {cmd['exit_code']}\n"
        result += f"  Started: {cmd['start_time']}\n"
        if cmd['end_time']:
            result += f"  Ended: {cmd['end_time']}\n"
    
    logger.info(f"Found {len(commands)} commands in history.")
    logger.debug(f"Command history response:\n{result}")
    return result


@mcp.tool()
def send_input(command_id: str, input_text: str) -> str:
    """Send input to a running async command and return any new output.
    
    Useful for interacting with commands that require user input, such as:
    - Pagers (less, more): send 'q' to quit, space to page down
    - Yes/no prompts: send 'y' or 'n'
    - Interactive programs: send appropriate responses
    
    Args:
        command_id: The command ID to send input to
        input_text: Text to send (e.g., 'q', 'y\n', etc.)
    """
    logger = session_manager.logger.getChild('tool_send_input')
    logger.info(f"Sending input to command ID: {command_id}")
    
    success, output, error = session_manager.send_input(command_id, input_text)
    
    if not success:
        logger.error(f"Error sending input to {command_id}: {error}")
        return f"Error: {error}"
    
    result = f"Input sent successfully\n"
    if output:
        result += f"\nOutput:\n{output}"
    else:
        result += "\nNo immediate output received"
    
    logger.info(f"Successfully sent input to {command_id}.")
    logger.debug(f"Send input response:\n{result}")
    return result


@mcp.tool()
def send_input_by_session(
    host: str,
    input_text: str,
    username: Optional[str] = None,
    port: Optional[int] = None
) -> str:
    """Send input to the active shell for a session.
    
    Useful for clearing stuck interactive states or sending input to the current shell.
    
    Args:
        host: Hostname, IP address, or SSH config alias
        input_text: Text to send (e.g., 'q\n' to quit pager, '\x03' for Ctrl+C)
        username: SSH username (optional)
        port: SSH port (optional)
    """
    logger = session_manager.logger.getChild('tool_send_input_session')
    logger.info(f"Sending input to session for host={host}, user={username}")
    
    success, output, error = session_manager.send_input_by_session(
        host, input_text, username, port
    )
    
    if not success:
        logger.error(f"Error sending input to session {host}: {error}")
        return f"Error: {error}"
    
    result = f"Input sent successfully\n"
    if output:
        result += f"\nOutput:\n{output}"
    else:
        result += "\nNo immediate output received"
    
    logger.info(f"Successfully sent input to session {host}.")
    logger.debug(f"Send input by session response:\n{result}")
    return result


@mcp.tool()
def read_screen(host: str, username: Optional[str] = None, port: Optional[int] = None, max_lines: int = 24) -> str:
    """Read the terminal screen state for a session.
    
    Returns the current screen content from the terminal emulator, including cursor position.
    Only works when MCP_SSH_INTERACTIVE_MODE=1 is set.
    
    Args:
        host: Hostname, IP address, or SSH config alias
        username: SSH username (optional, will use SSH config or current user)
        port: SSH port (optional, will use SSH config or default 22)
        max_lines: Maximum number of lines to return (default: 24)
    
    Returns:
        JSON string with screen lines, cursor position, and dimensions
    """
    logger = get_logger("read_screen")
    logger.info(f"Reading screen for {host}")
    
    _, _, _, _, session_key = session_manager._resolve_connection(host, username, port)
    snapshot = session_manager._get_screen_snapshot(session_key, max_lines)
    
    result = json.dumps(snapshot, indent=2)
    logger.debug(f"Screen snapshot:\n{result}")
    return result


@mcp.tool()
def send_keys(host: str, keys: str, username: Optional[str] = None, port: Optional[int] = None) -> str:
    """Send special keys or key sequences to a session.
    
    Supports special key tokens:
    - <enter> or <return>: Send newline
    - <esc> or <escape>: Send escape key
    - <tab>: Send tab key
    - <ctrl-c>: Send Ctrl+C (interrupt)
    - <ctrl-d>: Send Ctrl+D (EOF)
    - <ctrl-z>: Send Ctrl+Z (suspend)
    - <up>, <down>, <left>, <right>: Arrow keys
    - <space>: Space character
    
    Regular text is sent as-is. Mix special keys with text: "hello<enter>world<ctrl-c>"
    
    Args:
        host: Hostname, IP address, or SSH config alias
        keys: Key sequence to send (e.g., "q<enter>", "<esc>:wq<enter>", "<ctrl-c>")
        username: SSH username (optional)
        port: SSH port (optional)
    
    Returns:
        Success message
    """
    logger = get_logger("send_keys")
    logger.info(f"Sending keys to {host}: {repr(keys)}")
    
    # Parse special key tokens
    key_map = {
        "<enter>": "\n",
        "<return>": "\n",
        "<esc>": "\x1b",
        "<escape>": "\x1b",
        "<tab>": "\t",
        "<ctrl-c>": "\x03",
        "<ctrl-d>": "\x04",
        "<ctrl-z>": "\x1a",
        "<ctrl-g>": "\x07",
        "<up>": "\x1b[A",
        "<down>": "\x1b[B",
        "<right>": "\x1b[C",
        "<left>": "\x1b[D",
        "<space>": " ",
    }
    
    # Replace special tokens with actual control characters
    processed_keys = keys
    for token, char in key_map.items():
        processed_keys = processed_keys.replace(token, char)
    
    # Send to session
    success, stdout, stderr = session_manager.send_input_by_session(
        host, processed_keys, username, port
    )
    
    if success:
        result = f"Successfully sent keys to {host}"
        if stdout:
            result += f"\nOutput: {stdout}"
    else:
        result = f"Failed to send keys: {stderr}"
    
    logger.debug(f"Send keys result: {result}")
    return result