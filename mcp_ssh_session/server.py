"""MCP server for SSH session management."""
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

    The host parameter can be either a hostname/IP or an SSH config alias.
    If an SSH config alias is provided, configuration will be read from ~/.ssh/config.

    For network devices (routers, switches), use enable_password to automatically
    enter privileged/enable mode before executing commands.

    For Unix/Linux hosts requiring sudo, use sudo_password to automatically handle
    the sudo password prompt. The command will be automatically prefixed with 'sudo'
    if not already present.

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

    result = f"Exit Status: {exit_status}\n\n"
    if stdout:
        result += f"STDOUT:\n{stdout}\n"
    if stderr:
        result += f"STDERR:\n{stderr}\n"

    return result


@mcp.tool()
def list_sessions() -> str:
    """List all active SSH sessions."""
    sessions = session_manager.list_sessions()
    if sessions:
        return "Active SSH Sessions:\n" + "\n".join(f"- {s}" for s in sessions)
    else:
        return "No active SSH sessions"


@mcp.tool()
def close_session(host: str, username: Optional[str] = None, port: Optional[int] = None) -> str:
    """Close a specific SSH session.

    The host parameter can be either a hostname/IP or an SSH config alias.

    Args:
        host: Hostname, IP address, or SSH config alias
        username: SSH username (optional, will use SSH config or current user)
        port: SSH port (optional, will use SSH config or default 22)
    """
    session_manager.close_session(host, username, port)

    # Get the resolved values for the response message
    host_config = session_manager._ssh_config.lookup(host)
    resolved_host = host_config.get('hostname', host)
    resolved_username = username or host_config.get('user', 'current user')
    resolved_port = port or int(host_config.get('port', 22))

    return f"Closed session: {resolved_username}@{resolved_host}:{resolved_port}"


@mcp.tool()
def close_all_sessions() -> str:
    """Close all active SSH sessions."""
    session_manager.close_all()
    return "All SSH sessions closed"


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
    return result
