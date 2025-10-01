"""MCP server for SSH session management."""
from fastmcp import FastMCP
from .session_manager import SSHSessionManager


# Initialize the MCP server
mcp = FastMCP("mcp-ssh-session")
session_manager = SSHSessionManager()


@mcp.tool()
def execute_command(
    host: str,
    username: str,
    command: str,
    password: str = None,
    key_filename: str = None,
    port: int = 22
) -> str:
    """Execute a command on an SSH host using a persistent session.

    Args:
        host: Hostname or IP address
        username: SSH username
        command: Command to execute
        password: Password (optional)
        key_filename: Path to SSH key file (optional)
        port: SSH port (default: 22)
    """
    stdout, stderr, exit_status = session_manager.execute_command(
        host=host,
        username=username,
        command=command,
        password=password,
        key_filename=key_filename,
        port=port,
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
def close_session(host: str, username: str, port: int = 22) -> str:
    """Close a specific SSH session.

    Args:
        host: Hostname or IP address
        username: SSH username
        port: SSH port (default: 22)
    """
    session_manager.close_session(host, username, port)
    return f"Closed session: {username}@{host}:{port}"


@mcp.tool()
def close_all_sessions() -> str:
    """Close all active SSH sessions."""
    session_manager.close_all()
    return "All SSH sessions closed"
