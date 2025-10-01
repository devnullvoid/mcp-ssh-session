# MCP SSH Session

An MCP (Model Context Protocol) server that enables AI agents to establish and manage persistent SSH sessions, allowing them to execute commands on remote hosts while maintaining connection state.

## Overview

This MCP server provides tools for AI agents to:
- Establish persistent SSH connections to remote hosts
- Execute commands within existing sessions
- Manage multiple concurrent SSH sessions
- Track and close active connections

## Features

- **Persistent Sessions**: SSH connections are reused across multiple command executions, reducing connection overhead
- **SSH Config Support**: Automatically reads and uses settings from `~/.ssh/config`, including aliases, hosts, ports, users, and identity files
- **Multi-host Support**: Manage connections to multiple hosts simultaneously
- **Automatic Reconnection**: Dead connections are detected and automatically re-established
- **Thread-safe**: Safe for concurrent operations
- **Flexible Authentication**: Supports both password and key-based authentication

## Installation

Using `uv`:

```bash
uv venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
uv pip install -e .
```

## Usage

### Running the Server

```bash
python -m mcp_ssh_session
```

### Available Tools

#### `execute_command`
Execute a command on an SSH host using a persistent session.

The `host` parameter can be either a hostname/IP or an SSH config alias. If an SSH config alias is provided, configuration will be read from `~/.ssh/config`.

**Parameters:**
- `host` (str, required): Hostname, IP address, or SSH config alias (e.g., "myserver")
- `command` (str, required): Command to execute
- `username` (str, optional): SSH username (will use SSH config or current user if not provided)
- `password` (str, optional): Password for authentication
- `key_filename` (str, optional): Path to SSH private key file (will use SSH config if not provided)
- `port` (int, optional): SSH port (will use SSH config or default 22 if not provided)

**Returns:** Command output including exit status, stdout, and stderr

**Examples:**

Using SSH config alias:
```python
# If ~/.ssh/config has an entry for "myserver"
execute_command(
    host="myserver",
    command="ls -la /var/log"
)
```

Using explicit parameters:
```python
execute_command(
    host="example.com",
    username="user",
    command="ls -la /var/log",
    key_filename="~/.ssh/id_rsa"
)
```

#### `list_sessions`
List all active SSH sessions.

**Returns:** List of active sessions in format `username@host:port`

#### `close_session`
Close a specific SSH session.

**Parameters:**
- `host` (str): Hostname or IP address
- `username` (str): SSH username
- `port` (int, default=22): SSH port

#### `close_all_sessions`
Close all active SSH sessions.

## Project Structure

```
mcp-ssh-session/
├── mcp_ssh_session/
│   ├── __init__.py
│   ├── __main__.py          # Entry point
│   ├── server.py            # MCP server and tool definitions
│   └── session_manager.py   # SSH session management logic
├── pyproject.toml
└── CLAUDE.md
```

## Architecture

### SSHSessionManager
The core session management class that:
- Loads and parses `~/.ssh/config` on initialization
- Resolves SSH config aliases to actual connection parameters
- Maintains a dictionary of active SSH connections keyed by `username@host:port`
- Provides thread-safe access to sessions via a threading lock
- Automatically detects and removes dead connections
- Reuses existing connections when possible
- Falls back to sensible defaults when config is not available

### MCP Server
Built with FastMCP, exposing SSH functionality as MCP tools that can be called by AI agents.

## Security Considerations

- Uses Paramiko's `AutoAddPolicy` for host key verification (accepts new host keys automatically)
- Passwords and keys are handled in memory only
- Sessions are properly closed when no longer needed
- Thread-safe operations prevent race conditions

## Dependencies

- `fastmcp`: MCP server framework
- `paramiko>=3.4.0`: SSH protocol implementation

## Development

The project uses Python 3.10+ and is structured as a standard Python package.

### Key Components

- **[server.py](mcp_ssh_session/server.py)**: MCP tool definitions and request handling
- **[session_manager.py](mcp_ssh_session/session_manager.py)**: Core SSH session lifecycle management

## License

[Add license information]

## Contributing

[Add contribution guidelines]
