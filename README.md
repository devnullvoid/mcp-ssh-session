# MCP SSH Session

An MCP (Model Context Protocol) server that enables AI agents to establish and manage persistent SSH sessions.

## Features

- **Persistent Sessions**: SSH connections are reused across multiple command executions
- **SSH Config Support**: Automatically reads and uses settings from `~/.ssh/config`
- **Multi-host Support**: Manage connections to multiple hosts simultaneously
- **Automatic Reconnection**: Dead connections are detected and automatically re-established
- **Thread-safe**: Safe for concurrent operations
- **Network Device Support**: Automatic enable mode handling for routers and switches
- **Sudo Support**: Automatic password handling for sudo commands on Unix/Linux hosts
- **File Operations**: Safe helpers to read and write remote files over SFTP

## Installation

### Using Claude Code

Add to your `~/.claude.json`:

```json
{
  "mcpServers": {
    "ssh-session": {
      "type": "stdio",
      "command": "uvx",
      "args": ["uvx git+https://github.com/devnullvoid/mcp-ssh-session.git"],
      "env": {}
    }
  }
}
```

Replace `/path/to/mcp-ssh-session` with the actual path to this project.

### Using MCP Inspector

```bash
npx @modelcontextprotocol/inspector uvx --from /path/to/mcp-ssh-session mcp-ssh-session
```

### Development Installation

```bash
uv venv
source .venv/bin/activate
uv pip install -e .
```

## Usage

### Available Tools

#### `execute_command`
Execute a command on an SSH host using a persistent session.

**Using SSH config alias:**
```json
{
  "host": "myserver",
  "command": "uptime"
}
```

**Using explicit parameters:**
```json
{
  "host": "example.com",
  "username": "user",
  "command": "ls -la",
  "key_filename": "~/.ssh/id_rsa",
  "port": 22
}
```

**Network device with enable mode:**
```json
{
  "host": "router.example.com",
  "username": "admin",
  "password": "ssh_password",
  "enable_password": "enable_password",
  "command": "show running-config"
}
```

**Unix/Linux with sudo:**
```json
{
  "host": "server.example.com",
  "username": "user",
  "sudo_password": "user_password",
  "command": "systemctl restart nginx"
}
```

#### `list_sessions`
List all active SSH sessions.

#### `close_session`
Close a specific SSH session.

```json
{
  "host": "myserver"
}
```

#### `close_all_sessions`
Close all active SSH sessions.

#### `read_file`
Read the contents of a remote file via SFTP.

```json
{
  "host": "myserver",
  "remote_path": "/etc/nginx/nginx.conf",
  "max_bytes": 131072
}
```

- Uses persistent SSH sessions and opens short-lived SFTP channels
- Enforces a 2 MB maximum per request (configurable per call up to that limit)
- Returns truncated notice when the content size exceeds the requested limit

#### `write_file`
Write text content to a remote file via SFTP.

```json
{
  "host": "myserver",
  "remote_path": "/tmp/app.env",
  "content": "DEBUG=true\n",
  "append": true,
  "make_dirs": true
}
```

- Content larger than 2 MB is rejected for safety
- Optional `append` mode to add to existing files
- Optional `make_dirs` flag will create missing parent directories
- Supports `permissions` to set octal file modes after write (e.g., `420` for `0644`)

## SSH Config Support

The server automatically reads `~/.ssh/config` and supports:
- Host aliases
- Hostname mappings
- Port configurations
- User specifications
- IdentityFile settings

Example `~/.ssh/config`:
```
Host myserver
    HostName example.com
    User myuser
    Port 2222
    IdentityFile ~/.ssh/id_rsa
```

Then simply use:
```json
{
  "host": "myserver",
  "command": "uptime"
}
```

## Documentation

See [CLAUDE.md](CLAUDE.md) for detailed documentation.

## License

[Add license information]
