# MCP SSH Session

An MCP (Model Context Protocol) server that enables AI agents to establish and manage persistent SSH sessions.

## Features

- **Smart Command Execution**: Never hangs the server - automatically transitions to async mode if timeout is reached
- **Persistent Sessions**: SSH connections are reused across multiple command executions
- **Async Command Execution**: Non-blocking execution for long-running commands
- **SSH Config Support**: Automatically reads and uses settings from `~/.ssh/config`
- **Multi-host Support**: Manage connections to multiple hosts simultaneously
- **Automatic Reconnection**: Dead connections are detected and automatically re-established
- **Thread-safe**: Safe for concurrent operations
- **Network Device Support**: Automatic enable mode handling for routers and switches
- **Sudo Support**: Automatic password handling for sudo commands on Unix/Linux hosts
- **File Operations**: Safe helpers to read and write remote files over SFTP
- **Command Interruption**: Send Ctrl+C to interrupt running commands

## Installation

### Using `uvx`

```bash
uvx mcp-ssh-session
```

### Using Claude Code

Add to your `~/.claude.json`:

```json
{
  "mcpServers": {
    "ssh-session": {
      "type": "stdio",
      "command": "uvx",
      "args": ["mcp-ssh-session"],
      "env": {}
    }
  }
}
```

### Using MCP Inspector

```bash
npx @modelcontextprotocol/inspector uvx mcp-ssh-session
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

**Smart Execution**: Starts synchronously and waits for completion. If timeout is reached, automatically transitions to async mode and returns a command ID. Server never hangs!

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

#### `execute_command_async`
Execute a command asynchronously without blocking the server. Returns a command ID for tracking.

```json
{
  "host": "myserver",
  "command": "sleep 60 && echo 'Done'",
  "timeout": 300
}
```

#### `get_command_status`
Get the status and output of an async command.

```json
{
  "command_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
}
```

#### `interrupt_command_by_id`
Interrupt a running async command by sending Ctrl+C.

```json
{
  "command_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
}
```

#### `list_running_commands`
List all currently running async commands.

#### `list_command_history`
List recent command history (completed, failed, interrupted commands).

```json
{
  "limit": 50
}
```

#### `read_file`
Read the contents of a remote file via SFTP, with optional sudo support.

**Basic usage:**
```json
{
  "host": "myserver",
  "remote_path": "/etc/nginx/nginx.conf",
  "max_bytes": 131072
}
```

**With passwordless sudo (NOPASSWD in sudoers):**
```json
{
  "host": "myserver",
  "remote_path": "/etc/shadow",
  "use_sudo": true
}
```

**With sudo password:**
```json
{
  "host": "myserver",
  "remote_path": "/etc/shadow",
  "sudo_password": "user_password"
}
```

- Attempts SFTP first for best performance
- Falls back to `sudo cat` via shell if permission denied and `use_sudo=true` or `sudo_password` provided
- Supports both passwordless sudo (NOPASSWD) and password-based sudo
- Enforces a 2 MB maximum per request (configurable per call up to that limit)
- Returns truncated notice when the content size exceeds the requested limit

#### `write_file`
Write text content to a remote file via SFTP, with optional sudo support.

**Basic usage:**
```json
{
  "host": "myserver",
  "remote_path": "/tmp/app.env",
  "content": "DEBUG=true\n",
  "append": true,
  "make_dirs": true
}
```

**With passwordless sudo (NOPASSWD in sudoers):**
```json
{
  "host": "myserver",
  "remote_path": "/etc/nginx/nginx.conf",
  "content": "server { ... }",
  "use_sudo": true,
  "permissions": 420
}
```

**With sudo password:**
```json
{
  "host": "myserver",
  "remote_path": "/etc/nginx/nginx.conf",
  "content": "server { ... }",
  "sudo_password": "user_password",
  "permissions": 420
}
```

- Uses SFTP when `use_sudo=false` and no `sudo_password` provided
- Uses `sudo tee` via shell when `use_sudo=true` or `sudo_password` is provided
- Supports both passwordless sudo (NOPASSWD) and password-based sudo
- Content larger than 2 MB is rejected for safety
- Optional `append` mode to add to existing files
- Optional `make_dirs` flag will create missing parent directories
- Supports `permissions` to set octal file modes after write (e.g., `420` for `0644`)
- Note: Shell fallback is slower than SFTP but enables writing to protected files

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

## How It Works

### Persistent Shell Sessions
Commands execute in persistent interactive shells that maintain state:
- Current directory persists across commands (`cd /tmp` stays in `/tmp`)
- Environment variables remain set
- Shell history is maintained

### Smart Command Completion Detection
Commands complete when either:
1. **Prompt detected**: Standard shell prompts (`$`, `#`, `>`, `%`) at end of output
2. **Idle timeout**: No output for 2 seconds after receiving data

**Why idle timeout?** Custom themed prompts may not match standard patterns. The 2-second idle timeout ensures commands complete even with non-standard prompts.

**Long-running commands**: The idle timer resets every time new output arrives, so builds or scripts that output sporadically continue running until naturally complete or the overall timeout is reached.

## Documentation

- [ASYNC_COMMANDS.md](ASYNC_COMMANDS.md) - Smart execution and async commands
- [CLAUDE.md](CLAUDE.md) - Detailed usage documentation

## License

Distributed under the MIT License. See `LICENSE` for details.
