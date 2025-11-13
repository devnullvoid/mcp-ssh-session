# Async Command Execution

## Overview

Commands now use **smart execution** that never hangs the server:
- Starts synchronously, waits for completion
- If timeout reached, transitions to async mode
- Returns command ID, continues in background
- **Server never hangs**

## Quick Start

### Basic Usage

```python
# Quick command - returns output immediately
execute_command(host="server", command="uptime", timeout=30)
# Returns: stdout, stderr, exit_code

# Long command - auto-transitions to async after 30s
execute_command(host="server", command="sleep 60", timeout=30)
# After 30s returns: ("", "ASYNC:command_id", 124)
# Command continues in background
```

### Explicit Async

```python
# Returns immediately with command ID
cmd_id = execute_command_async(host="server", command="long_task.sh")

# Check status anytime
status = get_command_status(cmd_id)

# Interrupt if needed
interrupt_command_by_id(cmd_id)

# List all running
list_running_commands()
```

## Return Values

| Scenario | exit_code | stdout | stderr |
|----------|-----------|--------|--------|
| Success (< timeout) | 0-255 | output | errors |
| Async transition | 124 | "" | "ASYNC:cmd_id" |
| Validation error | 1 | "" | error message |

## MCP Client Timeout

The MCP client (e.g., Claude) has a ~60s timeout. If your command takes longer:

**What happens:**
- Client shows: "Request timed out"
- Server: Still responsive ✓
- Command: Still running ✓

**Solution:**
```python
# Find your command
running = list_running_commands()

# Check status
status = get_command_status(command_id)
```

**Avoid it:**
```python
# For long commands, use async directly
cmd_id = execute_command_async(host="server", command="backup.sh")
# Returns immediately, no MCP timeout
```

## Tools

### execute_command
Smart execution - use for everything.
- Waits up to timeout
- Returns output or command ID
- Never hangs server

### execute_command_async
Explicit async - returns command ID immediately.
- Best for known long operations
- Avoids MCP client timeout

### get_command_status
Check async command status and output.

### interrupt_command_by_id
Send Ctrl+C to running command.

### list_running_commands
List all active async commands.

## Best Practices

```python
# Quick commands (< 30s)
execute_command(host="server", command="ls", timeout=10)

# Medium commands (30-60s)
execute_command(host="server", command="apt update", timeout=45)

# Long commands (> 60s) - use async to avoid MCP timeout
cmd_id = execute_command_async(host="server", command="backup.sh", timeout=3600)
```

## Handling Results

```python
stdout, stderr, exit_code = execute_command(host="server", command="task.sh", timeout=60)

if exit_code == 124 and stderr.startswith("ASYNC:"):
    cmd_id = stderr.split(":", 1)[1]
    # Poll for completion
    while get_command_status(cmd_id)['status'] == 'running':
        time.sleep(5)
    result = get_command_status(cmd_id)
    print(result['stdout'])
else:
    print(stdout)
```

## Technical Details

- Commands run in ThreadPoolExecutor (max 10 concurrent)
- Uses Future.result() with timeout
- On timeout, returns command ID and continues in background
- Exit code 124 indicates async transition
- Output limited to 10MB per command
- State tracked in memory (lost on server restart)
