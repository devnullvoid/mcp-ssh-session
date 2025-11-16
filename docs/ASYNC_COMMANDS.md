# Async Command Execution

## Overview

**All commands execute asynchronously** - the server never hangs:
- Every command runs in a background thread
- `execute_command` polls until done or timeout
- `execute_command_async` returns command ID immediately
- Completed commands auto-cleanup (keeps last 100)
- **Server always responsive**

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
List all currently running async commands (status: running).

### list_command_history
List recent command history (completed, failed, interrupted).

```python
history = list_command_history(limit=50)
# Shows last 50 completed commands, most recent first
```

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

- All commands run in ThreadPoolExecutor (max 10 concurrent)
- `execute_command` polls status every 0.1s until done or timeout
- On timeout, returns command ID and continues in background
- Exit code 124 indicates async transition
- Output limited to 10MB per command
- Auto-cleanup keeps last 100 completed commands
- State tracked in memory (lost on server restart)

## Command Completion Detection

Commands complete when either:

1. **Prompt detected**: Standard shell prompts (`$`, `#`, `>`, `%`) at end of output
2. **Idle timeout**: No output for 2 seconds after receiving data

### Why Idle Timeout?

Custom themed prompts (e.g., colorized, multi-line, or custom PS1) may not match standard prompt patterns. The 2-second idle timeout ensures commands complete reliably regardless of prompt style.

### Long-Running Commands

The idle timer **resets every time new output arrives**:

```python
# Build that outputs sporadically - keeps running
execute_command_async(host="server", command="make all", timeout=3600)
# Outputs "Compiling file1.c" → timer resets
# ... 5 seconds of silence ...
# Outputs "Compiling file2.c" → timer resets
# Continues until build completes or 3600s timeout

# Command goes silent after completion - detects done
execute_command(host="server", command="ls -la", timeout=30)
# Outputs directory listing
# 2 seconds of silence → command complete
```

**Key insight**: The 2s idle timeout only triggers after receiving some output. It's a completion detector, not a command killer.
