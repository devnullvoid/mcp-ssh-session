# SSH Session Manager Safety Protections

## Overview
Safety features to prevent the MCP server from becoming unresponsive and handle edge cases gracefully.

## Key Features

### 1. **Thread-Based Async Execution**
- **What it does**: All commands execute in background threads
- **Why it matters**: Server remains responsive even during long operations
- **Implementation**: `ThreadPoolExecutor` with command state tracking
- **Benefit**: MCP server never hangs

### 2. **Smart Command Completion Detection**
Commands complete when either condition is met:

#### Prompt Detection
- Recognizes standard shell prompts: `$`, `#`, `>`, `%`
- Works with most default shell configurations

#### Idle Timeout (2 seconds)
- Triggers when no output received for 2s after getting data
- **Purpose**: Handles custom themed prompts that don't match standard patterns
- **Safe for long commands**: Timer resets every time new output arrives

**Example scenarios:**
```bash
# Custom prompt - relies on idle timeout
user@host [~/project] ❯ ls
# Output appears, then 2s silence → complete

# Long build - keeps running
make all
Compiling file1.c    # Timer resets
... 5 seconds ...
Compiling file2.c    # Timer resets
... continues until done or timeout ...
```

### 3. **Persistent Shell Sessions**
- **State maintenance**: Current directory, environment variables, shell history persist
- **Efficiency**: Reuses same shell channel across commands
- **Automatic recovery**: Dead shells detected and recreated

### 4. **Output Size Limiting**
- **Maximum output**: 10MB for stdout, 1MB for stderr
- **Graceful truncation**: Adds clear message when limit exceeded
- **Memory protection**: Prevents OOM errors from large outputs

### 5. **Safe File Transfers**
- **2 MB cap** per read/write operation
- **Permission-aware**: Automatic sudo fallback for protected files
- **Directory safeguards**: Optional recursive directory creation with validation

### 6. **Timeout Configuration**
```python
DEFAULT_COMMAND_TIMEOUT = 30      # 30 seconds default
MAX_COMMAND_TIMEOUT = 300         # 5 minutes hard maximum
ENABLE_MODE_TIMEOUT = 10          # 10 seconds for enable mode
```

### 7. **Session Recovery**
- **Active channel tracking**: Monitors all open SSH channels
- **Force close capability**: Can terminate hung channels
- **Executor shutdown**: Properly cleans up thread pool on exit
- **Resource cleanup**: All sessions and channels closed on `close_all()`

## How It Works

### Command Execution Flow:

```
User Request
    ↓
Submit to Thread Pool
    ↓
Execute in Persistent Shell
    ↓
Read Output (with size limiting)
    ↓
Detect Completion (prompt or idle timeout)
    ↓
Return Result or Command ID
```

### Completion Detection:

1. Command sent to persistent shell
2. Output collected with 10MB limit
3. Check for completion:
   - Prompt character at end? → Done
   - No data for 2s after output? → Done
   - Overall timeout reached? → Return command ID
4. Clean output and return

### Error Codes:
- **Exit 0**: Success
- **Exit 1**: General error (SSH error, validation, etc.)
- **Exit 124**: Timeout (command continues in background)

## Testing the Protections

### Test 1: Custom Prompt
```python
# Works even with fancy prompts
result = execute_command(
    host="myserver",
    command="ls -la"  # Completes via idle timeout
)
```

### Test 2: Long-Running Command
```python
# Outputs sporadically - keeps running
result = execute_command_async(
    host="myserver",
    command="make all",
    timeout=3600
)
# Timer resets on each output line
```

### Test 3: Timeout Handling
```python
# Returns command ID after 30s
stdout, stderr, exit_code = execute_command(
    host="myserver",
    command="sleep 100",
    timeout=30
)
# exit_code == 124, stderr == "ASYNC:command_id"
# Command continues in background
```

### Test 4: Output Limiting
```python
result = execute_command(
    host="myserver",
    command="cat /dev/zero | head -c 20M"
)
# Output truncated at 10MB with message
```

## Configuration

### Adjust Timeout Limits:
```python
# In session_manager.py, SSHSessionManager class
DEFAULT_COMMAND_TIMEOUT = 30      # Change default
MAX_COMMAND_TIMEOUT = 300         # Change maximum
```

### Adjust Output Limits:
```python
# In session_manager.py, CommandValidator class
MAX_OUTPUT_SIZE = 10 * 1024 * 1024  # Change from 10MB
```

### Adjust Idle Timeout:
```python
# In session_manager.py, _execute_standard_command_internal method
idle_timeout = 2.0  # Change from 2 seconds
```

## Important Notes

1. **Thread Pool Size**: Set to 10 workers max. Adjust `MAX_WORKERS` if needed for concurrent operations.

2. **Session Persistence**: Shells persist across commands. State (cd, env vars) is maintained.

3. **MCP Gateway Timeout**: Your MCP gateway has a ~60s timeout. For longer commands, use `execute_command_async` to avoid client timeout.

4. **Custom Prompts**: The 2s idle timeout handles any prompt style. No configuration needed.

5. **Recovery After Issues**:
   - Broken shell: Automatically recreated on next command
   - Hung command: Use `interrupt_command_by_id()`
   - Reset everything: Use `close_all_sessions()`

## Removed Features

### Command Validation (Removed)
Previously blocked streaming/interactive commands like `tail -f`, `top`, `watch`. **No longer needed** because:
- Persistent shells handle interactive commands gracefully
- Idle timeout detects completion reliably
- Commands can be interrupted with `interrupt_command_by_id()`

All commands are now allowed. The system handles them safely through:
- Async execution (never blocks server)
- Idle timeout detection (completes when output stops)
- Output limiting (prevents memory issues)
- Command interruption (can stop any command)

## Troubleshooting

### Commands Complete Too Quickly
- Check if idle timeout (2s) is too short for your use case
- Increase `idle_timeout` in `_execute_standard_command_internal`

### Commands Timeout Too Quickly
- Increase timeout parameter in tool call
- Use `execute_command_async` for known long operations
- Check for slow network/device responses

### Custom Prompt Issues
- Should work automatically via idle timeout
- If problems persist, check logs at `/tmp/mcp_ssh_session_logs/mcp_ssh_session.log`
- Look for `[CMD_IDLE]` and `[CMD_PROMPT]` log entries

## Logs

All operations are logged to:
```
/tmp/mcp_ssh_session_logs/mcp_ssh_session.log
```

Key log tags:
- `[EXEC_REQ]`: Command execution request
- `[CMD_START]`: Command started
- `[CMD_CHUNK]`: Output received
- `[CMD_IDLE]`: Idle timeout triggered
- `[CMD_PROMPT]`: Prompt detected
- `[CMD_SUCCESS]`: Command completed
- `[CMD_TIMEOUT]`: Overall timeout reached
