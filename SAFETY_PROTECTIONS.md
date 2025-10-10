# SSH Session Manager Safety Protections

## Overview
Enhanced safety features to prevent the MCP server from becoming unresponsive due to hung SSH commands or streaming operations.

## Key Features Implemented

### 1. **Thread-Based Timeout Enforcement**
- **What it does**: Wraps all SSH command execution in a thread pool with hard timeouts
- **Why it matters**: Even if Paramiko's timeout fails, the thread timeout will terminate the operation
- **Implementation**: `ThreadPoolExecutor` with `Future.result(timeout=...)`
- **Benefit**: Server remains responsive even if a command hangs

### 2. **Enhanced Command Validation**
Added patterns to detect and block problematic commands:

#### Streaming/Monitor Commands Blocked:
```bash
# Network device commands
monitor session       # ❌ Blocked - continuous output
debug all            # ❌ Blocked - continuous output

# System commands
tail -f              # ❌ Blocked
watch                # ❌ Blocked
top                  # ❌ Blocked
ping (without -c)    # ❌ Blocked
```

#### Suggested Alternatives:
```bash
# Use finite alternatives
tail -n 100 logfile  # ✅ Allowed
ping -c 5 host       # ✅ Allowed
show monitor         # ✅ Allowed (static command)
```

### 3. **Output Size Limiting**
- **Maximum output**: 10MB for stdout, 1MB for stderr
- **Graceful truncation**: Adds clear message when limit is exceeded
- **Memory protection**: Prevents OOM errors from large outputs

### 4. **Timeout Configuration**
```python
DEFAULT_COMMAND_TIMEOUT = 30      # 30 seconds default
MAX_COMMAND_TIMEOUT = 300         # 5 minutes hard maximum
ENABLE_MODE_TIMEOUT = 10          # 10 seconds for enable mode
```

### 5. **Session Recovery**
- **Active channel tracking**: Monitors all open SSH channels
- **Force close capability**: Can terminate hung channels
- **Executor shutdown**: Properly cleans up thread pool on exit
- **Resource cleanup**: All sessions and channels closed on `close_all()`

## How It Works

### Command Execution Flow:

```
User Request
    ↓
Command Validation (patterns checked)
    ↓
Timeout Enforcement (capped at MAX_COMMAND_TIMEOUT)
    ↓
Thread Pool Submission
    ↓
Internal Execution (with Paramiko timeout)
    ↓
Output Limiting (size checks)
    ↓
Thread Timeout Monitor (hard timeout + 5s buffer)
    ↓
Return Result or Timeout Error
```

### Thread Timeout Protection:

1. Command submitted to `ThreadPoolExecutor`
2. Internal timeout: User-specified (e.g., 30s)
3. Thread timeout: Internal + 5s buffer (e.g., 35s)
4. If thread timeout triggers:
   - Future is cancelled
   - Error returned: "Command timed out after Xs seconds"
   - Server remains responsive
   - Connection may need reset (logged)

### Error Codes:
- **Exit 1**: Command validation failed, SSH error, or general error
- **Exit 124**: Command timeout (standard timeout exit code)

## Testing the Protections

### Test 1: Streaming Command Blocked
```python
result = execute_command(
    host="myswitch",
    command="monitor session 1",  # Will be blocked
    enable_password="password"
)
# Expected: ("", "Streaming/interactive command blocked...", 1)
```

### Test 2: Timeout Enforcement
```python
result = execute_command(
    host="myserver",
    command="sleep 100",
    timeout=10  # Will timeout after 10 seconds
)
# Expected: ("", "Command timed out after 10 seconds...", 124)
```

### Test 3: Output Limiting
```python
result = execute_command(
    host="myserver",
    command="cat /dev/zero | head -c 20M",  # Would generate 20MB
    timeout=30
)
# Expected: Output truncated at 10MB with message
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

### Add Custom Blocking Patterns:
```python
# In session_manager.py, CommandValidator class
STREAMING_PATTERNS = [
    # Add your patterns here
    r'\byour_custom_command\b',
]
```

## Important Notes

1. **Thread Pool Size**: Set to 10 workers max. Adjust `MAX_WORKERS` if needed for concurrent operations.

2. **Session Persistence**: The timeout system preserves session persistence. Even after a timeout, the SSH connection is maintained (unless it needs reset).

3. **MCP Gateway Timeout**: Your MCP gateway has a 60-second timeout. Ensure `MAX_COMMAND_TIMEOUT` allows headroom:
   - Gateway timeout: 60s
   - Recommended MAX_COMMAND_TIMEOUT: 50-55s (leaves buffer for processing)

4. **Network Device Considerations**:
   - Enable mode commands still work normally
   - Only streaming/monitoring commands are blocked
   - Static "show" commands work fine

5. **Recovery After Timeout**:
   - If a command times out, try `close_session()` then reconnect
   - Or use `close_all_sessions()` to reset everything

## Future Enhancements

Potential additions:
- [ ] Automatic session reset after timeout
- [ ] Configurable timeout per host/command pattern
- [ ] Metrics/monitoring for timeout frequency
- [ ] Command queue with priority levels
- [ ] Automatic retry with exponential backoff

## Troubleshooting

### Server Still Hangs
1. Check if command matches blocking patterns
2. Verify timeout is being applied (check logs)
3. Ensure thread pool isn't exhausted (check `MAX_WORKERS`)

### Commands Timing Out Too Quickly
1. Increase timeout parameter in tool call
2. Adjust `MAX_COMMAND_TIMEOUT` if needed
3. Check for slow network/device responses

### False Positives in Command Validation
1. Review blocking patterns in `CommandValidator`
2. Add exceptions for specific commands
3. Temporarily disable validation for testing

## Logs

All operations are logged to:
```
/tmp/mcp_ssh_session_logs/mcp_ssh_session.log
```

Log levels:
- INFO: Command execution, timeouts
- WARNING: Output limits, timeout warnings
- ERROR: SSH errors, exceptions
