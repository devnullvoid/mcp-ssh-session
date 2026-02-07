# Interactive PTY Mode

## Overview

Interactive PTY mode adds terminal emulation to SSH sessions, enabling better command completion detection and support for interactive programs like vim, less, and top.

## Status

**Phase 0-2 Complete** (Foundation + Screen Snapshot API)

- ✅ Terminal emulator integration (pyte)
- ✅ Screen state tracking
- ✅ Screen snapshot API
- ✅ Interactive key sending

**Phase 3-4 Pending** (Mode Inference + Smart Detection)

- ⏳ Mode detection (editor, pager, shell, password_prompt)
- ⏳ Mode-aware command completion
- ⏳ Automatic awaiting-input detection improvements

## Interactive Mode Status

**As of v0.2.0, Interactive PTY mode is enabled by default.**

This provides better command completion detection and support for interactive programs.

### Disabling Interactive Mode

If you need to disable interactive mode (e.g., for compatibility with older scripts), set the environment variable to "0":

```bash
export MCP_SSH_INTERACTIVE_MODE=0
uvx mcp-ssh-session
```

Or in your MCP client configuration:

```json
{
  "mcpServers": {
    "ssh-session": {
      "command": "uvx",
      "args": ["mcp-ssh-session"],
      "env": {
        "MCP_SSH_INTERACTIVE_MODE": "0"
      }
    }
  }
}
```

## New MCP Tools

### `read_screen`

Get the current terminal screen state for a session.

**Parameters:**
- `host` (str, required): Hostname, IP, or SSH config alias
- `username` (str, optional): SSH username
- `port` (int, optional): SSH port
- `max_lines` (int, optional): Maximum lines to return (default: 24)

**Returns:**
```json
{
  "lines": ["line 1", "line 2", ...],
  "cursor_x": 0,
  "cursor_y": 5,
  "width": 100,
  "height": 24
}
```

**Example:**
```python
snapshot = read_screen(host="myserver")
# Check if vim is running
if any("-- INSERT --" in line for line in snapshot["lines"]):
    print("Vim is in insert mode")
```

### `send_keys`

Send special keys or key sequences to a session.

**Parameters:**
- `host` (str, required): Hostname, IP, or SSH config alias
- `keys` (str, required): Key sequence to send
- `username` (str, optional): SSH username
- `port` (int, optional): SSH port

**Supported Special Keys:**
- `<enter>` or `<return>`: Newline
- `<esc>` or `<escape>`: Escape key
- `<tab>`: Tab key
- `<ctrl-c>`: Ctrl+C (interrupt)
- `<ctrl-d>`: Ctrl+D (EOF)
- `<ctrl-z>`: Ctrl+Z (suspend)
- `<up>`, `<down>`, `<left>`, `<right>`: Arrow keys
- `<space>`: Space character

**Examples:**
```python
# Quit less/more pager
send_keys(host="myserver", keys="q")

# Save and quit vim
send_keys(host="myserver", keys="<esc>:wq<enter>")

# Navigate in less
send_keys(host="myserver", keys="<down><down><down>")

# Interrupt running command
send_keys(host="myserver", keys="<ctrl-c>")
```

## How It Works

### Terminal Emulation

When interactive mode is enabled:

1. A `pyte.Screen` (100x24) and `pyte.Stream` are created for each SSH session
2. All data received from the SSH channel is fed to the emulator
3. The emulator maintains a virtual screen buffer with cursor position
4. Screen snapshots can be retrieved at any time

### Screen State

The emulator tracks:
- **Screen content**: All visible lines (with ANSI codes interpreted)
- **Cursor position**: Current cursor location (x, y)
- **Screen dimensions**: Width and height in characters

### Backward Compatibility

- Interactive mode is **enabled by default** as of v0.2.0
- To disable, set `MCP_SSH_INTERACTIVE_MODE=0`
- When disabled, behavior is identical to previous versions
- No performance impact when disabled
- Existing prompt detection and command completion logic unchanged

## Use Cases

### Debugging Command Completion

```python
# Execute command
execute_command(host="myserver", command="ls -la")

# Check screen state
snapshot = read_screen(host="myserver")
print(f"Cursor at: ({snapshot['cursor_x']}, {snapshot['cursor_y']})")
print("Last line:", snapshot['lines'][-1])
```

### Interactive Programs

```python
# Start vim
execute_command_async(host="myserver", command="vim test.txt")

# Wait a moment
time.sleep(1)

# Check if vim loaded
snapshot = read_screen(host="myserver")
if any("~" in line for line in snapshot['lines']):
    print("Vim is ready")
    
# Enter insert mode and type
send_keys(host="myserver", keys="iHello World<esc>")

# Save and quit
send_keys(host="myserver", keys=":wq<enter>")
```

### Pager Handling

```python
# Command that triggers pager
execute_command_async(host="myserver", command="git log")

# Check if pager is active
snapshot = read_screen(host="myserver")
last_line = snapshot['lines'][-1]

if "(END)" in last_line or last_line.strip() == ":":
    print("Pager is active")
    # Quit pager
    send_keys(host="myserver", keys="q")
```

## Architecture

### Components

- **`SSHSessionManager._session_emulators`**: Dict mapping session_key → (Screen, Stream)
- **`SSHSessionManager._feed_emulator()`**: Helper to feed data to emulator
- **`SSHSessionManager._get_screen_snapshot()`**: Extract screen state
- **`server.read_screen()`**: MCP tool to expose screen state
- **`server.send_keys()`**: MCP tool to send special keys

### Data Flow

```
SSH Channel → recv() → chunk
                ↓
         _feed_emulator()
                ↓
         pyte.Stream.feed()
                ↓
         pyte.Screen (updates)
                ↓
    _get_screen_snapshot()
                ↓
         read_screen() MCP tool
```

## Future Enhancements (Phase 3-4)

### Mode Detection

Automatically detect what's running:
- **editor**: vim, nano, emacs (look for status lines, `~` markers)
- **pager**: less, more (look for `(END)`, `--More--`, `:`)
- **password_prompt**: password/passphrase prompts
- **shell**: normal shell prompt
- **unknown**: anything else

### Smart Command Completion

Use screen state instead of regex:
- Check if cursor is at a prompt position
- Verify prompt pattern appears at cursor location
- Reduce false positives from command output

### Automatic Input Detection

Improve `_detect_awaiting_input()`:
- Use screen state to identify interactive programs
- Don't flag editors/pagers as "awaiting input" incorrectly
- More reliable password prompt detection

## Performance

- **Memory**: ~10KB per session for screen buffer
- **CPU**: Minimal - pyte is efficient
- **Latency**: No measurable impact on command execution

## Limitations

- Screen size fixed at 100x24 (matches shell initialization)
- No scrollback buffer (only current screen visible)
- Complex terminal apps may not render perfectly
- Feature flag must be set before server starts

## Testing

Run the test suite with interactive mode:

```bash
export MCP_SSH_INTERACTIVE_MODE=1
pytest tests/
```

Manual testing:

```python
import os
os.environ["MCP_SSH_INTERACTIVE_MODE"] = "1"

from mcp_ssh_session.session_manager import SSHSessionManager

manager = SSHSessionManager()
assert manager._interactive_mode

# Execute command
manager.execute_command(host="localhost", command="echo test")

# Get screen
sessions = manager.list_sessions()
snapshot = manager._get_screen_snapshot(sessions[0])
print(snapshot)
```
