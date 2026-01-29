# Interactive PTY + Terminal Emulator Plan

## Summary
This document proposes an additive, opt-in interactive layer that enables the MCP SSH Session server to understand full-screen terminal apps (e.g., Vim, less, top) by attaching a VT100/ANSI terminal emulator to each persistent SSH shell. The plan is staged to avoid breaking existing behavior while providing a path toward richer interactivity and fewer false "awaiting input" detections.

## Goals
- Support fully interactive programs (Vim, less, top, mysql pager) by interpreting terminal output into screen state.
- Provide an API for screen snapshots so agents can reason about the current terminal state.
- Reduce false "awaiting input" detections by using screen state rather than pure regex heuristics.
- Keep current command execution behavior unchanged unless the interactive mode is explicitly enabled.

## Non-goals
- Perfect emulation of every terminal control sequence.
- Automatic handling of every interactive workflow without agent input.
- Replacing existing prompt detection or command execution paths wholesale.

## High-level Approach
- Keep the existing `invoke_shell()` persistent sessions.
- Add a VT100/ANSI emulator (e.g., `pyte`) per session.
- Feed all received bytes into the emulator to maintain a virtual screen buffer.
- Expose a read-only "screen snapshot" to the agent via MCP.
- Add a lightweight state machine that infers mode: `shell`, `pager`, `editor`, `password_prompt`, `unknown`.

## Phased Implementation Plan

### Phase 0 - Dependency and flags
- Add `pyte` as a dependency.
- Add a feature flag (env var) such as `MCP_SSH_INTERACTIVE_MODE=1` to enable emulator-aware behavior.

### Phase 1 - Emulator plumbing (no behavior change)
1) Store emulator per session
- Add fields in `SSHSessionManager.__init__`:
  - `_session_emulators: Dict[str, Tuple[pyte.Screen, pyte.Stream]]`
  - `_session_screen_cache: Dict[str, dict]` (optional)

2) Create emulator when shell is created
- In `_get_or_create_shell()`:
  - Initialize `pyte.Screen(width=100, height=24)` and `pyte.Stream(screen)`.
  - Store in `_session_emulators[session_key]`.

3) Feed emulator on recv
- In all recv loops (`_execute_standard_command_internal`, `_execute_sudo_command_internal`, `_enter_enable_mode`, etc.), feed raw bytes to emulator:
  - `stream.feed(chunk)`
- Keep existing output handling unchanged.

### Phase 2 - Screen snapshot API
1) Add helper method
- `SSHSessionManager._get_screen_snapshot(session_key, max_lines=10)`:
  - Returns last N lines, cursor position, width/height, timestamp.

2) Expose via MCP tool
- In `server.py`, add tool `read_screen(host, username?, port?)` that returns the snapshot.

### Phase 3 - Interactive mode inference
1) Track mode per session
- Add `_session_modes: Dict[str, str]` to the manager.

2) Infer mode from screen
- Add `_infer_mode_from_screen(session_key)`:
  - `editor`: status line contains `-- INSERT --`, `VISUAL`, `REPLACE`, or many `~` lines plus status bar.
  - `pager`: last line contains `(END)`, `--More--`, or a lone `:`.
  - `password_prompt`: last line ends with `password:` or `passphrase:`.
  - `shell`: prompt detection succeeds.
  - default `unknown`.

3) Update mode as data arrives
- After each recv chunk, update mode using the emulator state.

### Phase 4 - Mode-aware awaiting-input
1) Gate heuristics using mode
- If `mode == editor`, do not return `awaiting_input` automatically.
- If `mode == pager`, allow pager handling.
- If `mode == shell`, keep current regex-based detection.

2) Gate behavior behind feature flag
- Existing behavior stays default.
- `MCP_SSH_INTERACTIVE_MODE=1` enables mode-aware logic.

### Phase 5 - Interactive action API (optional but recommended)
1) Add `send_keys(host, keys)` MCP tool
- Supports special tokens like `<esc>`, `<enter>`, `<ctrl-c>`, `<ctrl-g>`.

2) Add editor convenience action (optional)
- `editor_action(host, action="save_quit")` -> sends `<esc>:wq<enter>`.

### Phase 6 - Tests and validation
- Unit test screen snapshot and mode inference on known VT100 output.
- Add tests for editor detection using recorded screen traces.
- Keep existing prompt detection tests intact; ensure pager `:` remains supported.

## Integration Points (current code)
- `mcp_ssh_session/session_manager.py`
  - `_get_or_create_shell()` (create emulator)
  - `_execute_standard_command_internal()` (feed emulator, update mode)
  - `_execute_sudo_command_internal()` (feed emulator, update mode)
  - `_detect_awaiting_input()` (mode-aware gating)
- `mcp_ssh_session/server.py`
  - New tool `read_screen` (and possibly `send_keys`).

## Risks & Mitigations
- Performance: feed emulator only when feature flag is enabled.
- Memory: cap screen scrollback length (use `pyte` screen size and limit snapshot length).
- Backward compatibility: default behavior unchanged; emulator behavior is opt-in.

## Review Checklist
- Does emulator integration preserve existing output collection?
- Are mode heuristics conservative enough to avoid false positives?
- Is the API minimal yet sufficient for interactive workflows?
- Are feature flags and defaults safe for current users?
