import re
from datetime import datetime

from mcp_ssh_session.command_executor import CommandExecutor
from mcp_ssh_session.datastructures import CommandStatus, RunningCommand
from mcp_ssh_session.file_manager import FileManager
from mcp_ssh_session.session_manager import SSHSessionManager
from mcp_ssh_session.validation import CommandValidator


def test_tmux_references_in_paths_are_allowed():
    allowed = [
        "which fish neovim nvim rg fzf lsd tmux",
        "pkg install tmux",
        "cat ~/.tmux.conf",
        "echo 'set -g mouse on' > ~/.tmux.conf",
        "ls /usr/bin/tmux",
    ]
    for command in allowed:
        is_valid, error = CommandValidator.validate_command(command)
        assert is_valid, f"{command} should be allowed, got: {error}"


def test_tmux_invocations_are_blocked():
    blocked = [
        "tmux",
        "tmux new-session -d",
        "tmux attach",
        "sudo tmux attach-session",
    ]
    for command in blocked:
        is_valid, error = CommandValidator.validate_command(command)
        assert not is_valid
        assert error is not None and "tmux" in error.lower()


def test_pty_aware_validation_relaxes_read_only_tmux_screen_commands():
    is_valid, error = CommandValidator.validate_command("tmux ls", pty_aware=True)
    assert is_valid, error

    is_valid, error = CommandValidator.validate_command("screen -ls", pty_aware=True)
    assert is_valid, error

    is_valid, error = CommandValidator.validate_command("tmux attach", pty_aware=True)
    assert not is_valid
    assert error is not None and "tmux" in error.lower()

    is_valid, error = CommandValidator.validate_command("screen -r", pty_aware=True)
    assert not is_valid
    assert error is not None and "screen" in error.lower()


def test_strict_validation_blocks_tmux_and_screen_invocations():
    is_valid, error = CommandValidator.validate_command("tmux ls", pty_aware=False)
    assert not is_valid
    assert error is not None and "tmux" in error.lower()

    is_valid, error = CommandValidator.validate_command("screen -ls", pty_aware=False)
    assert not is_valid
    assert error is not None and "screen" in error.lower()


def test_long_running_package_commands_start_async_immediately():
    assert CommandExecutor._should_start_async_immediately("pkg install -y ripgrep fzf")
    assert CommandExecutor._should_start_async_immediately("apt-get update && apt-get install -y git")
    assert not CommandExecutor._should_start_async_immediately("echo hello")


def test_sftp_path_expands_home_directory():
    class FakeSFTP:
        def normalize(self, _):
            return "/data/data/com.termux/files/home"

    manager = type("DummyManager", (), {})()
    fm = FileManager(manager)

    assert fm._resolve_sftp_path(FakeSFTP(), "~") == "/data/data/com.termux/files/home"
    assert fm._resolve_sftp_path(FakeSFTP(), "~/.config/fish/config.fish") == (
        "/data/data/com.termux/files/home/.config/fish/config.fish"
    )
    assert fm._resolve_sftp_path(FakeSFTP(), "/etc/hosts") == "/etc/hosts"


def test_sentinel_wrapping_preserves_heredoc_delimiter_line():
    manager = SSHSessionManager()
    command = "cat > ~/.config/fish/config.fish << 'EOF'\n# test content\nEOF"
    rendered = manager._build_command_with_sentinel(command, "__MCP_CMD_TEST__")

    assert "EOF; __mcp_status=$?" not in rendered
    assert re.search(r"EOF\n__mcp_status=\$\?", rendered)


def test_manager_reads_pty_aware_validation_flag(monkeypatch):
    monkeypatch.setenv("MCP_SSH_INTERACTIVE_MODE", "1")
    monkeypatch.setenv("MCP_SSH_PTY_AWARE_VALIDATION", "1")
    manager = SSHSessionManager()
    assert manager._interactive_mode is True
    assert manager._pty_aware_validation is True


def test_mikrotik_print_command_gets_without_paging_by_default(monkeypatch):
    monkeypatch.setenv("MCP_SSH_MIKROTIK_AUTO_WITHOUT_PAGING", "1")
    manager = SSHSessionManager()
    session_key = "u@h:22"
    manager._session_shell_types[session_key] = "mikrotik"
    manager._session_prompts[session_key] = "[u@router] >"

    rewritten = manager._maybe_rewrite_mikrotik_command(
        session_key, "/routing filter rule print where chain=main"
    )
    assert rewritten.endswith(" without-paging")

    unchanged = manager._maybe_rewrite_mikrotik_command(
        session_key, "/routing filter rule print without-paging"
    )
    assert unchanged == "/routing filter rule print without-paging"


def test_mikrotik_auto_without_paging_can_be_disabled(monkeypatch):
    monkeypatch.setenv("MCP_SSH_MIKROTIK_AUTO_WITHOUT_PAGING", "0")
    manager = SSHSessionManager()
    session_key = "u@h:22"
    manager._session_shell_types[session_key] = "mikrotik"

    original = "/routing filter rule print"
    assert manager._maybe_rewrite_mikrotik_command(session_key, original) == original


def test_mikrotik_no_rewrite_without_slash_or_menu_context(monkeypatch):
    monkeypatch.setenv("MCP_SSH_MIKROTIK_AUTO_WITHOUT_PAGING", "1")
    manager = SSHSessionManager()
    session_key = "u@h:22"
    manager._session_shell_types[session_key] = "mikrotik"
    manager._session_prompts[session_key] = "[u@router] >"

    original = "routing filter rule print"
    assert manager._maybe_rewrite_mikrotik_command(session_key, original) == original


def test_mikrotik_rewrite_in_menu_context_without_leading_slash(monkeypatch):
    monkeypatch.setenv("MCP_SSH_MIKROTIK_AUTO_WITHOUT_PAGING", "1")
    manager = SSHSessionManager()
    session_key = "u@h:22"
    manager._session_shell_types[session_key] = "mikrotik"
    manager._session_prompts[session_key] = "[u@router] /routing/filter/rule>"

    rewritten = manager._maybe_rewrite_mikrotik_command(session_key, "print detail")
    assert rewritten == "print detail without-paging"


def test_running_command_error_includes_actionable_next_steps():
    cmd = RunningCommand(
        command_id="abc123",
        session_key="u@h:22",
        command="/routing filter rule print",
        shell=None,
        future=None,
        status=CommandStatus.RUNNING,
        stdout="",
        stderr="",
        exit_code=None,
        start_time=datetime.now(),
        end_time=None,
    )

    message = CommandExecutor._build_running_command_error("u@h:22", cmd)
    assert "Active Command ID: abc123" in message
    assert "get_command_status('abc123')" in message
    assert "interrupt_command_by_id('abc123')" in message
