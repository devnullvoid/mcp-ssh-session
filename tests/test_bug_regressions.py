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
    assert CommandExecutor._should_start_async_immediately(
        "apt-get update && apt-get install -y git"
    )
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


def test_interactive_wizard_commands_are_detected():
    """Test that interactive wizard commands like fish_config are properly detected."""
    wizard_commands = [
        "fish_config",
        "fish -c \"fish_config theme save 'Catppuccin Mocha'\"",
        "dconf-editor",
        "nmtui",
        "raspi-config",
    ]

    for cmd in wizard_commands:
        assert CommandExecutor._is_interactive_wizard(cmd), (
            f"{cmd} should be detected as wizard"
        )

    # Non-wizard commands should not be detected
    non_wizard_commands = [
        "echo hello",
        "ls -la",
        "fish -c 'echo hello'",
        "pkg install -y git",
    ]

    for cmd in non_wizard_commands:
        assert not CommandExecutor._is_interactive_wizard(cmd), (
            f"{cmd} should NOT be detected as wizard"
        )


def test_package_manager_idle_timeout_is_extended():
    """Test that package manager commands use extended idle timeout."""
    manager = SSHSessionManager()

    # Test package manager detection patterns
    pkg_commands = [
        "pkg install -y vivid",
        "apt-get update && apt-get install -y git",
        "dnf install vim",
        "yum upgrade",
        "apt upgrade",
        "pacman -S vim",
        "apk add git",
    ]

    for cmd in pkg_commands:
        # Check if the command matches package manager patterns
        import re

        command_lower = cmd.lower().strip()
        is_pkg = any(
            [
                re.search(r"\bpkg\s+(install|upgrade|update)", command_lower),
                re.search(
                    r"\bapt(?:-get)?\s+(install|upgrade|update|dist-upgrade|full-upgrade)",
                    command_lower,
                ),
                re.search(
                    r"\b(dnf|yum|zypper)\s+(install|upgrade|update)", command_lower
                ),
                re.search(
                    r"\bpacman\s+(-[Ss]\b|--sync\b|install|upgrade|update)",
                    command_lower,
                ),
                re.search(r"\bapk\s+(add|install|upgrade|update)", command_lower),
                re.search(r"\bbrew\s+(install|upgrade|update)", command_lower),
            ]
        )
        assert is_pkg, f"{cmd} should be detected as package manager"


def test_all_package_manager_patterns_covered():
    """Ensure all package manager patterns from _should_start_async_immediately are covered."""
    import re

    # These should all trigger async immediately
    async_commands = [
        "pkg install -y vivid",
        "apt install git",
        "apt-get install git",
        "dnf install vim",
        "yum install vim",
        "zypper install vim",
        "pacman -S vim",
        "apk add vim",
        "brew install git",
        "pip install requests",
        "pip3 install numpy",
        "npm install express",
        "pnpm install",
        "yarn add lodash",
    ]

    for cmd in async_commands:
        assert CommandExecutor._should_start_async_immediately(cmd), (
            f"{cmd} should start async immediately"
        )


def test_package_manager_remove_commands_start_async_immediately():
    """Ensure package manager remove commands also start async."""
    remove_commands = [
        "apt-get remove -y sl",
        "apt remove sl",
        "apt-get purge sl",
        "apt purge sl",
        "dnf remove sl",
        "yum remove sl",
        "zypper remove sl",
        "pacman -R sl",
        "pacman --remove sl",
        "pkg remove sl",
        "pkg delete sl",
        "apk del sl",
        "apk delete sl",
        "brew uninstall sl",
        "brew remove sl",
    ]

    for cmd in remove_commands:
        assert CommandExecutor._should_start_async_immediately(cmd), (
            f"{cmd} should start async immediately"
        )
