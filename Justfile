# Justfile for mcp-ssh-session project

# Install project dependencies
install:
    @echo "Installing dependencies..."
    uv pip install -e .

# Run all tests, including integration tests.
# Usage:
#   just test                                           # Run without integration tests
#   just test host=myhost user=admin                    # Run with custom host and user
#   just test host=myhost user=admin password=secret    # Run with password auth
#   just test host=myhost user=admin keyfile=~/.ssh/id_rsa port=2222  # Custom key and port
#   just test host=myhost user=admin sudo_password=secret  # With sudo tests
#   just test host=router user=admin password=cisco enable_password=enable  # Network device tests
test host="" user="" password="" keyfile="" port="22" sudo_password="" enable_password="":
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Running tests..."
    echo ""
    echo "Raw parameters received:"
    echo "  host='{{host}}'"
    echo "  user='{{user}}'"
    echo "  port='{{port}}'"
    echo ""

    # Clear any existing SSH_TEST_* variables to avoid conflicts
    unset SSH_TEST_HOST SSH_TEST_USER SSH_TEST_PASSWORD SSH_TEST_KEY_FILE SSH_TEST_PORT SSH_TEST_SUDO_PASSWORD SSH_TEST_ENABLE_PASSWORD 2>/dev/null || true

    # Strip any "key=" prefix from values (workaround for shell/env issues)
    # This handles cases where parameters come in as "host=value" instead of just "value"
    HOST_VALUE="{{host}}"
    HOST_VALUE="${HOST_VALUE#host=}"

    USER_VALUE="{{user}}"
    USER_VALUE="${USER_VALUE#user=}"

    PASSWORD_VALUE="{{password}}"
    PASSWORD_VALUE="${PASSWORD_VALUE#password=}"

    KEYFILE_VALUE="{{keyfile}}"
    KEYFILE_VALUE="${KEYFILE_VALUE#keyfile=}"
    KEYFILE_VALUE="${KEYFILE_VALUE#key_filename=}"

    PORT_VALUE="{{port}}"
    PORT_VALUE="${PORT_VALUE#port=}"

    SUDO_PASSWORD_VALUE="{{sudo_password}}"
    SUDO_PASSWORD_VALUE="${SUDO_PASSWORD_VALUE#sudo_password=}"

    ENABLE_PASSWORD_VALUE="{{enable_password}}"
    ENABLE_PASSWORD_VALUE="${ENABLE_PASSWORD_VALUE#enable_password=}"

    echo "Cleaned parameters:"
    echo "  host='$HOST_VALUE'"
    echo "  user='$USER_VALUE'"
    echo "  port='$PORT_VALUE'"
    echo ""

    # Export environment variables based on provided parameters
    if [ -n "$HOST_VALUE" ]; then
        export SSH_TEST_HOST="$HOST_VALUE"
        echo "Setting: SSH_TEST_HOST='$HOST_VALUE'"
    fi

    if [ -n "$USER_VALUE" ]; then
        export SSH_TEST_USER="$USER_VALUE"
        echo "Setting: SSH_TEST_USER='$USER_VALUE'"
    fi

    if [ -n "$PASSWORD_VALUE" ]; then
        export SSH_TEST_PASSWORD="$PASSWORD_VALUE"
        echo "Setting: SSH_TEST_PASSWORD='***'"
    fi

    if [ -n "$KEYFILE_VALUE" ]; then
        export SSH_TEST_KEY_FILE="$KEYFILE_VALUE"
        echo "Setting: SSH_TEST_KEY_FILE='$KEYFILE_VALUE'"
    fi

    if [ -n "$PORT_VALUE" ] && [ "$PORT_VALUE" != "22" ]; then
        export SSH_TEST_PORT="$PORT_VALUE"
        echo "Setting: SSH_TEST_PORT='$PORT_VALUE'"
    fi

    if [ -n "$SUDO_PASSWORD_VALUE" ]; then
        export SSH_TEST_SUDO_PASSWORD="$SUDO_PASSWORD_VALUE"
        echo "Setting: SSH_TEST_SUDO_PASSWORD='***'"
    fi

    if [ -n "$ENABLE_PASSWORD_VALUE" ]; then
        export SSH_TEST_ENABLE_PASSWORD="$ENABLE_PASSWORD_VALUE"
        echo "Setting: SSH_TEST_ENABLE_PASSWORD='***'"
    fi

    echo ""
    echo "Final environment variables:"
    echo "  SSH_TEST_HOST='${SSH_TEST_HOST:-}'"
    echo "  SSH_TEST_USER='${SSH_TEST_USER:-}'"
    echo "  SSH_TEST_PORT='${SSH_TEST_PORT:-22}'"
    echo ""

    # Run pytest
    if [ -n "$HOST_VALUE" ] || [ -n "$USER_VALUE" ]; then
        echo "Running integration tests..."
    else
        echo "Running tests (integration tests will be skipped - no host specified)"
    fi
    echo ""

    uv run pytest tests/ -v -s

# Run the MCP SSH Session server
run:
    @echo "Starting MCP SSH Session server..."
    uv run mcp-ssh-session

# Run linting checks (requires flake8 to be installed)
lint:
    @echo "Running linter (flake8)..."
    @echo "If flake8 is not found, try: uv pip install flake8"
    uv run flake8 mcp_ssh_session/ tests/

# Clean up build artifacts, cache, and log files
clean:
    @echo "Cleaning up build artifacts, cache, and log files..."
    rm -rf dist/ build/ __pycache__/ .pytest_cache/ .venv/
    find . -name "*.pyc" -exec rm -f {} +
    find . -name "*.log" -exec rm -f {} +
    @echo "Cleanup complete."
