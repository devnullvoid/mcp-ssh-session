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

    # Export environment variables based on provided parameters
    if [ -n "{{host}}" ]; then
        export SSH_TEST_HOST="{{host}}"
        echo "  SSH_TEST_HOST={{host}}"
    fi

    if [ -n "{{user}}" ]; then
        export SSH_TEST_USER="{{user}}"
        echo "  SSH_TEST_USER={{user}}"
    fi

    if [ -n "{{password}}" ]; then
        export SSH_TEST_PASSWORD="{{password}}"
        echo "  SSH_TEST_PASSWORD=***"
    fi

    if [ -n "{{keyfile}}" ]; then
        export SSH_TEST_KEY_FILE="{{keyfile}}"
        echo "  SSH_TEST_KEY_FILE={{keyfile}}"
    fi

    if [ -n "{{port}}" ] && [ "{{port}}" != "22" ]; then
        export SSH_TEST_PORT="{{port}}"
        echo "  SSH_TEST_PORT={{port}}"
    fi

    if [ -n "{{sudo_password}}" ]; then
        export SSH_TEST_SUDO_PASSWORD="{{sudo_password}}"
        echo "  SSH_TEST_SUDO_PASSWORD=***"
    fi

    if [ -n "{{enable_password}}" ]; then
        export SSH_TEST_ENABLE_PASSWORD="{{enable_password}}"
        echo "  SSH_TEST_ENABLE_PASSWORD=***"
    fi

    # Run pytest
    if [ -n "{{host}}" ] || [ -n "{{user}}" ]; then
        echo "Running integration tests..."
    else
        echo "Running tests (integration tests will be skipped - no host specified)"
    fi

    uv run pytest tests/ -v

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
