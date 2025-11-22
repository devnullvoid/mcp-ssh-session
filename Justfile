# Justfile for mcp-ssh-session project

# Install project dependencies
install:
    @echo "Installing dependencies..."
    uv pip install -e .

# Run all tests, including integration tests.
# Set environment variables before calling this recipe:
#   SSH_TEST_HOST=myhost just test
#   SSH_TEST_HOST=myhost SSH_TEST_USER=admin SSH_TEST_PASSWORD=secret just test
#   SSH_TEST_HOST=myhost SSH_TEST_USER=admin SSH_TEST_SUDO_PASSWORD=secret just test
#   SSH_TEST_HOST=router SSH_TEST_USER=admin SSH_TEST_PASSWORD=cisco SSH_TEST_ENABLE_PASSWORD=enable just test
#
# Or use the convenience aliases below (test-basic, test-sudo, test-network)
test:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Running tests..."
    echo ""

    # Show what environment variables are set
    echo "SSH test environment variables:"
    echo "  SSH_TEST_HOST='${SSH_TEST_HOST:-<not set>}'"
    echo "  SSH_TEST_USER='${SSH_TEST_USER:-<not set>}'"
    if [ -n "${SSH_TEST_PASSWORD:-}" ]; then echo "  SSH_TEST_PASSWORD='***'"; else echo "  SSH_TEST_PASSWORD='<not set>'"; fi
    echo "  SSH_TEST_KEY_FILE='${SSH_TEST_KEY_FILE:-<not set>}'"
    echo "  SSH_TEST_PORT='${SSH_TEST_PORT:-22}'"
    if [ -n "${SSH_TEST_SUDO_PASSWORD:-}" ]; then echo "  SSH_TEST_SUDO_PASSWORD='***'"; else echo "  SSH_TEST_SUDO_PASSWORD='<not set>'"; fi
    if [ -n "${SSH_TEST_ENABLE_PASSWORD:-}" ]; then echo "  SSH_TEST_ENABLE_PASSWORD='***'"; else echo "  SSH_TEST_ENABLE_PASSWORD='<not set>'"; fi
    echo ""

    # Run pytest
    if [ -n "${SSH_TEST_HOST:-}" ]; then
        echo "Running integration tests against ${SSH_TEST_HOST}..."
    else
        echo "Running unit tests only (set SSH_TEST_HOST to run integration tests)"
    fi
    echo ""

    uv run pytest tests/ -v -s

# Convenience recipe: Run basic integration tests
# Usage: just test-basic host=myhost user=myuser [password=pass] [keyfile=~/.ssh/id_rsa] [port=22]
test-basic host user password="" keyfile="" port="22":
    #!/usr/bin/env bash
    set -euo pipefail
    export SSH_TEST_HOST="{{host}}"
    export SSH_TEST_USER="{{user}}"
    [ -n "{{password}}" ] && export SSH_TEST_PASSWORD="{{password}}"
    [ -n "{{keyfile}}" ] && export SSH_TEST_KEY_FILE="{{keyfile}}"
    [ "{{port}}" != "22" ] && export SSH_TEST_PORT="{{port}}"
    just test

# Convenience recipe: Run tests with sudo password
# Usage: just test-sudo host=myhost user=myuser sudo_password=pass [password=pass] [keyfile=~/.ssh/id_rsa]
test-sudo host user sudo_password password="" keyfile="":
    #!/usr/bin/env bash
    set -euo pipefail
    export SSH_TEST_HOST="{{host}}"
    export SSH_TEST_USER="{{user}}"
    export SSH_TEST_SUDO_PASSWORD="{{sudo_password}}"
    [ -n "{{password}}" ] && export SSH_TEST_PASSWORD="{{password}}"
    [ -n "{{keyfile}}" ] && export SSH_TEST_KEY_FILE="{{keyfile}}"
    just test

# Convenience recipe: Run network device tests (with enable password)
# Usage: just test-network host=router user=admin password=cisco enable_password=enable
test-network host user password enable_password:
    #!/usr/bin/env bash
    set -euo pipefail
    export SSH_TEST_HOST="{{host}}"
    export SSH_TEST_USER="{{user}}"
    export SSH_TEST_PASSWORD="{{password}}"
    export SSH_TEST_ENABLE_PASSWORD="{{enable_password}}"
    just test

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
