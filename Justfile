# Justfile for mcp-ssh-session project

# Phony targets, so that a file named 'install', 'test', etc. won't conflict.
.PHONY: install test run lint clean

# Install project dependencies
install:
    @echo "Installing dependencies..."
    uv pip install -e .

# Run all tests, including integration tests.
# Requires SSH_TEST_HOST, SSH_TEST_USER, SSH_TEST_PASSWORD, SSH_TEST_KEY_FILE (optional), SSH_TEST_PORT (optional)
# to be set in the environment for integration tests to run.
test:
    @echo "Running tests..."
    SSH_TEST_HOST=instance4 uv run pytest tests/

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
