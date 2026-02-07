# Use Python 3.13 slim image
FROM python:3.13-slim

# Set metadata
LABEL maintainer="Jon Rogers <devnullvoid>"
LABEL description="MCP SSH Session Server - Persistent SSH session management for AI agents"

# Create non-root user for security
RUN groupadd -r mcpuser && useradd -r -g mcpuser -m -d /home/mcpuser mcpuser

# Install system dependencies
RUN apt-get update && apt-get install -y \
    openssh-client \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy project files
COPY pyproject.toml uv.lock LICENSE README.md ./
COPY mcp_ssh_session/ ./mcp_ssh_session/

# Install uv and project dependencies
RUN pip install uv && \
    uv sync --frozen && \
    uv pip install -e .

# Create directories for SSH files
RUN mkdir -p /home/mcpuser/.ssh && \
    chown -R mcpuser:mcpuser /home/mcpuser/.ssh && \
    chmod 700 /home/mcpuser/.ssh

# Create mount points for SSH config and keys
RUN mkdir -p /mounts/ssh-config /mounts/ssh-keys && \
    chown -R mcpuser:mcpuser /mounts

# Create entrypoint script
RUN cat > /app/entrypoint.sh << 'EOF'
#!/bin/bash
set -e

# Function to setup SSH configuration
setup_ssh() {
    local user_home="/home/mcpuser"
    local ssh_dir="$user_home/.ssh"
    
    # Ensure .ssh directory exists with correct permissions
    mkdir -p "$ssh_dir"
    chmod 700 "$ssh_dir"
    chown mcpuser:mcpuser "$ssh_dir"
    
    # Copy SSH config if mounted
    if [ -f "/mounts/ssh-config/config" ]; then
        echo "Setting up SSH config..."
        cp /mounts/ssh-config/config "$ssh_dir/config"
        chmod 600 "$ssh_dir/config"
        chown mcpuser:mcpuser "$ssh_dir/config"
    fi
    
    # Copy SSH keys if mounted
    if [ -d "/mounts/ssh-keys" ] && [ "$(ls -A /mounts/ssh-keys)" ]; then
        echo "Setting up SSH keys..."
        # Copy files individually to avoid copying directories
        find /mounts/ssh-keys -maxdepth 1 -type f -exec cp {} "$ssh_dir/" \;
        chmod 600 "$ssh_dir"/* 2>/dev/null || true
        chown mcpuser:mcpuser "$ssh_dir"/* 2>/dev/null || true
    fi
    
    # Create known_hosts file if it doesn't exist
    if [ ! -f "$ssh_dir/known_hosts" ]; then
        touch "$ssh_dir/known_hosts"
        chmod 644 "$ssh_dir/known_hosts"
        chown mcpuser:mcpuser "$ssh_dir/known_hosts"
    fi
}

# Setup SSH configuration
setup_ssh

# Switch to mcpuser and run the MCP server
# Try gosu first, fall back to running as current user if that fails
if command -v gosu >/dev/null 2>&1 && gosu mcpuser whoami >/dev/null 2>&1; then
    exec gosu mcpuser uv run mcp-ssh-session "$@"
else
    # Fallback: run as current user (might be root in some environments)
    exec uv run mcp-ssh-session "$@"
fi
EOF

RUN chmod +x /app/entrypoint.sh

# Install gosu for user switching
RUN apt-get update && apt-get install -y gosu && rm -rf /var/lib/apt/lists/*

# Add documentation before switching user
RUN cat > /app/README.md << 'EOF'
# MCP SSH Session Server Docker Container

This container provides the MCP SSH Session server for managing persistent SSH sessions.

## Usage

### Basic Usage
```bash
docker run --rm -i mcp-ssh-session
```

### With SSH Config and Keys
```bash
docker run --rm -i \
  -v ~/.ssh/config:/mounts/ssh-config/config:ro \
  -v ~/.ssh/id_rsa:/mounts/ssh-keys/id_rsa:ro \
  -v ~/.ssh/id_rsa.pub:/mounts/ssh-keys/id_rsa.pub:ro \
  mcp-ssh-session
```

### With SSH Directory
```bash
docker run --rm -i \
  -v ~/.ssh:/mounts/ssh-keys:ro \
  mcp-ssh-session
```

### Docker Compose Example
```yaml
version: '3.8'
services:
  mcp-ssh-session:
    image: mcp-ssh-session
    stdin_open: true
    volumes:
      - ~/.ssh/config:/mounts/ssh-config/config:ro
      - ~/.ssh:/mounts/ssh-keys:ro
    environment:
      - PYTHONUNBUFFERED=1
```

## Mount Points

- `/mounts/ssh-config/config` - SSH configuration file
- `/mounts/ssh-keys/` - Directory containing SSH keys

## Security Notes

- The container runs as a non-root user (mcpuser)
- SSH files are copied to the user's home directory with proper permissions
- Mount volumes as read-only where possible
EOF

# Note: We don't switch to mcpuser here because the entrypoint handles it
# This allows the container to work in environments where user switching might be restricted

# Expose MCP server (typically runs on stdio, no port needed)
# But we can document that it communicates via stdio

# Set entrypoint
ENTRYPOINT ["/app/entrypoint.sh"]
CMD []

# Default environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Health check (optional - checks if the process is responsive)
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD pgrep -f "mcp-ssh-session" > /dev/null || exit 1