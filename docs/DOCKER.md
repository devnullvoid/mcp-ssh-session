# Docker Usage for MCP SSH Session Server

This document explains how to run the MCP SSH Session server in Docker containers.

## Quick Start

### 1. Build the Image
```bash
docker build -t mcp-ssh-session .
```

### 2. Run the Container
```bash
docker run --rm -i mcp-ssh-session
```

## SSH Configuration

The container supports mounting SSH configuration and keys through dedicated mount points.

### Option 1: Mount Individual Files
```bash
docker run --rm -i \
  -v ~/.ssh/config:/mounts/ssh-config/config:ro \
  -v ~/.ssh/id_rsa:/mounts/ssh-keys/id_rsa:ro \
  -v ~/.ssh/id_rsa.pub:/mounts/ssh-keys/id_rsa.pub:ro \
  mcp-ssh-session
```

### Option 2: Mount Entire SSH Directory
```bash
docker run --rm -i \
  -v ~/.ssh:/mounts/ssh-keys:ro \
  mcp-ssh-session
```

### Option 3: Using Docker Compose
```bash
# Edit docker-compose.yml to uncomment the volume mounts
docker-compose up mcp-ssh-session
```

## Mount Points

| Mount Point | Description | Required |
|-------------|-------------|----------|
| `/mounts/ssh-config/config` | SSH configuration file | No |
| `/mounts/ssh-keys/` | Directory containing SSH keys | No |

## Security Considerations

1. **Read-Only Mounts**: Always mount SSH files as read-only (`:ro`)
2. **Minimal Keys**: Only mount the keys you actually need
3. **Non-Root User**: Container runs as non-root user `mcpuser`
4. **File Permissions**: Container sets proper SSH file permissions automatically

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PYTHONUNBUFFERED` | `1` | Ensures Python output is not buffered |
| `PYTHONDONTWRITEBYTECODE` | `1` | Prevents Python from writing .pyc files |

## Examples

### Basic Usage with SSH Keys
```bash
docker run --rm -i \
  -v ~/.ssh/id_rsa:/mounts/ssh-keys/id_rsa:ro \
  -v ~/.ssh/id_rsa.pub:/mounts/ssh-keys/id_rsa.pub:ro \
  mcp-ssh-session
```

### With Custom SSH Config
```bash
docker run --rm -i \
  -v ./ssh-config:/mounts/ssh-config/config:ro \
  -v ~/.ssh:/mounts/ssh-keys:ro \
  mcp-ssh-session
```

### With Persistent Logs
```bash
mkdir -p ./logs
docker run --rm -i \
  -v ~/.ssh:/mounts/ssh-keys:ro \
  -v ./logs:/tmp/mcp_ssh_session_logs \
  mcp-ssh-session
```

### Development Mode
```bash
docker run --rm -i \
  -v ~/.ssh:/mounts/ssh-keys:ro \
  -v $(pwd):/app \
  -w /app \
  mcp-ssh-session uv run mcp-ssh-session
```

## Docker Compose Examples

### Basic Setup
```yaml
version: '3.8'
services:
  mcp-ssh-session:
    build: .
    stdin_open: true
    volumes:
      - ~/.ssh:/mounts/ssh-keys:ro
```

### Production Setup
```yaml
version: '3.8'
services:
  mcp-ssh-session:
    build: .
    stdin_open: true
    restart: unless-stopped
    volumes:
      - ~/.ssh/config:/mounts/ssh-config/config:ro
      - ~/.ssh:/mounts/ssh-keys:ro
      - ./logs:/tmp/mcp_ssh_session_logs
    environment:
      - PYTHONUNBUFFERED=1
      - PYTHONDONTWRITEBYTECODE=1
```

## Troubleshooting

### SSH Key Permissions
The container automatically sets correct permissions for SSH files:
- Private keys: `600` (read/write by owner only)
- Public keys: `644` (readable by all)
- SSH config: `600`
- `.ssh` directory: `700`

### Debug Mode
Run with verbose output:
```bash
docker run --rm -i \
  -v ~/.ssh:/mounts/ssh-keys:ro \
  -e DEBUG=1 \
  mcp-ssh-session
```

### Check SSH Setup
Enter the container to verify SSH configuration:
```bash
docker run --rm -it \
  -v ~/.ssh:/mounts/ssh-keys:ro \
  --entrypoint /bin/bash \
  mcp-ssh-session

# Inside container:
ls -la /home/mcpuser/.ssh/
ssh -T git@github.com  # Test SSH connection
```

## Building and Publishing

### Build for Different Platforms
```bash
# Build for current platform
docker build -t mcp-ssh-session .

# Build for multiple platforms
docker buildx build --platform linux/amd64,linux/arm64 -t mcp-ssh-session .
```

### Tag and Push
```bash
docker tag mcp-ssh-session:latest your-registry/mcp-ssh-session:latest
docker push your-registry/mcp-ssh-session:latest
```

## Integration with MCP Clients

The container communicates via stdio, so it can be used with any MCP client:

```bash
# Example with Claude Desktop
docker run --rm -i \
  -v ~/.ssh:/mounts/ssh-keys:ro \
  mcp-ssh-session | claude-desktop
```

## Health Checks

The container includes a health check that verifies the MCP server process is running:

```bash
docker ps --format "table {{.Names}}\t{{.Status}}"
```

## Logs

Application logs are written to `/tmp/mcp_ssh_session_logs/mcp_ssh_session.log` inside the container. Mount this directory to persist logs:

```bash
docker run --rm -i \
  -v ~/.ssh:/mounts/ssh-keys:ro \
  -v ./logs:/tmp/mcp_ssh_session_logs \
  mcp-ssh-session
```