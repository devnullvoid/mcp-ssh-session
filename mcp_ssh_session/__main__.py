"""Entry point for the MCP SSH session server."""
from .server import mcp

if __name__ == "__main__":
    mcp.run()
