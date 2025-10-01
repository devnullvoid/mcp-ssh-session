"""Entry point for the MCP SSH session server."""
from .server import mcp


def main():
    """Main entry point for the MCP SSH session server."""
    mcp.run()


if __name__ == "__main__":
    main()
