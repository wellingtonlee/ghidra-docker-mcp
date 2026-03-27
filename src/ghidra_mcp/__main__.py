"""CLI entry point for ghidra-mcp server."""

import argparse
import sys

from ghidra_mcp.server import create_server


def main() -> None:
    parser = argparse.ArgumentParser(description="Ghidra MCP Server")
    parser.add_argument(
        "--project-dir",
        default="./ghidra-projects",
        help="Directory for Ghidra projects (default: ./ghidra-projects)",
    )
    parser.add_argument(
        "--project-name",
        default="mcp_project",
        help="Ghidra project name (default: mcp_project)",
    )
    parser.add_argument(
        "--mode",
        choices=["full", "code", "script"],
        default="full",
        help="Server mode: 'full' registers all tools, 'code' registers search+execute, "
             "'script' registers API introspection and code execution (default: full)",
    )
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse"],
        default="stdio",
        help="Transport protocol: 'stdio' for local use, 'sse' for HTTP (default: stdio)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8080,
        help="Port for SSE transport (default: 8080)",
    )
    parser.add_argument(
        "--host",
        default="localhost",
        help="Host for SSE transport (default: localhost)",
    )
    args = parser.parse_args()

    server = create_server(
        project_dir=args.project_dir,
        project_name=args.project_name,
        mode=args.mode,
        host=args.host,
        port=args.port,
    )
    server.run(transport=args.transport)


if __name__ == "__main__":
    main()
