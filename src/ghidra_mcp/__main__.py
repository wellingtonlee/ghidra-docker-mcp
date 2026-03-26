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
    args = parser.parse_args()

    server = create_server(
        project_dir=args.project_dir,
        project_name=args.project_name,
        mode=args.mode,
    )
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
