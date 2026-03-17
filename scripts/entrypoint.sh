#!/bin/bash
set -e

# Ensure project directory exists
mkdir -p /home/ghidra/projects

# Start the MCP server via stdio transport
exec ghidra-mcp \
    --project-dir /home/ghidra/projects \
    --project-name mcp_project \
    "$@"
