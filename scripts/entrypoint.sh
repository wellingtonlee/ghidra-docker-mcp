#!/bin/bash
set -e

# Auto-detect JAVA_HOME if the configured path doesn't exist
if [ ! -d "${JAVA_HOME:-}" ]; then
    detected=$(find /usr/lib/jvm -maxdepth 1 -name 'java-21-openjdk-*' -type d | head -1)
    if [ -n "$detected" ]; then
        export JAVA_HOME="$detected"
    fi
fi

# Ensure project directory exists
mkdir -p /home/ghidra/projects

# Start the MCP server via stdio transport
exec ghidra-mcp \
    --project-dir /home/ghidra/projects \
    --project-name mcp_project \
    "$@"
