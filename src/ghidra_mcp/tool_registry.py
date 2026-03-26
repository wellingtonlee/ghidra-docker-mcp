"""Static registry of all Ghidra MCP tools for code mode search and execute."""

from __future__ import annotations

from typing import Any

# Each entry: tool_name -> {description, parameters: [{name, type, required, default?}]}
# Parameter "type" uses JSON-schema-style strings: "string", "integer", "boolean", "array", "object"

TOOL_REGISTRY: dict[str, dict[str, Any]] = {
    "import_binary": {
        "description": "Import a binary file into the Ghidra project for analysis.",
        "parameters": [
            {"name": "file_path", "type": "string", "required": True},
            {"name": "analyze", "type": "boolean", "required": False, "default": True},
        ],
    },
    "upload_binary": {
        "description": "Upload a binary via base64-encoded data.",
        "parameters": [
            {"name": "filename", "type": "string", "required": True},
            {"name": "data_base64", "type": "string", "required": True},
            {"name": "analyze", "type": "boolean", "required": False, "default": True},
        ],
    },
    "list_binaries": {
        "description": "List all binaries currently imported in the Ghidra project.",
        "parameters": [],
    },
    "delete_binary": {
        "description": "Remove a binary from the Ghidra project.",
        "parameters": [
            {"name": "binary_name", "type": "string", "required": True},
        ],
    },
    "list_functions": {
        "description": "List functions in a binary with pagination and optional name filter.",
        "parameters": [
            {"name": "binary_name", "type": "string", "required": True},
            {"name": "offset", "type": "integer", "required": False, "default": 0},
            {"name": "limit", "type": "integer", "required": False, "default": 100},
            {"name": "filter", "type": "string", "required": False, "default": None},
        ],
    },
    "decompile_function": {
        "description": "Decompile a function to C pseudocode.",
        "parameters": [
            {"name": "binary_name", "type": "string", "required": True},
            {"name": "name_or_addr", "type": "string", "required": True},
        ],
    },
    "rename_function": {
        "description": "Rename a function in the binary.",
        "parameters": [
            {"name": "binary_name", "type": "string", "required": True},
            {"name": "old_name", "type": "string", "required": True},
            {"name": "new_name", "type": "string", "required": True},
        ],
    },
    "rename_variable": {
        "description": "Rename a variable (parameter or local) within a function.",
        "parameters": [
            {"name": "binary_name", "type": "string", "required": True},
            {"name": "function_name", "type": "string", "required": True},
            {"name": "old_name", "type": "string", "required": True},
            {"name": "new_name", "type": "string", "required": True},
        ],
    },
    "rename_label": {
        "description": "Rename a symbol/label in the program.",
        "parameters": [
            {"name": "binary_name", "type": "string", "required": True},
            {"name": "old_name", "type": "string", "required": True},
            {"name": "new_name", "type": "string", "required": True},
        ],
    },
    "list_strings": {
        "description": "List defined strings in a binary with pagination.",
        "parameters": [
            {"name": "binary_name", "type": "string", "required": True},
            {"name": "min_length", "type": "integer", "required": False, "default": 4},
            {"name": "offset", "type": "integer", "required": False, "default": 0},
            {"name": "limit", "type": "integer", "required": False, "default": 100},
        ],
    },
    "search_strings": {
        "description": "Search for strings matching a pattern (substring or regex).",
        "parameters": [
            {"name": "binary_name", "type": "string", "required": True},
            {"name": "pattern", "type": "string", "required": True},
            {"name": "regex", "type": "boolean", "required": False, "default": False},
        ],
    },
    "list_imports": {
        "description": "List imported symbols/functions.",
        "parameters": [
            {"name": "binary_name", "type": "string", "required": True},
            {"name": "filter", "type": "string", "required": False, "default": None},
        ],
    },
    "list_exports": {
        "description": "List exported symbols/functions.",
        "parameters": [
            {"name": "binary_name", "type": "string", "required": True},
            {"name": "filter", "type": "string", "required": False, "default": None},
        ],
    },
    "get_xrefs": {
        "description": "Get cross-references to/from an address.",
        "parameters": [
            {"name": "binary_name", "type": "string", "required": True},
            {"name": "address", "type": "string", "required": True},
            {"name": "direction", "type": "string", "required": False, "default": "both"},
        ],
    },
    "search_bytes": {
        "description": "Search for a byte pattern in binary memory (use '??' for wildcards).",
        "parameters": [
            {"name": "binary_name", "type": "string", "required": True},
            {"name": "hex_pattern", "type": "string", "required": True},
            {"name": "max_results", "type": "integer", "required": False, "default": 50},
        ],
    },
    "get_entropy": {
        "description": "Calculate per-section Shannon entropy for packing detection (>7.0 suggests packed).",
        "parameters": [
            {"name": "binary_name", "type": "string", "required": True},
        ],
    },
    "detect_suspicious_apis": {
        "description": "Detect suspicious API imports categorized by behavior.",
        "parameters": [
            {"name": "binary_name", "type": "string", "required": True},
        ],
    },
    "get_sections": {
        "description": "Get binary sections with permissions, entropy, and anomaly flags.",
        "parameters": [
            {"name": "binary_name", "type": "string", "required": True},
        ],
    },
    "get_memory_bytes": {
        "description": "Read raw bytes from an address in binary memory (max 4096).",
        "parameters": [
            {"name": "binary_name", "type": "string", "required": True},
            {"name": "address", "type": "string", "required": True},
            {"name": "size", "type": "integer", "required": False, "default": 256},
        ],
    },
    "search_instructions": {
        "description": "Search disassembly for instructions matching a regex pattern.",
        "parameters": [
            {"name": "binary_name", "type": "string", "required": True},
            {"name": "mnemonic_pattern", "type": "string", "required": True},
            {"name": "operand_pattern", "type": "string", "required": False, "default": None},
            {"name": "max_results", "type": "integer", "required": False, "default": 100},
        ],
    },
    "get_function_summary": {
        "description": "Get rich function metadata: parameters, callees, callers, strings, complexity.",
        "parameters": [
            {"name": "binary_name", "type": "string", "required": True},
            {"name": "name_or_addr", "type": "string", "required": True},
        ],
    },
    "get_basic_blocks": {
        "description": "Get control-flow graph basic blocks for a function.",
        "parameters": [
            {"name": "binary_name", "type": "string", "required": True},
            {"name": "name_or_addr", "type": "string", "required": True},
        ],
    },
    "get_call_graph": {
        "description": "Get function call graph with BFS depth control.",
        "parameters": [
            {"name": "binary_name", "type": "string", "required": True},
            {"name": "name_or_addr", "type": "string", "required": True},
            {"name": "depth", "type": "integer", "required": False, "default": 2},
            {"name": "direction", "type": "string", "required": False, "default": "callees"},
        ],
    },
    "emulate_function": {
        "description": "Emulate a function with optional arguments and return the result.",
        "parameters": [
            {"name": "binary_name", "type": "string", "required": True},
            {"name": "name_or_addr", "type": "string", "required": True},
            {"name": "args", "type": "array", "required": False, "default": None},
            {"name": "max_steps", "type": "integer", "required": False, "default": 10000},
        ],
    },
    "emulate_step": {
        "description": "Single-step an emulator session, reading registers and memory.",
        "parameters": [
            {"name": "binary_name", "type": "string", "required": True},
            {"name": "name_or_addr", "type": "string", "required": True},
            {"name": "count", "type": "integer", "required": False, "default": 1},
            {"name": "read_registers", "type": "array", "required": False, "default": None},
            {"name": "read_memory", "type": "array", "required": False, "default": None},
        ],
    },
    "emulate_session_destroy": {
        "description": "Destroy an emulator session and free its resources.",
        "parameters": [
            {"name": "binary_name", "type": "string", "required": True},
            {"name": "name_or_addr", "type": "string", "required": True},
        ],
    },
    # ── Server tools ──────────────────────────────────────────────
    "connect_server": {
        "description": "Connect to a Ghidra server for collaborative reverse engineering.",
        "parameters": [
            {"name": "host", "type": "string", "required": True},
            {"name": "port", "type": "integer", "required": False, "default": 13100},
            {"name": "username", "type": "string", "required": False, "default": "ghidra"},
            {"name": "password", "type": "string", "required": False, "default": None},
        ],
    },
    "disconnect_server": {
        "description": "Disconnect from the Ghidra server and release all server-opened programs.",
        "parameters": [],
    },
    "list_repositories": {
        "description": "List available repositories on the connected Ghidra server.",
        "parameters": [],
    },
    "list_server_files": {
        "description": "List files and subfolders in a Ghidra server repository.",
        "parameters": [
            {"name": "repository_name", "type": "string", "required": True},
            {"name": "folder_path", "type": "string", "required": False, "default": "/"},
        ],
    },
    "open_from_server": {
        "description": "Open a program from the Ghidra server for analysis. Once opened, all analysis tools work on it.",
        "parameters": [
            {"name": "repository_name", "type": "string", "required": True},
            {"name": "file_path", "type": "string", "required": True},
            {"name": "checkout", "type": "boolean", "required": False, "default": True},
        ],
    },
    "checkin_file": {
        "description": "Check in changes to a server-opened program back to the Ghidra server.",
        "parameters": [
            {"name": "binary_name", "type": "string", "required": True},
            {"name": "comment", "type": "string", "required": False, "default": "Changes from MCP analysis"},
        ],
    },
}
