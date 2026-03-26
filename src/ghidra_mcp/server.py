"""FastMCP server — registers all tools and resources."""

from __future__ import annotations

import base64
import logging
import tempfile
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from ghidra_mcp.ghidra_bridge import GhidraBridge

logger = logging.getLogger(__name__)


def create_server(
    project_dir: str = "/home/ghidra/projects",
    project_name: str = "mcp_project",
    mode: str = "full",
) -> FastMCP:
    """Create and configure the Ghidra MCP server.

    Args:
        project_dir: Directory for Ghidra projects.
        project_name: Ghidra project name.
        mode: "full" registers all 32 tools + 5 resources;
              "code" registers only search + execute (saves tokens).
    """
    mcp = FastMCP(
        "ghidra-mcp",
        instructions="Ghidra binary analysis server for reverse engineering and malware analysis",
    )
    bridge = GhidraBridge(project_dir, project_name)

    if mode == "code":
        _register_code_mode_tools(mcp, bridge)
    else:
        _register_full_mode_tools(mcp, bridge)

    return mcp


# ── Code mode (search + execute) ─────────────────────────────────


def _dispatch(bridge: GhidraBridge, method: str, params: dict[str, Any]) -> Any:
    """Dispatch a code-mode execute call to the appropriate bridge method."""
    from ghidra_mcp.tool_registry import TOOL_REGISTRY

    if method not in TOOL_REGISTRY:
        raise ValueError(
            f"Unknown method '{method}'. Use the search tool to find available methods. "
            f"Available: {list(TOOL_REGISTRY.keys())}"
        )

    # Special case: upload_binary has base64 decode + temp file logic
    if method == "upload_binary":
        data = base64.b64decode(params["data_base64"])
        tmp_dir = Path(tempfile.mkdtemp(prefix="ghidra_upload_"))
        tmp_path = tmp_dir / params["filename"]
        tmp_path.write_bytes(data)
        try:
            return bridge.import_binary(str(tmp_path), analyze=params.get("analyze", True))
        finally:
            tmp_path.unlink(missing_ok=True)
            tmp_dir.rmdir()

    # Special case: delete_binary wraps bridge response
    if method == "delete_binary":
        binary_name = params["binary_name"]
        bridge.delete_binary(binary_name)
        return {"status": "deleted", "binary_name": binary_name}

    # Special case: emulate_session_destroy wraps bridge response + name differs
    if method == "emulate_session_destroy":
        binary_name = params["binary_name"]
        name_or_addr = params["name_or_addr"]
        bridge.destroy_emulator_session(binary_name, name_or_addr)
        return {"status": "destroyed", "binary_name": binary_name, "function": name_or_addr}

    # Rename "filter" -> "filter_name" for bridge methods that use the latter
    if method in ("list_functions", "list_imports", "list_exports"):
        params = dict(params)
        if "filter" in params:
            params["filter_name"] = params.pop("filter")

    # Standard dispatch
    bridge_method = getattr(bridge, method, None)
    if bridge_method is None:
        raise ValueError(f"No bridge method for '{method}'")

    return bridge_method(**params)


def _register_code_mode_tools(mcp: FastMCP, bridge: GhidraBridge) -> None:
    """Register the two code-mode tools: search and execute."""
    from ghidra_mcp.tool_registry import TOOL_REGISTRY

    @mcp.tool()
    def search(query: str | None = None) -> list[dict[str, Any]]:
        """Search the Ghidra tool catalog. Returns tool names, descriptions, and parameter signatures.

        Use this to discover available analysis methods before calling execute.

        Args:
            query: Optional substring to filter tool names and descriptions. Returns all tools if omitted.
        """
        results = []
        for name, info in TOOL_REGISTRY.items():
            if query and query.lower() not in name.lower() and query.lower() not in info["description"].lower():
                continue
            results.append({
                "tool": name,
                "description": info["description"],
                "parameters": info["parameters"],
            })
        return results

    @mcp.tool()
    def execute(method: str, params: dict[str, Any] | None = None) -> Any:
        """Execute a Ghidra analysis tool by name with the given parameters.

        Use 'search' to discover available tools and their parameter signatures.

        Args:
            method: Tool name from the catalog (e.g., "list_functions", "decompile_function").
            params: Keyword arguments for the tool as a dictionary. Omit for tools with no required params.
        """
        return _dispatch(bridge, method, params or {})


# ── Full mode (all tools + resources) ────────────────────────────


def _register_full_mode_tools(mcp: FastMCP, bridge: GhidraBridge) -> None:
    """Register all 32 tools and 5 resources for full mode."""

    # ── Project tools ──────────────────────────────────────────────

    @mcp.tool()
    def import_binary(file_path: str, analyze: bool = True) -> dict[str, Any]:
        """Import a binary file into the Ghidra project for analysis.

        Args:
            file_path: Path to the binary file to import.
            analyze: Whether to run Ghidra auto-analysis after import (default: True).
        """
        return bridge.import_binary(file_path, analyze=analyze)

    @mcp.tool()
    def upload_binary(
        filename: str, data_base64: str, analyze: bool = True
    ) -> dict[str, Any]:
        """Upload a binary via base64-encoded data.

        Args:
            filename: Name for the binary file.
            data_base64: Base64-encoded binary content.
            analyze: Whether to run Ghidra auto-analysis after import (default: True).
        """
        data = base64.b64decode(data_base64)
        tmp_dir = Path(tempfile.mkdtemp(prefix="ghidra_upload_"))
        tmp_path = tmp_dir / filename
        tmp_path.write_bytes(data)
        try:
            return bridge.import_binary(str(tmp_path), analyze=analyze)
        finally:
            tmp_path.unlink(missing_ok=True)
            tmp_dir.rmdir()

    @mcp.tool()
    def list_binaries() -> list[str]:
        """List all binaries currently imported in the Ghidra project."""
        return bridge.list_binaries()

    @mcp.tool()
    def delete_binary(binary_name: str) -> dict[str, str]:
        """Remove a binary from the Ghidra project.

        Args:
            binary_name: Name of the binary to remove.
        """
        bridge.delete_binary(binary_name)
        return {"status": "deleted", "binary_name": binary_name}

    # ── Function tools ─────────────────────────────────────────────

    @mcp.tool()
    def list_functions(
        binary_name: str,
        offset: int = 0,
        limit: int = 100,
        filter: str | None = None,
    ) -> dict[str, Any]:
        """List functions in a binary with pagination and optional name filter.

        Args:
            binary_name: Name of the binary.
            offset: Number of results to skip (for pagination).
            limit: Maximum number of results to return.
            filter: Optional substring to filter function names.
        """
        return bridge.list_functions(binary_name, offset=offset, limit=limit, filter_name=filter)

    @mcp.tool()
    def decompile_function(binary_name: str, name_or_addr: str) -> dict[str, Any]:
        """Decompile a function to C pseudocode.

        Args:
            binary_name: Name of the binary.
            name_or_addr: Function name or hex address (e.g., "main" or "0x00401000").
        """
        return bridge.decompile_function(binary_name, name_or_addr)

    @mcp.tool()
    def rename_function(
        binary_name: str, old_name: str, new_name: str
    ) -> dict[str, Any]:
        """Rename a function in the binary.

        Args:
            binary_name: Name of the binary.
            old_name: Current function name or hex address.
            new_name: New name for the function.
        """
        return bridge.rename_function(binary_name, old_name, new_name)

    @mcp.tool()
    def rename_variable(
        binary_name: str, function_name: str, old_name: str, new_name: str
    ) -> dict[str, Any]:
        """Rename a variable (parameter or local) within a function.

        Args:
            binary_name: Name of the binary.
            function_name: Function name or hex address containing the variable.
            old_name: Current variable name.
            new_name: New name for the variable.
        """
        return bridge.rename_variable(binary_name, function_name, old_name, new_name)

    @mcp.tool()
    def rename_label(
        binary_name: str, old_name: str, new_name: str
    ) -> dict[str, Any]:
        """Rename a symbol/label in the program.

        Args:
            binary_name: Name of the binary.
            old_name: Current label name or hex address.
            new_name: New name for the label.
        """
        return bridge.rename_label(binary_name, old_name, new_name)

    # ── String tools ───────────────────────────────────────────────

    @mcp.tool()
    def list_strings(
        binary_name: str,
        min_length: int = 4,
        offset: int = 0,
        limit: int = 100,
    ) -> dict[str, Any]:
        """List defined strings in a binary with pagination.

        Args:
            binary_name: Name of the binary.
            min_length: Minimum string length to include (default: 4).
            offset: Number of results to skip.
            limit: Maximum number of results to return.
        """
        return bridge.list_strings(binary_name, min_length=min_length, offset=offset, limit=limit)

    @mcp.tool()
    def search_strings(
        binary_name: str, pattern: str, regex: bool = False
    ) -> list[dict[str, Any]]:
        """Search for strings matching a pattern.

        Args:
            binary_name: Name of the binary.
            pattern: Search pattern (substring or regex).
            regex: If True, treat pattern as a regular expression.
        """
        return bridge.search_strings(binary_name, pattern, regex=regex)

    # ── Import/Export tools ────────────────────────────────────────

    @mcp.tool()
    def list_imports(
        binary_name: str, filter: str | None = None
    ) -> list[dict[str, Any]]:
        """List imported symbols/functions.

        Args:
            binary_name: Name of the binary.
            filter: Optional substring to filter import names.
        """
        return bridge.list_imports(binary_name, filter_name=filter)

    @mcp.tool()
    def list_exports(
        binary_name: str, filter: str | None = None
    ) -> list[dict[str, Any]]:
        """List exported symbols/functions.

        Args:
            binary_name: Name of the binary.
            filter: Optional substring to filter export names.
        """
        return bridge.list_exports(binary_name, filter_name=filter)

    # ── Cross-reference tools ──────────────────────────────────────

    @mcp.tool()
    def get_xrefs(
        binary_name: str, address: str, direction: str = "both"
    ) -> dict[str, Any]:
        """Get cross-references to/from an address.

        Args:
            binary_name: Name of the binary.
            address: Hex address (e.g., "0x00401000").
            direction: "to", "from", or "both" (default: "both").
        """
        return bridge.get_xrefs(binary_name, address, direction=direction)

    # ── Search tools ───────────────────────────────────────────────

    @mcp.tool()
    def search_bytes(
        binary_name: str, hex_pattern: str, max_results: int = 50
    ) -> list[dict[str, Any]]:
        """Search for a byte pattern in binary memory.

        Args:
            binary_name: Name of the binary.
            hex_pattern: Hex byte pattern, use '??' for wildcards (e.g., "4D5A??00").
            max_results: Maximum number of matches to return (default: 50).
        """
        return bridge.search_bytes(binary_name, hex_pattern, max_results=max_results)

    # ── Malware analysis tools ─────────────────────────────────────

    @mcp.tool()
    def get_entropy(binary_name: str) -> dict[str, Any]:
        """Calculate per-section Shannon entropy for packing detection.

        High entropy (>7.0) suggests packed or encrypted content.

        Args:
            binary_name: Name of the binary.
        """
        return bridge.get_entropy(binary_name)

    @mcp.tool()
    def detect_suspicious_apis(binary_name: str) -> dict[str, Any]:
        """Detect suspicious API imports categorized by behavior.

        Categories: process_injection, persistence, crypto, network,
        anti_debug, dynamic_loading, process_manipulation, file_system.

        Args:
            binary_name: Name of the binary.
        """
        return bridge.detect_suspicious_apis(binary_name)

    @mcp.tool()
    def get_sections(binary_name: str) -> list[dict[str, Any]]:
        """Get binary sections with permissions, entropy, and anomaly flags.

        Flags anomalies like W+X permissions, unusual section names,
        and high entropy (potential packing).

        Args:
            binary_name: Name of the binary.
        """
        return bridge.get_sections(binary_name)

    # ── Advanced analysis tools ────────────────────────────────────

    @mcp.tool()
    def get_memory_bytes(
        binary_name: str, address: str, size: int = 256
    ) -> dict[str, Any]:
        """Read raw bytes from an address in binary memory.

        Args:
            binary_name: Name of the binary.
            address: Hex address to read from (e.g., "0x00401000").
            size: Number of bytes to read (default: 256, max: 4096).
        """
        return bridge.get_memory_bytes(binary_name, address, size=size)

    @mcp.tool()
    def search_instructions(
        binary_name: str,
        mnemonic_pattern: str,
        operand_pattern: str | None = None,
        max_results: int = 100,
    ) -> dict[str, Any]:
        """Search disassembly for instructions matching a regex pattern.

        Args:
            binary_name: Name of the binary.
            mnemonic_pattern: Regex pattern to match instruction mnemonics (e.g., "xor|sub").
            operand_pattern: Optional regex to match operand text.
            max_results: Maximum matches to return (default: 100).
        """
        return bridge.search_instructions(
            binary_name, mnemonic_pattern, operand_pattern=operand_pattern, max_results=max_results
        )

    @mcp.tool()
    def get_function_summary(binary_name: str, name_or_addr: str) -> dict[str, Any]:
        """Get rich function metadata without decompilation: parameters, callees, callers, strings, complexity.

        Args:
            binary_name: Name of the binary.
            name_or_addr: Function name or hex address (e.g., "main" or "0x00401000").
        """
        return bridge.get_function_summary(binary_name, name_or_addr)

    @mcp.tool()
    def get_basic_blocks(binary_name: str, name_or_addr: str) -> dict[str, Any]:
        """Get control-flow graph basic blocks for a function.

        Returns blocks with instructions, successor/predecessor edges for CFG reconstruction.

        Args:
            binary_name: Name of the binary.
            name_or_addr: Function name or hex address (e.g., "main" or "0x00401000").
        """
        return bridge.get_basic_blocks(binary_name, name_or_addr)

    @mcp.tool()
    def get_call_graph(
        binary_name: str,
        name_or_addr: str,
        depth: int = 2,
        direction: str = "callees",
    ) -> dict[str, Any]:
        """Get function call graph with BFS depth control.

        Args:
            binary_name: Name of the binary.
            name_or_addr: Root function name or hex address.
            depth: How many levels to traverse (default: 2, max: 10).
            direction: "callees", "callers", or "both" (default: "callees").
        """
        return bridge.get_call_graph(
            binary_name, name_or_addr, depth=depth, direction=direction
        )

    # ── Emulation tools ────────────────────────────────────────────

    @mcp.tool()
    def emulate_function(
        binary_name: str,
        name_or_addr: str,
        args: list[int] | None = None,
        max_steps: int = 10000,
    ) -> dict[str, Any]:
        """Emulate a function with optional arguments and return the result.

        Sets up the emulator using the function's calling convention, places
        arguments in the correct registers/stack locations, runs until return
        or max_steps, and extracts the return value.

        Only self-contained functions emulate correctly — external/imported
        calls (printf, malloc, etc.) will cause emulation to stop or fail.

        Args:
            binary_name: Name of the binary.
            name_or_addr: Function name or hex address (e.g., "main" or "0x00401000").
            args: Integer arguments to pass to the function (placed per calling convention).
            max_steps: Maximum emulation steps before stopping (default: 10000).
        """
        return bridge.emulate_function(
            binary_name, name_or_addr, args=args, max_steps=max_steps
        )

    @mcp.tool()
    def emulate_step(
        binary_name: str,
        name_or_addr: str,
        count: int = 1,
        read_registers: list[str] | None = None,
        read_memory: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Single-step an emulator session, reading registers and memory.

        Requires a session created by a prior emulate_function call.

        Args:
            binary_name: Name of the binary.
            name_or_addr: Function name or hex address identifying the session.
            count: Number of steps to execute (default: 1).
            read_registers: Register names to read after stepping (e.g., ["RAX", "RBX"]).
            read_memory: Memory regions to read: [{"address": "0x...", "size": 16}].
        """
        return bridge.emulate_step(
            binary_name, name_or_addr, count=count,
            read_registers=read_registers, read_memory=read_memory,
        )

    @mcp.tool()
    def emulate_session_destroy(
        binary_name: str, name_or_addr: str
    ) -> dict[str, str]:
        """Destroy an emulator session and free its resources.

        Args:
            binary_name: Name of the binary.
            name_or_addr: Function name or hex address identifying the session.
        """
        bridge.destroy_emulator_session(binary_name, name_or_addr)
        return {"status": "destroyed", "binary_name": binary_name, "function": name_or_addr}

    # ── Server tools ──────────────────────────────────────────────

    @mcp.tool()
    def connect_server(
        host: str, port: int = 13100, username: str = "ghidra", password: str | None = None
    ) -> dict[str, Any]:
        """Connect to a Ghidra server for collaborative reverse engineering.

        Args:
            host: Ghidra server hostname or IP address.
            port: Ghidra server port (default: 13100).
            username: Username for authentication.
            password: Optional password (omit for anonymous/passwordless servers).
        """
        return bridge.connect_server(host, port=port, username=username, password=password)

    @mcp.tool()
    def disconnect_server() -> dict[str, Any]:
        """Disconnect from the Ghidra server and release all server-opened programs."""
        return bridge.disconnect_server()

    @mcp.tool()
    def list_repositories() -> list[dict[str, Any]]:
        """List available repositories on the connected Ghidra server."""
        return bridge.list_repositories()

    @mcp.tool()
    def list_server_files(
        repository_name: str, folder_path: str = "/"
    ) -> dict[str, Any]:
        """List files and subfolders in a Ghidra server repository.

        Args:
            repository_name: Name of the repository.
            folder_path: Folder path within the repository (default: root "/").
        """
        return bridge.list_server_files(repository_name, folder_path=folder_path)

    @mcp.tool()
    def open_from_server(
        repository_name: str, file_path: str, checkout: bool = True
    ) -> dict[str, Any]:
        """Open a program from the Ghidra server for analysis.

        Once opened, all analysis tools work on it (decompile, list_functions, etc.).

        Args:
            repository_name: Name of the repository.
            file_path: Path to the file within the repository (e.g., "/malware/sample.exe").
            checkout: If True, exclusively check out the file for editing (default: True).
        """
        return bridge.open_from_server(repository_name, file_path, checkout=checkout)

    @mcp.tool()
    def checkin_file(
        binary_name: str, comment: str = "Changes from MCP analysis"
    ) -> dict[str, Any]:
        """Check in changes to a server-opened program.

        Saves all modifications (renames, annotations, etc.) back to the Ghidra server.

        Args:
            binary_name: Name of the binary (as shown in list_binaries).
            comment: Check-in comment describing the changes.
        """
        return bridge.checkin_file(binary_name, comment=comment)

    # ── Resources ──────────────────────────────────────────────────

    @mcp.resource("ghidra://binaries")
    def resource_binaries() -> list[str]:
        """List all binaries in the Ghidra project."""
        return bridge.list_binaries()

    @mcp.resource("ghidra://binary/{name}/info")
    def resource_binary_info(name: str) -> dict[str, Any]:
        """Get binary metadata: architecture, format, hashes, entry point."""
        return bridge.get_binary_info(name)

    @mcp.resource("ghidra://binary/{name}/functions")
    def resource_binary_functions(name: str) -> dict[str, Any]:
        """Get full function list for a binary."""
        return bridge.list_functions(name, offset=0, limit=999999)

    @mcp.resource("ghidra://binary/{name}/strings")
    def resource_binary_strings(name: str) -> dict[str, Any]:
        """Get all defined strings in a binary."""
        return bridge.list_strings(name, min_length=1, offset=0, limit=999999)

    @mcp.resource("ghidra://binary/{name}/imports")
    def resource_binary_imports(name: str) -> list[dict[str, Any]]:
        """Get all imported symbols for a binary."""
        return bridge.list_imports(name)
