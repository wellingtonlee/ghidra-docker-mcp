"""Test fixtures and mocked GhidraBridge for unit tests."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

import pytest


class MockGhidraBridge:
    """Mock GhidraBridge that doesn't require Ghidra/JVM."""

    def __init__(self) -> None:
        self._programs: dict[str, dict[str, Any]] = {}
        self._emulator_sessions: dict[str, dict[str, Any]] = {}
        self._server_connected = False
        self._server_host: str | None = None
        self._server_repos: dict[str, list[dict[str, Any]]] = {
            "test-repo": [
                {"name": "malware.exe", "path": "/malware.exe", "content_type": "Program", "version": 3},
                {"name": "sample.dll", "path": "/samples/sample.dll", "content_type": "Program", "version": 1},
            ],
        }
        self._server_files: dict[str, str] = {}

    def start(self) -> None:
        pass

    def import_binary(self, file_path: str, analyze: bool = True) -> dict[str, Any]:
        from pathlib import Path

        name = Path(file_path).name
        info = {
            "name": name,
            "architecture": "x86",
            "address_size": 64,
            "endian": "little",
            "format": "ELF",
            "base_address": "0x00100000",
            "entry_points": ["0x00101000"],
            "md5": "d41d8cd98f00b204e9800998ecf8427e",
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "file_path": file_path,
            "num_functions": 5,
            "memory_size": 4096,
        }
        self._programs[name] = info
        return info

    def list_binaries(self) -> list[str]:
        return list(self._programs.keys())

    def delete_binary(self, binary_name: str) -> None:
        if binary_name not in self._programs:
            raise KeyError(f"Binary '{binary_name}' not found.")
        keys_to_remove = [k for k in self._emulator_sessions if k.startswith(f"{binary_name}:")]
        for key in keys_to_remove:
            self._emulator_sessions.pop(key)
        del self._programs[binary_name]

    def get_binary_info(self, binary_name: str) -> dict[str, Any]:
        if binary_name not in self._programs:
            raise KeyError(f"Binary '{binary_name}' not found.")
        return self._programs[binary_name]

    def _check_binary(self, binary_name: str) -> None:
        if binary_name not in self._programs:
            raise KeyError(f"Binary '{binary_name}' not found.")

    def list_functions(
        self, binary_name: str, offset: int = 0, limit: int = 100, filter_name: str | None = None
    ) -> dict[str, Any]:
        self._check_binary(binary_name)
        funcs = [
            {"name": "main", "address": "0x00101000", "size": 120, "is_thunk": False,
             "calling_convention": "__stdcall", "parameter_count": 2},
            {"name": "_start", "address": "0x00100000", "size": 40, "is_thunk": False,
             "calling_convention": "__stdcall", "parameter_count": 0},
            {"name": "printf", "address": "0x00102000", "size": 10, "is_thunk": True,
             "calling_convention": "__cdecl", "parameter_count": 1},
        ]
        if filter_name:
            funcs = [f for f in funcs if filter_name.lower() in f["name"].lower()]
        total = len(funcs)
        funcs = funcs[offset:offset + limit]
        return {"functions": funcs, "total": total, "offset": offset, "limit": limit}

    def decompile_function(self, binary_name: str, name_or_addr: str) -> dict[str, Any]:
        self._check_binary(binary_name)
        return {
            "name": name_or_addr,
            "address": "0x00101000",
            "decompiled_c": f"int {name_or_addr}(int argc, char **argv) {{\n  puts(\"Hello, World!\");\n  return 0;\n}}",
            "signature": f"int {name_or_addr}(int, char **)",
        }

    def rename_function(self, binary_name: str, old_name: str, new_name: str) -> dict[str, Any]:
        self._check_binary(binary_name)
        return {"old_name": old_name, "new_name": new_name, "address": "0x00101000"}

    def rename_variable(
        self, binary_name: str, function_name: str, old_name: str, new_name: str
    ) -> dict[str, Any]:
        self._check_binary(binary_name)
        return {
            "function": function_name,
            "old_name": old_name,
            "new_name": new_name,
            "variable_type": "local",
            "storage": "Stack[-0x10]",
        }

    def rename_label(self, binary_name: str, old_name: str, new_name: str) -> dict[str, Any]:
        self._check_binary(binary_name)
        return {
            "old_name": old_name,
            "new_name": new_name,
            "address": "0x00101000",
            "symbol_type": "Label",
        }

    def list_strings(
        self, binary_name: str, min_length: int = 4, offset: int = 0, limit: int = 100
    ) -> dict[str, Any]:
        self._check_binary(binary_name)
        strings = [
            {"address": "0x00200000", "value": "Hello, World!", "length": 13},
            {"address": "0x00200010", "value": "/lib/ld-linux.so.2", "length": 18},
        ]
        strings = [s for s in strings if s["length"] >= min_length]
        total = len(strings)
        strings = strings[offset:offset + limit]
        return {"strings": strings, "total": total, "offset": offset, "limit": limit}

    def search_strings(self, binary_name: str, pattern: str, regex: bool = False) -> list[dict[str, Any]]:
        self._check_binary(binary_name)
        all_strings = self.list_strings(binary_name, min_length=1)["strings"]
        return [s for s in all_strings if pattern.lower() in s["value"].lower()]

    def list_imports(self, binary_name: str, filter_name: str | None = None) -> list[dict[str, Any]]:
        self._check_binary(binary_name)
        imports = [
            {"name": "printf", "address": "EXTERNAL:00000001", "library": "libc.so.6", "type": "Function"},
            {"name": "puts", "address": "EXTERNAL:00000002", "library": "libc.so.6", "type": "Function"},
        ]
        if filter_name:
            imports = [i for i in imports if filter_name.lower() in i["name"].lower()]
        return imports

    def list_exports(self, binary_name: str, filter_name: str | None = None) -> list[dict[str, Any]]:
        self._check_binary(binary_name)
        exports = [
            {"name": "main", "address": "0x00101000", "type": "Function"},
        ]
        if filter_name:
            exports = [e for e in exports if filter_name.lower() in e["name"].lower()]
        return exports

    def get_xrefs(self, binary_name: str, address: str, direction: str = "both") -> dict[str, Any]:
        self._check_binary(binary_name)
        result: dict[str, Any] = {"address": address, "direction": direction}
        if direction in ("to", "both"):
            result["references_to"] = [
                {"from_address": "0x00101020", "type": "UNCONDITIONAL_CALL", "is_call": True},
            ]
        if direction in ("from", "both"):
            result["references_from"] = [
                {"to_address": "0x00102000", "type": "UNCONDITIONAL_CALL", "is_call": True},
            ]
        return result

    def search_bytes(self, binary_name: str, hex_pattern: str, max_results: int = 50) -> list[dict[str, Any]]:
        self._check_binary(binary_name)
        return [{"address": "0x00100000", "function": "main"}]

    def get_entropy(self, binary_name: str) -> dict[str, Any]:
        self._check_binary(binary_name)
        return {
            "binary_name": binary_name,
            "overall_entropy": 5.8432,
            "packed_likely": False,
            "sections": [
                {"name": ".text", "address": "0x00100000", "size": 2048, "entropy": 6.1234},
                {"name": ".data", "address": "0x00200000", "size": 512, "entropy": 3.4567},
            ],
        }

    def detect_suspicious_apis(self, binary_name: str) -> dict[str, Any]:
        self._check_binary(binary_name)
        return {
            "binary_name": binary_name,
            "total_suspicious": 0,
            "categories": {},
        }

    def get_sections(self, binary_name: str) -> list[dict[str, Any]]:
        self._check_binary(binary_name)
        return [
            {
                "name": ".text", "address": "0x00100000", "size": 2048,
                "permissions": "r-x", "entropy": 6.1234,
                "initialized": True, "anomalies": [],
            },
            {
                "name": ".data", "address": "0x00200000", "size": 512,
                "permissions": "rw-", "entropy": 3.4567,
                "initialized": True, "anomalies": [],
            },
        ]

    def get_memory_bytes(
        self, binary_name: str, address: str, size: int = 256
    ) -> dict[str, Any]:
        self._check_binary(binary_name)
        size = min(size, 4096)
        # Return a mock MZ header
        raw = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"
        data = raw[:size] if size <= len(raw) else raw + b"\x00" * (size - len(raw))
        hex_str = data.hex()
        ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
        return {
            "address": address,
            "size": size,
            "hex": hex_str,
            "ascii": ascii_str,
            "containing_section": ".text",
        }

    def search_instructions(
        self,
        binary_name: str,
        mnemonic_pattern: str,
        operand_pattern: str | None = None,
        max_results: int = 100,
    ) -> dict[str, Any]:
        self._check_binary(binary_name)
        import re
        matches = [
            {"address": "0x00101010", "mnemonic": "XOR", "operands": "EAX,EAX",
             "full_text": "XOR EAX,EAX", "function": "main"},
            {"address": "0x00101050", "mnemonic": "XOR", "operands": "EDX,ECX",
             "full_text": "XOR EDX,ECX", "function": "main"},
        ]
        compiled = re.compile(mnemonic_pattern, re.IGNORECASE)
        matches = [m for m in matches if compiled.search(m["mnemonic"])]
        if operand_pattern:
            op_re = re.compile(operand_pattern, re.IGNORECASE)
            matches = [m for m in matches if op_re.search(m["operands"])]
        return {
            "pattern": mnemonic_pattern,
            "operand_pattern": operand_pattern,
            "matches": matches[:max_results],
            "total": len(matches),
        }

    def get_function_summary(self, binary_name: str, name_or_addr: str) -> dict[str, Any]:
        self._check_binary(binary_name)
        return {
            "name": name_or_addr,
            "address": "0x00101000",
            "size": 120,
            "calling_convention": "__stdcall",
            "signature": f"int {name_or_addr}(int argc, char ** argv)",
            "parameters": [
                {"name": "argc", "type": "int", "storage": "EDI"},
                {"name": "argv", "type": "char **", "storage": "RSI"},
            ],
            "return_type": "int",
            "local_variable_count": 3,
            "stack_frame_size": 48,
            "is_thunk": False,
            "called_functions": [
                {"name": "printf", "address": "0x00102000"},
                {"name": "init_payload", "address": "0x00101200"},
                {"name": "exit", "address": "0x00102010"},
            ],
            "calling_functions": [
                {"name": "_start", "address": "0x00100000"},
            ],
            "referenced_strings": [
                {"address": "0x00200000", "value": "Hello, World!"},
                {"address": "0x00200020", "value": "Error: %d"},
            ],
            "instruction_count": 35,
            "cyclomatic_complexity": 4,
        }

    def get_basic_blocks(self, binary_name: str, name_or_addr: str) -> dict[str, Any]:
        self._check_binary(binary_name)
        return {
            "function": name_or_addr,
            "address": "0x00101000",
            "total_blocks": 3,
            "blocks": [
                {
                    "start": "0x00101000", "end": "0x00101010", "size": 16,
                    "instruction_count": 4,
                    "instructions": [
                        {"address": "0x00101000", "text": "PUSH RBP"},
                        {"address": "0x00101001", "text": "MOV RBP,RSP"},
                        {"address": "0x00101004", "text": "CMP EDI,0x1"},
                        {"address": "0x00101007", "text": "JLE 0x00101020"},
                    ],
                    "successors": ["0x00101010", "0x00101020"],
                    "predecessors": [],
                },
                {
                    "start": "0x00101010", "end": "0x0010101f", "size": 16,
                    "instruction_count": 3,
                    "instructions": [
                        {"address": "0x00101010", "text": "MOV EDI,0x00200000"},
                        {"address": "0x00101015", "text": "CALL printf"},
                        {"address": "0x0010101a", "text": "JMP 0x00101030"},
                    ],
                    "successors": [],
                    "predecessors": ["0x00101000"],
                },
                {
                    "start": "0x00101020", "end": "0x0010102f", "size": 16,
                    "instruction_count": 3,
                    "instructions": [
                        {"address": "0x00101020", "text": "MOV EDI,0x00200020"},
                        {"address": "0x00101025", "text": "CALL puts"},
                        {"address": "0x0010102a", "text": "JMP 0x00101030"},
                    ],
                    "successors": [],
                    "predecessors": ["0x00101000"],
                },
            ],
        }

    def get_call_graph(
        self,
        binary_name: str,
        name_or_addr: str,
        depth: int = 2,
        direction: str = "callees",
    ) -> dict[str, Any]:
        self._check_binary(binary_name)
        return {
            "root": name_or_addr,
            "root_address": "0x00101000",
            "direction": direction,
            "depth": depth,
            "nodes": [
                {"name": name_or_addr, "address": "0x00101000", "depth": 0},
                {"name": "init_payload", "address": "0x00101200", "depth": 1},
                {"name": "printf", "address": "0x00102000", "depth": 1},
            ],
            "edges": [
                {"from": name_or_addr, "to": "init_payload"},
                {"from": name_or_addr, "to": "printf"},
            ],
            "total_nodes": 3,
            "total_edges": 2,
        }

    def emulate_function(
        self,
        binary_name: str,
        name_or_addr: str,
        args: list[int] | None = None,
        max_steps: int = 10000,
    ) -> dict[str, Any]:
        self._check_binary(binary_name)
        session_key = f"{binary_name}:{name_or_addr}"
        simulated_steps = 42
        timed_out = max_steps < simulated_steps
        actual_steps = min(max_steps, simulated_steps)
        self._emulator_sessions[session_key] = {
            "pc": 0x00101078, "steps": actual_steps, "at_breakpoint": not timed_out,
        }
        return {
            "session_key": session_key,
            "function": name_or_addr,
            "entry_address": "0x00101000",
            "args_provided": args or [],
            "return_value": 0 if not args else sum(args),
            "steps_executed": actual_steps,
            "max_steps": max_steps,
            "hit_breakpoint": not timed_out,
            "timed_out": timed_out,
            "final_pc": "0xdeadbeef",
            "final_sp": "0x7fff0000",
        }

    def emulate_step(
        self,
        binary_name: str,
        name_or_addr: str,
        count: int = 1,
        read_registers: list[str] | None = None,
        read_memory: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        self._check_binary(binary_name)
        session_key = f"{binary_name}:{name_or_addr}"
        if session_key not in self._emulator_sessions:
            raise KeyError(f"No emulator session for '{session_key}'. Call emulate_function first.")
        actual_steps = max(0, count)
        registers = {r: "0x0" for r in (read_registers or [])}
        memory = [
            {"address": m["address"], "hex": "00" * m.get("size", 16)}
            for m in (read_memory or [])
        ]
        return {
            "session_key": session_key,
            "steps_executed": actual_steps,
            "hit_breakpoint": False,
            "current_pc": "0x00101004",
            "registers": registers,
            "memory": memory,
        }

    def destroy_emulator_session(self, binary_name: str, name_or_addr: str) -> None:
        self._check_binary(binary_name)
        session_key = f"{binary_name}:{name_or_addr}"
        self._emulator_sessions.pop(session_key, None)

    # ── Script mode mock methods ─────────────────────────────────

    _MOCK_API_CLASSES: dict[str, dict[str, Any]] = {
        "ghidra.program.model.listing.Function": {
            "class": "ghidra.program.model.listing.Function",
            "is_interface": True,
            "superclass": None,
            "interfaces": ["ghidra.program.model.listing.Namespace"],
            "methods": [
                {"name": "getName", "params": [], "returns": "String", "modifiers": "public abstract"},
                {"name": "setName", "params": ["String", "SourceType"], "returns": "void", "modifiers": "public abstract"},
                {"name": "getEntryPoint", "params": [], "returns": "Address", "modifiers": "public abstract"},
                {"name": "getParameters", "params": [], "returns": "Parameter[]", "modifiers": "public abstract"},
            ],
        },
        "ghidra.program.model.listing.Program": {
            "class": "ghidra.program.model.listing.Program",
            "is_interface": True,
            "superclass": None,
            "interfaces": [],
            "methods": [
                {"name": "getFunctionManager", "params": [], "returns": "FunctionManager", "modifiers": "public abstract"},
                {"name": "getListing", "params": [], "returns": "Listing", "modifiers": "public abstract"},
                {"name": "getMemory", "params": [], "returns": "Memory", "modifiers": "public abstract"},
            ],
        },
        "ghidra.program.model.symbol.SymbolTable": {
            "class": "ghidra.program.model.symbol.SymbolTable",
            "is_interface": True,
            "superclass": None,
            "interfaces": [],
            "methods": [
                {"name": "getSymbol", "params": ["String", "Namespace"], "returns": "Symbol", "modifiers": "public abstract"},
                {"name": "getGlobalSymbols", "params": ["String"], "returns": "List", "modifiers": "public abstract"},
            ],
        },
    }

    def search_api(self, query: str, package: str | None = None) -> list[dict[str, Any]]:
        query_lower = query.lower()
        results: list[dict[str, Any]] = []
        for fqcn, info in self._MOCK_API_CLASSES.items():
            if package and not fqcn.startswith(package):
                continue
            cls_name = fqcn.rsplit(".", 1)[-1]
            if query_lower in cls_name.lower() or query_lower in fqcn.lower():
                results.append(info)
                continue
            matching = [m for m in info["methods"] if query_lower in m["name"].lower()]
            if matching:
                results.append({**info, "methods": matching})
        return results

    def get_class_info(self, class_name: str) -> dict[str, Any]:
        # Try FQCN
        if class_name in self._MOCK_API_CLASSES:
            return self._MOCK_API_CLASSES[class_name]
        # Try short name
        for fqcn, info in self._MOCK_API_CLASSES.items():
            if fqcn.endswith(f".{class_name}"):
                return info
        raise KeyError(f"Class '{class_name}' not found. Use search_api to discover available classes.")

    def execute_script(self, code: str, binary_name: str | None = None) -> Any:
        import textwrap
        import traceback

        context: dict[str, Any] = {"bridge": self}
        if binary_name:
            self._check_binary(binary_name)
            context["program"] = self._programs[binary_name]
            context["currentProgram"] = context["program"]
        context["monitor"] = None

        wrapped = "def __script__():\n" + textwrap.indent(code, "    ") + "\n__result__ = __script__()"
        try:
            exec(wrapped, context)  # noqa: S102
        except Exception:
            return {"error": traceback.format_exc()}

        result = context.get("__result__")
        if result is None:
            return None
        if isinstance(result, (str, int, float, bool, list, dict)):
            return result
        return str(result)

    # ── Server mock methods ──────────────────────────────────────

    def connect_server(
        self, host: str, port: int = 13100, username: str = "ghidra", password: str | None = None
    ) -> dict[str, Any]:
        self._server_connected = True
        self._server_host = host
        return {
            "status": "connected", "host": host, "port": port,
            "username": username, "repositories": list(self._server_repos.keys()),
        }

    def disconnect_server(self) -> dict[str, Any]:
        if not self._server_connected:
            raise RuntimeError("Not connected to any Ghidra server.")
        host = self._server_host
        for name in list(self._server_files.keys()):
            self._programs.pop(name, None)
        self._server_files.clear()
        self._server_connected = False
        self._server_host = None
        return {"status": "disconnected", "host": host, "port": 13100}

    def list_repositories(self) -> list[dict[str, Any]]:
        if not self._server_connected:
            raise RuntimeError("Not connected to any Ghidra server. Use connect_server first.")
        return [{"name": n} for n in self._server_repos]

    def list_server_files(
        self, repository_name: str, folder_path: str = "/"
    ) -> dict[str, Any]:
        if not self._server_connected:
            raise RuntimeError("Not connected to any Ghidra server. Use connect_server first.")
        if repository_name not in self._server_repos:
            raise KeyError(f"Repository '{repository_name}' not found.")
        return {
            "repository": repository_name, "folder": folder_path,
            "subfolders": [], "files": self._server_repos[repository_name],
        }

    def open_from_server(
        self, repository_name: str, file_path: str, checkout: bool = True
    ) -> dict[str, Any]:
        if not self._server_connected:
            raise RuntimeError("Not connected to any Ghidra server. Use connect_server first.")
        binary_name = file_path.rsplit("/", 1)[-1]
        info = {
            "name": binary_name, "architecture": "x86", "address_size": 64,
            "endian": "little", "format": "PE", "base_address": "0x00400000",
            "entry_points": ["0x00401000"], "md5": "abc123", "sha256": "def456",
            "file_path": file_path, "num_functions": 10, "memory_size": 8192,
        }
        self._programs[binary_name] = info
        self._server_files[binary_name] = repository_name
        return {
            "source": "server", "repository": repository_name,
            "path": file_path, "checked_out": checkout, **info,
        }

    def checkin_file(
        self, binary_name: str, comment: str = "Changes from MCP analysis"
    ) -> dict[str, Any]:
        if not self._server_connected:
            raise RuntimeError("Not connected to any Ghidra server. Use connect_server first.")
        if binary_name not in self._server_files:
            raise KeyError(f"Binary '{binary_name}' was not opened from server.")
        return {"status": "checked_in", "binary_name": binary_name, "comment": comment}

    def close(self) -> None:
        self._programs.clear()
        self._emulator_sessions.clear()
        self._server_files.clear()
        self._server_connected = False


@pytest.fixture
def mock_bridge():
    """Provide a MockGhidraBridge instance."""
    return MockGhidraBridge()


@pytest.fixture
def mcp_server(mock_bridge):
    """Create an MCP server with a mocked GhidraBridge."""
    with patch("ghidra_mcp.server.GhidraBridge", return_value=mock_bridge):
        from ghidra_mcp.server import create_server

        server = create_server(project_dir="/tmp/test_projects", project_name="test")
        yield server, mock_bridge


@pytest.fixture
def mcp_server_code_mode(mock_bridge):
    """Create an MCP server in code mode with a mocked GhidraBridge."""
    with patch("ghidra_mcp.server.GhidraBridge", return_value=mock_bridge):
        from ghidra_mcp.server import create_server

        server = create_server(project_dir="/tmp/test_projects", project_name="test", mode="code")
        yield server, mock_bridge


@pytest.fixture
def mcp_server_script_mode(mock_bridge):
    """Create an MCP server in script mode with a mocked GhidraBridge."""
    with patch("ghidra_mcp.server.GhidraBridge", return_value=mock_bridge):
        from ghidra_mcp.server import create_server

        server = create_server(project_dir="/tmp/test_projects", project_name="test", mode="script")
        yield server, mock_bridge
