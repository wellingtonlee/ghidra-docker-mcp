"""Test fixtures and mocked GhidraBridge for unit tests."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

import pytest


class MockGhidraBridge:
    """Mock GhidraBridge that doesn't require Ghidra/JVM."""

    def __init__(self) -> None:
        self._programs: dict[str, dict[str, Any]] = {}

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

    def close(self) -> None:
        self._programs.clear()


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
