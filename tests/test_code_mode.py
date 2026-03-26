"""Tests for code mode (search + execute tools)."""

from __future__ import annotations

import base64

import pytest

from ghidra_mcp.tool_registry import TOOL_REGISTRY


class TestToolRegistry:
    """Verify the registry structure is correct."""

    def test_registry_has_all_tools(self):
        assert len(TOOL_REGISTRY) == 32

    def test_each_entry_has_required_keys(self):
        for name, info in TOOL_REGISTRY.items():
            assert "description" in info, f"{name} missing description"
            assert "parameters" in info, f"{name} missing parameters"
            assert isinstance(info["parameters"], list)

    def test_each_parameter_has_required_keys(self):
        for name, info in TOOL_REGISTRY.items():
            for param in info["parameters"]:
                assert "name" in param, f"{name}: param missing name"
                assert "type" in param, f"{name}: param missing type"
                assert "required" in param, f"{name}: param missing required"
                if not param["required"]:
                    assert "default" in param, f"{name}.{param['name']}: optional param missing default"

    def test_registry_tool_names_are_strings(self):
        for name in TOOL_REGISTRY:
            assert isinstance(name, str)
            assert len(name) > 0


class TestSearch:
    def test_search_no_query_returns_all(self, mcp_server_code_mode):
        from ghidra_mcp.tool_registry import TOOL_REGISTRY

        server, bridge = mcp_server_code_mode
        # Simulate search with no filter
        results = []
        for name, info in TOOL_REGISTRY.items():
            results.append({"tool": name, "description": info["description"], "parameters": info["parameters"]})
        assert len(results) == 32

    def test_search_with_query_filters(self, mcp_server_code_mode):
        server, bridge = mcp_server_code_mode
        query = "emulate"
        results = []
        for name, info in TOOL_REGISTRY.items():
            if query.lower() in name.lower() or query.lower() in info["description"].lower():
                results.append({"tool": name})
        assert len(results) == 3
        tool_names = {r["tool"] for r in results}
        assert tool_names == {"emulate_function", "emulate_step", "emulate_session_destroy"}

    def test_search_no_match_returns_empty(self, mcp_server_code_mode):
        server, bridge = mcp_server_code_mode
        query = "zzz_nonexistent_zzz"
        results = [
            name for name, info in TOOL_REGISTRY.items()
            if query.lower() in name.lower() or query.lower() in info["description"].lower()
        ]
        assert results == []

    def test_search_matches_description(self, mcp_server_code_mode):
        server, bridge = mcp_server_code_mode
        query = "Shannon"
        results = [
            name for name, info in TOOL_REGISTRY.items()
            if query.lower() in name.lower() or query.lower() in info["description"].lower()
        ]
        assert "get_entropy" in results


class TestDispatch:
    """Test the _dispatch function directly."""

    def test_dispatch_list_binaries(self, mcp_server_code_mode):
        server, bridge = mcp_server_code_mode
        bridge.import_binary("/tmp/test.elf")
        from ghidra_mcp.server import _dispatch
        result = _dispatch(bridge, "list_binaries", {})
        assert "test.elf" in result

    def test_dispatch_list_functions(self, mcp_server_code_mode):
        server, bridge = mcp_server_code_mode
        bridge.import_binary("/tmp/test.elf")
        from ghidra_mcp.server import _dispatch
        result = _dispatch(bridge, "list_functions", {"binary_name": "test.elf", "limit": 10})
        assert "functions" in result
        assert result["limit"] == 10

    def test_dispatch_decompile_function(self, mcp_server_code_mode):
        server, bridge = mcp_server_code_mode
        bridge.import_binary("/tmp/test.elf")
        from ghidra_mcp.server import _dispatch
        result = _dispatch(bridge, "decompile_function", {"binary_name": "test.elf", "name_or_addr": "main"})
        assert "decompiled_c" in result

    def test_dispatch_filter_param_renamed(self, mcp_server_code_mode):
        server, bridge = mcp_server_code_mode
        bridge.import_binary("/tmp/test.elf")
        from ghidra_mcp.server import _dispatch
        result = _dispatch(bridge, "list_functions", {"binary_name": "test.elf", "filter": "main"})
        assert result["total"] == 1

    def test_dispatch_list_imports_filter_renamed(self, mcp_server_code_mode):
        server, bridge = mcp_server_code_mode
        bridge.import_binary("/tmp/test.elf")
        from ghidra_mcp.server import _dispatch
        result = _dispatch(bridge, "list_imports", {"binary_name": "test.elf", "filter": "printf"})
        assert len(result) == 1

    def test_dispatch_list_exports_filter_renamed(self, mcp_server_code_mode):
        server, bridge = mcp_server_code_mode
        bridge.import_binary("/tmp/test.elf")
        from ghidra_mcp.server import _dispatch
        result = _dispatch(bridge, "list_exports", {"binary_name": "test.elf", "filter": "main"})
        assert len(result) == 1

    def test_dispatch_delete_binary_wraps_response(self, mcp_server_code_mode):
        server, bridge = mcp_server_code_mode
        bridge.import_binary("/tmp/test.elf")
        from ghidra_mcp.server import _dispatch
        result = _dispatch(bridge, "delete_binary", {"binary_name": "test.elf"})
        assert result == {"status": "deleted", "binary_name": "test.elf"}

    def test_dispatch_emulate_session_destroy_wraps_response(self, mcp_server_code_mode):
        server, bridge = mcp_server_code_mode
        bridge.import_binary("/tmp/test.elf")
        bridge.emulate_function("test.elf", "main")
        from ghidra_mcp.server import _dispatch
        result = _dispatch(bridge, "emulate_session_destroy", {"binary_name": "test.elf", "name_or_addr": "main"})
        assert result["status"] == "destroyed"
        assert result["function"] == "main"

    def test_dispatch_upload_binary(self, mcp_server_code_mode):
        server, bridge = mcp_server_code_mode
        data = base64.b64encode(b"\x7fELF").decode()
        from ghidra_mcp.server import _dispatch
        result = _dispatch(bridge, "upload_binary", {"filename": "test.elf", "data_base64": data})
        assert result["name"] == "test.elf"

    def test_dispatch_unknown_method_raises(self, mcp_server_code_mode):
        server, bridge = mcp_server_code_mode
        from ghidra_mcp.server import _dispatch
        with pytest.raises(ValueError, match="Unknown method"):
            _dispatch(bridge, "nonexistent_tool", {})

    def test_dispatch_missing_required_param(self, mcp_server_code_mode):
        server, bridge = mcp_server_code_mode
        from ghidra_mcp.server import _dispatch
        with pytest.raises(TypeError):
            _dispatch(bridge, "decompile_function", {})

    def test_dispatch_bridge_exception_propagates(self, mcp_server_code_mode):
        server, bridge = mcp_server_code_mode
        from ghidra_mcp.server import _dispatch
        with pytest.raises(KeyError):
            _dispatch(bridge, "list_functions", {"binary_name": "nonexistent.elf"})

    def test_dispatch_emulate_function(self, mcp_server_code_mode):
        server, bridge = mcp_server_code_mode
        bridge.import_binary("/tmp/test.elf")
        from ghidra_mcp.server import _dispatch
        result = _dispatch(bridge, "emulate_function", {
            "binary_name": "test.elf", "name_or_addr": "main", "args": [1, 2],
        })
        assert result["return_value"] == 3

    def test_dispatch_get_entropy(self, mcp_server_code_mode):
        server, bridge = mcp_server_code_mode
        bridge.import_binary("/tmp/test.elf")
        from ghidra_mcp.server import _dispatch
        result = _dispatch(bridge, "get_entropy", {"binary_name": "test.elf"})
        assert "overall_entropy" in result

    def test_dispatch_search_bytes(self, mcp_server_code_mode):
        server, bridge = mcp_server_code_mode
        bridge.import_binary("/tmp/test.elf")
        from ghidra_mcp.server import _dispatch
        result = _dispatch(bridge, "search_bytes", {"binary_name": "test.elf", "hex_pattern": "4D5A"})
        assert isinstance(result, list)

    def test_dispatch_rename_variable(self, mcp_server_code_mode):
        server, bridge = mcp_server_code_mode
        bridge.import_binary("/tmp/test.elf")
        from ghidra_mcp.server import _dispatch
        result = _dispatch(bridge, "rename_variable", {
            "binary_name": "test.elf",
            "function_name": "main",
            "old_name": "local_var",
            "new_name": "buffer_size",
        })
        assert result["old_name"] == "local_var"
        assert result["new_name"] == "buffer_size"
        assert result["function"] == "main"

    def test_dispatch_rename_label(self, mcp_server_code_mode):
        server, bridge = mcp_server_code_mode
        bridge.import_binary("/tmp/test.elf")
        from ghidra_mcp.server import _dispatch
        result = _dispatch(bridge, "rename_label", {
            "binary_name": "test.elf",
            "old_name": "LAB_00101000",
            "new_name": "loop_start",
        })
        assert result["old_name"] == "LAB_00101000"
        assert result["new_name"] == "loop_start"

    def test_dispatch_connect_server(self, mcp_server_code_mode):
        server, bridge = mcp_server_code_mode
        from ghidra_mcp.server import _dispatch
        result = _dispatch(bridge, "connect_server", {"host": "ghidra.example.com"})
        assert result["status"] == "connected"

    def test_dispatch_disconnect_server(self, mcp_server_code_mode):
        server, bridge = mcp_server_code_mode
        from ghidra_mcp.server import _dispatch
        _dispatch(bridge, "connect_server", {"host": "ghidra.example.com"})
        result = _dispatch(bridge, "disconnect_server", {})
        assert result["status"] == "disconnected"

    def test_dispatch_list_repositories(self, mcp_server_code_mode):
        server, bridge = mcp_server_code_mode
        from ghidra_mcp.server import _dispatch
        _dispatch(bridge, "connect_server", {"host": "ghidra.example.com"})
        result = _dispatch(bridge, "list_repositories", {})
        assert isinstance(result, list)

    def test_dispatch_list_server_files(self, mcp_server_code_mode):
        server, bridge = mcp_server_code_mode
        from ghidra_mcp.server import _dispatch
        _dispatch(bridge, "connect_server", {"host": "ghidra.example.com"})
        result = _dispatch(bridge, "list_server_files", {"repository_name": "test-repo"})
        assert result["repository"] == "test-repo"

    def test_dispatch_open_from_server(self, mcp_server_code_mode):
        server, bridge = mcp_server_code_mode
        from ghidra_mcp.server import _dispatch
        _dispatch(bridge, "connect_server", {"host": "ghidra.example.com"})
        result = _dispatch(bridge, "open_from_server", {
            "repository_name": "test-repo", "file_path": "/malware.exe",
        })
        assert result["name"] == "malware.exe"

    def test_dispatch_checkin_file(self, mcp_server_code_mode):
        server, bridge = mcp_server_code_mode
        from ghidra_mcp.server import _dispatch
        _dispatch(bridge, "connect_server", {"host": "ghidra.example.com"})
        _dispatch(bridge, "open_from_server", {
            "repository_name": "test-repo", "file_path": "/malware.exe",
        })
        result = _dispatch(bridge, "checkin_file", {"binary_name": "malware.exe"})
        assert result["status"] == "checked_in"


class TestFullModeUnchanged:
    """Ensure default full mode is unaffected by the refactor."""

    def test_full_mode_list_functions(self, mcp_server):
        server, bridge = mcp_server
        bridge.import_binary("/tmp/test.elf")
        result = bridge.list_functions("test.elf")
        assert result["total"] == 3

    def test_full_mode_decompile(self, mcp_server):
        server, bridge = mcp_server
        bridge.import_binary("/tmp/test.elf")
        result = bridge.decompile_function("test.elf", "main")
        assert "decompiled_c" in result

    def test_full_mode_emulate(self, mcp_server):
        server, bridge = mcp_server
        bridge.import_binary("/tmp/test.elf")
        result = bridge.emulate_function("test.elf", "main", args=[1, 2])
        assert result["return_value"] == 3
