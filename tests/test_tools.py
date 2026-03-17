"""Tests for MCP tools using mocked GhidraBridge."""

from __future__ import annotations

import pytest


class TestProjectTools:
    def test_list_binaries_empty(self, mcp_server):
        server, bridge = mcp_server
        result = bridge.list_binaries()
        assert result == []

    def test_import_binary(self, mcp_server):
        server, bridge = mcp_server
        result = bridge.import_binary("/tmp/test.elf")
        assert result["name"] == "test.elf"
        assert result["architecture"] == "x86"
        assert "test.elf" in bridge.list_binaries()

    def test_delete_binary(self, mcp_server):
        server, bridge = mcp_server
        bridge.import_binary("/tmp/test.elf")
        bridge.delete_binary("test.elf")
        assert "test.elf" not in bridge.list_binaries()

    def test_delete_nonexistent_binary(self, mcp_server):
        server, bridge = mcp_server
        with pytest.raises(KeyError):
            bridge.delete_binary("nonexistent.elf")


class TestFunctionTools:
    def test_list_functions(self, mcp_server):
        server, bridge = mcp_server
        bridge.import_binary("/tmp/test.elf")
        result = bridge.list_functions("test.elf")
        assert result["total"] == 3
        assert len(result["functions"]) == 3

    def test_list_functions_with_filter(self, mcp_server):
        server, bridge = mcp_server
        bridge.import_binary("/tmp/test.elf")
        result = bridge.list_functions("test.elf", filter_name="main")
        assert result["total"] == 1
        assert result["functions"][0]["name"] == "main"

    def test_list_functions_pagination(self, mcp_server):
        server, bridge = mcp_server
        bridge.import_binary("/tmp/test.elf")
        result = bridge.list_functions("test.elf", offset=1, limit=1)
        assert len(result["functions"]) == 1
        assert result["offset"] == 1

    def test_decompile_function(self, mcp_server):
        server, bridge = mcp_server
        bridge.import_binary("/tmp/test.elf")
        result = bridge.decompile_function("test.elf", "main")
        assert "decompiled_c" in result
        assert "main" in result["decompiled_c"]

    def test_rename_function(self, mcp_server):
        server, bridge = mcp_server
        bridge.import_binary("/tmp/test.elf")
        result = bridge.rename_function("test.elf", "main", "entry_main")
        assert result["old_name"] == "main"
        assert result["new_name"] == "entry_main"


class TestStringTools:
    def test_list_strings(self, mcp_server):
        server, bridge = mcp_server
        bridge.import_binary("/tmp/test.elf")
        result = bridge.list_strings("test.elf")
        assert result["total"] > 0
        assert all("value" in s for s in result["strings"])

    def test_search_strings(self, mcp_server):
        server, bridge = mcp_server
        bridge.import_binary("/tmp/test.elf")
        result = bridge.search_strings("test.elf", "Hello")
        assert len(result) == 1
        assert "Hello" in result[0]["value"]


class TestImportExportTools:
    def test_list_imports(self, mcp_server):
        server, bridge = mcp_server
        bridge.import_binary("/tmp/test.elf")
        result = bridge.list_imports("test.elf")
        assert len(result) == 2
        assert any(i["name"] == "printf" for i in result)

    def test_list_imports_with_filter(self, mcp_server):
        server, bridge = mcp_server
        bridge.import_binary("/tmp/test.elf")
        result = bridge.list_imports("test.elf", filter_name="print")
        assert len(result) == 1

    def test_list_exports(self, mcp_server):
        server, bridge = mcp_server
        bridge.import_binary("/tmp/test.elf")
        result = bridge.list_exports("test.elf")
        assert len(result) == 1
        assert result[0]["name"] == "main"


class TestXrefTools:
    def test_get_xrefs_both(self, mcp_server):
        server, bridge = mcp_server
        bridge.import_binary("/tmp/test.elf")
        result = bridge.get_xrefs("test.elf", "0x00101000", direction="both")
        assert "references_to" in result
        assert "references_from" in result

    def test_get_xrefs_to_only(self, mcp_server):
        server, bridge = mcp_server
        bridge.import_binary("/tmp/test.elf")
        result = bridge.get_xrefs("test.elf", "0x00101000", direction="to")
        assert "references_to" in result
        assert "references_from" not in result


class TestSearchTools:
    def test_search_bytes(self, mcp_server):
        server, bridge = mcp_server
        bridge.import_binary("/tmp/test.elf")
        result = bridge.search_bytes("test.elf", "4D5A")
        assert len(result) > 0
        assert "address" in result[0]


class TestMalwareTools:
    def test_get_entropy(self, mcp_server):
        server, bridge = mcp_server
        bridge.import_binary("/tmp/test.elf")
        result = bridge.get_entropy("test.elf")
        assert "overall_entropy" in result
        assert "packed_likely" in result
        assert "sections" in result

    def test_detect_suspicious_apis(self, mcp_server):
        server, bridge = mcp_server
        bridge.import_binary("/tmp/test.elf")
        result = bridge.detect_suspicious_apis("test.elf")
        assert "total_suspicious" in result
        assert "categories" in result

    def test_get_sections(self, mcp_server):
        server, bridge = mcp_server
        bridge.import_binary("/tmp/test.elf")
        result = bridge.get_sections("test.elf")
        assert len(result) == 2
        assert result[0]["name"] == ".text"
        assert "permissions" in result[0]
        assert "entropy" in result[0]
        assert "anomalies" in result[0]


class TestBinaryNotFound:
    def test_functions_binary_not_found(self, mcp_server):
        server, bridge = mcp_server
        with pytest.raises(KeyError):
            bridge.list_functions("nonexistent.elf")

    def test_strings_binary_not_found(self, mcp_server):
        server, bridge = mcp_server
        with pytest.raises(KeyError):
            bridge.list_strings("nonexistent.elf")

    def test_entropy_binary_not_found(self, mcp_server):
        server, bridge = mcp_server
        with pytest.raises(KeyError):
            bridge.get_entropy("nonexistent.elf")
