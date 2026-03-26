"""Tests for script mode (search_api + get_class_info + execute_script tools)."""

from __future__ import annotations

import pytest


class TestSearchApi:
    def test_search_returns_matching_class(self, mcp_server_script_mode):
        server, bridge = mcp_server_script_mode
        results = bridge.search_api("Function")
        assert len(results) > 0
        class_names = [r["class"] for r in results]
        assert "ghidra.program.model.listing.Function" in class_names

    def test_search_by_method_name(self, mcp_server_script_mode):
        server, bridge = mcp_server_script_mode
        results = bridge.search_api("getName")
        assert len(results) > 0
        # Should return classes that have a getName method
        for r in results:
            method_names = [m["name"] for m in r["methods"]]
            assert "getName" in method_names

    def test_search_with_package_filter(self, mcp_server_script_mode):
        server, bridge = mcp_server_script_mode
        results = bridge.search_api("Function", package="ghidra.program.model.listing")
        assert len(results) > 0
        for r in results:
            assert r["class"].startswith("ghidra.program.model.listing")

    def test_search_no_match_returns_empty(self, mcp_server_script_mode):
        server, bridge = mcp_server_script_mode
        results = bridge.search_api("xyznonexistent")
        assert results == []

    def test_search_case_insensitive(self, mcp_server_script_mode):
        server, bridge = mcp_server_script_mode
        results_lower = bridge.search_api("function")
        results_upper = bridge.search_api("FUNCTION")
        assert len(results_lower) == len(results_upper)


class TestGetClassInfo:
    def test_get_known_class_fqcn(self, mcp_server_script_mode):
        server, bridge = mcp_server_script_mode
        info = bridge.get_class_info("ghidra.program.model.listing.Function")
        assert info["class"] == "ghidra.program.model.listing.Function"
        assert len(info["methods"]) > 0

    def test_get_known_class_short_name(self, mcp_server_script_mode):
        server, bridge = mcp_server_script_mode
        info = bridge.get_class_info("Function")
        assert "Function" in info["class"]

    def test_get_unknown_class_raises(self, mcp_server_script_mode):
        server, bridge = mcp_server_script_mode
        with pytest.raises(KeyError):
            bridge.get_class_info("NonExistentClass12345")

    def test_class_info_has_required_keys(self, mcp_server_script_mode):
        server, bridge = mcp_server_script_mode
        info = bridge.get_class_info("Function")
        assert "class" in info
        assert "is_interface" in info
        assert "methods" in info
        assert "interfaces" in info
        assert "superclass" in info

    def test_method_entries_have_required_keys(self, mcp_server_script_mode):
        server, bridge = mcp_server_script_mode
        info = bridge.get_class_info("Function")
        for method in info["methods"]:
            assert "name" in method
            assert "params" in method
            assert "returns" in method
            assert "modifiers" in method


class TestExecuteScript:
    def test_simple_return(self, mcp_server_script_mode):
        server, bridge = mcp_server_script_mode
        result = bridge.execute_script("return 42")
        assert result == 42

    def test_string_return(self, mcp_server_script_mode):
        server, bridge = mcp_server_script_mode
        result = bridge.execute_script('return "hello"')
        assert result == "hello"

    def test_list_return(self, mcp_server_script_mode):
        server, bridge = mcp_server_script_mode
        result = bridge.execute_script("return [1, 2, 3]")
        assert result == [1, 2, 3]

    def test_dict_return(self, mcp_server_script_mode):
        server, bridge = mcp_server_script_mode
        result = bridge.execute_script('return {"key": "value"}')
        assert result == {"key": "value"}

    def test_none_return(self, mcp_server_script_mode):
        server, bridge = mcp_server_script_mode
        result = bridge.execute_script("x = 1")
        assert result is None

    def test_access_bridge(self, mcp_server_script_mode):
        server, bridge = mcp_server_script_mode
        bridge.import_binary("/tmp/test.elf")
        result = bridge.execute_script("return bridge.list_binaries()")
        assert "test.elf" in result

    def test_access_program(self, mcp_server_script_mode):
        server, bridge = mcp_server_script_mode
        bridge.import_binary("/tmp/test.elf")
        result = bridge.execute_script(
            "return program is not None",
            binary_name="test.elf",
        )
        assert result is True

    def test_currentProgram_alias(self, mcp_server_script_mode):
        server, bridge = mcp_server_script_mode
        bridge.import_binary("/tmp/test.elf")
        result = bridge.execute_script(
            "return currentProgram is program",
            binary_name="test.elf",
        )
        assert result is True

    def test_no_binary_no_program(self, mcp_server_script_mode):
        server, bridge = mcp_server_script_mode
        result = bridge.execute_script('return "program" not in dir()')
        assert result is True

    def test_syntax_error_returns_error(self, mcp_server_script_mode):
        server, bridge = mcp_server_script_mode
        result = bridge.execute_script("def incomplete(")
        assert isinstance(result, dict)
        assert "error" in result
        assert "SyntaxError" in result["error"]

    def test_runtime_error_returns_error(self, mcp_server_script_mode):
        server, bridge = mcp_server_script_mode
        result = bridge.execute_script("return 1 / 0")
        assert isinstance(result, dict)
        assert "error" in result
        assert "ZeroDivisionError" in result["error"]

    def test_invalid_binary_raises(self, mcp_server_script_mode):
        server, bridge = mcp_server_script_mode
        with pytest.raises(KeyError):
            bridge.execute_script("return 1", binary_name="nonexistent.elf")

    def test_multiline_code(self, mcp_server_script_mode):
        server, bridge = mcp_server_script_mode
        code = """
total = 0
for i in range(10):
    total += i
return total
"""
        result = bridge.execute_script(code)
        assert result == 45


class TestScriptModeBinaryManagement:
    def test_import_binary(self, mcp_server_script_mode):
        server, bridge = mcp_server_script_mode
        result = bridge.import_binary("/tmp/test.elf")
        assert result["name"] == "test.elf"

    def test_list_binaries(self, mcp_server_script_mode):
        server, bridge = mcp_server_script_mode
        bridge.import_binary("/tmp/test.elf")
        result = bridge.list_binaries()
        assert "test.elf" in result

    def test_delete_binary(self, mcp_server_script_mode):
        server, bridge = mcp_server_script_mode
        bridge.import_binary("/tmp/test.elf")
        bridge.delete_binary("test.elf")
        assert "test.elf" not in bridge.list_binaries()


class TestSerializeResult:
    def test_none(self):
        from ghidra_mcp.ghidra_bridge import _serialize_result
        assert _serialize_result(None) is None

    def test_primitives(self):
        from ghidra_mcp.ghidra_bridge import _serialize_result
        assert _serialize_result("hello") == "hello"
        assert _serialize_result(42) == 42
        assert _serialize_result(3.14) == 3.14
        assert _serialize_result(True) is True

    def test_list(self):
        from ghidra_mcp.ghidra_bridge import _serialize_result
        assert _serialize_result([1, "two", 3.0]) == [1, "two", 3.0]

    def test_dict(self):
        from ghidra_mcp.ghidra_bridge import _serialize_result
        assert _serialize_result({"a": 1, "b": [2]}) == {"a": 1, "b": [2]}

    def test_unknown_object_becomes_str(self):
        from ghidra_mcp.ghidra_bridge import _serialize_result

        class Custom:
            def __str__(self):
                return "custom_object"

        result = _serialize_result(Custom())
        assert result == "custom_object"
