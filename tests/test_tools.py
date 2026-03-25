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


class TestAdvancedAnalysisTools:
    def test_get_memory_bytes(self, mcp_server):
        server, bridge = mcp_server
        bridge.import_binary("/tmp/test.elf")
        result = bridge.get_memory_bytes("test.elf", "0x00100000", size=16)
        assert result["address"] == "0x00100000"
        assert result["size"] == 16
        assert result["hex"].startswith("4d5a")  # MZ header
        assert result["containing_section"] == ".text"

    def test_get_memory_bytes_size_cap(self, mcp_server):
        server, bridge = mcp_server
        bridge.import_binary("/tmp/test.elf")
        result = bridge.get_memory_bytes("test.elf", "0x00100000", size=9999)
        assert result["size"] == 4096

    def test_search_instructions(self, mcp_server):
        server, bridge = mcp_server
        bridge.import_binary("/tmp/test.elf")
        result = bridge.search_instructions("test.elf", "xor")
        assert result["total"] == 2
        assert len(result["matches"]) == 2
        assert result["matches"][0]["mnemonic"] == "XOR"

    def test_search_instructions_with_operand(self, mcp_server):
        server, bridge = mcp_server
        bridge.import_binary("/tmp/test.elf")
        result = bridge.search_instructions("test.elf", "xor", operand_pattern="EAX")
        assert result["total"] == 1
        assert result["matches"][0]["operands"] == "EAX,EAX"

    def test_search_instructions_no_match(self, mcp_server):
        server, bridge = mcp_server
        bridge.import_binary("/tmp/test.elf")
        result = bridge.search_instructions("test.elf", "syscall")
        assert result["total"] == 0
        assert result["matches"] == []

    def test_get_function_summary(self, mcp_server):
        server, bridge = mcp_server
        bridge.import_binary("/tmp/test.elf")
        result = bridge.get_function_summary("test.elf", "main")
        assert result["name"] == "main"
        assert result["size"] == 120
        assert len(result["parameters"]) == 2
        assert result["parameters"][0]["name"] == "argc"
        assert len(result["called_functions"]) == 3
        assert len(result["calling_functions"]) == 1
        assert len(result["referenced_strings"]) == 2
        assert result["cyclomatic_complexity"] == 4
        assert result["instruction_count"] == 35

    def test_get_function_summary_has_thunk_flag(self, mcp_server):
        server, bridge = mcp_server
        bridge.import_binary("/tmp/test.elf")
        result = bridge.get_function_summary("test.elf", "main")
        assert "is_thunk" in result
        assert result["is_thunk"] is False

    def test_get_basic_blocks(self, mcp_server):
        server, bridge = mcp_server
        bridge.import_binary("/tmp/test.elf")
        result = bridge.get_basic_blocks("test.elf", "main")
        assert result["function"] == "main"
        assert result["total_blocks"] == 3
        assert len(result["blocks"]) == 3
        # Entry block has two successors (branch)
        entry = result["blocks"][0]
        assert len(entry["successors"]) == 2
        assert entry["predecessors"] == []

    def test_get_basic_blocks_instructions(self, mcp_server):
        server, bridge = mcp_server
        bridge.import_binary("/tmp/test.elf")
        result = bridge.get_basic_blocks("test.elf", "main")
        for block in result["blocks"]:
            assert len(block["instructions"]) > 0
            assert "address" in block["instructions"][0]
            assert "text" in block["instructions"][0]

    def test_get_call_graph_callees(self, mcp_server):
        server, bridge = mcp_server
        bridge.import_binary("/tmp/test.elf")
        result = bridge.get_call_graph("test.elf", "main", depth=2, direction="callees")
        assert result["root"] == "main"
        assert result["direction"] == "callees"
        assert result["total_nodes"] == 3
        assert result["total_edges"] == 2
        names = {n["name"] for n in result["nodes"]}
        assert "main" in names
        assert "init_payload" in names
        assert "printf" in names

    def test_get_call_graph_depth(self, mcp_server):
        server, bridge = mcp_server
        bridge.import_binary("/tmp/test.elf")
        result = bridge.get_call_graph("test.elf", "main", depth=1)
        # All non-root nodes should be at depth 1
        for node in result["nodes"]:
            assert node["depth"] <= 1

    def test_get_call_graph_edges(self, mcp_server):
        server, bridge = mcp_server
        bridge.import_binary("/tmp/test.elf")
        result = bridge.get_call_graph("test.elf", "main")
        for edge in result["edges"]:
            assert "from" in edge
            assert "to" in edge
            assert edge["from"] == "main"


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

    def test_memory_bytes_binary_not_found(self, mcp_server):
        server, bridge = mcp_server
        with pytest.raises(KeyError):
            bridge.get_memory_bytes("nonexistent.elf", "0x00100000")

    def test_search_instructions_binary_not_found(self, mcp_server):
        server, bridge = mcp_server
        with pytest.raises(KeyError):
            bridge.search_instructions("nonexistent.elf", "xor")

    def test_function_summary_binary_not_found(self, mcp_server):
        server, bridge = mcp_server
        with pytest.raises(KeyError):
            bridge.get_function_summary("nonexistent.elf", "main")

    def test_basic_blocks_binary_not_found(self, mcp_server):
        server, bridge = mcp_server
        with pytest.raises(KeyError):
            bridge.get_basic_blocks("nonexistent.elf", "main")

    def test_call_graph_binary_not_found(self, mcp_server):
        server, bridge = mcp_server
        with pytest.raises(KeyError):
            bridge.get_call_graph("nonexistent.elf", "main")

    def test_emulate_function_binary_not_found(self, mcp_server):
        server, bridge = mcp_server
        with pytest.raises(KeyError):
            bridge.emulate_function("nonexistent.elf", "main")

    def test_emulate_step_binary_not_found(self, mcp_server):
        server, bridge = mcp_server
        with pytest.raises(KeyError):
            bridge.emulate_step("nonexistent.elf", "main")

    def test_emulate_session_destroy_binary_not_found(self, mcp_server):
        server, bridge = mcp_server
        with pytest.raises(KeyError):
            bridge.destroy_emulator_session("nonexistent.elf", "main")


class TestEmulationTools:
    def test_emulate_function_basic(self, mcp_server):
        server, bridge = mcp_server
        bridge.import_binary("/tmp/test.elf")
        result = bridge.emulate_function("test.elf", "main", args=[1, 2])
        assert result["function"] == "main"
        assert result["return_value"] == 3
        assert result["hit_breakpoint"] is True
        assert result["timed_out"] is False
        assert result["args_provided"] == [1, 2]

    def test_emulate_function_no_args(self, mcp_server):
        server, bridge = mcp_server
        bridge.import_binary("/tmp/test.elf")
        result = bridge.emulate_function("test.elf", "main")
        assert result["args_provided"] == []
        assert result["return_value"] == 0

    def test_emulate_function_custom_max_steps(self, mcp_server):
        server, bridge = mcp_server
        bridge.import_binary("/tmp/test.elf")
        result = bridge.emulate_function("test.elf", "main", max_steps=500)
        assert result["max_steps"] == 500

    def test_emulate_function_by_address(self, mcp_server):
        server, bridge = mcp_server
        bridge.import_binary("/tmp/test.elf")
        result = bridge.emulate_function("test.elf", "0x00101000", args=[42])
        assert result["session_key"] == "test.elf:0x00101000"
        assert result["return_value"] == 42

    def test_emulate_step_requires_session(self, mcp_server):
        server, bridge = mcp_server
        bridge.import_binary("/tmp/test.elf")
        with pytest.raises(KeyError):
            bridge.emulate_step("test.elf", "main")

    def test_emulate_step_after_function(self, mcp_server):
        server, bridge = mcp_server
        bridge.import_binary("/tmp/test.elf")
        bridge.emulate_function("test.elf", "main")
        result = bridge.emulate_step("test.elf", "main", count=5, read_registers=["RAX", "RBX"])
        assert result["steps_executed"] == 5
        assert "RAX" in result["registers"]
        assert "RBX" in result["registers"]

    def test_emulate_step_with_memory_read(self, mcp_server):
        server, bridge = mcp_server
        bridge.import_binary("/tmp/test.elf")
        bridge.emulate_function("test.elf", "main")
        result = bridge.emulate_step(
            "test.elf", "main",
            read_memory=[{"address": "0x00200000", "size": 8}],
        )
        assert len(result["memory"]) == 1
        assert result["memory"][0]["address"] == "0x00200000"
        assert result["memory"][0]["hex"] == "00" * 8

    def test_emulate_session_destroy(self, mcp_server):
        server, bridge = mcp_server
        bridge.import_binary("/tmp/test.elf")
        bridge.emulate_function("test.elf", "main")
        bridge.destroy_emulator_session("test.elf", "main")
        with pytest.raises(KeyError):
            bridge.emulate_step("test.elf", "main")

    def test_emulate_session_destroy_nonexistent_is_safe(self, mcp_server):
        server, bridge = mcp_server
        bridge.import_binary("/tmp/test.elf")
        bridge.destroy_emulator_session("test.elf", "main")  # no-op, should not raise

    # ── Session Lifecycle ─────────────────────────────────────────

    def test_emulate_function_session_reuse(self, mcp_server):
        server, bridge = mcp_server
        bridge.import_binary("/tmp/test.elf")
        r1 = bridge.emulate_function("test.elf", "main", args=[1])
        r2 = bridge.emulate_function("test.elf", "main", args=[2])
        assert r1["session_key"] == r2["session_key"]
        assert r2["return_value"] == 2

    def test_emulate_function_multiple_functions(self, mcp_server):
        server, bridge = mcp_server
        bridge.import_binary("/tmp/test.elf")
        r1 = bridge.emulate_function("test.elf", "main", args=[1])
        r2 = bridge.emulate_function("test.elf", "_start", args=[2])
        assert r1["session_key"] != r2["session_key"]
        assert r1["session_key"] == "test.elf:main"
        assert r2["session_key"] == "test.elf:_start"

    def test_emulate_function_multiple_binaries(self, mcp_server):
        server, bridge = mcp_server
        bridge.import_binary("/tmp/test.elf")
        bridge.import_binary("/tmp/other.elf")
        r1 = bridge.emulate_function("test.elf", "main", args=[1])
        r2 = bridge.emulate_function("other.elf", "main", args=[2])
        assert r1["session_key"] == "test.elf:main"
        assert r2["session_key"] == "other.elf:main"

    def test_delete_binary_cleans_emulator_sessions(self, mcp_server):
        server, bridge = mcp_server
        bridge.import_binary("/tmp/test.elf")
        bridge.emulate_function("test.elf", "main")
        bridge.delete_binary("test.elf")
        bridge.import_binary("/tmp/test.elf")
        with pytest.raises(KeyError):
            bridge.emulate_step("test.elf", "main")

    def test_close_clears_emulator_sessions(self, mcp_server):
        server, bridge = mcp_server
        bridge.import_binary("/tmp/test.elf")
        bridge.emulate_function("test.elf", "main")
        bridge.close()
        assert len(bridge._emulator_sessions) == 0

    def test_emulate_session_destroy_then_recreate(self, mcp_server):
        server, bridge = mcp_server
        bridge.import_binary("/tmp/test.elf")
        bridge.emulate_function("test.elf", "main", args=[1])
        bridge.destroy_emulator_session("test.elf", "main")
        result = bridge.emulate_function("test.elf", "main", args=[5])
        assert result["return_value"] == 5
        # Step should work on recreated session
        step_result = bridge.emulate_step("test.elf", "main")
        assert step_result["steps_executed"] == 1

    # ── Parameter Edge Cases ──────────────────────────────────────

    def test_emulate_function_empty_args_list(self, mcp_server):
        server, bridge = mcp_server
        bridge.import_binary("/tmp/test.elf")
        result = bridge.emulate_function("test.elf", "main", args=[])
        assert result["args_provided"] == []
        assert result["return_value"] == 0

    def test_emulate_function_single_arg(self, mcp_server):
        server, bridge = mcp_server
        bridge.import_binary("/tmp/test.elf")
        result = bridge.emulate_function("test.elf", "main", args=[42])
        assert result["return_value"] == 42

    def test_emulate_function_many_args(self, mcp_server):
        server, bridge = mcp_server
        bridge.import_binary("/tmp/test.elf")
        result = bridge.emulate_function("test.elf", "main", args=[1, 2, 3, 4, 5])
        assert result["return_value"] == 15
        assert result["args_provided"] == [1, 2, 3, 4, 5]

    def test_emulate_function_negative_args(self, mcp_server):
        server, bridge = mcp_server
        bridge.import_binary("/tmp/test.elf")
        result = bridge.emulate_function("test.elf", "main", args=[-1, -2])
        assert result["return_value"] == -3

    def test_emulate_function_large_arg_values(self, mcp_server):
        server, bridge = mcp_server
        bridge.import_binary("/tmp/test.elf")
        result = bridge.emulate_function("test.elf", "main", args=[0xFFFFFFFF, 1])
        assert result["return_value"] == 0xFFFFFFFF + 1

    # ── Step Parameter Edge Cases ─────────────────────────────────

    def test_emulate_step_count_zero(self, mcp_server):
        server, bridge = mcp_server
        bridge.import_binary("/tmp/test.elf")
        bridge.emulate_function("test.elf", "main")
        result = bridge.emulate_step("test.elf", "main", count=0)
        assert result["steps_executed"] == 0

    def test_emulate_step_no_registers_no_memory(self, mcp_server):
        server, bridge = mcp_server
        bridge.import_binary("/tmp/test.elf")
        bridge.emulate_function("test.elf", "main")
        result = bridge.emulate_step("test.elf", "main")
        assert result["registers"] == {}
        assert result["memory"] == []

    def test_emulate_step_multiple_memory_regions(self, mcp_server):
        server, bridge = mcp_server
        bridge.import_binary("/tmp/test.elf")
        bridge.emulate_function("test.elf", "main")
        result = bridge.emulate_step(
            "test.elf", "main",
            read_memory=[
                {"address": "0x00200000", "size": 4},
                {"address": "0x00300000", "size": 8},
                {"address": "0x00400000", "size": 16},
            ],
        )
        assert len(result["memory"]) == 3
        assert result["memory"][0]["hex"] == "00" * 4
        assert result["memory"][1]["hex"] == "00" * 8
        assert result["memory"][2]["hex"] == "00" * 16

    # ── Error Handling ────────────────────────────────────────────

    def test_emulate_session_destroy_after_binary_delete(self, mcp_server):
        server, bridge = mcp_server
        bridge.import_binary("/tmp/test.elf")
        bridge.emulate_function("test.elf", "main")
        bridge.delete_binary("test.elf")
        with pytest.raises(KeyError):
            bridge.destroy_emulator_session("test.elf", "main")

    def test_emulate_step_after_binary_delete(self, mcp_server):
        server, bridge = mcp_server
        bridge.import_binary("/tmp/test.elf")
        bridge.emulate_function("test.elf", "main")
        bridge.delete_binary("test.elf")
        with pytest.raises(KeyError):
            bridge.emulate_step("test.elf", "main")

    # ── Response Structure Validation ─────────────────────────────

    def test_emulate_function_response_has_all_keys(self, mcp_server):
        server, bridge = mcp_server
        bridge.import_binary("/tmp/test.elf")
        result = bridge.emulate_function("test.elf", "main", args=[1])
        expected_keys = {
            "session_key", "function", "entry_address", "args_provided",
            "return_value", "steps_executed", "max_steps", "hit_breakpoint",
            "timed_out", "final_pc", "final_sp",
        }
        assert set(result.keys()) == expected_keys

    def test_emulate_step_response_has_all_keys(self, mcp_server):
        server, bridge = mcp_server
        bridge.import_binary("/tmp/test.elf")
        bridge.emulate_function("test.elf", "main")
        result = bridge.emulate_step("test.elf", "main", count=1, read_registers=["RAX"])
        expected_keys = {
            "session_key", "steps_executed", "hit_breakpoint",
            "current_pc", "registers", "memory",
        }
        assert set(result.keys()) == expected_keys
