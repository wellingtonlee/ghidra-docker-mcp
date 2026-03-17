"""Unit tests for GhidraBridge helper methods (no JVM needed)."""

from ghidra_mcp.ghidra_bridge import GhidraBridge, SUSPICIOUS_API_CATEGORIES


class TestShannonEntropy:
    def test_empty_data(self):
        assert GhidraBridge._shannon_entropy(b"") == 0.0

    def test_uniform_data(self):
        # All zeros = 0 entropy
        data = bytes(256)
        assert GhidraBridge._shannon_entropy(data) == 0.0

    def test_single_byte_value(self):
        data = b"\x41" * 100
        assert GhidraBridge._shannon_entropy(data) == 0.0

    def test_two_equal_values(self):
        data = b"\x00" * 50 + b"\xff" * 50
        entropy = GhidraBridge._shannon_entropy(data)
        assert abs(entropy - 1.0) < 0.01  # Should be ~1.0 bit

    def test_random_like_data(self):
        # 256 unique bytes = max entropy of 8.0
        data = bytes(range(256))
        entropy = GhidraBridge._shannon_entropy(data)
        assert abs(entropy - 8.0) < 0.01

    def test_high_entropy_detection(self):
        # Simulated packed/encrypted data
        import os
        data = os.urandom(1024)
        entropy = GhidraBridge._shannon_entropy(data)
        assert entropy > 7.0


class TestSuspiciousApiCategories:
    def test_categories_exist(self):
        expected = {
            "process_injection", "persistence", "crypto", "network",
            "anti_debug", "dynamic_loading", "process_manipulation", "file_system",
        }
        assert set(SUSPICIOUS_API_CATEGORIES.keys()) == expected

    def test_all_categories_non_empty(self):
        for category, apis in SUSPICIOUS_API_CATEGORIES.items():
            assert len(apis) > 0, f"Category '{category}' is empty"

    def test_no_duplicate_apis_within_category(self):
        for category, apis in SUSPICIOUS_API_CATEGORIES.items():
            assert len(apis) == len(set(apis)), f"Duplicates in '{category}'"
