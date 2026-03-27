"""Tests for GhidraBridge._validate_environment() pre-flight checks."""

from __future__ import annotations

import importlib
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from ghidra_mcp.ghidra_bridge import GhidraBridge


def _make_bridge() -> GhidraBridge:
    """Create a GhidraBridge without running __init__ (avoids side effects)."""
    bridge = object.__new__(GhidraBridge)
    bridge.project_dir = Path("/tmp/test_project")
    bridge.project_name = "test"
    bridge._project = None
    bridge._programs = {}
    bridge._decompilers = {}
    bridge._emulators = {}
    bridge._flat_api = None
    bridge._started = False
    bridge._server = None
    bridge._server_host = None
    bridge._server_port = None
    bridge._server_repos = {}
    bridge._server_files = {}
    bridge._server_project = None
    bridge._analysis_timeout = 300
    bridge._vm_args = ["-Xmx2g"]
    return bridge


def _java_version_output(version: str) -> MagicMock:
    """Create a mock subprocess result with a java -version stderr output."""
    return MagicMock(stderr=f'openjdk version "{version}" 2024-01-16\n')


def _make_ghidra_dir(tmp: str) -> str:
    """Create a fake Ghidra install directory with a ghidraRun marker file."""
    ghidra_dir = os.path.join(tmp, "ghidra")
    os.makedirs(ghidra_dir, exist_ok=True)
    marker = "ghidraRun.bat" if sys.platform == "win32" else "ghidraRun"
    Path(os.path.join(ghidra_dir, marker)).touch()
    return ghidra_dir


def _mock_pyghidra_import(name: str, *args: object, **kwargs: object) -> object:
    """Selective importlib.import_module that allows pyghidra to succeed."""
    if name == "pyghidra":
        return MagicMock()
    return importlib.import_module(name, *args, **kwargs)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Java checks
# ---------------------------------------------------------------------------


class TestJavaValidation:
    """Tests for Java version detection."""

    def test_java_not_found_exits(self) -> None:
        bridge = _make_bridge()
        with patch.dict("os.environ", {}, clear=True):
            with patch("subprocess.run", side_effect=FileNotFoundError("java not found")):
                with pytest.raises(SystemExit) as exc_info:
                    bridge._validate_environment()
                assert exc_info.value.code == 1

    def test_java_too_old_exits(self) -> None:
        bridge = _make_bridge()
        with patch.dict("os.environ", {}, clear=True):
            with patch("subprocess.run", return_value=_java_version_output("17.0.1")):
                with pytest.raises(SystemExit) as exc_info:
                    bridge._validate_environment()
                assert exc_info.value.code == 1

    def test_java_21_passes(self) -> None:
        bridge = _make_bridge()
        with tempfile.TemporaryDirectory() as tmp:
            ghidra_dir = _make_ghidra_dir(tmp)
            with patch.dict("os.environ", {"GHIDRA_INSTALL_DIR": ghidra_dir}, clear=True):
                with patch("subprocess.run", return_value=_java_version_output("21.0.2")):
                    with patch("importlib.import_module", side_effect=_mock_pyghidra_import):
                        bridge._validate_environment()
        # Should not raise

    def test_java_home_preferred(self) -> None:
        bridge = _make_bridge()
        mock_run = MagicMock(return_value=_java_version_output("21.0.2"))
        with tempfile.TemporaryDirectory() as tmp:
            ghidra_dir = _make_ghidra_dir(tmp)
            env = {
                "JAVA_HOME": "/usr/lib/jvm/java-21",
                "GHIDRA_INSTALL_DIR": ghidra_dir,
            }
            with patch.dict("os.environ", env, clear=True):
                with patch("subprocess.run", mock_run):
                    with patch("importlib.import_module", side_effect=_mock_pyghidra_import):
                        bridge._validate_environment()
        # Verify the java binary used was from JAVA_HOME
        call_args = mock_run.call_args
        java_bin = call_args[0][0][0]
        assert str(Path("/usr/lib/jvm/java-21") / "bin" / "java") == java_bin

    def test_java_22_passes(self) -> None:
        bridge = _make_bridge()
        with tempfile.TemporaryDirectory() as tmp:
            ghidra_dir = _make_ghidra_dir(tmp)
            with patch.dict("os.environ", {"GHIDRA_INSTALL_DIR": ghidra_dir}, clear=True):
                with patch("subprocess.run", return_value=_java_version_output("22.0.1")):
                    with patch("importlib.import_module", side_effect=_mock_pyghidra_import):
                        bridge._validate_environment()


# ---------------------------------------------------------------------------
# GHIDRA_INSTALL_DIR checks
# ---------------------------------------------------------------------------


class TestGhidraInstallDirValidation:
    """Tests for GHIDRA_INSTALL_DIR validation."""

    def test_ghidra_install_dir_missing_exits(self) -> None:
        bridge = _make_bridge()
        with patch.dict("os.environ", {}, clear=True):
            with patch("subprocess.run", return_value=_java_version_output("21.0.2")):
                with pytest.raises(SystemExit) as exc_info:
                    bridge._validate_environment()
                assert exc_info.value.code == 1

    def test_ghidra_install_dir_invalid_path_exits(self) -> None:
        bridge = _make_bridge()
        env = {"GHIDRA_INSTALL_DIR": "/nonexistent/ghidra/path/that/does/not/exist"}
        with patch.dict("os.environ", env, clear=True):
            with patch("subprocess.run", return_value=_java_version_output("21.0.2")):
                with pytest.raises(SystemExit) as exc_info:
                    bridge._validate_environment()
                assert exc_info.value.code == 1

    def test_ghidra_install_dir_missing_marker_exits(self) -> None:
        """Directory exists but ghidraRun marker file is missing."""
        bridge = _make_bridge()
        with tempfile.TemporaryDirectory() as tmp:
            # Directory exists but has no ghidraRun marker
            env = {"GHIDRA_INSTALL_DIR": tmp}
            with patch.dict("os.environ", env, clear=True):
                with patch("subprocess.run", return_value=_java_version_output("21.0.2")):
                    with pytest.raises(SystemExit) as exc_info:
                        bridge._validate_environment()
                    assert exc_info.value.code == 1


# ---------------------------------------------------------------------------
# PyGhidra import check
# ---------------------------------------------------------------------------


class TestPyGhidraValidation:
    """Tests for PyGhidra import check."""

    def test_pyghidra_not_installed_exits(self) -> None:
        bridge = _make_bridge()

        def fail_pyghidra(name: str, *args: object, **kwargs: object) -> object:
            if name == "pyghidra":
                raise ImportError("No module named 'pyghidra'")
            return importlib.import_module(name, *args, **kwargs)  # type: ignore[arg-type]

        with tempfile.TemporaryDirectory() as tmp:
            ghidra_dir = _make_ghidra_dir(tmp)
            with patch.dict("os.environ", {"GHIDRA_INSTALL_DIR": ghidra_dir}, clear=True):
                with patch("subprocess.run", return_value=_java_version_output("21.0.2")):
                    with patch("importlib.import_module", side_effect=fail_pyghidra):
                        with pytest.raises(SystemExit) as exc_info:
                            bridge._validate_environment()
                        assert exc_info.value.code == 1


# ---------------------------------------------------------------------------
# Decompiler binary check (non-fatal)
# ---------------------------------------------------------------------------


class TestDecompilerValidation:
    """Tests for decompiler binary check (non-fatal warning)."""

    def test_missing_decompiler_does_not_exit(self) -> None:
        """Missing decompiler binary should warn, not exit."""
        bridge = _make_bridge()
        with tempfile.TemporaryDirectory() as tmp:
            ghidra_dir = _make_ghidra_dir(tmp)
            # No decompiler binary created — just the marker file
            with patch.dict("os.environ", {"GHIDRA_INSTALL_DIR": ghidra_dir}, clear=True):
                with patch("subprocess.run", return_value=_java_version_output("21.0.2")):
                    with patch("importlib.import_module", side_effect=_mock_pyghidra_import):
                        bridge._validate_environment()  # should NOT raise
