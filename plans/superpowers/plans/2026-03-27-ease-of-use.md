# Ease-of-Use Improvements Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make ghidra-mcp easier to set up and run: validate dependencies on startup, support SSE transport for persistent servers, and provide one-command installer scripts.

**Architecture:** Three independent features implemented sequentially. Feature 1 adds a `_validate_environment()` method to `GhidraBridge.start()`. Feature 2 adds `--transport`/`--port`/`--host` CLI flags and passes them through to FastMCP (which already supports SSE natively). Feature 3 adds bash and PowerShell installer scripts.

**Tech Stack:** Python 3.11+, FastMCP (mcp>=1.9), subprocess for Java version checks, uvicorn for SSE transport.

---

## File Structure

| File | Action | Responsibility |
|------|--------|----------------|
| `src/ghidra_mcp/ghidra_bridge.py` | Modify | Add `_validate_environment()`, call from `start()` |
| `tests/test_validation.py` | Create | Tests for `_validate_environment()` |
| `src/ghidra_mcp/__main__.py` | Modify | Add `--transport`, `--port`, `--host` CLI flags |
| `src/ghidra_mcp/server.py` | Modify | Pass `host`/`port` through `create_server()` to `FastMCP()` |
| `tests/test_cli.py` | Create | Tests for CLI argument parsing |
| `pyproject.toml` | Modify | Add `[sse]` optional dependency |
| `scripts/install.sh` | Create | Bash installer for Linux/macOS |
| `scripts/install.ps1` | Create | PowerShell installer for Windows |
| `README.md` | Modify | Add SSE docs, installer script references |
| `CHANGELOG.md` | Modify | Add entries for all three features |

---

### Task 1: Write tests for startup validation

**Files:**
- Create: `tests/test_validation.py`

- [ ] **Step 1: Create test file with Java validation tests**

```python
"""Tests for startup environment validation."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from ghidra_mcp.ghidra_bridge import GhidraBridge


class TestValidateEnvironment:
    """Tests for GhidraBridge._validate_environment()."""

    def _make_bridge(self) -> GhidraBridge:
        """Create a bridge instance without starting it."""
        with patch.object(GhidraBridge, "__init__", lambda self, *a, **kw: None):
            bridge = GhidraBridge.__new__(GhidraBridge)
            bridge.project_dir = Path("./test")
            bridge.project_name = "test"
            bridge._started = False
            bridge._project = None
            bridge._programs = {}
            bridge._decompilers = {}
            bridge._emulators = {}
            bridge._flat_api = None
            bridge._server = None
            bridge._server_host = None
            bridge._server_port = None
            bridge._server_repos = {}
            bridge._server_files = {}
            bridge._server_project = None
            bridge._analysis_timeout = 300
            bridge._vm_args = ["-Xmx2g"]
            return bridge

    def test_java_not_found_exits(self):
        bridge = self._make_bridge()
        with patch("subprocess.run", side_effect=FileNotFoundError("java not found")), \
             patch.dict(os.environ, {}, clear=True), \
             pytest.raises(SystemExit) as exc_info:
            bridge._validate_environment()
        assert exc_info.value.code == 1

    def test_java_old_version_exits(self):
        bridge = self._make_bridge()
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stderr = 'openjdk version "17.0.1" 2021-10-19'
        with patch("subprocess.run", return_value=mock_result), \
             patch.dict(os.environ, {"GHIDRA_INSTALL_DIR": "/fake"}, clear=True), \
             pytest.raises(SystemExit) as exc_info:
            bridge._validate_environment()
        assert exc_info.value.code == 1

    def test_java_21_passes(self):
        bridge = self._make_bridge()
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stderr = 'openjdk version "21.0.2" 2024-01-16'
        with patch("subprocess.run", return_value=mock_result), \
             patch.dict(os.environ, {"GHIDRA_INSTALL_DIR": "/fake"}, clear=True), \
             patch("pathlib.Path.is_dir", return_value=True), \
             patch("pathlib.Path.exists", return_value=True), \
             patch("importlib.import_module", return_value=MagicMock()):
            bridge._validate_environment()  # should not raise

    def test_ghidra_install_dir_missing_exits(self):
        bridge = self._make_bridge()
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stderr = 'openjdk version "21.0.2" 2024-01-16'
        with patch("subprocess.run", return_value=mock_result), \
             patch.dict(os.environ, {}, clear=True), \
             pytest.raises(SystemExit) as exc_info:
            bridge._validate_environment()
        assert exc_info.value.code == 1

    def test_ghidra_install_dir_invalid_path_exits(self):
        bridge = self._make_bridge()
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stderr = 'openjdk version "21.0.2" 2024-01-16'
        with patch("subprocess.run", return_value=mock_result), \
             patch.dict(os.environ, {"GHIDRA_INSTALL_DIR": "/nonexistent/path"}, clear=True), \
             pytest.raises(SystemExit) as exc_info:
            bridge._validate_environment()
        assert exc_info.value.code == 1

    def test_pyghidra_missing_exits(self):
        bridge = self._make_bridge()
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stderr = 'openjdk version "21.0.2" 2024-01-16'
        with patch("subprocess.run", return_value=mock_result), \
             patch.dict(os.environ, {"GHIDRA_INSTALL_DIR": "/fake"}, clear=True), \
             patch("pathlib.Path.is_dir", return_value=True), \
             patch("pathlib.Path.exists", return_value=True), \
             patch("importlib.import_module", side_effect=ImportError("no pyghidra")), \
             pytest.raises(SystemExit) as exc_info:
            bridge._validate_environment()
        assert exc_info.value.code == 1

    def test_java_home_preferred_for_java_binary(self):
        bridge = self._make_bridge()
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stderr = 'openjdk version "21.0.2" 2024-01-16'
        java_home = "/opt/java21"
        with patch("subprocess.run", return_value=mock_result) as mock_run, \
             patch.dict(os.environ, {"JAVA_HOME": java_home, "GHIDRA_INSTALL_DIR": "/fake"}, clear=True), \
             patch("pathlib.Path.is_dir", return_value=True), \
             patch("pathlib.Path.exists", return_value=True), \
             patch("importlib.import_module", return_value=MagicMock()):
            bridge._validate_environment()
        # Should have called java from JAVA_HOME
        call_args = mock_run.call_args[0][0]
        assert java_home in call_args[0]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `./venv/bin/python -m pytest tests/test_validation.py -v --tb=short`
Expected: FAIL — `AttributeError: type object 'GhidraBridge' has no attribute '_validate_environment'`

- [ ] **Step 3: Commit test file**

```bash
git add tests/test_validation.py
git commit -m "test: add tests for startup environment validation"
```

---

### Task 2: Implement startup validation

**Files:**
- Modify: `src/ghidra_mcp/ghidra_bridge.py:5-9` (add `import subprocess`)
- Modify: `src/ghidra_mcp/ghidra_bridge.py:151-156` (call `_validate_environment` in `start()`)
- Modify: `src/ghidra_mcp/ghidra_bridge.py` (add `_validate_environment` method after `__init__`)

- [ ] **Step 1: Add `import subprocess` and `import importlib` to ghidra_bridge.py**

At `src/ghidra_mcp/ghidra_bridge.py`, add to the imports block (after `import sys`):

```python
import importlib
import subprocess
```

- [ ] **Step 2: Add `_validate_environment` method after `__init__`**

Insert after the `__init__` method (after line 149, before `def start`):

```python
    def _validate_environment(self) -> None:
        """Pre-flight checks before JVM launch. Exits with code 1 on fatal errors."""
        import sys as _sys

        # 1. Check Java 21+
        java_home = os.environ.get("JAVA_HOME")
        if java_home:
            java_bin = str(Path(java_home) / "bin" / "java")
        else:
            java_bin = "java"

        try:
            result = subprocess.run(
                [java_bin, "-version"],
                capture_output=True, text=True, timeout=10,
            )
            # Java prints version to stderr
            version_output = result.stderr or result.stdout or ""
            # Parse version: look for "version \"X.Y" or "version \"X"
            import re
            match = re.search(r'version "(\d+)', version_output)
            if match:
                major = int(match.group(1))
                if major < 21:
                    print(
                        f"Java {major} detected, but Java 21+ is required.\n"
                        f"Install OpenJDK 21 and set JAVA_HOME. See: https://adoptium.net",
                        file=_sys.stderr,
                    )
                    _sys.exit(1)
            else:
                logger.warning("Could not parse Java version from: %s", version_output.strip())
        except FileNotFoundError:
            print(
                "Java not found. Java 21+ is required.\n"
                "Install OpenJDK 21 and set JAVA_HOME. See: https://adoptium.net",
                file=_sys.stderr,
            )
            _sys.exit(1)
        except subprocess.TimeoutExpired:
            logger.warning("Java version check timed out, continuing anyway")

        # 2. Check GHIDRA_INSTALL_DIR
        ghidra_dir = os.environ.get("GHIDRA_INSTALL_DIR")
        if not ghidra_dir:
            print(
                "GHIDRA_INSTALL_DIR environment variable is not set.\n"
                "Set it to your Ghidra installation directory "
                "(e.g., /path/to/ghidra_12.0.4_PUBLIC)",
                file=_sys.stderr,
            )
            _sys.exit(1)

        ghidra_path = Path(ghidra_dir)
        if not ghidra_path.is_dir():
            print(
                f"GHIDRA_INSTALL_DIR points to a non-existent directory: {ghidra_dir}\n"
                f"Set it to your Ghidra installation directory.",
                file=_sys.stderr,
            )
            _sys.exit(1)

        # Check for ghidraRun marker file
        marker = "ghidraRun.bat" if sys.platform == "win32" else "ghidraRun"
        if not (ghidra_path / marker).exists():
            logger.warning(
                "GHIDRA_INSTALL_DIR=%s does not contain '%s'. "
                "Verify this is a valid Ghidra installation.",
                ghidra_dir, marker,
            )

        # 3. Check PyGhidra importable
        try:
            importlib.import_module("pyghidra")
        except ImportError:
            print(
                "PyGhidra is not installed.\n"
                "Run: pip install pyghidra>=3.0.2",
                file=_sys.stderr,
            )
            _sys.exit(1)

        # 4. Check decompiler binary (non-fatal)
        try:
            import platform as _platform
            arch = _platform.machine().lower()
            if sys.platform == "win32":
                platform_dir = "win_x86_64"
                decomp_name = "decompile.exe"
            elif sys.platform == "darwin":
                platform_dir = "mac_x86_64" if arch == "x86_64" else "mac_arm_64"
                decomp_name = "decompile"
            else:
                platform_dir = "linux_arm_64" if "aarch64" in arch or "arm" in arch else "linux_x86_64"
                decomp_name = "decompile"

            decomp_path = ghidra_path / "Ghidra" / "Features" / "Decompiler" / "os" / platform_dir / decomp_name
            if not decomp_path.exists():
                logger.warning(
                    "Native decompiler binary not found at %s. "
                    "Decompilation will fail. See README for platform-specific setup.",
                    decomp_path,
                )
        except Exception:
            pass  # Best-effort check
```

- [ ] **Step 3: Call `_validate_environment()` at the top of `start()`**

In the `start()` method, add the call right after the early return check (after `if self._started: return`):

```python
    def start(self) -> None:
        """Start PyGhidra JVM and open/create the Ghidra project."""
        if self._started:
            return

        self._validate_environment()

        logger.info("Starting PyGhidra JVM...")
```

- [ ] **Step 4: Run validation tests**

Run: `./venv/bin/python -m pytest tests/test_validation.py -v --tb=short`
Expected: All tests PASS

- [ ] **Step 5: Run full test suite to verify no regressions**

Run: `./venv/bin/python -m pytest tests/ -v --tb=short`
Expected: 177+ tests PASS (existing tests use MockGhidraBridge which skips `start()`)

- [ ] **Step 6: Commit**

```bash
git add src/ghidra_mcp/ghidra_bridge.py
git commit -m "feat: validate Java, Ghidra, and PyGhidra on startup"
```

---

### Task 3: Write tests for SSE CLI flags

**Files:**
- Create: `tests/test_cli.py`

- [ ] **Step 1: Create test file for CLI argument parsing**

```python
"""Tests for CLI argument parsing."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from ghidra_mcp.__main__ import main


class TestCLIArgs:
    """Tests for CLI argument parsing and transport selection."""

    def test_default_transport_is_stdio(self):
        mock_server = MagicMock()
        with patch("ghidra_mcp.__main__.create_server", return_value=mock_server), \
             patch("sys.argv", ["ghidra-mcp"]):
            main()
        mock_server.run.assert_called_once_with(transport="stdio")

    def test_transport_sse(self):
        mock_server = MagicMock()
        with patch("ghidra_mcp.__main__.create_server", return_value=mock_server), \
             patch("sys.argv", ["ghidra-mcp", "--transport", "sse"]):
            main()
        mock_server.run.assert_called_once_with(transport="sse")

    def test_sse_port_passed_to_create_server(self):
        mock_server = MagicMock()
        with patch("ghidra_mcp.__main__.create_server", return_value=mock_server) as mock_create, \
             patch("sys.argv", ["ghidra-mcp", "--transport", "sse", "--port", "3000"]):
            main()
        _, kwargs = mock_create.call_args
        assert kwargs.get("port") == 3000

    def test_sse_host_passed_to_create_server(self):
        mock_server = MagicMock()
        with patch("ghidra_mcp.__main__.create_server", return_value=mock_server) as mock_create, \
             patch("sys.argv", ["ghidra-mcp", "--transport", "sse", "--host", "0.0.0.0"]):
            main()
        _, kwargs = mock_create.call_args
        assert kwargs.get("host") == "0.0.0.0"

    def test_default_port_is_8080(self):
        mock_server = MagicMock()
        with patch("ghidra_mcp.__main__.create_server", return_value=mock_server) as mock_create, \
             patch("sys.argv", ["ghidra-mcp", "--transport", "sse"]):
            main()
        _, kwargs = mock_create.call_args
        assert kwargs.get("port") == 8080

    def test_default_host_is_localhost(self):
        mock_server = MagicMock()
        with patch("ghidra_mcp.__main__.create_server", return_value=mock_server) as mock_create, \
             patch("sys.argv", ["ghidra-mcp", "--transport", "sse"]):
            main()
        _, kwargs = mock_create.call_args
        assert kwargs.get("host") == "localhost"

    def test_mode_still_works(self):
        mock_server = MagicMock()
        with patch("ghidra_mcp.__main__.create_server", return_value=mock_server) as mock_create, \
             patch("sys.argv", ["ghidra-mcp", "--mode", "code"]):
            main()
        _, kwargs = mock_create.call_args
        assert kwargs.get("mode") == "code"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `./venv/bin/python -m pytest tests/test_cli.py -v --tb=short`
Expected: FAIL — `create_server()` doesn't accept `host`/`port` yet, tests fail with `TypeError`

- [ ] **Step 3: Commit test file**

```bash
git add tests/test_cli.py
git commit -m "test: add tests for CLI transport flags"
```

---

### Task 4: Implement SSE transport support

**Files:**
- Modify: `src/ghidra_mcp/__main__.py`
- Modify: `src/ghidra_mcp/server.py:18-34` (`create_server` signature)
- Modify: `pyproject.toml`

- [ ] **Step 1: Update `create_server` to accept `host` and `port`**

In `src/ghidra_mcp/server.py`, update the function signature and `FastMCP` constructor:

```python
def create_server(
    project_dir: str = "./ghidra-projects",
    project_name: str = "mcp_project",
    mode: str = "full",
    host: str = "localhost",
    port: int = 8080,
) -> FastMCP:
    """Create and configure the Ghidra MCP server.

    Args:
        project_dir: Directory for Ghidra projects.
        project_name: Ghidra project name.
        mode: "full" registers all 32 tools + 5 resources;
              "code" registers only search + execute (saves tokens).
        host: Bind address for SSE transport (default: localhost).
        port: Port for SSE transport (default: 8080).
    """
    mcp = FastMCP(
        "ghidra-mcp",
        instructions="Ghidra binary analysis server for reverse engineering and malware analysis",
        host=host,
        port=port,
    )
    bridge = GhidraBridge(project_dir, project_name)
```

- [ ] **Step 2: Update `__main__.py` with transport flags**

Replace the entire contents of `src/ghidra_mcp/__main__.py`:

```python
"""CLI entry point for ghidra-mcp server."""

import argparse
import sys

from ghidra_mcp.server import create_server


def main() -> None:
    parser = argparse.ArgumentParser(description="Ghidra MCP Server")
    parser.add_argument(
        "--project-dir",
        default="./ghidra-projects",
        help="Directory for Ghidra projects (default: ./ghidra-projects)",
    )
    parser.add_argument(
        "--project-name",
        default="mcp_project",
        help="Ghidra project name (default: mcp_project)",
    )
    parser.add_argument(
        "--mode",
        choices=["full", "code", "script"],
        default="full",
        help="Server mode: 'full' registers all tools, 'code' registers search+execute, "
             "'script' registers API introspection and code execution (default: full)",
    )
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse"],
        default="stdio",
        help="Transport protocol: 'stdio' for standard I/O, 'sse' for HTTP/SSE (default: stdio)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8080,
        help="Port for SSE transport (default: 8080, ignored for stdio)",
    )
    parser.add_argument(
        "--host",
        default="localhost",
        help="Bind address for SSE transport (default: localhost, ignored for stdio)",
    )
    args = parser.parse_args()

    server = create_server(
        project_dir=args.project_dir,
        project_name=args.project_name,
        mode=args.mode,
        host=args.host,
        port=args.port,
    )
    server.run(transport=args.transport)


if __name__ == "__main__":
    main()
```

- [ ] **Step 3: Add `[sse]` optional dependency to `pyproject.toml`**

In `pyproject.toml`, add the `sse` extra:

```toml
[project.optional-dependencies]
sse = ["uvicorn>=0.30"]
dev = [
    "pytest>=8.0",
    "pytest-asyncio>=0.24",
]
```

- [ ] **Step 4: Run CLI tests**

Run: `./venv/bin/python -m pytest tests/test_cli.py -v --tb=short`
Expected: All tests PASS

- [ ] **Step 5: Run full test suite**

Run: `./venv/bin/python -m pytest tests/ -v --tb=short`
Expected: All tests PASS

- [ ] **Step 6: Commit**

```bash
git add src/ghidra_mcp/__main__.py src/ghidra_mcp/server.py pyproject.toml
git commit -m "feat: add SSE transport support via --transport sse"
```

---

### Task 5: Create bash installer script

**Files:**
- Create: `scripts/install.sh`

- [ ] **Step 1: Write the installer script**

Create `scripts/install.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail

# Colors (disable if not a terminal)
if [ -t 1 ]; then
    GREEN='\033[0;32m'
    RED='\033[0;31m'
    YELLOW='\033[0;33m'
    NC='\033[0m'
else
    GREEN='' RED='' YELLOW='' NC=''
fi

pass() { echo -e "  ${GREEN}[PASS]${NC} $1"; }
fail() { echo -e "  ${RED}[FAIL]${NC} $1"; }
warn() { echo -e "  ${YELLOW}[WARN]${NC} $1"; }

echo "=== Ghidra MCP Server Installer ==="
echo ""

ERRORS=0

# 1. Check Python 3.11+
echo "Checking prerequisites..."
if command -v python3 &>/dev/null; then
    PY_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
    PY_MAJOR=$(echo "$PY_VERSION" | cut -d. -f1)
    PY_MINOR=$(echo "$PY_VERSION" | cut -d. -f2)
    if [ "$PY_MAJOR" -ge 3 ] && [ "$PY_MINOR" -ge 11 ]; then
        pass "Python $PY_VERSION"
    else
        fail "Python $PY_VERSION (need 3.11+)"
        ERRORS=$((ERRORS + 1))
    fi
else
    fail "Python 3 not found (need 3.11+)"
    ERRORS=$((ERRORS + 1))
fi

# 2. Check Java 21+
if command -v java &>/dev/null; then
    JAVA_VERSION=$(java -version 2>&1 | head -1 | grep -oP '(?<=version ")(\d+)' || echo "0")
    if [ "$JAVA_VERSION" -ge 21 ]; then
        pass "Java $JAVA_VERSION"
    else
        fail "Java $JAVA_VERSION (need 21+). Install from https://adoptium.net"
        ERRORS=$((ERRORS + 1))
    fi
else
    fail "Java not found (need 21+). Install from https://adoptium.net"
    ERRORS=$((ERRORS + 1))
fi

# 3. Check GHIDRA_INSTALL_DIR
if [ -n "${GHIDRA_INSTALL_DIR:-}" ]; then
    if [ -d "$GHIDRA_INSTALL_DIR" ]; then
        if [ -f "$GHIDRA_INSTALL_DIR/ghidraRun" ]; then
            pass "GHIDRA_INSTALL_DIR=$GHIDRA_INSTALL_DIR"
        else
            warn "GHIDRA_INSTALL_DIR=$GHIDRA_INSTALL_DIR (ghidraRun not found, may not be valid)"
        fi
    else
        fail "GHIDRA_INSTALL_DIR=$GHIDRA_INSTALL_DIR (directory does not exist)"
        ERRORS=$((ERRORS + 1))
    fi
else
    fail "GHIDRA_INSTALL_DIR is not set"
    ERRORS=$((ERRORS + 1))
fi

# Stop if prerequisites failed
if [ "$ERRORS" -gt 0 ]; then
    echo ""
    echo -e "${RED}$ERRORS prerequisite(s) failed. Fix the issues above and re-run.${NC}"
    exit 1
fi

echo ""

# 4. Create venv if needed
if [ -d "venv" ]; then
    pass "Virtual environment exists (venv/)"
else
    echo "Creating virtual environment..."
    python3 -m venv venv
    pass "Created virtual environment (venv/)"
fi

# 5. Install package
echo "Installing ghidra-mcp..."
./venv/bin/pip install -e . --quiet
pass "Installed ghidra-mcp"

# 6. Verify
if ./venv/bin/ghidra-mcp --help &>/dev/null; then
    pass "ghidra-mcp runs successfully"
else
    fail "ghidra-mcp failed to run"
    exit 1
fi

echo ""
echo -e "${GREEN}=== Installation complete ===${NC}"
echo ""
echo "To get started:"
echo "  source venv/bin/activate"
echo "  ghidra-mcp                          # stdio mode"
echo "  ghidra-mcp --transport sse          # SSE mode (persistent server)"
```

- [ ] **Step 2: Make the script executable**

```bash
chmod +x scripts/install.sh
```

- [ ] **Step 3: Commit**

```bash
git add scripts/install.sh
git commit -m "feat: add bash installer script for Linux/macOS"
```

---

### Task 6: Create PowerShell installer script

**Files:**
- Create: `scripts/install.ps1`

- [ ] **Step 1: Write the PowerShell installer script**

Create `scripts/install.ps1`:

```powershell
# Ghidra MCP Server Installer for Windows
$ErrorActionPreference = "Stop"

function Pass($msg) { Write-Host "  [PASS] $msg" -ForegroundColor Green }
function Fail($msg) { Write-Host "  [FAIL] $msg" -ForegroundColor Red; $script:Errors++ }
function Warn($msg) { Write-Host "  [WARN] $msg" -ForegroundColor Yellow }

Write-Host "=== Ghidra MCP Server Installer ===" -ForegroundColor Cyan
Write-Host ""

$script:Errors = 0

# 1. Check Python 3.11+
Write-Host "Checking prerequisites..."
try {
    $pyVersion = & python --version 2>&1
    if ($pyVersion -match "Python (\d+)\.(\d+)") {
        $major = [int]$Matches[1]
        $minor = [int]$Matches[2]
        if ($major -ge 3 -and $minor -ge 11) {
            Pass "Python $major.$minor"
        } else {
            Fail "Python $major.$minor (need 3.11+)"
        }
    } else {
        Fail "Could not parse Python version"
    }
} catch {
    Fail "Python not found (need 3.11+). Download from https://python.org"
}

# 2. Check Java 21+
try {
    $javaOutput = & java -version 2>&1 | Out-String
    if ($javaOutput -match 'version "(\d+)') {
        $javaVersion = [int]$Matches[1]
        if ($javaVersion -ge 21) {
            Pass "Java $javaVersion"
        } else {
            Fail "Java $javaVersion (need 21+). Install from https://adoptium.net"
        }
    } else {
        Fail "Could not parse Java version"
    }
} catch {
    Fail "Java not found (need 21+). Install from https://adoptium.net"
}

# 3. Check GHIDRA_INSTALL_DIR
if ($env:GHIDRA_INSTALL_DIR) {
    if (Test-Path $env:GHIDRA_INSTALL_DIR -PathType Container) {
        if (Test-Path (Join-Path $env:GHIDRA_INSTALL_DIR "ghidraRun.bat")) {
            Pass "GHIDRA_INSTALL_DIR=$($env:GHIDRA_INSTALL_DIR)"
        } else {
            Warn "GHIDRA_INSTALL_DIR=$($env:GHIDRA_INSTALL_DIR) (ghidraRun.bat not found)"
        }
    } else {
        Fail "GHIDRA_INSTALL_DIR=$($env:GHIDRA_INSTALL_DIR) (directory does not exist)"
    }
} else {
    Fail "GHIDRA_INSTALL_DIR is not set"
}

# Stop if prerequisites failed
if ($script:Errors -gt 0) {
    Write-Host ""
    Write-Host "$($script:Errors) prerequisite(s) failed. Fix the issues above and re-run." -ForegroundColor Red
    exit 1
}

Write-Host ""

# 4. Create venv if needed
if (Test-Path "venv") {
    Pass "Virtual environment exists (venv\)"
} else {
    Write-Host "Creating virtual environment..."
    & python -m venv venv
    Pass "Created virtual environment (venv\)"
}

# 5. Install package
Write-Host "Installing ghidra-mcp..."
& .\venv\Scripts\pip install -e . --quiet
Pass "Installed ghidra-mcp"

# 6. Verify
try {
    & .\venv\Scripts\ghidra-mcp.exe --help | Out-Null
    Pass "ghidra-mcp runs successfully"
} catch {
    Fail "ghidra-mcp failed to run"
    exit 1
}

Write-Host ""
Write-Host "=== Installation complete ===" -ForegroundColor Green
Write-Host ""
Write-Host "To get started:"
Write-Host "  .\venv\Scripts\activate"
Write-Host "  ghidra-mcp                          # stdio mode"
Write-Host "  ghidra-mcp --transport sse           # SSE mode (persistent server)"
```

- [ ] **Step 2: Commit**

```bash
git add scripts/install.ps1
git commit -m "feat: add PowerShell installer script for Windows"
```

---

### Task 7: Update README and CHANGELOG

**Files:**
- Modify: `README.md`
- Modify: `CHANGELOG.md`

- [ ] **Step 1: Add installer script references to README**

In `README.md`, replace the Installation section (after Prerequisites, before Usage) with:

```markdown
#### Installation

**Quick install** (checks prerequisites, creates venv, installs):

```bash
# Linux/macOS
./scripts/install.sh

# Windows (PowerShell)
.\scripts\install.ps1
```

**Manual install:**

```bash
python -m venv venv

# Linux/macOS:
source venv/bin/activate

# Windows (Command Prompt):
venv\Scripts\activate

# Windows (PowerShell):
venv\Scripts\Activate.ps1

pip install -e .
```
```

- [ ] **Step 2: Add SSE transport to Usage section**

In the Usage section of `README.md`, add after the existing examples:

```markdown
# SSE transport — persistent HTTP server (JVM stays warm between sessions)
ghidra-mcp --transport sse
ghidra-mcp --transport sse --port 3000
# Windows: same commands work after activating venv
```

- [ ] **Step 3: Add SSE client configuration section**

After the existing Client Configuration sections in `README.md`, add a note about SSE:

```markdown
#### SSE Transport

For persistent server mode, start the server first then configure your client to connect via URL:

```bash
ghidra-mcp --transport sse --port 8080
```

Configure your MCP client to connect to `http://localhost:8080/sse` instead of using a command-based stdio configuration. Refer to your client's documentation for URL-based MCP server configuration.
```

- [ ] **Step 4: Update CHANGELOG.md**

Add to the `[0.2.4]` entry (or create `[0.2.5]`):

```markdown
- **Startup validation** — checks Java 21+, `GHIDRA_INSTALL_DIR`, and PyGhidra on startup with clear error messages before JVM launch. No more cryptic JVM crashes from misconfiguration.
- **SSE transport** — run as a persistent HTTP server with `ghidra-mcp --transport sse`. JVM stays warm between sessions. Supports `--port` and `--host` flags.
- **Installer scripts** — one-command setup via `./scripts/install.sh` (Linux/macOS) or `.\scripts\install.ps1` (Windows). Checks prerequisites, creates venv, installs, and validates.
```

- [ ] **Step 5: Run full test suite**

Run: `./venv/bin/python -m pytest tests/ -v --tb=short`
Expected: All tests PASS

- [ ] **Step 6: Commit**

```bash
git add README.md CHANGELOG.md
git commit -m "docs: add SSE transport, installer scripts, and validation to README"
```
