# Ease-of-Use Improvements Design

## Context

Setting up ghidra-mcp locally requires Java 21+, Ghidra, PyGhidra, and correct environment variables. Misconfiguration produces opaque JVM crashes. The server only supports stdio transport, requiring restart per session. No automated setup exists — users follow manual README steps.

These three features reduce onboarding friction and improve the daily running experience.

## Feature 1: Startup Dependency Validation

### Goal
Catch misconfiguration before JVM launch with clear, actionable error messages.

### Checks (run in order)

1. **Java 21+**: Run `java -version`, parse version number. If `JAVA_HOME` is set, verify directory exists and contains `bin/java` (or `bin\java.exe` on Windows). Fail message: `"Java 21+ required. Install OpenJDK 21 and set JAVA_HOME. See: https://adoptium.net"`

2. **GHIDRA_INSTALL_DIR**: Verify env var is set, directory exists, contains `ghidraRun` (Linux/macOS) or `ghidraRun.bat` (Windows). Fail message: `"Set GHIDRA_INSTALL_DIR to your Ghidra installation (e.g., /path/to/ghidra_12.0.4_PUBLIC)"`

3. **PyGhidra**: Attempt `import pyghidra`. Fail message: `"PyGhidra not installed. Run: pip install pyghidra>=3.0.2"`

4. **Decompiler binary**: Detect platform, check `<GHIDRA_INSTALL_DIR>/Ghidra/Features/Decompiler/os/<platform>/decompile[.exe]` exists. Warn (non-fatal): `"Native decompiler binary not found at <path>. Decompilation will fail. See README for platform-specific setup."`

### Behavior

- All checks run before `HeadlessPyGhidraLauncher.start()`.
- Fatal failures (checks 1-3): print error to stderr, `sys.exit(1)`.
- Non-fatal warnings (check 4): log warning, continue startup.
- Validation adds ~200ms (subprocess call for `java -version` + filesystem checks).

### Implementation

- New `_validate_environment()` method on `GhidraBridge`, called at the top of `start()`.
- Java version check uses `subprocess.run(["java", "-version"], capture_output=True)`, parsing stderr output (Java prints version to stderr).
- If `JAVA_HOME` is set, prefer `$JAVA_HOME/bin/java` for the version check.
- Platform-aware decompiler path check reuses logic from `_init_decompiler` error hint (already handles `win_*` prefix for `.exe`).

### Files modified
- `src/ghidra_mcp/ghidra_bridge.py` — add `_validate_environment()`, call from `start()`

## Feature 2: SSE Transport

### Goal
Allow the server to run as a persistent HTTP service so the JVM stays warm between sessions.

### CLI interface

```
ghidra-mcp                                    # stdio (default, unchanged)
ghidra-mcp --transport sse                    # SSE on localhost:8080
ghidra-mcp --transport sse --port 3000        # SSE on localhost:3000
ghidra-mcp --transport sse --host 0.0.0.0     # SSE on all interfaces
```

### Arguments

| Flag | Default | Description |
|------|---------|-------------|
| `--transport` | `stdio` | Transport: `stdio` or `sse` |
| `--port` | `8080` | Port for SSE transport |
| `--host` | `localhost` | Bind address for SSE transport |

### Implementation

- `__main__.py`: Add `--transport`, `--port`, `--host` arguments. Pass transport to `server.run()`.
- FastMCP already supports `server.run(transport="sse")` natively. The SSE transport starts a Starlette/uvicorn server. No changes to `server.py` or `ghidra_bridge.py` needed.
- If `starlette` or `uvicorn` are not installed when `--transport sse` is used, print: `"SSE transport requires additional dependencies. Run: pip install ghidra-mcp[sse]"`

### Dependencies

Add optional `[sse]` extra to `pyproject.toml`:
```toml
[project.optional-dependencies]
sse = ["uvicorn>=0.30"]
dev = ["pytest>=8.0", "pytest-asyncio>=0.24"]
```

(FastMCP may already pull in starlette. Check at implementation time — only add what's missing.)

### Documentation

- README: Add SSE section under "Usage" showing `--transport sse` examples.
- Client config sections: Add SSE config examples for each client showing HTTP URL-based connection.

### Files modified
- `src/ghidra_mcp/__main__.py` — add CLI flags, transport switching
- `pyproject.toml` — add `[sse]` optional dependency
- `README.md` — SSE documentation

## Feature 3: Installer Scripts

### Goal
One-command setup that checks prerequisites, creates a virtual environment, installs the package, and validates the environment.

### Scripts

#### `scripts/install.sh` (Linux/macOS)

```
./scripts/install.sh
```

Steps:
1. Check Python 3.11+ is available (`python3 --version`)
2. Check Java 21+ is available (`java -version`)
3. Check `GHIDRA_INSTALL_DIR` is set and valid
4. Create `venv/` if it doesn't exist
5. Install `pip install -e .` into the venv
6. Run `venv/bin/ghidra-mcp --help` to verify installation
7. Print summary: what passed, what failed, next steps

#### `scripts/install.ps1` (Windows PowerShell)

```powershell
.\scripts\install.ps1
```

Same logic adapted for PowerShell:
- Uses `Get-Command` to find `python`/`java`
- Uses `venv\Scripts\` paths
- Uses `$env:GHIDRA_INSTALL_DIR`

### Characteristics

- **Idempotent**: Safe to re-run. Skips steps already completed.
- **Non-destructive**: Never deletes existing venv. Creates only if missing.
- **Informative**: Prints colored pass/fail status for each check.
- **Exit code**: 0 if all prerequisites met and install succeeded, 1 otherwise.

### Files added
- `scripts/install.sh` — bash installer
- `scripts/install.ps1` — PowerShell installer
- `README.md` — reference installer scripts in Local setup section

## Implementation Order

1. **Startup validation** (Feature 1) — quick win, 1 file changed
2. **SSE transport** (Feature 2) — CLI + optional dep, 3 files changed
3. **Installer scripts** (Feature 3) — 2 new files + README update

## Verification

- Feature 1: Run `ghidra-mcp` with `GHIDRA_INSTALL_DIR` unset — should get clear error. Run with valid env — should start normally. Run tests — 177 should still pass (validation is skipped in tests since bridge is mocked).
- Feature 2: Run `ghidra-mcp --transport sse --port 8080`, verify server starts and is reachable. Run existing tests — should still pass (tests use mocked bridge, don't test transport).
- Feature 3: Run `./scripts/install.sh` on a clean checkout. Verify it creates venv, installs, and reports status. Run `.\scripts\install.ps1` on Windows.
