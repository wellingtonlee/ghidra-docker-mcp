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
