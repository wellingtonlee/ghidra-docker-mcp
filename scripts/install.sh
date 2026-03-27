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
    JAVA_VERSION=$(java -version 2>&1 | head -1 | sed -n 's/.*version "\([0-9]*\).*/\1/p')
    if [ -n "$JAVA_VERSION" ] && [ "$JAVA_VERSION" -ge 21 ]; then
        pass "Java $JAVA_VERSION"
    else
        fail "Java ${JAVA_VERSION:-unknown} (need 21+). Install from https://adoptium.net"
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
