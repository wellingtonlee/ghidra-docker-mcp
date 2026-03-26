# Ghidra MCP Server

## Build & Test

```bash
# Install (requires Python 3.11+)
pip install -e ".[dev]"

# Run tests (mocked, no Ghidra needed)
pytest tests/ -v

# Docker build
docker compose build

# Docker run (stdio transport)
docker compose run --rm -i ghidra-mcp
```

## Architecture

- `src/ghidra_mcp/server.py` — FastMCP server, all 32 tools + 5 resources registered here
- `src/ghidra_mcp/tool_registry.py` — Tool metadata registry for code mode (search/execute)
- `src/ghidra_mcp/api_registry.py` — Static Ghidra API class registry + runtime Java reflection for script mode
- `src/ghidra_mcp/ghidra_bridge.py` — Core logic: PyGhidra JVM lifecycle, Ghidra project/program management, all analysis methods
- `src/ghidra_mcp/__main__.py` — CLI entry point
- `tests/conftest.py` — MockGhidraBridge for unit testing without Ghidra
- Tools accept `binary_name` to select which imported binary to operate on
- All list tools support offset/limit pagination

## Key Patterns

- GhidraBridge lazy-starts JVM on first use (`_ensure_started`)
- Decompilers are cached per program in `_decompilers` dict
- Functions resolved by name first, then hex address fallback
- Ghidra Java imports are deferred (inside methods) since JVM must be running first
