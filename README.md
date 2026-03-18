# Ghidra MCP Server

A Dockerized [Ghidra](https://ghidra-sre.org/) headless server exposed via the [Model Context Protocol (MCP)](https://modelcontextprotocol.io/), designed for binary analysis and malware reverse engineering with AI assistants.

## Features

- **19 MCP tools** for binary analysis: decompilation, function listing, string search, cross-references, byte pattern search, malware-focused analysis, and advanced RE tools (CFG, call graphs, instruction search)
- **5 MCP resources** for browsing binary metadata, functions, strings, and imports
- **Multi-binary support** — analyze multiple binaries simultaneously in a single Ghidra project
- **Malware analysis tools** — entropy analysis (packing detection), suspicious API categorization, section anomaly detection
- **Docker-first** — runs in an isolated container with stdio transport
- **PyGhidra 3.0** — direct Ghidra Java API access via in-process JVM (no Ghidra scripts needed)

## Quick Start

### Docker (recommended)

```bash
# Build the image
docker compose build

# Run with Claude Desktop
# Add to your Claude Desktop config:
```

**Claude Desktop configuration** (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "ghidra": {
      "command": "docker",
      "args": ["compose", "-f", "/path/to/docker-compose.yml", "run", "--rm", "-i", "ghidra-mcp"]
    }
  }
}
```

#### Apple Silicon

The Docker image builds natively on arm64. Since Ghidra releases don't include pre-built `linux_arm_64` decompiler binaries, the Dockerfile automatically builds the decompiler from source during `docker compose build` (adds ~2 min to build time, requires no extra configuration). If you encounter issues, you can force x86_64 emulation by uncommenting `platform: linux/amd64` in `docker-compose.yml` (slower due to Rosetta/QEMU).

### Local Development

Requires Ghidra 12.0.4 installed and `GHIDRA_INSTALL_DIR` set.

```bash
pip install -e ".[dev]"
ghidra-mcp --project-dir ./projects --project-name my_project
```

## MCP Tools

### Project Management

| Tool | Description |
|------|-------------|
| `import_binary` | Import a binary file for analysis |
| `upload_binary` | Upload a binary via base64-encoded data |
| `list_binaries` | List all imported binaries |
| `delete_binary` | Remove a binary from the project |

### Analysis

| Tool | Description |
|------|-------------|
| `list_functions` | List functions with pagination and name filtering |
| `decompile_function` | Decompile a function to C pseudocode |
| `rename_function` | Rename a function |
| `list_strings` | List defined strings |
| `search_strings` | Search strings by substring or regex |
| `list_imports` | List imported symbols |
| `list_exports` | List exported symbols |
| `get_xrefs` | Get cross-references to/from an address |
| `search_bytes` | Search for hex byte patterns with wildcards |
| `get_memory_bytes` | Read raw bytes from an address |
| `search_instructions` | Regex search over disassembly mnemonics/operands |

### Malware Analysis

| Tool | Description |
|------|-------------|
| `get_entropy` | Per-section Shannon entropy, packing detection |
| `detect_suspicious_apis` | Categorized suspicious imports (injection, persistence, crypto, network, anti-debug) |
| `get_sections` | Sections with permissions, entropy, and anomaly flags (W+X, unusual names) |

### Advanced Analysis

| Tool | Description |
|------|-------------|
| `get_function_summary` | Rich function metadata (params, callees, callers, strings, complexity) without decompilation |
| `get_basic_blocks` | Control-flow graph basic blocks with instructions and edges |
| `get_call_graph` | Function call graph with BFS depth control (callees/callers/both) |

## MCP Resources

| URI | Description |
|-----|-------------|
| `ghidra://binaries` | All binaries in the project |
| `ghidra://binary/{name}/info` | Binary metadata (arch, format, hashes, entry point) |
| `ghidra://binary/{name}/functions` | Full function list |
| `ghidra://binary/{name}/strings` | All defined strings |
| `ghidra://binary/{name}/imports` | All imported symbols |

## Configuration

Environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `GHIDRA_INSTALL_DIR` | *(auto-detect)* | Path to Ghidra installation directory (required if PyGhidra auto-detection fails) |
| `GHIDRA_ANALYSIS_TIMEOUT_SECONDS` | `300` | Analysis timeout per binary |
| `GHIDRA_MAX_HEAP` | `2g` | JVM max heap size |

## Docker Volumes

| Path | Purpose |
|------|---------|
| `/home/ghidra/binaries` | Input binaries (mounted read-only) |
| `/home/ghidra/projects` | Persistent Ghidra project data |

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests (uses mocked GhidraBridge, no Ghidra needed)
pytest tests/

# Run with verbose output
pytest tests/ -v
```

## Architecture

```
Client (Claude Desktop) ←stdio→ FastMCP Server ← GhidraBridge → PyGhidra/JVM → Ghidra API
```

- **FastMCP** handles MCP protocol over stdio
- **GhidraBridge** manages the JVM lifecycle, Ghidra project, cached program handles, and decompiler instances
- **PyGhidra** provides in-process access to Ghidra's Java API via JPype (no separate Ghidra process needed)

## License

MIT
