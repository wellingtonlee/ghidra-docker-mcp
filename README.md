# Ghidra MCP Server

A [Ghidra](https://ghidra-sre.org/) headless server exposed via the [Model Context Protocol (MCP)](https://modelcontextprotocol.io/), designed for binary analysis and malware reverse engineering with AI assistants. Runs locally or in Docker.

## Features

- **32 MCP tools** for binary analysis: decompilation, function listing, string search, cross-references, byte pattern search, malware-focused analysis, advanced RE tools (CFG, call graphs, instruction search), and emulation
- **3 emulation tools** — emulate functions with automatic calling convention handling, single-step through code, read registers and memory
- **5 MCP resources** for browsing binary metadata, functions, strings, and imports
- **Multi-binary support** — analyze multiple binaries simultaneously in a single Ghidra project
- **Malware analysis tools** — entropy analysis (packing detection), suspicious API categorization, section anomaly detection
- **Code Mode** — token-saving operating mode that exposes only 2 tools (`search` + `execute`) instead of all 32, for LLM-efficient usage
- **Ghidra Server** — connect to a shared Ghidra server for collaborative reverse engineering with checkout/checkin workflow
- **Docker or local** — runs in an isolated container or directly on your machine via stdio transport
- **PyGhidra 3.0** — direct Ghidra Java API access via in-process JVM (no Ghidra scripts needed)

## Quick Start

### Docker (recommended)

```bash
# Build the image
docker compose build

# Run in full mode (all 32 tools)
docker compose run --rm -i ghidra-mcp

# Run in code mode (2 tools: search + execute, saves tokens)
docker compose run --rm -i ghidra-mcp --mode code
```

See [Client Configuration](#client-configuration) for setup with Claude Desktop, Claude Code, OpenCode, and Continue.dev.

#### Apple Silicon

The Docker image builds natively on arm64. Since Ghidra releases don't include pre-built `linux_arm_64` decompiler binaries, the Dockerfile automatically builds the decompiler from source during `docker compose build` (adds ~2 min to build time, requires no extra configuration). If you encounter issues, you can force x86_64 emulation by uncommenting `platform: linux/amd64` in `docker-compose.yml` (slower due to Rosetta/QEMU).

### Local (no Docker)

#### Prerequisites

- Python 3.11+
- Java 21+ (e.g., OpenJDK 21)
- [Ghidra 12.0.4](https://github.com/NationalSecurityAgency/ghidra/releases)
- `GHIDRA_INSTALL_DIR` environment variable pointing to your Ghidra installation

#### Installation

```bash
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows
pip install -e .
```

#### Usage

```bash
# Activate the virtual environment first
source venv/bin/activate

# Full mode (default) — all 32 tools
ghidra-mcp

# Code mode — 2 meta-tools (search + execute)
ghidra-mcp --mode code

# Custom project directory and name
ghidra-mcp --project-dir ~/my-projects --project-name my_project
```

See [Client Configuration](#client-configuration) for setup with Claude Desktop, Claude Code, OpenCode, and Continue.dev.

## Client Configuration

> All examples show **full mode**. For **code mode**, append `--mode code` (Docker: add `"--mode", "code"` to the args array; Local: add `"--mode", "code"` to args or the command).

### Claude Desktop

Config file: `claude_desktop_config.json`

**Docker:**

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

**Local:**

```json
{
  "mcpServers": {
    "ghidra": {
      "command": "/path/to/venv/bin/ghidra-mcp",
      "env": {
        "GHIDRA_INSTALL_DIR": "/path/to/ghidra_12.0.4_PUBLIC"
      }
    }
  }
}
```

> **Note:** Use the full path to `ghidra-mcp` inside your virtual environment. If `GHIDRA_INSTALL_DIR` is already set in your shell profile, you can omit the `env` block.

### Claude Code

**Docker — via CLI:**

```bash
claude mcp add ghidra -- docker compose -f /path/to/docker-compose.yml run --rm -i ghidra-mcp
```

**Docker — via project config** (`.mcp.json` in project root):

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

**Local — via CLI:**

```bash
claude mcp add ghidra --env GHIDRA_INSTALL_DIR=/path/to/ghidra_12.0.4_PUBLIC -- /path/to/venv/bin/ghidra-mcp
```

**Local — via project config** (`.mcp.json`):

```json
{
  "mcpServers": {
    "ghidra": {
      "command": "/path/to/venv/bin/ghidra-mcp",
      "env": {
        "GHIDRA_INSTALL_DIR": "/path/to/ghidra_12.0.4_PUBLIC"
      }
    }
  }
}
```

> **Note:** Use the full path to `ghidra-mcp` inside your virtual environment. If `GHIDRA_INSTALL_DIR` is already set in your shell profile, you can omit the `env` block and `--env` flag.

### OpenCode

Config file: `opencode.json` (project root or `~/.config/opencode/opencode.json`)

**Docker:**

```json
{
  "mcp": {
    "ghidra": {
      "type": "local",
      "command": ["docker", "compose", "-f", "/path/to/docker-compose.yml", "run", "--rm", "-i", "ghidra-mcp"],
      "enabled": true
    }
  }
}
```

**Local:**

```json
{
  "mcp": {
    "ghidra": {
      "type": "local",
      "command": ["/path/to/venv/bin/ghidra-mcp"],
      "environment": {
        "GHIDRA_INSTALL_DIR": "/path/to/ghidra_12.0.4_PUBLIC"
      },
      "enabled": true
    }
  }
}
```

> **Note:** Use the full path to `ghidra-mcp` inside your virtual environment. If `GHIDRA_INSTALL_DIR` is already set in your shell profile, you can omit the `"environment"` block.

### Continue.dev

Config file: `.continue/mcpServers/ghidra.json`

> **Note:** MCP tools are only available in Continue's **Agent mode**, not Chat mode.

**Docker:**

```json
{
  "mcpServers": [
    {
      "name": "Ghidra",
      "type": "stdio",
      "command": "docker",
      "args": ["compose", "-f", "/path/to/docker-compose.yml", "run", "--rm", "-i", "ghidra-mcp"]
    }
  ]
}
```

**Local:**

```json
{
  "mcpServers": [
    {
      "name": "Ghidra",
      "type": "stdio",
      "command": "/path/to/venv/bin/ghidra-mcp",
      "env": {
        "GHIDRA_INSTALL_DIR": "/path/to/ghidra_12.0.4_PUBLIC"
      }
    }
  ]
}
```

> **Note:** Use the full path to `ghidra-mcp` inside your virtual environment. If `GHIDRA_INSTALL_DIR` is already set in your shell profile, you can omit the `env` block.

## Server Modes

The server supports two operating modes, selectable via the `--mode` flag:

| Mode | Flag | Tools Registered | Use Case |
|------|------|-----------------|----------|
| **Full** | `--mode full` (default) | All 32 tools + 5 resources | Direct tool access, best for exploration and interactive use |
| **Code** | `--mode code` | 2 tools (`search` + `execute`) | Token-efficient, best for automated pipelines and cost-sensitive usage |

Both modes provide identical analytical capabilities — Code Mode simply routes all calls through a dynamic dispatcher instead of registering each tool individually.

## MCP Tools (Full Mode)

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
| `rename_variable` | Rename a variable (parameter or local) within a function |
| `rename_label` | Rename a symbol/label in the program |
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

### Emulation

Emulate functions using Ghidra's `EmulatorHelper` API. The emulator automatically handles calling conventions — arguments are placed in the correct registers or stack locations based on the function's parameter metadata, and return values are extracted from the appropriate return register.

| Tool | Description |
|------|-------------|
| `emulate_function` | Emulate a function with optional integer arguments, get return value |
| `emulate_step` | Single-step an existing emulator session, read registers and memory |
| `emulate_session_destroy` | Destroy an emulator session and free its resources |

### Server Connectivity

Connect to a shared Ghidra server for collaborative reverse engineering. Programs opened from the server are available to all analysis tools. Supports checkout/checkin workflow with exclusive locking.

| Tool | Description |
|------|-------------|
| `connect_server` | Connect to a Ghidra server (host, port, username, optional password) |
| `disconnect_server` | Disconnect from server, release checkouts, clean up |
| `list_repositories` | List available repositories on the connected server |
| `list_server_files` | List files and subfolders in a server repository |
| `open_from_server` | Open a program from the server for analysis (with optional checkout) |
| `checkin_file` | Check in changes back to the Ghidra server |

#### Server Workflow

```
# 1. Connect to the Ghidra server
connect_server(host="ghidra.example.com", port=13100, username="analyst")

# 2. Browse available repositories and files
list_repositories()
list_server_files(repository_name="malware-lab")

# 3. Open a program (checkout for editing)
open_from_server(repository_name="malware-lab", file_path="/samples/trojan.exe", checkout=True)

# 4. Analyze with any tool — decompile, rename functions, etc.
decompile_function(binary_name="trojan.exe", name_or_addr="main")
rename_function(binary_name="trojan.exe", old_name="FUN_00401000", new_name="decrypt_payload")

# 5. Save changes back to the server
checkin_file(binary_name="trojan.exe", comment="Identified decryption routine")

# 6. Disconnect when done
disconnect_server()
```

#### Emulation Workflow

The typical emulation workflow is:

1. **Start emulation** with `emulate_function` — sets up the emulator, places arguments, runs until the function returns or the step limit is reached, and returns the result including the return value.

2. **Inspect interactively** (optional) with `emulate_step` — after `emulate_function` creates a session, you can single-step through the remaining execution, reading specific registers and memory regions at each step.

3. **Clean up** with `emulate_session_destroy` — disposes the emulator and frees resources. Sessions are also cleaned up automatically when a binary is deleted or the server shuts down.

#### Emulation Example

```
# Step 1: Emulate a function with arguments
emulate_function(binary_name="malware.exe", name_or_addr="decrypt_string", args=[0x00402000, 16])
# Returns: {
#   "session_key": "malware.exe:decrypt_string",
#   "return_value": 4198400,
#   "steps_executed": 847,
#   "hit_breakpoint": true,
#   ...
# }

# Step 2: Inspect registers and memory after execution
emulate_step(binary_name="malware.exe", name_or_addr="decrypt_string",
             count=0, read_registers=["RAX", "RCX"],
             read_memory=[{"address": "0x00402000", "size": 32}])
# Returns: {
#   "registers": {"RAX": "0x401000", "RCX": "0x0"},
#   "memory": [{"address": "0x00402000", "hex": "48656c6c6f..."}],
#   ...
# }

# Step 3: Clean up
emulate_session_destroy(binary_name="malware.exe", name_or_addr="decrypt_string")
```

#### Emulation Limitations

- **External calls**: If the emulated function calls imported/external functions (e.g., `printf`, `malloc`), emulation will stop or produce undefined behavior. Only self-contained functions emulate correctly without additional stubbing.
- **Architecture support**: x86/x86-64 (push sentinel return address to stack) and ARM/AARCH64 (set LR register) are supported. Other architectures will raise an error.
- **Integer arguments only**: The current implementation handles integer arguments via register/stack writes. Floating-point and struct arguments are not supported.
- **Step limit**: A `max_steps` parameter (default: 10,000) prevents runaway emulation.

## MCP Resources

| URI | Description |
|-----|-------------|
| `ghidra://binaries` | All binaries in the project |
| `ghidra://binary/{name}/info` | Binary metadata (arch, format, hashes, entry point) |
| `ghidra://binary/{name}/functions` | Full function list |
| `ghidra://binary/{name}/strings` | All defined strings |
| `ghidra://binary/{name}/imports` | All imported symbols |

## Code Mode

Code Mode is a token-efficient operating mode that replaces all 26 individual tool registrations with just 2 meta-tools: `search` and `execute`. This dramatically reduces the number of tool schemas sent to the LLM on every request, saving tokens and cost while preserving full analytical capability.

### Activation

```bash
# Docker
docker compose run --rm -i ghidra-mcp --mode code

# Local
ghidra-mcp --mode code
```

### Tools

#### `search(query?)`

Search the tool catalog. Returns tool names, descriptions, and full parameter signatures.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `query` | string | No | Substring to filter tool names and descriptions. Returns all 32 tools if omitted. |

**Example — find emulation tools:**
```
search(query="emulate")
# Returns:
# [
#   {"tool": "emulate_function", "description": "Emulate a function with optional arguments...",
#    "parameters": [{"name": "binary_name", "type": "string", "required": true}, ...]},
#   {"tool": "emulate_step", ...},
#   {"tool": "emulate_session_destroy", ...}
# ]
```

**Example — find tools related to entropy:**
```
search(query="entropy")
# Returns tools whose name or description contains "entropy"
```

#### `execute(method, params?)`

Execute any Ghidra analysis tool by name with the given parameters.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `method` | string | Yes | Tool name from the catalog (use `search` to discover available tools). |
| `params` | object | No | Keyword arguments as a dictionary. Omit for tools with no required params. |

**Example — list functions:**
```
execute(method="list_functions", params={"binary_name": "test.elf", "filter": "main", "limit": 10})
```

**Example — decompile a function:**
```
execute(method="decompile_function", params={"binary_name": "test.elf", "name_or_addr": "main"})
```

**Example — emulate a function:**
```
execute(method="emulate_function", params={"binary_name": "test.elf", "name_or_addr": "decrypt", "args": [1, 2]})
```

**Example — list all binaries (no params needed):**
```
execute(method="list_binaries")
```

### Error Handling

- **Unknown method**: Raises `ValueError` with the list of all available method names.
- **Missing required parameter**: Raises `TypeError` from the underlying Python method call.
- **Bridge errors**: `KeyError` (binary not found), `RuntimeError` (decompilation failure), etc. propagate directly with descriptive messages.

### When to Use Code Mode

| Scenario | Recommended Mode |
|----------|-----------------|
| Interactive exploration with Claude Desktop | Full |
| Automated analysis pipelines | Code |
| Cost-sensitive / high-volume usage | Code |
| First time using the server | Full |
| LLM with small context window | Code |

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
pytest tests/ -v

# 131 tests covering full mode, emulation, server, and code mode
```

## Architecture

```
MCP Client (Claude Desktop / Claude Code / OpenCode / Continue.dev / ...)
  ↕ stdio
FastMCP Server (server.py)
  ├── Full Mode: 26 @mcp.tool() + 5 @mcp.resource()
  └── Code Mode: search + execute → _dispatch()
        ↕
GhidraBridge (ghidra_bridge.py)
  ├── Programs cache     (dict[str, Program])
  ├── Decompilers cache  (dict[str, DecompInterface])
  └── Emulators cache    (dict[str, EmulatorHelper])
        ↕
PyGhidra / JPype / JVM
        ↕
Ghidra Java API
```

- **FastMCP** handles MCP protocol over stdio
- **GhidraBridge** manages the JVM lifecycle, Ghidra project, cached program handles, decompiler instances, and emulator sessions
- **PyGhidra** provides in-process access to Ghidra's Java API via JPype (no separate Ghidra process needed)
- **Code Mode dispatcher** (`_dispatch`) translates `execute(method, params)` calls into the appropriate bridge method invocations, handling parameter renaming and response wrapping

## License

MIT
