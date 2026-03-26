# Changelog

## [0.2.3] - 2026-03-26

### Added

- Client configuration examples for Claude Code, OpenCode, and Continue.dev in README.
- Consolidated all MCP client configs into a dedicated "Client Configuration" section.

## [0.2.2] - 2026-03-17

### Fixed

- `import_binary` crashed on arm64 Linux with `Failed to import 'ghidra.util.Platform'`. The `Platform` Java enum's static initializer fails when Ghidra has no matching enum value for the host architecture. Since the import is only used for startup logging, it is now wrapped in `try/except` with a warning that includes `arch`, `JAVA_HOME`, and `GHIDRA_INSTALL_DIR`.
- **BLOCKING**: Decompiler not found on Apple Silicon (arm64). `JAVA_HOME` was hardcoded to `java-21-openjdk-amd64` in the Dockerfile, breaking JVM init on arm64 and preventing Ghidra's `Application` framework from registering modules. Now uses an architecture-neutral symlink.
- Dockerfile build-time verification: fails fast if the decompiler binary is missing for the target architecture instead of silently continuing.
- Dockerfile now builds the decompiler from source on arm64 when pre-built binary is absent (Ghidra releases don't include `linux_arm_64` binaries).
- `entrypoint.sh`: auto-detects `JAVA_HOME` at runtime if the configured path doesn't exist.
- `ghidra_bridge.py`: logs `Platform` and `JAVA_HOME` at startup; decompiler-not-found errors now include platform, expected path, and available `os/` directories.

## [0.2.1] - 2026-03-17

### Fixed

- **BLOCKING**: `get_sections` and `get_entropy` failed with "Class must be array type" because `block.getSize()` returns a JPype-wrapped Java `long`. `_java_byte_array` now casts non-sequence args to Python `int`.
- **BLOCKING**: `get_sections`, `get_entropy`, `search_bytes`, `get_memory_bytes` crashed with `No module named 'jarray'`. PyGhidra 3.0 uses JPype (CPython), not Jython — replaced all `jarray` usage with `jpype.JArray(jpype.JByte)`.
- **BLOCKING**: `decompile_function` silently failed (empty error message). `DecompileOptions` were never set on `DecompInterface`, and `openProgram()` return value was unchecked. Now sets options and verifies program opened successfully.
- **BLOCKING**: `decompile_function` raised "Decompiler failed to open program" even on success. JPype returns `None` for Java `synchronized boolean` methods; `not None` evaluated `True`, triggering a false error. Now treats `None` as success and only fails on explicit `False`. Also loads program-specific decompiler settings via `grabFromProgram()` and includes `getLastMessage()` diagnostics on real failures.
- **BLOCKING**: `decompile_function` failed with "Could not find decompiler executable" because `HeadlessPyGhidraLauncher` was created without an explicit `install_dir`, relying on auto-detection that fails when PyGhidra is installed from PyPI. Now passes `GHIDRA_INSTALL_DIR` env var to the launcher. Dockerfile also `chmod +x`es the native decompiler binaries after extraction.
- Improved decompilation error messages to include function name and binary name.
- `import_binary` no longer fails when decompiler init fails — decompiler is now best-effort during import and retried lazily on first `decompile_function` call.

## [0.2.0] - 2026-03-17

### Added

- **`get_memory_bytes`** — Read raw bytes from an address with hex/ascii output and section identification.
- **`search_instructions`** — Regex search over disassembly mnemonics and operands.
- **`get_function_summary`** — Rich function metadata (parameters, callees, callers, referenced strings, cyclomatic complexity) without decompilation.
- **`get_basic_blocks`** — Control-flow graph basic blocks with instructions and successor/predecessor edges.
- **`get_call_graph`** — Function call graph with BFS depth control, supporting callees/callers/both directions.
- Tests for all 5 new tools plus binary-not-found edge cases.

## [0.1.3] - 2026-03-17

### Fixed

- **BLOCKING**: `setAnalyzedFlag(program, True)` removed in Ghidra 12.x. Replaced with `markProgramAnalyzed(program)`.

## [0.1.2] - 2026-03-17

### Fixed

- **BLOCKING**: `createProject` call missing required 3rd `boolean` parameter (overwrite flag), causing `No matching overloads found` error on import.

## [0.1.1] - 2026-03-17

### Fixed

- **BLOCKING**: `import_binary` failed because `GhidraProject` was imported from `ghidra` (wrong) instead of `ghidra.base.project`.
- **BLOCKING**: `start()` used wrong PyGhidra API (`pyghidra.start(vm_args=...)` doesn't accept `vm_args`). Now uses `HeadlessPyGhidraLauncher` directly.
- `get_entropy()` / `get_sections()`: Python `bytearray` not writable by Java `getBytes()` — entropy was always 0. Now uses `jarray.zeros()`.
- `search_bytes()`: Java signed byte overflow for values > 127. Now converts unsigned to signed before `jarray` creation.
- `list_imports()`: `getExternalLocation()` doesn't exist on Symbol — library was always `None`. Now uses `getParentNamespace().getName()`.
- `list_strings()`: `StringDataType` missed unicode/pascal strings. Now uses `AbstractStringDataType`.
- Removed dead code: unused `ghidra_pattern` variable, `MemoryBytePatternSearcher` import, `SymbolType` import, top-level `pyghidra`/`hashlib` imports.

## [0.1.0] - 2026-03-16

### Added

- Initial release of Ghidra MCP Server.
- **14 MCP tools**: import/upload/list/delete binaries, list/decompile/rename functions, list/search strings, list imports/exports, get cross-references, search bytes, get entropy, detect suspicious APIs, get sections.
- **5 MCP resources**: binaries list, binary info, functions, strings, imports.
- **GhidraBridge**: PyGhidra-based JVM lifecycle management with cached decompilers and multi-binary project support.
- **Malware analysis**: Shannon entropy per section with packing detection, suspicious API categorization (8 categories), section anomaly detection (W+X, unusual names, high entropy).
- **Docker support**: Ubuntu 24.04 slim base, JDK 21, Ghidra 12.0.4, stdio transport.
- **docker-compose.yml**: stdio transport, volume mounts, 4GB memory limit.
- **Test suite**: Unit tests with mocked GhidraBridge (no Ghidra/JVM required).
