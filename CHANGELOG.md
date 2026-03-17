# Changelog

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
