# Changelog

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
