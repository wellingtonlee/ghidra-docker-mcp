"""GhidraBridge — manages PyGhidra JVM lifecycle, Ghidra project, and program handles."""

from __future__ import annotations

import hashlib
import logging
import math
import os
from pathlib import Path
from typing import Any

import pyghidra

logger = logging.getLogger(__name__)

# Suspicious API categories for malware analysis
SUSPICIOUS_API_CATEGORIES: dict[str, list[str]] = {
    "process_injection": [
        "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
        "NtCreateThreadEx", "RtlCreateUserThread", "QueueUserAPC",
        "NtQueueApcThread", "SetThreadContext", "NtMapViewOfSection",
        "NtUnmapViewOfSection", "VirtualAlloc", "VirtualProtect",
        "NtAllocateVirtualMemory", "NtWriteVirtualMemory",
    ],
    "persistence": [
        "RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA",
        "RegCreateKeyExW", "CreateServiceA", "CreateServiceW",
        "StartServiceA", "StartServiceW", "SetWindowsHookExA",
        "SetWindowsHookExW", "SHSetValueA", "SHSetValueW",
    ],
    "crypto": [
        "CryptEncrypt", "CryptDecrypt", "CryptCreateHash",
        "CryptHashData", "CryptDeriveKey", "CryptGenKey",
        "CryptAcquireContextA", "CryptAcquireContextW",
        "BCryptEncrypt", "BCryptDecrypt", "BCryptGenerateSymmetricKey",
    ],
    "network": [
        "InternetOpenA", "InternetOpenW", "InternetOpenUrlA",
        "InternetOpenUrlW", "InternetConnectA", "InternetConnectW",
        "HttpOpenRequestA", "HttpOpenRequestW", "HttpSendRequestA",
        "HttpSendRequestW", "URLDownloadToFileA", "URLDownloadToFileW",
        "WSAStartup", "socket", "connect", "send", "recv",
        "getaddrinfo", "gethostbyname",
    ],
    "anti_debug": [
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess", "OutputDebugStringA",
        "OutputDebugStringW", "GetTickCount", "QueryPerformanceCounter",
        "NtSetInformationThread",
    ],
    "dynamic_loading": [
        "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA",
        "LoadLibraryExW", "GetProcAddress", "LdrLoadDll",
        "LdrGetProcedureAddress",
    ],
    "process_manipulation": [
        "OpenProcess", "TerminateProcess", "CreateProcessA",
        "CreateProcessW", "ShellExecuteA", "ShellExecuteW",
        "ShellExecuteExA", "ShellExecuteExW", "WinExec",
        "CreateProcessInternalW",
    ],
    "file_system": [
        "DeleteFileA", "DeleteFileW", "MoveFileA", "MoveFileW",
        "CopyFileA", "CopyFileW", "CreateFileA", "CreateFileW",
        "WriteFile", "ReadFile", "SetFileAttributesA",
        "SetFileAttributesW",
    ],
}


class GhidraBridge:
    """Manages Ghidra project, programs, and decompiler instances via PyGhidra."""

    def __init__(self, project_dir: str, project_name: str) -> None:
        self.project_dir = Path(project_dir)
        self.project_name = project_name
        self._project: Any = None
        self._programs: dict[str, Any] = {}
        self._decompilers: dict[str, Any] = {}
        self._flat_api: Any = None
        self._started = False

        self._analysis_timeout = int(
            os.environ.get("GHIDRA_ANALYSIS_TIMEOUT_SECONDS", "300")
        )
        max_heap = os.environ.get("GHIDRA_MAX_HEAP", "2g")
        self._vm_args = [f"-Xmx{max_heap}"]

    def start(self) -> None:
        """Start PyGhidra JVM and open/create the Ghidra project."""
        if self._started:
            return

        logger.info("Starting PyGhidra JVM...")
        pyghidra.start(vm_args=self._vm_args)
        self._started = True

        self.project_dir.mkdir(parents=True, exist_ok=True)

        from ghidra import GhidraProject  # type: ignore[import]

        project_path = self.project_dir / self.project_name
        gpr_file = project_path.with_suffix(".gpr")

        if gpr_file.exists():
            logger.info("Opening existing project: %s", self.project_name)
            self._project = GhidraProject.openProject(
                str(self.project_dir), self.project_name
            )
        else:
            logger.info("Creating new project: %s", self.project_name)
            self._project = GhidraProject.createProject(
                str(self.project_dir), self.project_name
            )

        logger.info("Ghidra project ready: %s", self.project_name)

    def _ensure_started(self) -> None:
        if not self._started:
            self.start()

    def import_binary(self, file_path: str, analyze: bool = True) -> dict[str, Any]:
        """Import a binary into the Ghidra project and optionally analyze it."""
        self._ensure_started()
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Binary not found: {file_path}")

        binary_name = path.name

        from java.io import File  # type: ignore[import]

        program = self._project.importProgram(File(str(path)))
        if program is None:
            raise RuntimeError(f"Failed to import binary: {file_path}")

        if analyze:
            from ghidra.program.util import GhidraProgramUtilities  # type: ignore[import]

            self._project.analyze(program)
            GhidraProgramUtilities.setAnalyzedFlag(program, True)

        self._programs[binary_name] = program
        self._init_decompiler(binary_name, program)

        return self.get_binary_info(binary_name)

    def _init_decompiler(self, binary_name: str, program: Any) -> None:
        """Initialize a cached decompiler for a program."""
        from ghidra.app.decompiler import DecompInterface  # type: ignore[import]

        decomp = DecompInterface()
        decomp.openProgram(program)
        self._decompilers[binary_name] = decomp

    def get_program(self, binary_name: str) -> Any:
        """Get an open program by name, raising if not found."""
        program = self._programs.get(binary_name)
        if program is None:
            available = list(self._programs.keys())
            raise KeyError(
                f"Binary '{binary_name}' not found. "
                f"Available binaries: {available}. Use list_binaries to see all."
            )
        return program

    def get_decompiler(self, binary_name: str) -> Any:
        """Get the cached decompiler for a program."""
        decomp = self._decompilers.get(binary_name)
        if decomp is None:
            program = self.get_program(binary_name)
            self._init_decompiler(binary_name, program)
            decomp = self._decompilers[binary_name]
        return decomp

    def list_binaries(self) -> list[str]:
        """List all imported binary names."""
        self._ensure_started()
        return list(self._programs.keys())

    def delete_binary(self, binary_name: str) -> None:
        """Remove a binary from the project and close its handles."""
        program = self.get_program(binary_name)

        decomp = self._decompilers.pop(binary_name, None)
        if decomp is not None:
            decomp.dispose()

        self._project.close(program)
        del self._programs[binary_name]

    def get_binary_info(self, binary_name: str) -> dict[str, Any]:
        """Get metadata about an imported binary."""
        program = self.get_program(binary_name)
        lang = program.getLanguage()
        memory = program.getMemory()

        file_path = None
        exe_path = program.getExecutablePath()
        if exe_path:
            file_path = exe_path

        md5 = program.getExecutableMD5()
        sha256 = program.getExecutableSHA256()

        return {
            "name": binary_name,
            "architecture": str(lang.getProcessor()),
            "address_size": lang.getLanguageDescription().getSize(),
            "endian": str(lang.getLanguageDescription().getEndian()),
            "format": str(program.getExecutableFormat()),
            "base_address": str(program.getImageBase()),
            "entry_points": [
                str(ep) for ep in program.getSymbolTable().getExternalEntryPointIterator()
            ],
            "md5": md5 if md5 else None,
            "sha256": sha256 if sha256 else None,
            "file_path": file_path,
            "num_functions": program.getFunctionManager().getFunctionCount(),
            "memory_size": memory.getSize(),
        }

    def list_functions(
        self,
        binary_name: str,
        offset: int = 0,
        limit: int = 100,
        filter_name: str | None = None,
    ) -> dict[str, Any]:
        """List functions in a binary with pagination and optional name filter."""
        program = self.get_program(binary_name)
        fm = program.getFunctionManager()

        functions = []
        total = 0
        idx = 0

        for func in fm.getFunctions(True):
            name = func.getName()
            if filter_name and filter_name.lower() not in name.lower():
                continue

            total += 1
            if idx < offset:
                idx += 1
                continue
            if len(functions) >= limit:
                idx += 1
                continue

            functions.append({
                "name": name,
                "address": str(func.getEntryPoint()),
                "size": func.getBody().getNumAddresses(),
                "is_thunk": func.isThunk(),
                "calling_convention": str(func.getCallingConventionName()),
                "parameter_count": func.getParameterCount(),
            })
            idx += 1

        return {"functions": functions, "total": total, "offset": offset, "limit": limit}

    def decompile_function(
        self, binary_name: str, name_or_addr: str
    ) -> dict[str, Any]:
        """Decompile a function by name or address."""
        program = self.get_program(binary_name)
        func = self._resolve_function(program, name_or_addr)
        if func is None:
            raise KeyError(
                f"Function '{name_or_addr}' not found in '{binary_name}'. "
                f"Try using list_functions to find available functions."
            )

        decomp = self.get_decompiler(binary_name)
        from ghidra.util.task import ConsoleTaskMonitor  # type: ignore[import]

        result = decomp.decompileFunction(func, self._analysis_timeout, ConsoleTaskMonitor())

        if result is None or not result.decompileCompleted():
            error_msg = result.getErrorMessage() if result else "Unknown error"
            raise RuntimeError(f"Decompilation failed: {error_msg}")

        decomp_func = result.getDecompiledFunction()
        c_code = decomp_func.getC() if decomp_func else ""

        return {
            "name": func.getName(),
            "address": str(func.getEntryPoint()),
            "decompiled_c": c_code,
            "signature": str(func.getSignature()),
        }

    def rename_function(
        self, binary_name: str, old_name: str, new_name: str
    ) -> dict[str, Any]:
        """Rename a function."""
        program = self.get_program(binary_name)
        func = self._resolve_function(program, old_name)
        if func is None:
            raise KeyError(f"Function '{old_name}' not found in '{binary_name}'.")

        from ghidra.program.model.symbol import SourceType  # type: ignore[import]

        tx_id = program.startTransaction("Rename function")
        try:
            func.setName(new_name, SourceType.USER_DEFINED)
            program.endTransaction(tx_id, True)
        except Exception:
            program.endTransaction(tx_id, False)
            raise

        return {
            "old_name": old_name,
            "new_name": new_name,
            "address": str(func.getEntryPoint()),
        }

    def _resolve_function(self, program: Any, name_or_addr: str) -> Any:
        """Resolve a function by name or hex address."""
        fm = program.getFunctionManager()

        # Try by name first
        for func in fm.getFunctions(True):
            if func.getName() == name_or_addr:
                return func

        # Try as hex address
        try:
            addr_str = name_or_addr.removeprefix("0x")
            addr_factory = program.getAddressFactory()
            addr = addr_factory.getDefaultAddressSpace().getAddress(int(addr_str, 16))
            func = fm.getFunctionAt(addr)
            if func is not None:
                return func
        except (ValueError, Exception):
            pass

        return None

    def list_strings(
        self,
        binary_name: str,
        min_length: int = 4,
        offset: int = 0,
        limit: int = 100,
    ) -> dict[str, Any]:
        """List defined strings in a binary."""
        program = self.get_program(binary_name)
        from ghidra.program.model.data import StringDataType  # type: ignore[import]

        listing = program.getListing()
        strings = []
        total = 0
        idx = 0

        for data in listing.getDefinedData(True):
            if not isinstance(data.getDataType(), StringDataType) and \
               "string" not in str(data.getDataType()).lower():
                continue

            value = data.getValue()
            if value is None:
                continue
            s = str(value)
            if len(s) < min_length:
                continue

            total += 1
            if idx < offset:
                idx += 1
                continue
            if len(strings) >= limit:
                idx += 1
                continue

            strings.append({
                "address": str(data.getAddress()),
                "value": s,
                "length": len(s),
            })
            idx += 1

        return {"strings": strings, "total": total, "offset": offset, "limit": limit}

    def search_strings(
        self, binary_name: str, pattern: str, regex: bool = False
    ) -> list[dict[str, Any]]:
        """Search strings matching a pattern (substring or regex)."""
        import re

        all_strings = self.list_strings(binary_name, min_length=1, offset=0, limit=999999)
        results = []

        if regex:
            compiled = re.compile(pattern, re.IGNORECASE)
            for s in all_strings["strings"]:
                if compiled.search(s["value"]):
                    results.append(s)
        else:
            pattern_lower = pattern.lower()
            for s in all_strings["strings"]:
                if pattern_lower in s["value"].lower():
                    results.append(s)

        return results

    def list_imports(
        self, binary_name: str, filter_name: str | None = None
    ) -> list[dict[str, Any]]:
        """List imported symbols."""
        program = self.get_program(binary_name)
        sym_table = program.getSymbolTable()
        from ghidra.program.model.symbol import SymbolType  # type: ignore[import]

        imports = []
        for sym in sym_table.getExternalSymbols():
            name = sym.getName()
            if filter_name and filter_name.lower() not in name.lower():
                continue

            ext_loc = sym.getExternalLocation() if hasattr(sym, 'getExternalLocation') else None
            library = None
            if ext_loc:
                library = str(ext_loc.getLibraryName())

            imports.append({
                "name": name,
                "address": str(sym.getAddress()),
                "library": library,
                "type": str(sym.getSymbolType()),
            })

        return imports

    def list_exports(
        self, binary_name: str, filter_name: str | None = None
    ) -> list[dict[str, Any]]:
        """List exported symbols."""
        program = self.get_program(binary_name)
        sym_table = program.getSymbolTable()

        exports = []
        for addr in sym_table.getExternalEntryPointIterator():
            sym = sym_table.getPrimarySymbol(addr)
            if sym is None:
                continue
            name = sym.getName()
            if filter_name and filter_name.lower() not in name.lower():
                continue

            exports.append({
                "name": name,
                "address": str(addr),
                "type": str(sym.getSymbolType()),
            })

        return exports

    def get_xrefs(
        self, binary_name: str, address: str, direction: str = "both"
    ) -> dict[str, Any]:
        """Get cross-references to/from an address."""
        program = self.get_program(binary_name)
        ref_mgr = program.getReferenceManager()

        addr_str = address.removeprefix("0x")
        addr_factory = program.getAddressFactory()
        addr = addr_factory.getDefaultAddressSpace().getAddress(int(addr_str, 16))

        result: dict[str, Any] = {"address": address, "direction": direction}

        if direction in ("to", "both"):
            refs_to = []
            for ref in ref_mgr.getReferencesTo(addr):
                refs_to.append({
                    "from_address": str(ref.getFromAddress()),
                    "type": str(ref.getReferenceType()),
                    "is_call": ref.getReferenceType().isCall(),
                })
            result["references_to"] = refs_to

        if direction in ("from", "both"):
            refs_from = []
            for ref in ref_mgr.getReferencesFrom(addr):
                refs_from.append({
                    "to_address": str(ref.getToAddress()),
                    "type": str(ref.getReferenceType()),
                    "is_call": ref.getReferenceType().isCall(),
                })
            result["references_from"] = refs_from

        return result

    def search_bytes(
        self, binary_name: str, hex_pattern: str, max_results: int = 50
    ) -> list[dict[str, Any]]:
        """Search for a byte pattern (hex string, '??' for wildcards)."""
        program = self.get_program(binary_name)
        memory = program.getMemory()

        from ghidra.util.task import ConsoleTaskMonitor  # type: ignore[import]

        # Convert hex pattern to Ghidra search format
        # Ghidra uses '.' for wildcard nibbles
        ghidra_pattern = hex_pattern.replace("??", "..")
        ghidra_pattern = ghidra_pattern.replace(" ", "")

        start_addr = memory.getMinAddress()
        results = []

        from ghidra.program.model.mem import MemoryBytePatternSearcher  # type: ignore[import]
        # Use simple iteration approach with findBytes
        addr = start_addr
        search_bytes_arr = []
        mask_arr = []

        # Parse hex pattern into bytes and mask
        clean = hex_pattern.replace(" ", "")
        i = 0
        while i < len(clean):
            pair = clean[i:i+2]
            if pair == "??" or pair == "..":
                search_bytes_arr.append(0)
                mask_arr.append(0)
            else:
                search_bytes_arr.append(int(pair, 16))
                mask_arr.append(0xFF)
            i += 2

        import jarray  # type: ignore[import]
        search_bytes_j = jarray.array([x & 0xFF for x in search_bytes_arr], 'b')
        mask_bytes_j = jarray.array([x & 0xFF for x in mask_arr], 'b')

        monitor = ConsoleTaskMonitor()
        addr = memory.findBytes(
            start_addr, search_bytes_j, mask_bytes_j, True, monitor
        )

        while addr is not None and len(results) < max_results:
            # Find which function contains this address
            func = program.getFunctionManager().getFunctionContaining(addr)
            results.append({
                "address": str(addr),
                "function": func.getName() if func else None,
            })
            # Search from next address
            next_addr = addr.add(1)
            addr = memory.findBytes(
                next_addr, search_bytes_j, mask_bytes_j, True, monitor
            )

        return results

    def get_entropy(self, binary_name: str) -> dict[str, Any]:
        """Calculate per-section Shannon entropy for packing detection."""
        program = self.get_program(binary_name)
        memory = program.getMemory()

        sections = []
        overall_bytes = bytearray()

        for block in memory.getBlocks():
            if not block.isInitialized():
                continue

            size = block.getSize()
            if size == 0:
                continue

            # Read block bytes
            data = bytearray(size)
            try:
                block.getBytes(block.getStart(), data)
            except Exception:
                continue

            entropy = self._shannon_entropy(data)
            overall_bytes.extend(data)

            sections.append({
                "name": block.getName(),
                "address": str(block.getStart()),
                "size": size,
                "entropy": round(entropy, 4),
            })

        overall_entropy = self._shannon_entropy(overall_bytes) if overall_bytes else 0.0

        # Heuristic: overall entropy > 7.0 suggests packing
        packed_likely = overall_entropy > 7.0

        return {
            "binary_name": binary_name,
            "overall_entropy": round(overall_entropy, 4),
            "packed_likely": packed_likely,
            "sections": sections,
        }

    @staticmethod
    def _shannon_entropy(data: bytes | bytearray) -> float:
        """Calculate Shannon entropy of a byte sequence."""
        if not data:
            return 0.0

        freq = [0] * 256
        for b in data:
            freq[b] += 1

        length = len(data)
        entropy = 0.0
        for count in freq:
            if count == 0:
                continue
            p = count / length
            entropy -= p * math.log2(p)

        return entropy

    def detect_suspicious_apis(self, binary_name: str) -> dict[str, Any]:
        """Detect suspicious API imports categorized by behavior."""
        imports = self.list_imports(binary_name)
        import_names = {imp["name"] for imp in imports}

        findings: dict[str, list[dict[str, Any]]] = {}
        total_suspicious = 0

        for category, apis in SUSPICIOUS_API_CATEGORIES.items():
            matches = []
            for api in apis:
                if api in import_names:
                    # Find the import details
                    for imp in imports:
                        if imp["name"] == api:
                            matches.append(imp)
                            break
            if matches:
                findings[category] = matches
                total_suspicious += len(matches)

        return {
            "binary_name": binary_name,
            "total_suspicious": total_suspicious,
            "categories": findings,
        }

    def get_sections(self, binary_name: str) -> list[dict[str, Any]]:
        """Get sections with permissions, entropy, and anomaly flags."""
        program = self.get_program(binary_name)
        memory = program.getMemory()

        known_section_names = {
            ".text", ".data", ".bss", ".rdata", ".rodata", ".rsrc",
            ".reloc", ".idata", ".edata", ".tls", ".pdata", ".debug",
            ".got", ".plt", ".init", ".fini", ".ctors", ".dtors",
            ".dynamic", ".dynsym", ".dynstr", ".gnu.hash",
        }

        sections = []
        for block in memory.getBlocks():
            name = block.getName()
            size = block.getSize()

            # Calculate entropy for initialized blocks
            entropy = 0.0
            if block.isInitialized() and size > 0:
                data = bytearray(size)
                try:
                    block.getBytes(block.getStart(), data)
                    entropy = self._shannon_entropy(data)
                except Exception:
                    pass

            r = block.isRead()
            w = block.isWrite()
            x = block.isExecute()

            anomalies = []
            if w and x:
                anomalies.append("W+X (writable and executable)")
            if name not in known_section_names and not name.startswith("."):
                anomalies.append(f"unusual section name: {name}")
            if entropy > 7.0 and size > 512:
                anomalies.append("high entropy (possibly packed/encrypted)")
            if x and entropy < 1.0 and size > 512:
                anomalies.append("very low entropy for executable section")

            sections.append({
                "name": name,
                "address": str(block.getStart()),
                "size": size,
                "permissions": f"{'r' if r else '-'}{'w' if w else '-'}{'x' if x else '-'}",
                "entropy": round(entropy, 4),
                "initialized": block.isInitialized(),
                "anomalies": anomalies,
            })

        return sections

    def close(self) -> None:
        """Close all programs, decompilers, and the project."""
        for name, decomp in self._decompilers.items():
            try:
                decomp.dispose()
            except Exception:
                logger.warning("Failed to dispose decompiler for %s", name)

        self._decompilers.clear()

        if self._project is not None:
            try:
                self._project.close()
            except Exception:
                logger.warning("Failed to close project")

        self._programs.clear()
        self._project = None
