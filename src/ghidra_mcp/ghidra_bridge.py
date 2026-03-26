"""GhidraBridge — manages PyGhidra JVM lifecycle, Ghidra project, and program handles."""

from __future__ import annotations

import logging
import math
import os
from pathlib import Path
from typing import Any

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


def _serialize_result(obj: Any, depth: int = 0, max_depth: int = 3) -> Any:
    """Convert Java objects and complex Python objects to JSON-serializable types."""
    if obj is None:
        return None
    if isinstance(obj, (str, int, float, bool)):
        return obj
    if isinstance(obj, (list, tuple)):
        return [_serialize_result(item, depth + 1, max_depth) for item in obj]
    if isinstance(obj, dict):
        return {str(k): _serialize_result(v, depth + 1, max_depth) for k, v in obj.items()}

    # Java objects via JPype
    try:
        import jpype  # type: ignore[import]
        if jpype.isJVMStarted():
            obj_str = str(obj)
            # Java String
            if isinstance(obj, jpype.JString):
                return str(obj)
            # Java Number (BigInteger, Long, Integer, etc.)
            try:
                if hasattr(obj, "longValue"):
                    return int(str(obj))
            except Exception:
                pass
            # Java Boolean
            try:
                if hasattr(obj, "booleanValue"):
                    return bool(obj.booleanValue())
            except Exception:
                pass
            # Java arrays and iterables
            if depth < max_depth:
                try:
                    if hasattr(obj, "__len__") and hasattr(obj, "__getitem__"):
                        return [_serialize_result(obj[i], depth + 1, max_depth) for i in range(len(obj))]
                except Exception:
                    pass
                try:
                    if hasattr(obj, "iterator"):
                        return [_serialize_result(item, depth + 1, max_depth) for item in obj]
                except Exception:
                    pass
            # Default: structured representation
            try:
                class_name = str(obj.getClass().getName())
                return {"_java_class": class_name, "_str": obj_str}
            except Exception:
                return obj_str
    except ImportError:
        pass

    return str(obj)


class GhidraBridge:
    """Manages Ghidra project, programs, and decompiler instances via PyGhidra."""

    def __init__(self, project_dir: str, project_name: str) -> None:
        self.project_dir = Path(project_dir).resolve()
        self.project_name = project_name
        self._project: Any = None
        self._programs: dict[str, Any] = {}
        self._decompilers: dict[str, Any] = {}
        self._emulators: dict[str, Any] = {}  # key: "binary:func" -> EmulatorHelper
        self._flat_api: Any = None
        self._started = False

        # Server connectivity state
        self._server: Any = None
        self._server_host: str | None = None
        self._server_port: int | None = None
        self._server_repos: dict[str, Any] = {}
        self._server_files: dict[str, Any] = {}  # binary_name -> DomainFile
        self._server_project: Any = None

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
        from pyghidra.launcher import HeadlessPyGhidraLauncher  # type: ignore[import]

        install_dir = os.environ.get("GHIDRA_INSTALL_DIR")
        launcher = HeadlessPyGhidraLauncher(install_dir=install_dir)
        launcher.add_vmargs(*self._vm_args)
        launcher.start()
        self._started = True

        try:
            from ghidra.util import Platform  # type: ignore[import]
            logger.info("Platform: %s, JAVA_HOME: %s", Platform.CURRENT_PLATFORM, os.environ.get("JAVA_HOME", "<not set>"))
        except Exception:
            import platform as _platform
            logger.warning(
                "Could not import ghidra.util.Platform (arch=%s). "
                "JAVA_HOME: %s, GHIDRA_INSTALL_DIR: %s",
                _platform.machine(),
                os.environ.get("JAVA_HOME", "<not set>"),
                os.environ.get("GHIDRA_INSTALL_DIR", "<not set>"),
            )

        self._init_project()

    def _init_project(self) -> None:
        """Initialize or re-initialize the Ghidra project."""
        self.project_dir.mkdir(parents=True, exist_ok=True)

        from ghidra.base.project import GhidraProject  # type: ignore[import]

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
                str(self.project_dir), self.project_name, True
            )

        logger.info("Ghidra project ready: %s", self.project_name)

    def _ensure_started(self) -> None:
        if not self._started:
            self.start()
        if self._project is None:
            self._init_project()

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
            GhidraProgramUtilities.markProgramAnalyzed(program)

        self._programs[binary_name] = program
        try:
            self._init_decompiler(binary_name, program)
        except Exception:
            logger.warning("Decompiler init failed for '%s'; will retry on first decompile call", binary_name)

        return self.get_binary_info(binary_name)

    def _init_decompiler(self, binary_name: str, program: Any) -> None:
        """Initialize a cached decompiler for a program."""
        from ghidra.app.decompiler import DecompInterface, DecompileOptions  # type: ignore[import]

        decomp = DecompInterface()
        options = DecompileOptions()
        options.grabFromProgram(program)
        decomp.setOptions(options)
        result = decomp.openProgram(program)
        # JPype may return None for Java boolean on success; only explicit False is failure
        if result is not None and not bool(result):
            msg = decomp.getLastMessage() or "unknown reason"
            hint = ""
            if "Could not find decompiler executable" in msg:
                ghidra_dir = os.environ.get("GHIDRA_INSTALL_DIR", "<not set>")
                try:
                    from ghidra.util import Platform as GhidraPlatform  # type: ignore[import]
                    platform_dir = GhidraPlatform.CURRENT_PLATFORM.getDirectoryName()
                    expected = Path(ghidra_dir) / "Ghidra" / "Features" / "Decompiler" / "os" / platform_dir / "decompile"
                    decomp_os_dir = Path(ghidra_dir) / "Ghidra" / "Features" / "Decompiler" / "os"
                    available = list(decomp_os_dir.iterdir()) if decomp_os_dir.is_dir() else []
                    hint = (
                        f"\n  GHIDRA_INSTALL_DIR={ghidra_dir}"
                        f"\n  JAVA_HOME={os.environ.get('JAVA_HOME', '<not set>')}"
                        f"\n  Platform: {platform_dir}"
                        f"\n  Expected: {expected} (exists={expected.exists()})"
                        f"\n  Available os/ dirs: {[d.name for d in available]}"
                    )
                except Exception:
                    hint = (
                        f"\n  GHIDRA_INSTALL_DIR={ghidra_dir}"
                        f"\n  JAVA_HOME={os.environ.get('JAVA_HOME', '<not set>')}"
                        f"\n  Verify the native decompiler binary exists at:"
                        f"\n    <GHIDRA_INSTALL_DIR>/Ghidra/Features/Decompiler/os/<platform>/decompile"
                    )
            raise RuntimeError(
                f"Decompiler failed to open program '{binary_name}': {msg}{hint}"
            )
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

        keys_to_remove = [k for k in self._emulators if k.startswith(f"{binary_name}:")]
        for key in keys_to_remove:
            emu = self._emulators.pop(key)
            try:
                emu.dispose()
            except Exception:
                logger.warning("Failed to dispose emulator session %s", key)

        # Undo server checkout if this binary came from a server
        domain_file = self._server_files.pop(binary_name, None)
        if domain_file is not None:
            try:
                if domain_file.isCheckedOut():
                    from ghidra.util.task import ConsoleTaskMonitor  # type: ignore[import]
                    domain_file.undoCheckout(False, ConsoleTaskMonitor())
            except Exception:
                logger.warning("Failed to undo checkout for '%s'", binary_name)

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
            raise RuntimeError(
                f"Decompilation failed for '{name_or_addr}' in '{binary_name}': {error_msg}"
            )

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

    def rename_variable(
        self, binary_name: str, function_name: str, old_name: str, new_name: str
    ) -> dict[str, Any]:
        """Rename a variable (parameter or local) within a function."""
        program = self.get_program(binary_name)
        func = self._resolve_function(program, function_name)
        if func is None:
            raise KeyError(f"Function '{function_name}' not found in '{binary_name}'.")

        target_var = None
        for var in func.getAllVariables():
            if var.getName() == old_name:
                target_var = var
                break

        if target_var is None:
            raise KeyError(
                f"Variable '{old_name}' not found in function '{function_name}' of '{binary_name}'."
            )

        from ghidra.program.model.symbol import SourceType  # type: ignore[import]

        variable_type = "parameter" if target_var.isParameter() else "local"
        storage = str(target_var.getVariableStorage())

        tx_id = program.startTransaction("Rename variable")
        try:
            target_var.setName(new_name, SourceType.USER_DEFINED)
            program.endTransaction(tx_id, True)
        except Exception:
            program.endTransaction(tx_id, False)
            raise

        return {
            "function": func.getName(),
            "old_name": old_name,
            "new_name": new_name,
            "variable_type": variable_type,
            "storage": storage,
        }

    def rename_label(
        self, binary_name: str, old_name: str, new_name: str
    ) -> dict[str, Any]:
        """Rename a symbol/label in the program's symbol table."""
        program = self.get_program(binary_name)
        sym_table = program.getSymbolTable()

        symbol = None
        symbols = sym_table.getGlobalSymbols(old_name)
        if symbols and len(symbols) > 0:
            symbol = symbols[0]

        if symbol is None:
            try:
                addr_str = old_name.removeprefix("0x")
                addr_factory = program.getAddressFactory()
                addr = addr_factory.getDefaultAddressSpace().getAddress(int(addr_str, 16))
                symbol = sym_table.getPrimarySymbol(addr)
            except (ValueError, Exception):
                pass

        if symbol is None:
            raise KeyError(f"Symbol/label '{old_name}' not found in '{binary_name}'.")

        from ghidra.program.model.symbol import SourceType  # type: ignore[import]

        old_sym_name = symbol.getName()
        address = str(symbol.getAddress())
        symbol_type = str(symbol.getSymbolType())

        tx_id = program.startTransaction("Rename label")
        try:
            symbol.setName(new_name, SourceType.USER_DEFINED)
            program.endTransaction(tx_id, True)
        except Exception:
            program.endTransaction(tx_id, False)
            raise

        return {
            "old_name": old_sym_name,
            "new_name": new_name,
            "address": address,
            "symbol_type": symbol_type,
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
        from ghidra.program.model.data import AbstractStringDataType  # type: ignore[import]

        listing = program.getListing()
        strings = []
        total = 0
        idx = 0

        for data in listing.getDefinedData(True):
            if not isinstance(data.getDataType(), AbstractStringDataType) and \
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
        imports = []
        for sym in sym_table.getExternalSymbols():
            name = sym.getName()
            if filter_name and filter_name.lower() not in name.lower():
                continue

            library = None
            parent_ns = sym.getParentNamespace()
            if parent_ns is not None:
                library = parent_ns.getName()

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

        start_addr = memory.getMinAddress()
        results = []

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

        search_bytes_j = self._java_byte_array(
            [v - 256 if v > 127 else v for v in search_bytes_arr]
        )
        mask_bytes_j = self._java_byte_array(
            [v - 256 if v > 127 else v for v in mask_arr]
        )

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

            # Read block bytes — must use Java byte array for getBytes()
            data = self._java_byte_array(size)
            try:
                block.getBytes(block.getStart(), data)
            except Exception:
                continue

            py_data = bytes(v & 0xFF for v in data)
            entropy = self._shannon_entropy(py_data)
            overall_bytes.extend(py_data)

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
    def _java_byte_array(size_or_values):
        """Create a Java byte[] via JPype. Pass int for zeros, list for values.

        Automatically converts unsigned bytes (0-255) to Java signed range (-128 to 127).
        """
        import jpype  # type: ignore[import]
        if not isinstance(size_or_values, (list, tuple)):
            size_or_values = int(size_or_values)
            return jpype.JArray(jpype.JByte)(size_or_values)
        signed = [(v - 256) if v > 127 else v for v in size_or_values]
        return jpype.JArray(jpype.JByte)(signed)

    @staticmethod
    def _read_register_int(emu: Any, reg: Any) -> int:
        """Read a register value as Python int. Handles Java BigInteger from JPype."""
        val = emu.readRegister(reg)
        return int(str(val))

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
                data = self._java_byte_array(size)
                try:
                    block.getBytes(block.getStart(), data)
                    entropy = self._shannon_entropy(bytes(v & 0xFF for v in data))
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

    # ── Advanced analysis methods ─────────────────────────────────

    def get_memory_bytes(
        self, binary_name: str, address: str, size: int = 256
    ) -> dict[str, Any]:
        """Read raw bytes from an address."""
        size = min(size, 4096)
        program = self.get_program(binary_name)
        memory = program.getMemory()

        addr_str = address.removeprefix("0x")
        addr_factory = program.getAddressFactory()
        addr = addr_factory.getDefaultAddressSpace().getAddress(int(addr_str, 16))

        buf = self._java_byte_array(size)
        truncated = False
        try:
            memory.getBytes(addr, buf)
        except Exception:
            # Partial read — find how many bytes we can actually get
            truncated = True
            for i in range(size):
                try:
                    memory.getByte(addr.add(i))
                except Exception:
                    buf = self._java_byte_array(i)
                    if i > 0:
                        memory.getBytes(addr, buf)
                    size = i
                    break

        py_bytes = bytes(v & 0xFF for v in buf)
        hex_str = py_bytes.hex()
        ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in py_bytes)

        # Find containing section
        block = memory.getBlock(addr)
        containing_section = block.getName() if block else None

        result: dict[str, Any] = {
            "address": address,
            "size": size,
            "hex": hex_str,
            "ascii": ascii_str,
            "containing_section": containing_section,
        }
        if truncated:
            result["truncated"] = True
        return result

    def search_instructions(
        self,
        binary_name: str,
        mnemonic_pattern: str,
        operand_pattern: str | None = None,
        max_results: int = 100,
    ) -> dict[str, Any]:
        """Search instructions by mnemonic regex, optionally matching operands."""
        import re

        program = self.get_program(binary_name)
        listing = program.getListing()
        fm = program.getFunctionManager()

        mnemonic_re = re.compile(mnemonic_pattern, re.IGNORECASE)
        operand_re = re.compile(operand_pattern, re.IGNORECASE) if operand_pattern else None

        matches = []
        total = 0

        for instr in listing.getInstructions(True):
            mnemonic = instr.getMnemonicString()
            if not mnemonic_re.search(mnemonic):
                continue

            if operand_re:
                full_text = str(instr)
                # Operand text is everything after the mnemonic
                operand_text = full_text[len(mnemonic):].strip()
                if not operand_re.search(operand_text):
                    continue

            total += 1
            if len(matches) < max_results:
                addr = instr.getAddress()
                func = fm.getFunctionContaining(addr)
                full_text = str(instr)
                operand_text = full_text[len(mnemonic):].strip()
                matches.append({
                    "address": str(addr),
                    "mnemonic": mnemonic,
                    "operands": operand_text,
                    "full_text": full_text,
                    "function": func.getName() if func else None,
                })

        return {
            "pattern": mnemonic_pattern,
            "operand_pattern": operand_pattern,
            "matches": matches,
            "total": total,
        }

    def get_function_summary(
        self, binary_name: str, name_or_addr: str
    ) -> dict[str, Any]:
        """Get rich function metadata without decompilation."""
        program = self.get_program(binary_name)
        func = self._resolve_function(program, name_or_addr)
        if func is None:
            raise KeyError(
                f"Function '{name_or_addr}' not found in '{binary_name}'. "
                f"Try using list_functions to find available functions."
            )

        from ghidra.util.task import ConsoleTaskMonitor  # type: ignore[import]

        monitor = ConsoleTaskMonitor()

        # Basic metadata
        params = []
        for p in func.getParameters():
            params.append({
                "name": p.getName(),
                "type": str(p.getDataType()),
                "storage": str(p.getVariableStorage()),
            })

        # Callees and callers
        called = [
            {"name": f.getName(), "address": str(f.getEntryPoint())}
            for f in func.getCalledFunctions(monitor)
        ]
        callers = [
            {"name": f.getName(), "address": str(f.getEntryPoint())}
            for f in func.getCallingFunctions(monitor)
        ]

        # Referenced strings
        listing = program.getListing()
        ref_mgr = program.getReferenceManager()
        referenced_strings = []
        body = func.getBody()

        for addr_range in body:
            addr = addr_range.getMinAddress()
            while addr is not None and addr.compareTo(addr_range.getMaxAddress()) <= 0:
                for ref in ref_mgr.getReferencesFrom(addr):
                    to_addr = ref.getToAddress()
                    data = listing.getDefinedDataAt(to_addr)
                    if data is not None and "string" in str(data.getDataType()).lower():
                        val = data.getValue()
                        if val is not None:
                            referenced_strings.append({
                                "address": str(to_addr),
                                "value": str(val),
                            })
                addr = addr.next()

        # Instruction count and cyclomatic complexity
        instruction_count = 0
        conditional_branches = 0
        for instr in listing.getInstructions(body, True):
            instruction_count += 1
            if instr.getFlowType().isConditional():
                conditional_branches += 1
        cyclomatic_complexity = conditional_branches + 1

        return {
            "name": func.getName(),
            "address": str(func.getEntryPoint()),
            "size": func.getBody().getNumAddresses(),
            "calling_convention": str(func.getCallingConventionName()),
            "signature": str(func.getSignature()),
            "parameters": params,
            "return_type": str(func.getReturnType()),
            "local_variable_count": len(func.getAllVariables()) - len(func.getParameters()),
            "stack_frame_size": func.getStackFrame().getFrameSize(),
            "is_thunk": func.isThunk(),
            "called_functions": called,
            "calling_functions": callers,
            "referenced_strings": referenced_strings,
            "instruction_count": instruction_count,
            "cyclomatic_complexity": cyclomatic_complexity,
        }

    def get_basic_blocks(
        self, binary_name: str, name_or_addr: str
    ) -> dict[str, Any]:
        """Get control-flow graph basic blocks for a function."""
        program = self.get_program(binary_name)
        func = self._resolve_function(program, name_or_addr)
        if func is None:
            raise KeyError(
                f"Function '{name_or_addr}' not found in '{binary_name}'. "
                f"Try using list_functions to find available functions."
            )

        from ghidra.program.model.block import BasicBlockModel  # type: ignore[import]
        from ghidra.util.task import ConsoleTaskMonitor  # type: ignore[import]

        monitor = ConsoleTaskMonitor()
        block_model = BasicBlockModel(program)
        listing = program.getListing()
        func_body = func.getBody()

        blocks = []
        block_iter = block_model.getCodeBlocksContaining(func_body, monitor)

        while block_iter.hasNext():
            block = block_iter.next()
            start = block.getMinAddress()
            end = block.getMaxAddress()

            # Instructions (capped at 50)
            instructions = []
            for instr in listing.getInstructions(block, True):
                if len(instructions) >= 50:
                    break
                instructions.append({
                    "address": str(instr.getAddress()),
                    "text": str(instr),
                })

            # Successors
            successors = []
            dest_iter = block.getDestinations(monitor)
            while dest_iter.hasNext():
                dest = dest_iter.next()
                dest_addr = dest.getDestinationAddress()
                if func_body.contains(dest_addr):
                    successors.append(str(dest_addr))

            # Predecessors
            predecessors = []
            src_iter = block.getSources(monitor)
            while src_iter.hasNext():
                src = src_iter.next()
                src_addr = src.getSourceAddress()
                if func_body.contains(src_addr):
                    predecessors.append(str(src_addr))

            blocks.append({
                "start": str(start),
                "end": str(end),
                "size": block.getNumAddresses(),
                "instruction_count": len(instructions),
                "instructions": instructions,
                "successors": successors,
                "predecessors": predecessors,
            })

        return {
            "function": func.getName(),
            "address": str(func.getEntryPoint()),
            "total_blocks": len(blocks),
            "blocks": blocks,
        }

    def get_call_graph(
        self,
        binary_name: str,
        name_or_addr: str,
        depth: int = 2,
        direction: str = "callees",
    ) -> dict[str, Any]:
        """Get function call graph with BFS depth control."""
        depth = min(depth, 10)
        program = self.get_program(binary_name)
        func = self._resolve_function(program, name_or_addr)
        if func is None:
            raise KeyError(
                f"Function '{name_or_addr}' not found in '{binary_name}'. "
                f"Try using list_functions to find available functions."
            )

        from collections import deque

        from ghidra.util.task import ConsoleTaskMonitor  # type: ignore[import]

        monitor = ConsoleTaskMonitor()
        max_nodes = 500

        nodes: dict[str, int] = {}  # name -> depth
        edges: list[dict[str, str]] = []
        visited: set[str] = set()

        root_name = func.getName()
        root_addr = str(func.getEntryPoint())
        nodes[root_name] = 0
        visited.add(root_name)

        queue: deque[tuple[Any, int]] = deque([(func, 0)])

        while queue and len(nodes) < max_nodes:
            current_func, current_depth = queue.popleft()
            if current_depth >= depth:
                continue

            neighbors = []
            if direction in ("callees", "both"):
                for callee in current_func.getCalledFunctions(monitor):
                    neighbors.append((current_func.getName(), callee.getName(), callee))
            if direction in ("callers", "both"):
                for caller in current_func.getCallingFunctions(monitor):
                    neighbors.append((caller.getName(), current_func.getName(), caller))

            for from_name, to_name, neighbor_func in neighbors:
                edge = {"from": from_name, "to": to_name}
                if edge not in edges:
                    edges.append(edge)

                neighbor_name = neighbor_func.getName()
                if neighbor_name not in visited and len(nodes) < max_nodes:
                    visited.add(neighbor_name)
                    nodes[neighbor_name] = current_depth + 1
                    queue.append((neighbor_func, current_depth + 1))

        node_list = [
            {"name": name, "address": None, "depth": d}
            for name, d in nodes.items()
        ]
        # Fill in addresses from program
        fm = program.getFunctionManager()
        for node in node_list:
            resolved = self._resolve_function(program, node["name"])
            if resolved:
                node["address"] = str(resolved.getEntryPoint())

        return {
            "root": root_name,
            "root_address": root_addr,
            "direction": direction,
            "depth": depth,
            "nodes": node_list,
            "edges": edges,
            "total_nodes": len(node_list),
            "total_edges": len(edges),
        }

    # ── Emulation ──────────────────────────────────────────────────

    def _get_or_create_emulator(
        self, binary_name: str, name_or_addr: str
    ) -> tuple[Any, Any, str]:
        """Get or create an EmulatorHelper for a function, returning (emu, func, session_key)."""
        program = self.get_program(binary_name)
        func = self._resolve_function(program, name_or_addr)
        if func is None:
            raise KeyError(f"Function '{name_or_addr}' not found in '{binary_name}'.")

        session_key = f"{binary_name}:{func.getName()}"
        emu = self._emulators.get(session_key)
        if emu is None:
            from ghidra.app.emulator import EmulatorHelper  # type: ignore[import]

            emu = EmulatorHelper(program)
            self._emulators[session_key] = emu
        return emu, func, session_key

    def emulate_function(
        self,
        binary_name: str,
        name_or_addr: str,
        args: list[int] | None = None,
        max_steps: int = 10000,
    ) -> dict[str, Any]:
        """Emulate a function with optional integer arguments.

        Sets up the emulator using calling convention metadata, runs until
        the function returns (sentinel breakpoint) or max_steps is reached,
        then extracts the return value.
        """
        self._ensure_started()
        from ghidra.util.task import ConsoleTaskMonitor  # type: ignore[import]

        emu, func, session_key = self._get_or_create_emulator(binary_name, name_or_addr)
        monitor = ConsoleTaskMonitor()
        program = self.get_program(binary_name)
        entry = func.getEntryPoint()
        addr_factory = program.getAddressFactory()
        default_space = addr_factory.getDefaultAddressSpace()

        # Set up stack pointer
        sp_reg = program.getCompilerSpec().getStackPointer()
        stack_addr = 0x7FFF0000
        emu.writeRegister(sp_reg, stack_addr)

        # Place arguments using calling convention metadata
        if args:
            params = func.getParameters()
            for param, val in zip(params, args):
                storage = param.getVariableStorage()
                if storage.isRegisterStorage():
                    emu.writeRegister(storage.getRegister(), val)
                elif storage.isStackStorage():
                    offset = storage.getStackOffset()
                    addr = default_space.getAddress(stack_addr + offset)
                    data = val.to_bytes(8, byteorder="little", signed=(val < 0))
                    emu.writeMemory(addr, self._java_byte_array(list(data)))

        # Set sentinel return address and breakpoint
        sentinel = 0xDEADBEEF
        sentinel_addr = default_space.getAddress(sentinel)
        emu.setBreakpoint(sentinel_addr)

        # Architecture-specific return address setup
        processor = program.getLanguage().getProcessor().toString().lower()
        if "arm" in processor or "aarch" in processor:
            # ARM: set link register
            emu.writeRegister("lr", sentinel)
        else:
            # x86/default: push sentinel onto stack
            stack_addr -= 8
            emu.writeRegister(sp_reg, stack_addr)
            ret_addr = default_space.getAddress(stack_addr)
            data = sentinel.to_bytes(8, byteorder="little")
            emu.writeMemory(ret_addr, self._java_byte_array(list(data)))

        # Set PC to function entry and execute
        emu.writeRegister(emu.getPCRegister(), entry.getOffset())
        steps = 0
        hit_breakpoint = False
        while steps < max_steps:
            state = emu.getEmulateExecutionState()
            if state is not None and state.toString() == "BREAKPOINT":
                hit_breakpoint = True
                break
            emu.step(monitor)
            steps += 1

        # Extract return value
        return_value = None
        try:
            ret_storage = func.getReturn().getVariableStorage()
            if ret_storage.isRegisterStorage():
                return_value = self._read_register_int(emu, ret_storage.getRegister())
        except Exception:
            logger.debug("Could not extract return value for %s", func.getName())

        pc_val = self._read_register_int(emu, emu.getPCRegister())
        sp_val = self._read_register_int(emu, sp_reg)

        return {
            "session_key": session_key,
            "function": func.getName(),
            "entry_address": str(entry),
            "args_provided": args or [],
            "return_value": return_value,
            "steps_executed": steps,
            "max_steps": max_steps,
            "hit_breakpoint": hit_breakpoint,
            "timed_out": steps >= max_steps,
            "final_pc": hex(pc_val),
            "final_sp": hex(sp_val),
        }

    def emulate_step(
        self,
        binary_name: str,
        name_or_addr: str,
        count: int = 1,
        read_registers: list[str] | None = None,
        read_memory: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Single-step an existing emulator session, reading registers and memory."""
        self._ensure_started()
        from ghidra.util.task import ConsoleTaskMonitor  # type: ignore[import]

        program = self.get_program(binary_name)
        func = self._resolve_function(program, name_or_addr)
        if func is None:
            raise KeyError(f"Function '{name_or_addr}' not found in '{binary_name}'.")
        session_key = f"{binary_name}:{func.getName()}"
        emu = self._emulators.get(session_key)
        if emu is None:
            raise KeyError(f"No emulator session for '{session_key}'. Call emulate_function first.")
        monitor = ConsoleTaskMonitor()

        steps_done = 0
        hit_breakpoint = False
        for _ in range(count):
            state = emu.getEmulateExecutionState()
            if state is not None and state.toString() == "BREAKPOINT":
                hit_breakpoint = True
                break
            emu.step(monitor)
            steps_done += 1

        pc_val = self._read_register_int(emu, emu.getPCRegister())

        # Read requested registers
        registers = {}
        if read_registers:
            for reg_name in read_registers:
                registers[reg_name] = hex(self._read_register_int(emu, reg_name))

        # Read requested memory regions
        memory_reads = []
        if read_memory:
            program = self.get_program(binary_name)
            default_space = program.getAddressFactory().getDefaultAddressSpace()
            for req in read_memory:
                addr = default_space.getAddress(int(req["address"].removeprefix("0x"), 16))
                size = req.get("size", 16)
                data = emu.readMemory(addr, size)
                memory_reads.append({
                    "address": req["address"],
                    "hex": bytes(v & 0xFF for v in data).hex(),
                })

        return {
            "session_key": session_key,
            "steps_executed": steps_done,
            "hit_breakpoint": hit_breakpoint,
            "current_pc": hex(pc_val),
            "registers": registers,
            "memory": memory_reads,
        }

    def destroy_emulator_session(self, binary_name: str, name_or_addr: str) -> None:
        """Destroy an emulator session and free its resources."""
        self._ensure_started()
        program = self.get_program(binary_name)
        func = self._resolve_function(program, name_or_addr)
        if func is None:
            raise KeyError(f"Function '{name_or_addr}' not found in '{binary_name}'.")
        session_key = f"{binary_name}:{func.getName()}"
        emu = self._emulators.pop(session_key, None)
        if emu is not None:
            emu.dispose()

    # ── Script mode (API introspection + code execution) ────────

    def search_api(self, query: str, package: str | None = None) -> list[dict[str, Any]]:
        """Search Ghidra Java API classes and methods by keyword."""
        self._ensure_started()
        from ghidra_mcp.api_registry import search_api as _search_api
        return _search_api(query, package=package)

    def get_class_info(self, class_name: str) -> dict[str, Any]:
        """Get detailed reflection info for a Ghidra Java class."""
        self._ensure_started()
        from ghidra_mcp.api_registry import get_class_info as _get_class_info
        return _get_class_info(class_name)

    def execute_script(self, code: str, binary_name: str | None = None) -> Any:
        """Execute a Python code snippet with Ghidra API access."""
        self._ensure_started()
        import textwrap
        import traceback

        context: dict[str, Any] = {"bridge": self}

        if binary_name:
            program = self.get_program(binary_name)
            context["program"] = program
            context["currentProgram"] = program

        from ghidra.util.task import ConsoleTaskMonitor  # type: ignore[import]
        context["monitor"] = ConsoleTaskMonitor()

        wrapped = "def __script__():\n" + textwrap.indent(code, "    ") + "\n__result__ = __script__()"

        try:
            exec(wrapped, context)  # noqa: S102
        except Exception:
            return {"error": traceback.format_exc()}

        return _serialize_result(context.get("__result__"))

    # ── Server connectivity ─────────────────────────────────────

    def _ensure_server_connected(self) -> None:
        if self._server is None:
            raise RuntimeError(
                "Not connected to a Ghidra server. Use connect_server first."
            )

    def _get_or_open_repo(self, repository_name: str) -> Any:
        if repository_name in self._server_repos:
            return self._server_repos[repository_name]
        repo = self._server.getRepository(repository_name)
        repo.connect()
        self._server_repos[repository_name] = repo
        return repo

    def connect_server(
        self, host: str, port: int = 13100, username: str = "ghidra", password: str | None = None
    ) -> dict[str, Any]:
        """Connect to a Ghidra server."""
        self._ensure_started()

        # Disconnect existing connection if any
        if self._server is not None:
            try:
                self.disconnect_server()
            except Exception:
                logger.warning("Failed to disconnect existing server connection")

        from ghidra.framework.client import ClientUtil  # type: ignore[import]

        if password is not None:
            from ghidra.framework.client import PasswordClientAuthenticator  # type: ignore[import]
            auth = PasswordClientAuthenticator(username, password)
            ClientUtil.setClientAuthenticator(auth)
        else:
            from ghidra.framework.client import HeadlessClientAuthenticator  # type: ignore[import]
            HeadlessClientAuthenticator.installHeadlessClientAuthenticator(
                username, None, False
            )

        server = ClientUtil.getRepositoryServer(host, port)
        connected = server.connect()
        if not connected:
            error = server.getLastConnectError()
            raise ConnectionError(
                f"Failed to connect to Ghidra server at {host}:{port}: {error or 'unknown error'}"
            )

        self._server = server
        self._server_host = host
        self._server_port = port

        repo_names = list(server.getRepositoryNames())

        return {
            "status": "connected",
            "host": host,
            "port": port,
            "username": username,
            "repositories": repo_names,
        }

    def disconnect_server(self) -> dict[str, Any]:
        """Disconnect from the Ghidra server and release all server-opened programs."""
        self._ensure_server_connected()

        host = self._server_host
        port = self._server_port

        # Release checked-out files and remove server programs
        for name in list(self._server_files.keys()):
            domain_file = self._server_files[name]
            try:
                if domain_file.isCheckedOut():
                    from ghidra.util.task import ConsoleTaskMonitor  # type: ignore[import]
                    domain_file.undoCheckout(False, ConsoleTaskMonitor())
            except Exception:
                logger.warning("Failed to undo checkout for '%s' during disconnect", name)

            # Clean up decompiler and emulators for this binary
            decomp = self._decompilers.pop(name, None)
            if decomp is not None:
                try:
                    decomp.dispose()
                except Exception:
                    pass
            keys_to_remove = [k for k in self._emulators if k.startswith(f"{name}:")]
            for key in keys_to_remove:
                emu = self._emulators.pop(key)
                try:
                    emu.dispose()
                except Exception:
                    pass
            self._programs.pop(name, None)

        self._server_files.clear()
        self._server_repos.clear()

        if self._server_project is not None:
            try:
                self._server_project.close()
            except Exception:
                logger.warning("Failed to close server project")
            self._server_project = None

        self._server.disconnect()
        self._server = None
        self._server_host = None
        self._server_port = None

        return {"status": "disconnected", "host": host, "port": port}

    def list_repositories(self) -> list[dict[str, Any]]:
        """List available repositories on the connected Ghidra server."""
        self._ensure_server_connected()
        repo_names = list(self._server.getRepositoryNames())
        return [{"name": name} for name in repo_names]

    def list_server_files(
        self, repository_name: str, folder_path: str = "/"
    ) -> dict[str, Any]:
        """List files and subfolders in a Ghidra server repository."""
        self._ensure_server_connected()

        try:
            repo = self._get_or_open_repo(repository_name)
        except Exception:
            raise KeyError(f"Repository '{repository_name}' not found or access denied.")

        subfolders = list(repo.getSubfolderList(folder_path))
        items = list(repo.getItemList(folder_path))
        files = []
        for item in items:
            files.append({
                "name": item.getName(),
                "path": f"{folder_path.rstrip('/')}/{item.getName()}",
                "content_type": str(item.getContentType()),
                "version": item.getVersion(),
            })

        return {
            "repository": repository_name,
            "folder": folder_path,
            "subfolders": subfolders,
            "files": files,
        }

    def open_from_server(
        self, repository_name: str, file_path: str, checkout: bool = True
    ) -> dict[str, Any]:
        """Open a program from the Ghidra server for analysis."""
        self._ensure_started()
        self._ensure_server_connected()

        from ghidra.util.task import ConsoleTaskMonitor  # type: ignore[import]
        monitor = ConsoleTaskMonitor()

        # Create/open a shared local project linked to this repo
        if self._server_project is None:
            from ghidra.framework.model import ProjectLocator  # type: ignore[import]
            from ghidra.framework.project import DefaultProjectManager  # type: ignore[import]

            cache_dir = self.project_dir / "_server_cache"
            cache_dir.mkdir(parents=True, exist_ok=True)

            locator = ProjectLocator(str(cache_dir), f"server_{repository_name}")
            pm = DefaultProjectManager.getInstance()
            repo = self._get_or_open_repo(repository_name)
            self._server_project = pm.createProject(locator, repo, False)

        project_data = self._server_project.getProjectData()
        domain_file = project_data.getFile(file_path)
        if domain_file is None:
            raise KeyError(
                f"File '{file_path}' not found in repository '{repository_name}'."
            )

        binary_name = domain_file.getName()

        # Check for name collision with local binaries
        if binary_name in self._programs and binary_name not in self._server_files:
            raise ValueError(
                f"A locally imported binary named '{binary_name}' already exists. "
                f"Delete it first before opening from server."
            )

        checked_out = False
        if checkout:
            if not domain_file.isCheckedOut():
                domain_file.checkout(True, monitor)
            checked_out = domain_file.isCheckedOut()

        # Open the program
        if checked_out:
            program = domain_file.getDomainObject(self, True, False, monitor)
        else:
            program = domain_file.getReadOnlyDomainObject(self, -1, False, monitor)

        self._programs[binary_name] = program
        self._server_files[binary_name] = domain_file

        # Initialize decompiler
        try:
            self._init_decompiler(binary_name, program)
        except Exception:
            logger.warning("Decompiler init failed for server file '%s'", binary_name)

        info = self.get_binary_info(binary_name)
        return {
            "source": "server",
            "repository": repository_name,
            "path": file_path,
            "checked_out": checked_out,
            **info,
        }

    def checkin_file(
        self, binary_name: str, comment: str = "Changes from MCP analysis"
    ) -> dict[str, Any]:
        """Check in changes to a server-opened program."""
        self._ensure_server_connected()

        domain_file = self._server_files.get(binary_name)
        if domain_file is None:
            raise KeyError(
                f"Binary '{binary_name}' was not opened from server. "
                f"Use open_from_server first."
            )

        if not domain_file.isCheckedOut():
            raise RuntimeError(
                f"Binary '{binary_name}' is not checked out. "
                f"Open it with checkout=True to enable checkin."
            )

        from ghidra.util.task import ConsoleTaskMonitor  # type: ignore[import]
        monitor = ConsoleTaskMonitor()

        # Save current program state
        program = self._programs.get(binary_name)
        if program is not None:
            program.save(comment, monitor)

        # Check in to server
        domain_file.checkin(None, comment, False, monitor)

        return {
            "status": "checked_in",
            "binary_name": binary_name,
            "comment": comment,
        }

    def close(self) -> None:
        """Close all programs, decompilers, emulators, server connection, and the project."""
        for name, decomp in self._decompilers.items():
            try:
                decomp.dispose()
            except Exception:
                logger.warning("Failed to dispose decompiler for %s", name)

        self._decompilers.clear()

        for key, emu in self._emulators.items():
            try:
                emu.dispose()
            except Exception:
                logger.warning("Failed to dispose emulator session %s", key)

        self._emulators.clear()

        # Disconnect server if connected
        if self._server is not None:
            try:
                self.disconnect_server()
            except Exception:
                logger.warning("Failed to disconnect from server during close")

        if self._project is not None:
            try:
                self._project.close()
            except Exception:
                logger.warning("Failed to close project")

        self._programs.clear()
        self._project = None
