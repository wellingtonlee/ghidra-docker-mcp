"""Ghidra Java API registry and runtime reflection for script mode."""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

# Static registry of key Ghidra API classes organized by package.
# Class names are static (Java can't enumerate classes in a package at runtime),
# but method signatures are obtained via live Java reflection for version accuracy.
GHIDRA_API_CLASSES: dict[str, list[str]] = {
    "ghidra.program.model.listing": [
        "Program", "Function", "FunctionManager", "FunctionIterator",
        "Instruction", "InstructionIterator", "CodeUnit", "Listing",
        "Data", "BookmarkManager", "ParameterImpl",
    ],
    "ghidra.program.model.symbol": [
        "Symbol", "SymbolTable", "SymbolIterator", "SourceType",
        "SymbolType", "Namespace", "Reference", "ReferenceManager",
    ],
    "ghidra.program.model.mem": [
        "Memory", "MemoryBlock",
    ],
    "ghidra.program.model.address": [
        "Address", "AddressFactory", "AddressSpace", "AddressSet",
        "AddressSetView", "AddressRange",
    ],
    "ghidra.program.model.pcode": [
        "PcodeOp", "Varnode", "HighFunction", "HighVariable",
        "HighSymbol", "HighParam",
    ],
    "ghidra.app.decompiler": [
        "DecompInterface", "DecompileResults", "DecompileOptions",
        "ClangTokenGroup", "DecompiledFunction",
    ],
    "ghidra.program.model.data": [
        "DataType", "DataTypeManager", "Structure", "StructureDataType",
        "PointerDataType", "ArrayDataType", "FunctionDefinitionDataType",
        "AbstractIntegerDataType", "Undefined",
    ],
    "ghidra.program.model.lang": [
        "Language", "Register", "CompilerSpec", "Processor",
        "PrototypeModel",
    ],
    "ghidra.program.model.block": [
        "BasicBlockModel", "CodeBlock", "CodeBlockIterator",
    ],
    "ghidra.app.emulator": [
        "EmulatorHelper",
    ],
    "ghidra.program.util": [
        "GhidraProgramUtilities", "DefinedDataIterator",
    ],
    "ghidra.util.task": [
        "ConsoleTaskMonitor", "TaskMonitor",
    ],
}

# Session-lifetime cache for reflection results
_reflection_cache: dict[str, dict[str, Any]] = {}

# Set of java.lang.Object method names to filter from results
_OBJECT_METHODS = frozenset({
    "getClass", "hashCode", "equals", "toString", "notify",
    "notifyAll", "wait", "clone", "finalize",
})


def _format_type(java_type: Any) -> str:
    """Convert a Java Class object to a readable type name string."""
    name = str(java_type.getName())
    # Arrays: "[Ljava.lang.String;" -> "String[]"
    if name.startswith("[L") and name.endswith(";"):
        inner = name[2:-1]
        short = inner.rsplit(".", 1)[-1] if "." in inner else inner
        return f"{short}[]"
    if name.startswith("["):
        # Primitive arrays like "[I" -> "int[]"
        prim_map = {"I": "int", "J": "long", "Z": "boolean", "B": "byte",
                     "S": "short", "C": "char", "F": "float", "D": "double"}
        return f"{prim_map.get(name[1], name[1])}[]"
    # Shorten java.lang types
    if name.startswith("java.lang."):
        return name[len("java.lang."):]
    return name


def _reflect_class(fqcn: str) -> dict[str, Any]:
    """Use Java reflection via JPype to introspect a Ghidra class.

    Returns methods (excluding java.lang.Object defaults), interfaces, superclass.
    Results are cached for the session lifetime.
    """
    if fqcn in _reflection_cache:
        return _reflection_cache[fqcn]

    import jpype  # type: ignore[import]

    cls = jpype.JClass(fqcn)
    java_cls = cls.class_
    Modifier = jpype.JClass("java.lang.reflect.Modifier")

    methods = []
    for m in java_cls.getMethods():
        name = str(m.getName())
        if name in _OBJECT_METHODS:
            continue
        mod = m.getModifiers()
        methods.append({
            "name": name,
            "params": [_format_type(p) for p in m.getParameterTypes()],
            "returns": _format_type(m.getReturnType()),
            "modifiers": str(Modifier.toString(mod)),
        })

    # Sort methods alphabetically for consistent output
    methods.sort(key=lambda m: m["name"])

    superclass = _format_type(java_cls.getSuperclass()) if java_cls.getSuperclass() else None
    interfaces = [_format_type(i) for i in java_cls.getInterfaces()]

    result: dict[str, Any] = {
        "class": fqcn,
        "is_interface": bool(java_cls.isInterface()),
        "superclass": superclass,
        "interfaces": interfaces,
        "methods": methods,
    }
    _reflection_cache[fqcn] = result
    return result


def search_api(query: str, package: str | None = None) -> list[dict[str, Any]]:
    """Search Ghidra Java API classes and methods by keyword.

    Matches against class names first, then method names within each class.
    Returns reflection info for matching classes (with methods filtered to
    matches when the match is method-level).
    """
    query_lower = query.lower()
    results: list[dict[str, Any]] = []

    for pkg, classes in GHIDRA_API_CLASSES.items():
        if package and not pkg.startswith(package):
            continue
        for cls_name in classes:
            fqcn = f"{pkg}.{cls_name}"

            # Match against class name
            if query_lower in cls_name.lower() or query_lower in fqcn.lower():
                try:
                    results.append(_reflect_class(fqcn))
                except Exception:
                    results.append({"class": fqcn, "error": "Could not reflect class"})
                continue

            # Match against method names
            try:
                info = _reflect_class(fqcn)
                matching = [m for m in info["methods"] if query_lower in m["name"].lower()]
                if matching:
                    results.append({**info, "methods": matching})
            except Exception:
                pass

    return results


def get_class_info(class_name: str) -> dict[str, Any]:
    """Get full reflection info for a specific Ghidra Java class.

    Accepts fully-qualified class names (e.g. "ghidra.program.model.listing.Function")
    or short names that will be resolved against the registry.
    """
    # Try as fully-qualified name first
    try:
        return _reflect_class(class_name)
    except Exception:
        pass

    # Try resolving short name against registry
    for pkg, classes in GHIDRA_API_CLASSES.items():
        if class_name in classes:
            fqcn = f"{pkg}.{class_name}"
            try:
                return _reflect_class(fqcn)
            except Exception:
                pass

    raise KeyError(
        f"Class '{class_name}' not found. Use search_api to discover available classes."
    )
