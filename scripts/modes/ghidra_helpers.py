"""Small wrappers around common Ghidra/PyGhidra lookups.

These helpers keep the high-level mode export logic focused on heuristics and data
flow, while centralizing Ghidra-specific "try a few ways to do X" details.
"""

from export_config import DEFAULT_MAX_DECOMPILE_FUNCTION_SIZE
from export_profile import profiled_decompile


def _find_function_by_name(program, name):
    if not name:
        return None
    func_manager = program.getFunctionManager()
    funcs = None
    try:
        funcs = func_manager.getFunctions(name)
    except Exception:
        funcs = None
    if funcs:
        for func in funcs:
            return func
    try:
        funcs = func_manager.getFunctions(name, True)
        for func in funcs:
            return func
    except Exception:
        pass
    try:
        symbol_table = program.getSymbolTable()
        symbols = symbol_table.getSymbols(name)
    except Exception:
        symbols = None
    if symbols:
        for sym in symbols:
            try:
                obj = sym.getObject()
            except Exception:
                obj = None
            if obj and hasattr(obj, "getEntryPoint"):
                return obj
    return None


def _decompile_function_text(decomp_interface, func, monitor=None):
    if func is None:
        return None
    try:
        if func.getBody().getNumAddresses() > DEFAULT_MAX_DECOMPILE_FUNCTION_SIZE:
            return None
    except Exception:
        pass
    try:
        result = profiled_decompile(
            decomp_interface,
            func,
            30,
            monitor,
            purpose="export_modes._decompile_function_text",
        )
    except Exception:
        return None
    if not result or not result.decompileCompleted():
        return None
    try:
        decomp_func = result.getDecompiledFunction()
    except Exception:
        decomp_func = None
    if not decomp_func:
        return None
    try:
        return decomp_func.getC()
    except Exception:
        return None

