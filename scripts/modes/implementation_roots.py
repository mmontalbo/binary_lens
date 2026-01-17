"""Implementation-root attachment for mode candidates.

Mode candidates start from dispatch-site evidence (compare callsites + token
strings). This module attaches higher-signal "implementation roots" by linking
those candidates to handler targets via:
- compare-chain callgraph adjacency
- compare-chain assignment pcode (function-pointer variable assignments)
- table-dispatch table scanning near the token string
- lightweight decompiler text scans for handler names

The end result is a set of handler-callsite IDs (for callsite export) and
auxiliary metadata used by dispatch classification.
"""

from collectors.ghidra_memory import _to_address
from export_bounds import Bounds
from export_primitives import addr_str, addr_to_int
from ghidra.app.decompiler import DecompInterface
from modes.common import _add_implementation_root, _c_string_literal
from modes.compare_chain import (
    _build_callsite_maps,
    _collect_compare_chain_assignments,
    _collect_compare_chain_targets,
)
from modes.ghidra_helpers import _decompile_function_text, _find_function_by_name
from modes.handlers import _extract_handler_candidates_from_decomp, _is_ignored_handler_name
from modes.table_dispatch_scan import _collect_table_dispatch_targets


def _attach_implementation_roots(
    program,
    mode_candidates,
    call_edges,
    compare_callsites_by_func,
    function_meta_by_addr,
    bounds: Bounds,
    monitor=None,
):
    if not mode_candidates:
        return set(), set(), {}
    callsites_by_func, callsite_targets = _build_callsite_maps(call_edges)
    compare_chain_targets = _collect_compare_chain_targets(
        callsites_by_func, callsite_targets, compare_callsites_by_func
    )
    max_roots = bounds.max_mode_dispatch_roots_per_mode
    max_table_targets = max_roots if max_roots else 6
    max_table_refs = max(8, max_table_targets * 2)
    table_cache = {}
    handler_callsites = set()
    table_dispatch_funcs = set()
    compare_callsite_to_func = {}
    compare_callsite_counts = {}
    for func_id, callsites in compare_callsites_by_func.items():
        compare_callsite_counts[func_id] = len(callsites)
        for callsite_id in callsites:
            compare_callsite_to_func[callsite_id] = func_id

    func_manager = program.getFunctionManager()
    func_cache = {}
    name_cache = {}
    decomp_cache = {}
    decomp_holder = {"iface": None}
    token_scan_cache = {}
    compare_chain_assignments = {}
    handler_diversity_by_func = {}

    def _get_func_by_id(func_id):
        if func_id in func_cache:
            return func_cache[func_id]
        addr = _to_address(program, func_id)
        func = func_manager.getFunctionAt(addr) if addr else None
        func_cache[func_id] = func
        return func

    def _get_decomp_text(func_id):
        if func_id in decomp_cache:
            return decomp_cache[func_id]
        func = _get_func_by_id(func_id)
        if func is None:
            decomp_cache[func_id] = None
            return None
        if decomp_holder["iface"] is None:
            decomp_holder["iface"] = DecompInterface()
            decomp_holder["iface"].openProgram(program)
        text = _decompile_function_text(decomp_holder["iface"], func, monitor)
        decomp_cache[func_id] = text
        return text

    def _is_valid_handler_target(func_id, func_name, source, external_flag=None):
        if not func_id:
            return False
        if external_flag:
            return False
        meta = function_meta_by_addr.get(func_id, {}) if function_meta_by_addr else {}
        if meta.get("is_external") or meta.get("is_thunk"):
            return False
        name = func_name or meta.get("name")
        if name and _is_ignored_handler_name(name):
            return False
        return True

    def _resolve_function_by_name(name):
        if name in name_cache:
            return name_cache[name]
        if _is_ignored_handler_name(name):
            name_cache[name] = (None, None)
            return name_cache[name]
        func = _find_function_by_name(program, name)
        if func is None:
            name_cache[name] = (None, None)
            return name_cache[name]
        func_id = addr_str(func.getEntryPoint())
        func_name = func.getName()
        if not _is_valid_handler_target(func_id, func_name, "symbol_lookup"):
            name_cache[name] = (None, None)
            return name_cache[name]
        name_cache[name] = (func_id, func_name)
        return name_cache[name]

    dispatch_func_ids = set()
    for mode in mode_candidates.values():
        for func_id in (mode.get("dispatch_roots") or {}).keys():
            if func_id:
                dispatch_func_ids.add(func_id)
    if dispatch_func_ids:
        if decomp_holder["iface"] is None:
            decomp_holder["iface"] = DecompInterface()
            decomp_holder["iface"].openProgram(program)
        for func_id in sorted(dispatch_func_ids, key=addr_to_int):
            compare_callsites = compare_callsites_by_func.get(func_id) or []
            if not compare_callsites:
                continue
            func_obj = _get_func_by_id(func_id)
            mapping = _collect_compare_chain_assignments(
                program,
                decomp_holder["iface"],
                func_obj,
                compare_callsites,
                monitor=monitor,
                name_hints_source=bounds,
            )
            for callsite_id, targets in mapping.items():
                if callsite_id and targets:
                    compare_chain_assignments[callsite_id] = targets

    for mode in mode_candidates.values():
        token_value = mode.get("name")
        token_literal = _c_string_literal(token_value) if token_value else None
        string_id = mode.get("string_id")
        string_address = mode.get("address")
        string_addr = mode.get("address")
        has_table_dispatch = False
        existing_table_source = False
        for root in (mode.get("implementation_roots") or {}).values():
            if "table_dispatch" in (root.get("sources") or set()):
                existing_table_source = True
                break
        if string_addr and not existing_table_source:
            roots = table_cache.get(string_addr)
            if roots is None:
                roots = _collect_table_dispatch_targets(
                    program,
                    string_addr,
                    max_refs=max_table_refs,
                    max_targets=max_table_targets,
                )
                table_cache[string_addr] = roots
            for root in roots:
                if not _is_valid_handler_target(
                    root.get("function_id"),
                    root.get("function_name"),
                    "table_dispatch",
                ):
                    continue
                has_table_dispatch = True
                _add_implementation_root(
                    mode,
                    root.get("function_id"),
                    root.get("function_name"),
                    "table_dispatch",
                    {
                        "table_entry_address": root.get("table_entry_address"),
                        "string_id": mode.get("string_id"),
                        "string_address": string_addr,
                    },
                )

        for callsite_id in mode.get("dispatch_sites") or []:
            for root in compare_chain_targets.get(callsite_id, []):
                if not _is_valid_handler_target(
                    root.get("function_id"),
                    root.get("function_name"),
                    "compare_chain",
                    external_flag=root.get("external"),
                ):
                    continue
                handler_callsite_id = root.get("handler_callsite_id")
                if handler_callsite_id:
                    handler_callsites.add(handler_callsite_id)
                _add_implementation_root(
                    mode,
                    root.get("function_id"),
                    root.get("function_name"),
                    "compare_chain",
                    {
                        "compare_callsite_id": callsite_id,
                        "handler_callsite_id": handler_callsite_id,
                    },
                )
            func_id = compare_callsite_to_func.get(callsite_id)
            if not func_id:
                continue
            if has_table_dispatch:
                table_dispatch_funcs.add(func_id)
            for root in compare_chain_assignments.get(callsite_id, []) or []:
                handler_id = root.get("function_id")
                handler_name = root.get("function_name")
                if not _is_valid_handler_target(
                    handler_id,
                    handler_name,
                    "compare_chain_assignment",
                ):
                    continue
                _add_implementation_root(
                    mode,
                    handler_id,
                    handler_name,
                    "compare_chain_assignment",
                    {
                        "compare_callsite_id": callsite_id,
                        "handler_callsite_id": root.get("assignment_id"),
                        "string_id": string_id,
                        "string_address": string_address,
                    },
                )
            if token_literal:
                cache_key = (func_id, token_literal)
                if cache_key in token_scan_cache:
                    handler_names = token_scan_cache[cache_key]
                else:
                    decomp_text = _get_decomp_text(func_id)
                    handler_names = _extract_handler_candidates_from_decomp(
                        decomp_text,
                        token_literal,
                    )
                    token_scan_cache[cache_key] = handler_names
                for name in handler_names:
                    handler_id, handler_name = _resolve_function_by_name(name)
                    if not handler_id:
                        continue
                    _add_implementation_root(
                        mode,
                        handler_id,
                        handler_name,
                        "compare_chain_handler",
                        {
                            "compare_callsite_id": callsite_id,
                            "string_id": string_id,
                            "string_address": string_address,
                        },
                    )
    # Derive handler diversity per dispatch function from the collected roots so
    # dispatch classification can downrank non-dispatch compare chains.
    handler_targets_by_func = {}
    for mode in mode_candidates.values():
        impl_roots = mode.get("implementation_roots") or {}
        if not impl_roots:
            continue
        for impl_func_id, root in impl_roots.items():
            compare_sites = root.get("compare_callsites") or set()
            if compare_sites:
                for compare_callsite in compare_sites:
                    dispatch_func = compare_callsite_to_func.get(compare_callsite)
                    if not dispatch_func:
                        continue
                    handler_targets_by_func.setdefault(dispatch_func, set()).add(impl_func_id)
                continue
            for dispatch_func in (mode.get("dispatch_roots") or {}).keys():
                if dispatch_func:
                    handler_targets_by_func.setdefault(dispatch_func, set()).add(impl_func_id)

    handler_diversity_by_func = {
        func_id: len(targets) for func_id, targets in handler_targets_by_func.items()
    }
    return handler_callsites, table_dispatch_funcs, handler_diversity_by_func
