"""Mode candidate collection entrypoint (Milestone 3).

This module wires together the smaller mode-export subsystems:
- dispatch-site grouping + ranking
- token extraction from compare callsites
- implementation-root attachment (handler targets)
- dispatch classification
- stable payload construction

Public API: `collect_mode_candidates` (re-exported from `export_modes.py`).
"""

from export_collectors import collect_cli_option_compare_sites, extract_call_args_for_callsites
from export_config import DEFAULT_MAX_DECOMPILE_FUNCTION_SIZE
from export_primitives import addr_str, addr_to_int
from modes.dispatch_classify import _classify_dispatch_groups
from modes.dispatch_groups import (
    _build_callgraph_out_degree,
    _build_entry_distances,
    _group_compare_sites,
    _select_dispatch_groups,
)
from modes.implementation_roots import _attach_implementation_roots
from modes.mode_candidates import _build_mode_candidates
from modes.name_heuristics import entry_name_candidates
from modes.payloads import _build_dispatch_sites_payload, _build_modes_index_payload
from modes.table_dispatch import (
    _attach_table_dispatch_sites,
    _collect_table_dispatch_mode_candidates,
    _collect_table_dispatch_site_infos,
    _collect_table_dispatch_tokens,
)


def collect_mode_candidates(
    program,
    call_edges,
    function_meta_by_addr,
    string_addr_map_all,
    options,
    monitor=None,
):
    compare_sites = collect_cli_option_compare_sites(call_edges, function_meta_by_addr)
    groups, callsite_meta = _group_compare_sites(compare_sites)
    compare_callsites_by_func = {}
    for func_addr, group in groups.items():
        callsites = sorted(set(group.get("callsites") or []), key=addr_to_int)
        compare_callsites_by_func[func_addr] = callsites
    total_dispatch_sites = len(groups)

    callgraph_callees_by_func, out_degree_by_func = _build_callgraph_out_degree(call_edges)
    entry_names = entry_name_candidates(options)
    entry_func_ids = []
    for func_id, meta in (function_meta_by_addr or {}).items():
        name = (meta or {}).get("name")
        if name in entry_names:
            entry_func_ids.append(func_id)
    if program is not None:
        try:
            entry_addr = program.getEntryPoint()
        except Exception:
            entry_addr = None
        if entry_addr is not None:
            try:
                entry_func = program.getFunctionManager().getFunctionContaining(entry_addr)
            except Exception:
                entry_func = None
            if entry_func is not None:
                entry_func_ids.append(addr_str(entry_func.getEntryPoint()))
    entry_distances = _build_entry_distances(callgraph_callees_by_func, entry_func_ids)

    max_dispatch_functions = options.get("max_mode_dispatch_functions", 0)
    max_callsites_per_function = options.get("max_mode_callsites_per_function", 0)
    max_token_len = options.get("max_mode_token_length", 0)
    max_tokens_per_callsite = options.get("max_mode_tokens_per_callsite", 0)
    min_token_len = 1

    selected_groups, callsite_ids = _select_dispatch_groups(
        groups,
        max_dispatch_functions,
        max_callsites_per_function,
        entry_distances=entry_distances,
        out_degree_by_func=out_degree_by_func,
    )

    # Resolve call arguments only for the highest-signal compare callers.
    callsite_ids_for_args = []
    for callsite_id in callsite_ids:
        meta = callsite_meta.get(callsite_id, {}) if callsite_meta else {}
        caller = meta.get("caller") or {}
        func_id = caller.get("address")
        if not func_id:
            continue
        func_meta = function_meta_by_addr.get(func_id, {}) if function_meta_by_addr else {}
        size = func_meta.get("size")
        try:
            size = int(size)
        except Exception:
            size = 0
        if size and size > DEFAULT_MAX_DECOMPILE_FUNCTION_SIZE:
            continue
        callsite_ids_for_args.append(callsite_id)
    call_args_by_callsite = extract_call_args_for_callsites(
        program,
        callsite_ids_for_args,
        monitor,
        purpose="export_modes.collect_mode_candidates",
    )

    mode_candidates, callsite_tokens, callsite_ignored, callsite_token_stats = (
        _build_mode_candidates(
            selected_groups,
            call_args_by_callsite,
            string_addr_map_all,
            max_token_len,
            max_tokens_per_callsite,
            min_token_len,
        )
    )

    handler_callsite_ids, table_dispatch_funcs, handler_diversity_by_func = (
        _attach_implementation_roots(
            program,
            mode_candidates,
            call_edges,
            compare_callsites_by_func,
            function_meta_by_addr,
            options,
            monitor=monitor,
        )
    )
    dispatch_meta_by_func, dispatch_meta_by_callsite = _classify_dispatch_groups(
        program,
        selected_groups,
        callsite_tokens,
        table_dispatch_funcs=table_dispatch_funcs,
        handler_diversity_by_func=handler_diversity_by_func,
        monitor=monitor,
    )
    table_dispatch_site_infos = _collect_table_dispatch_site_infos(
        selected_groups, dispatch_meta_by_func
    )
    modes_payload, selected_mode_ids = _build_modes_index_payload(
        mode_candidates,
        callsite_meta,
        dispatch_meta_by_callsite,
        options,
        min_token_len,
    )

    min_table_dispatch_modes = options.get("min_table_dispatch_modes", 0) or 5
    if len(selected_mode_ids) < min_table_dispatch_modes:
        added = False
        for mode_id, mode in _collect_table_dispatch_mode_candidates(
            program,
            function_meta_by_addr,
            string_addr_map_all,
            options,
            monitor=monitor,
        ).items():
            if mode_id in mode_candidates:
                continue
            mode_candidates[mode_id] = mode
            added = True
        if added:
            _attach_table_dispatch_sites(mode_candidates, table_dispatch_site_infos)
            modes_payload, selected_mode_ids = _build_modes_index_payload(
                mode_candidates,
                callsite_meta,
                dispatch_meta_by_callsite,
                options,
                min_token_len,
            )

    table_dispatch_tokens = _collect_table_dispatch_tokens(mode_candidates, selected_mode_ids)
    dispatch_sites_payload = _build_dispatch_sites_payload(
        selected_groups,
        callsite_tokens,
        callsite_ignored,
        callsite_token_stats,
        call_args_by_callsite,
        selected_mode_ids,
        table_dispatch_tokens,
        dispatch_meta_by_func,
        options,
        total_dispatch_sites,
    )

    all_callsite_ids = sorted(set(callsite_ids) | set(handler_callsite_ids), key=addr_to_int)
    return modes_payload, dispatch_sites_payload, all_callsite_ids
