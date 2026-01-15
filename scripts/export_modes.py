"""Mode ("Milestone 3") export logic.

Most implementation lives in the `modes/` package; this module preserves the original
import path for the Ghidra exporter and other tooling.
"""

import re
from collections import deque

from export_collectors import (
    _to_address,
    collect_cli_option_compare_sites,
    extract_call_args_for_callsites,
)
from export_config import DEFAULT_MAX_DECOMPILE_FUNCTION_SIZE
from export_primitives import addr_str, addr_to_int
from ghidra.app.decompiler import DecompInterface
from modes.common import (
    _add_implementation_root,
    _c_string_literal,
    _confidence_from_count,
    _escape_preview,
    _mode_id,
    _source_rank,
    _token_candidate,
    _token_kind,
)
from modes.compare_chain import (
    _build_callsite_maps,
    _collect_compare_chain_assignments,
    _collect_compare_chain_targets,
)
from modes.ghidra_helpers import _decompile_function_text, _find_function_by_name
from modes.handlers import (
    _extract_handler_candidates_from_decomp,
    _is_ignored_handler_name,
)
from modes.slices import build_mode_slices
from modes.surface import attach_mode_callsite_refs, build_modes_surface
from modes.table_dispatch import (
    _attach_table_dispatch_sites,
    _collect_table_dispatch_mode_candidates,
    _collect_table_dispatch_site_infos,
    _collect_table_dispatch_targets,
    _collect_table_dispatch_tokens,
)

__all__ = [
    "attach_mode_callsite_refs",
    "build_mode_slices",
    "build_modes_surface",
    "collect_mode_candidates",
]


def _group_compare_sites(compare_sites):
    groups = {}
    callsite_meta = {}
    for site in compare_sites:
        callsite = site.get("callsite")
        caller = site.get("caller") or {}
        func_addr = caller.get("address")
        if not callsite or not func_addr:
            continue
        callsite_meta[callsite] = {
            "caller": caller,
            "callee": site.get("callee"),
            "callee_norm": site.get("callee_norm"),
        }
        group = groups.get(func_addr)
        if group is None:
            group = {
                "function": caller,
                "callsites": [],
                "callee_names": set(),
            }
            groups[func_addr] = group
        group["callsites"].append(callsite)
        if site.get("callee"):
            group["callee_names"].add(site.get("callee"))
    return groups, callsite_meta


def _build_callgraph_out_degree(call_edges):
    callees_by_func = {}
    out_degree = {}
    if not call_edges:
        return callees_by_func, out_degree
    for edge in call_edges:
        caller = (edge.get("from") or {}).get("address")
        callee = edge.get("to") or {}
        if not caller or not callee or callee.get("external"):
            continue
        callee_addr = callee.get("address")
        if not callee_addr:
            continue
        callees_by_func.setdefault(caller, set()).add(callee_addr)
    out_degree = {caller: len(callees) for caller, callees in callees_by_func.items()}
    return callees_by_func, out_degree


def _build_entry_distances(callees_by_func, entry_func_ids, max_depth=3, max_nodes=2000):
    if not callees_by_func or not entry_func_ids:
        return {}
    distances = {}
    queue = deque()
    for func_id in entry_func_ids:
        if not func_id or func_id in distances:
            continue
        distances[func_id] = 0
        queue.append(func_id)
    while queue:
        func_id = queue.popleft()
        depth = distances.get(func_id, 0)
        if depth >= max_depth:
            continue
        for callee_id in callees_by_func.get(func_id, []) or []:
            if not callee_id or callee_id in distances:
                continue
            distances[callee_id] = depth + 1
            queue.append(callee_id)
            if max_nodes and len(distances) >= max_nodes:
                return distances
    return distances


def _select_dispatch_groups(
    groups,
    max_functions,
    max_callsites_per_function,
    entry_distances=None,
    out_degree_by_func=None,
):
    group_list = []
    for group in groups.values():
        callsites = sorted(set(group["callsites"]), key=addr_to_int)
        group["callsites"] = callsites
        group["compare_callsite_count"] = len(callsites)
        func_addr = (group.get("function") or {}).get("address")
        group["entry_distance"] = (
            entry_distances.get(func_addr) if entry_distances and func_addr else None
        )
        group["out_degree"] = (
            out_degree_by_func.get(func_addr) if out_degree_by_func and func_addr else None
        ) or 0
        group_list.append(group)

    group_list.sort(
        key=lambda item: (
            1 if item.get("entry_distance") is None else 0,
            item.get("entry_distance") if item.get("entry_distance") is not None else 999,
            -item.get("out_degree", 0),
            -item.get("compare_callsite_count", 0),
            addr_to_int((item.get("function") or {}).get("address")),
        )
    )
    if max_functions and len(group_list) > max_functions:
        group_list = group_list[:max_functions]

    selected_callsite_ids = []
    for group in group_list:
        callsites = group.get("callsites") or []
        if max_callsites_per_function and len(callsites) > max_callsites_per_function:
            group["callsites_truncated"] = True
            callsites = callsites[:max_callsites_per_function]
        else:
            group["callsites_truncated"] = False
        group["callsites"] = callsites
        group["callee_names"] = sorted(group.get("callee_names") or [])
        selected_callsite_ids.extend(callsites)
    return group_list, selected_callsite_ids


def _build_mode_candidates(
    groups,
    call_args_by_callsite,
    string_addr_map_all,
    max_token_len,
    max_tokens_per_callsite,
    min_token_len,
):
    mode_candidates = {}
    callsite_tokens = {}
    callsite_ignored = {}
    callsite_token_stats = {}

    for group in groups:
        func = group.get("function") or {}
        func_addr = func.get("address")
        func_name = func.get("name")
        for callsite_id in group.get("callsites") or []:
            args = call_args_by_callsite.get(callsite_id, {})
            tokens = []
            ignored = []
            candidate_count = 0
            kept_count = 0
            for entry in args.get("string_args", []):
                value = entry.get("value")
                token_value, reason = _token_candidate(value, min_token_len, max_token_len)
                if token_value is None:
                    ignored.append(
                        {
                            "preview": _escape_preview(value),
                            "reason": reason,
                            "address": entry.get("address"),
                            "length": len(value) if value is not None else 0,
                            "callsite_id": callsite_id,
                        }
                    )
                    continue
                candidate_count += 1
                if max_tokens_per_callsite and len(tokens) >= max_tokens_per_callsite:
                    continue
                address = entry.get("address")
                string_id = string_addr_map_all.get(address)
                mode_id = _mode_id(string_id, address, token_value)
                kind, kind_strength, kind_confidence = _token_kind(token_value)
                token_entry = {
                    "mode_id": mode_id,
                    "value": token_value,
                    "address": address,
                    "string_id": string_id,
                    "kind": kind,
                    "kind_strength": kind_strength,
                    "kind_confidence": kind_confidence,
                }
                tokens.append(token_entry)
                kept_count += 1

                mode = mode_candidates.get(mode_id)
                if mode is None:
                    mode = {
                        "mode_id": mode_id,
                        "name": token_value,
                        "string_id": string_id,
                        "address": address,
                        "kind": kind,
                        "kind_strength": kind_strength,
                        "kind_confidence": kind_confidence,
                        "dispatch_sites": set(),
                        "dispatch_roots": {},
                    }
                    mode_candidates[mode_id] = mode
                mode["dispatch_sites"].add(callsite_id)
                roots = mode["dispatch_roots"]
                root = roots.get(func_addr)
                if root is None:
                    root = {
                        "function_name": func_name,
                        "callsite_ids": set(),
                        "compare_callsite_count": group.get("compare_callsite_count", 0),
                    }
                    roots[func_addr] = root
                root["callsite_ids"].add(callsite_id)
                if "compare_callsite_count" not in root:
                    root["compare_callsite_count"] = group.get("compare_callsite_count", 0)

            if tokens:
                callsite_tokens[callsite_id] = tokens
            if ignored:
                callsite_ignored[callsite_id] = ignored
            if candidate_count:
                callsite_token_stats[callsite_id] = {
                    "candidate_count": candidate_count,
                    "kept_count": kept_count,
                    "truncated": candidate_count > kept_count,
                }

    return mode_candidates, callsite_tokens, callsite_ignored, callsite_token_stats


_ARGV0_RE = re.compile(r"\bargv\s*\[\s*0\s*\]|\*\s*argv\b|\bargv\s*\+\s*0\b")
_ARGV1_RE = re.compile(r"\bargv\s*\[\s*1\s*\]|\bargv\s*\+\s*1\b")
_SWITCH_RE = re.compile(r"\bswitch\s*\(")


def _detect_argv_index(decomp_text, token_literals):
    if not decomp_text or not token_literals:
        return 0, 0
    argv0_hits = 0
    argv1_hits = 0
    for line in decomp_text.splitlines():
        if not any(literal in line for literal in token_literals):
            continue
        if _ARGV0_RE.search(line):
            argv0_hits += 1
        if _ARGV1_RE.search(line):
            argv1_hits += 1
    return argv0_hits, argv1_hits


def _detect_argv_index_for_callees(decomp_text, callee_names):
    if not decomp_text or not callee_names:
        return 0, 0
    argv0_hits = 0
    argv1_hits = 0
    for line in decomp_text.splitlines():
        if not any(name and name in line for name in callee_names):
            continue
        if _ARGV0_RE.search(line):
            argv0_hits += 1
        if _ARGV1_RE.search(line):
            argv1_hits += 1
    return argv0_hits, argv1_hits


def _classify_dispatch_groups(
    program,
    groups,
    callsite_tokens,
    table_dispatch_funcs=None,
    handler_diversity_by_func=None,
    monitor=None,
):
    dispatch_meta_by_func = {}
    dispatch_meta_by_callsite = {}
    if not groups:
        return dispatch_meta_by_func, dispatch_meta_by_callsite

    func_manager = program.getFunctionManager()
    decomp_iface = DecompInterface()
    decomp_iface.openProgram(program)
    decomp_cache = {}

    for group in groups:
        func = group.get("function") or {}
        func_addr = func.get("address")
        func_name = func.get("name")
        callsite_ids = group.get("callsites") or []
        base_kind = "string_compare_chain" if len(callsite_ids) > 1 else "string_compare"

        token_values = []
        token_literals = []
        seen_values = set()
        dash_count = 0
        for callsite_id in callsite_ids:
            for token in callsite_tokens.get(callsite_id, []):
                value = token.get("value")
                if not value or value in seen_values:
                    continue
                seen_values.add(value)
                token_values.append(value)
                token_literals.append(_c_string_literal(value))
                if value.startswith("-"):
                    dash_count += 1

        decomp_text = None
        if func_addr:
            if func_addr in decomp_cache:
                decomp_text = decomp_cache[func_addr]
            else:
                addr = _to_address(program, func_addr)
                func_obj = func_manager.getFunctionAt(addr) if addr else None
                decomp_text = _decompile_function_text(decomp_iface, func_obj, monitor)
                decomp_cache[func_addr] = decomp_text

        kind = base_kind
        strength = "heuristic"
        confidence = "low"
        basis = "compare_callsite_count"
        argv_index = None
        argv_index_basis = None

        if table_dispatch_funcs and func_addr in table_dispatch_funcs:
            kind = "table_dispatch"
            strength = "derived"
            confidence = "medium"
            basis = "string_table_adjacent_function_ptrs"
            argv0_hits, argv1_hits = _detect_argv_index(decomp_text, token_literals)
            if not (argv0_hits or argv1_hits):
                argv0_hits, argv1_hits = _detect_argv_index_for_callees(
                    decomp_text,
                    group.get("callee_names") or [],
                )
                if argv0_hits or argv1_hits:
                    argv_index_basis = "argv_index_in_compare_lines"
            else:
                argv_index_basis = "argv_index_in_token_lines"
            if argv0_hits or argv1_hits:
                argv_index = 0 if argv0_hits >= argv1_hits else 1
        else:
            flag_ratio = 0.0
            if token_values and dash_count:
                flag_ratio = float(dash_count) / float(len(token_values))
            if flag_ratio >= 0.6:
                kind = "flag_compare_chain"
                confidence = "low"
                basis = "token_prefix_dash"
            else:
                argv0_hits, argv1_hits = _detect_argv_index(decomp_text, token_literals)
                argv_basis = None
                if not (argv0_hits or argv1_hits):
                    argv0_hits, argv1_hits = _detect_argv_index_for_callees(
                        decomp_text,
                        group.get("callee_names") or [],
                    )
                    if argv0_hits or argv1_hits:
                        argv_basis = "argv_index_in_compare_lines"
                else:
                    argv_basis = "argv_index_in_token_lines"
                if argv0_hits or argv1_hits:
                    if argv0_hits >= argv1_hits and argv0_hits > 0:
                        kind = "argv0_compare_chain"
                        confidence = "medium" if argv0_hits > 1 else "low"
                    else:
                        kind = "argv1_compare_chain"
                        confidence = "medium" if argv1_hits > 1 else "low"
                    basis = argv_basis or "argv_index_in_decomp"
                elif handler_diversity_by_func and func_addr:
                    diversity = handler_diversity_by_func.get(func_addr, 0) or 0
                    if diversity >= 8:
                        kind = "argv0_compare_chain"
                        basis = "handler_assignment_diversity"
                        if func_name and func_name == "main":
                            kind = "argv1_compare_chain"
                            basis = "handler_assignment_diversity_in_main"
                        strength = "derived"
                        confidence = "high"
                elif decomp_text and _SWITCH_RE.search(decomp_text):
                    kind = "switch_dispatch"
                    confidence = "low"
                    basis = "switch_in_decomp"

        meta = {
            "kind": kind,
            "strength": strength,
            "confidence": confidence,
            "basis": basis,
        }
        if argv_index is not None:
            meta["argv_index"] = argv_index
            if argv_index_basis:
                meta["argv_index_basis"] = argv_index_basis
        if func_addr:
            dispatch_meta_by_func[func_addr] = meta
        for callsite_id in callsite_ids:
            dispatch_meta_by_callsite[callsite_id] = meta

    return dispatch_meta_by_func, dispatch_meta_by_callsite


def _attach_implementation_roots(
    program,
    mode_candidates,
    call_edges,
    compare_callsites_by_func,
    function_meta_by_addr,
    options,
    monitor=None,
):
    if not mode_candidates:
        return set(), set(), {}
    callsites_by_func, callsite_targets = _build_callsite_maps(call_edges)
    compare_chain_targets = _collect_compare_chain_targets(
        callsites_by_func, callsite_targets, compare_callsites_by_func
    )
    max_roots = options.get("max_mode_dispatch_roots_per_mode", 0)
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
                    "derived",
                    "medium",
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
                    "heuristic",
                    "low",
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
                    "derived",
                    "medium",
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
                        "derived",
                        "medium",
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


def _derive_mode_kind(mode, dispatch_kind_by_callsite):
    kind = mode.get("kind")
    kind_strength = mode.get("kind_strength")
    kind_confidence = mode.get("kind_confidence")
    if kind == "flag_mode":
        return kind, kind_strength, kind_confidence, "token_prefix_dash"
    if not dispatch_kind_by_callsite:
        return kind, kind_strength, kind_confidence, None

    dispatch_kind_priority = [
        ("argv0_compare_chain", "argv0"),
        ("argv1_compare_chain", "subcommand"),
        ("table_dispatch", None),
        ("flag_compare_chain", "flag_mode"),
    ]
    for dispatch_kind, mode_kind in dispatch_kind_priority:
        for callsite_id in mode.get("dispatch_sites") or []:
            meta = dispatch_kind_by_callsite.get(callsite_id)
            if not meta or meta.get("kind") != dispatch_kind:
                continue
            if dispatch_kind == "table_dispatch":
                argv_index = meta.get("argv_index")
                if argv_index == 0:
                    return (
                        "argv0",
                        meta.get("strength") or "derived",
                        meta.get("confidence") or "low",
                        "dispatch_kind:table_dispatch:argv0",
                    )
                if argv_index == 1:
                    return (
                        "subcommand",
                        meta.get("strength") or "derived",
                        meta.get("confidence") or "low",
                        "dispatch_kind:table_dispatch:argv1",
                    )
                return (
                    "subcommand",
                    meta.get("strength") or "derived",
                    "low",
                    "dispatch_kind:table_dispatch",
                )
            return (
                mode_kind,
                meta.get("strength") or "heuristic",
                meta.get("confidence") or "low",
                "dispatch_kind:%s" % dispatch_kind,
            )
    return kind, kind_strength, kind_confidence, None


def _build_modes_index_payload(
    mode_candidates, callsite_meta, dispatch_kind_by_callsite, options, min_token_len
):
    max_modes = options.get("max_modes", 0)
    max_sites = options.get("max_mode_dispatch_sites_per_mode", 0)
    max_roots = options.get("max_mode_dispatch_roots_per_mode", 0)
    max_token_len = options.get("max_mode_token_length", 0)
    max_tokens_per_callsite = options.get("max_mode_tokens_per_callsite", 0)
    preferred_dispatch_kinds = set(
        [
            "argv0_compare_chain",
            "argv1_compare_chain",
            "table_dispatch",
        ]
    )

    candidate_modes = list(mode_candidates.values())
    total_mode_candidates = len(candidate_modes)

    low_confidence_reason_counts = {}
    low_confidence_candidates = []
    filtered_modes = []
    for mode in candidate_modes:
        impl_roots = mode.get("implementation_roots") or {}
        derived_kind, derived_strength, derived_confidence, derived_basis = _derive_mode_kind(
            mode,
            dispatch_kind_by_callsite,
        )
        has_preferred_dispatch_kind = False
        for callsite_id in mode.get("dispatch_sites") or []:
            meta = dispatch_kind_by_callsite.get(callsite_id) if dispatch_kind_by_callsite else None
            if not meta:
                continue
            if (meta.get("kind") or "") in preferred_dispatch_kinds:
                has_preferred_dispatch_kind = True
                break
        if not has_preferred_dispatch_kind:
            for root in impl_roots.values():
                if "table_dispatch" in (root.get("sources") or set()):
                    has_preferred_dispatch_kind = True
                    break

        reasons = []
        if mode.get("kind") == "flag_mode" or derived_kind == "flag_mode":
            reasons.append("flag_mode_token")
        if not has_preferred_dispatch_kind:
            reasons.append("unpreferred_dispatch_kind")
        if derived_kind == "unknown":
            reasons.append("unclassified_kind")
        if not impl_roots:
            reasons.append("missing_implementation_roots")

        if (
            "flag_mode_token" in reasons
            or "unpreferred_dispatch_kind" in reasons
            or "unclassified_kind" in reasons
        ):
            primary_reason = reasons[0]
            low_confidence_reason_counts[primary_reason] = (
                low_confidence_reason_counts.get(primary_reason, 0) + 1
            )
            dispatch_site_ids = sorted(mode.get("dispatch_sites") or [], key=addr_to_int)
            representative_callsite = dispatch_site_ids[0] if dispatch_site_ids else None
            token = {
                "value": mode.get("name"),
                "string_id": mode.get("string_id"),
                "address": mode.get("address"),
            }
            dispatch_root_entries = []
            dispatch_cluster_score = 0
            for func_addr, root in (mode.get("dispatch_roots") or {}).items():
                callsite_count = len(root.get("callsite_ids") or [])
                compare_callsite_count = root.get("compare_callsite_count")
                if compare_callsite_count is None:
                    compare_callsite_count = callsite_count
                dispatch_cluster_score += compare_callsite_count or 0
                dispatch_root_entries.append(
                    {
                        "function_id": func_addr,
                        "function_name": root.get("function_name"),
                        "callsite_count": callsite_count,
                        "compare_callsite_count": compare_callsite_count,
                        "strength": "derived",
                        "confidence": _confidence_from_count(callsite_count),
                    }
                )
            dispatch_root_entries.sort(
                key=lambda item: (
                    -item.get("callsite_count", 0),
                    addr_to_int(item.get("function_id")),
                )
            )
            if max_roots and len(dispatch_root_entries) > max_roots:
                dispatch_root_entries = dispatch_root_entries[:max_roots]

            dispatch_sites = []
            dispatch_site_sources = mode.get("dispatch_site_sources") or {}
            for callsite_id in dispatch_site_ids[: max_sites or 3]:
                meta = callsite_meta.get(callsite_id, {})
                strength = "observed"
                confidence = "high"
                if dispatch_site_sources.get(callsite_id) == "table_dispatch":
                    strength = "derived"
                    confidence = "medium"
                dispatch_sites.append(
                    {
                        "callsite_id": callsite_id,
                        "caller": meta.get("caller"),
                        "callee": meta.get("callee"),
                        "strength": strength,
                        "confidence": confidence,
                    }
                )

            low_confidence_candidates.append(
                {
                    "mode_id": mode.get("mode_id"),
                    "name": mode.get("name"),
                    "token": token,
                    "kind": derived_kind,
                    "kind_strength": derived_strength,
                    "kind_confidence": derived_confidence,
                    "kind_basis": derived_basis,
                    "primary_reason": primary_reason,
                    "reasons": reasons,
                    "dispatch_sites": dispatch_sites,
                    "dispatch_site_count": len(dispatch_site_ids),
                    "dispatch_roots": dispatch_root_entries,
                    "dispatch_root_count": len(mode.get("dispatch_roots") or {}),
                    "dispatch_cluster_score": dispatch_cluster_score,
                    "implementation_root_count": len(impl_roots),
                    "representative_callsite_id": representative_callsite,
                    "evidence": {
                        "strings": [mode.get("string_id")] if mode.get("string_id") else [],
                        "callsites": dispatch_site_ids,
                        "functions": sorted(
                            (mode.get("dispatch_roots") or {}).keys(), key=addr_to_int
                        ),
                    },
                }
            )
            continue

        filtered_modes.append(mode)

    filtered_out_modes = max(0, total_mode_candidates - len(filtered_modes))

    modes = []
    for mode in filtered_modes:
        callsite_ids = sorted(mode.get("dispatch_sites") or [], key=addr_to_int)
        dispatch_sites = []
        dispatch_site_sources = mode.get("dispatch_site_sources") or {}
        for callsite_id in callsite_ids:
            meta = callsite_meta.get(callsite_id, {})
            strength = "observed"
            confidence = "high"
            if dispatch_site_sources.get(callsite_id) == "table_dispatch":
                strength = "derived"
                confidence = "medium"
            dispatch_sites.append(
                {
                    "callsite_id": callsite_id,
                    "caller": meta.get("caller"),
                    "callee": meta.get("callee"),
                    "strength": strength,
                    "confidence": confidence,
                }
            )
        sites_truncated = False
        if max_sites and len(dispatch_sites) > max_sites:
            dispatch_sites = dispatch_sites[:max_sites]
            sites_truncated = True

        root_entries = []
        dispatch_cluster_score = 0
        for func_addr, root in (mode.get("dispatch_roots") or {}).items():
            callsite_count = len(root.get("callsite_ids") or [])
            compare_callsite_count = root.get("compare_callsite_count")
            if compare_callsite_count is None:
                compare_callsite_count = callsite_count
            dispatch_cluster_score += compare_callsite_count or 0
            root_entries.append(
                {
                    "function_id": func_addr,
                    "function_name": root.get("function_name"),
                    "callsite_count": callsite_count,
                    "compare_callsite_count": compare_callsite_count,
                    "strength": "derived",
                    "confidence": _confidence_from_count(callsite_count),
                }
            )
        root_entries.sort(
            key=lambda item: (-item.get("callsite_count", 0), addr_to_int(item.get("function_id")))
        )
        roots_truncated = False
        if max_roots and len(root_entries) > max_roots:
            root_entries = root_entries[:max_roots]
            roots_truncated = True

        dispatch_site_count = len(callsite_ids)
        dispatch_root_count = len(mode.get("dispatch_roots") or {})
        implementation_root_count = len(mode.get("implementation_roots") or {})
        name = mode.get("name")
        string_id = mode.get("string_id")
        strength = "observed" if dispatch_site_count else "heuristic"
        confidence = _confidence_from_count(dispatch_site_count)
        token = {
            "value": name,
            "string_id": string_id,
            "address": mode.get("address"),
        }
        kind, kind_strength, kind_confidence, kind_basis = _derive_mode_kind(
            mode,
            dispatch_kind_by_callsite,
        )
        evidence_strings = [string_id] if string_id else []
        implementation_roots = []
        max_impl_evidence = 3
        for func_id, root in (mode.get("implementation_roots") or {}).items():
            sources = sorted(root.get("sources") or [])
            evidence = {}
            table_entries = sorted(root.get("table_entry_addresses") or [], key=addr_to_int)
            compare_callsites = sorted(root.get("compare_callsites") or [], key=addr_to_int)
            handler_callsites = sorted(root.get("handler_callsites") or [], key=addr_to_int)
            string_ids = sorted(root.get("string_ids") or [])
            string_addresses = sorted(root.get("string_addresses") or [], key=addr_to_int)
            if table_entries:
                evidence["table_entry_addresses"] = table_entries[:max_impl_evidence]
            if compare_callsites:
                evidence["compare_callsites"] = compare_callsites[:max_impl_evidence]
            if handler_callsites:
                evidence["handler_callsites"] = handler_callsites[:max_impl_evidence]
            if string_ids:
                evidence["strings"] = string_ids[:max_impl_evidence]
            elif string_addresses:
                evidence["string_addresses"] = string_addresses[:max_impl_evidence]
            entry = {
                "function_id": func_id,
                "function_name": root.get("function_name"),
                "sources": sources,
                "strength": root.get("strength") or "heuristic",
                "confidence": root.get("confidence") or "low",
            }
            if evidence:
                entry["evidence"] = evidence
            implementation_roots.append(entry)
        implementation_roots.sort(
            key=lambda item: (
                -_source_rank(item.get("sources")),
                addr_to_int(item.get("function_id")),
            )
        )
        impl_roots_truncated = False
        if max_roots and len(implementation_roots) > max_roots:
            implementation_roots = implementation_roots[:max_roots]
            impl_roots_truncated = True
        entry = {
            "mode_id": mode.get("mode_id"),
            "name": name,
            "unknown_name": not bool(name),
            "token": token,
            "kind": kind,
            "kind_strength": kind_strength,
            "kind_confidence": kind_confidence,
            "name_strength": "observed" if name else "unknown",
            "name_confidence": "high" if name else "unknown",
            "dispatch_roots": root_entries,
            "dispatch_roots_truncated": roots_truncated,
            "dispatch_sites": dispatch_sites,
            "dispatch_sites_truncated": sites_truncated,
            "dispatch_site_count": dispatch_site_count,
            "dispatch_root_count": dispatch_root_count,
            "dispatch_cluster_score": dispatch_cluster_score,
            "implementation_roots": implementation_roots,
            "implementation_root_count": implementation_root_count,
            "implementation_roots_truncated": impl_roots_truncated,
            "strength": strength,
            "confidence": confidence,
            "evidence": {
                "strings": evidence_strings,
                "callsites": callsite_ids,
                "functions": sorted((mode.get("dispatch_roots") or {}).keys(), key=addr_to_int),
            },
        }
        if kind_basis:
            entry["kind_basis"] = kind_basis
        modes.append(entry)

    modes.sort(
        key=lambda item: (
            -item.get("dispatch_cluster_score", 0),
            -item.get("dispatch_site_count", 0),
            -item.get("dispatch_root_count", 0),
            item.get("name") or "",
            item.get("mode_id") or "",
        )
    )
    total_modes = len(modes)
    truncated = False
    if max_modes and total_modes > max_modes:
        modes = modes[:max_modes]
        truncated = True

    selected_mode_ids = set([entry.get("mode_id") for entry in modes if entry.get("mode_id")])

    low_confidence_candidates.sort(
        key=lambda item: (
            -item.get("dispatch_cluster_score", 0),
            -item.get("dispatch_site_count", 0),
            -item.get("dispatch_root_count", 0),
            item.get("name") or "",
            item.get("mode_id") or "",
        )
    )
    max_low_confidence = options.get("max_mode_low_confidence_candidates", 0) or 50
    low_confidence_truncated = False
    if max_low_confidence and len(low_confidence_candidates) > max_low_confidence:
        low_confidence_candidates = low_confidence_candidates[:max_low_confidence]
        low_confidence_truncated = True

    reason_entries = []
    for reason, count in sorted(
        low_confidence_reason_counts.items(), key=lambda item: (-item[1], item[0] or "")
    ):
        reason_entries.append(
            {
                "reason": reason,
                "count": count,
            }
        )

    payload = {
        "total_mode_candidates": total_mode_candidates,
        "filtered_out_modes": filtered_out_modes,
        "candidate_filter": {
            "require_implementation_roots": False,
            "preferred_dispatch_kinds": sorted(preferred_dispatch_kinds),
            "exclude_flag_mode_tokens": True,
            "exclude_unclassified_kinds": True,
        },
        "low_confidence_candidates": {
            "total_low_confidence_candidates": filtered_out_modes,
            "selected_low_confidence_candidates": len(low_confidence_candidates),
            "truncated": low_confidence_truncated,
            "max_low_confidence_candidates": max_low_confidence,
            "primary_reason_counts": reason_entries,
            "candidates": low_confidence_candidates,
        },
        "total_modes": total_modes,
        "selected_modes": len(modes),
        "truncated": truncated,
        "max_modes": max_modes,
        "max_mode_token_length": max_token_len,
        "max_mode_tokens_per_callsite": max_tokens_per_callsite,
        "max_dispatch_sites_per_mode": max_sites,
        "max_dispatch_roots_per_mode": max_roots,
        "selection_strategy": "prefer_dispatch_kinds_then_compare_callsite_groups_then_token_clusters_by_cluster_score",
        "token_filters": {
            "min_length": min_token_len,
            "max_length": max_token_len,
            "exclude_whitespace": True,
            "exclude_non_printable": True,
        },
        "modes": modes,
    }
    return payload, selected_mode_ids


def _build_dispatch_sites_payload(
    groups,
    callsite_tokens,
    callsite_ignored,
    callsite_token_stats,
    call_args_by_callsite,
    selected_mode_ids,
    table_dispatch_tokens,
    dispatch_meta_by_func,
    options,
    total_dispatch_sites,
):
    max_tokens = options.get("max_mode_dispatch_site_tokens", 0)
    max_callsites = options.get("max_mode_dispatch_site_callsites", 0)
    max_ignored = options.get("max_mode_dispatch_site_ignored_tokens", 0)
    max_dispatch_sites = options.get("max_mode_dispatch_functions", 0)

    dispatch_sites = []
    for group in groups:
        callsite_ids_all = group.get("callsites") or []
        callsite_ids = callsite_ids_all
        callsites_truncated = group.get("callsites_truncated", False)
        if max_callsites and len(callsite_ids) > max_callsites:
            callsite_ids = callsite_ids[:max_callsites]
            callsites_truncated = True

        token_counts = {}
        token_meta = {}
        token_counts_selected = {}
        token_meta_selected = {}
        token_occurrence_total = 0
        token_occurrence_kept = 0
        for callsite_id in callsite_ids_all:
            stats = callsite_token_stats.get(callsite_id, {})
            token_occurrence_total += stats.get("candidate_count", 0)
            token_occurrence_kept += stats.get("kept_count", 0)
            for token in callsite_tokens.get(callsite_id, []):
                mode_id = token.get("mode_id")
                key = mode_id or token.get("value")
                token_counts[key] = token_counts.get(key, 0) + 1
                if key not in token_meta:
                    token_meta[key] = token
                if selected_mode_ids and mode_id not in selected_mode_ids:
                    continue
                token_counts_selected[key] = token_counts_selected.get(key, 0) + 1
                if key not in token_meta_selected:
                    token_meta_selected[key] = token

        func_addr = (group.get("function") or {}).get("address")
        dispatch_meta = dispatch_meta_by_func.get(func_addr) if dispatch_meta_by_func else None
        if dispatch_meta:
            dispatch_kind = dispatch_meta.get("kind") or "string_compare_chain"
            dispatch_kind_strength = dispatch_meta.get("strength") or "heuristic"
            dispatch_kind_confidence = dispatch_meta.get("confidence") or "low"
            dispatch_kind_basis = dispatch_meta.get("basis")
        else:
            dispatch_kind = "string_compare_chain" if len(callsite_ids) > 1 else "string_compare"
            dispatch_kind_strength = "heuristic"
            dispatch_kind_confidence = "low"
            dispatch_kind_basis = "compare_callsite_count"

        if dispatch_kind == "table_dispatch" and table_dispatch_tokens:
            for token in table_dispatch_tokens:
                mode_id = token.get("mode_id")
                key = mode_id or token.get("value")
                if not key:
                    continue
                if key not in token_meta:
                    token_meta[key] = token
                if key not in token_counts:
                    token_counts[key] = 1
                if selected_mode_ids and mode_id and mode_id not in selected_mode_ids:
                    continue
                if key not in token_meta_selected:
                    token_meta_selected[key] = token
                if key not in token_counts_selected:
                    token_counts_selected[key] = 1

        token_entries = []
        for key, count in token_counts_selected.items():
            token = token_meta_selected.get(key, {})
            token_source = token.get("source")
            strength = "observed"
            confidence = _confidence_from_count(count)
            if token_source == "table_dispatch":
                strength = "derived"
                confidence = token.get("confidence") or "medium"
            token_entries.append(
                {
                    "mode_id": token.get("mode_id"),
                    "name": token.get("value"),
                    "string_id": token.get("string_id"),
                    "address": token.get("address"),
                    "kind": token.get("kind"),
                    "kind_strength": token.get("kind_strength"),
                    "kind_confidence": token.get("kind_confidence"),
                    "occurrence_count": count,
                    "strength": strength,
                    "confidence": confidence,
                }
            )

        token_entries.sort(
            key=lambda item: (
                -item.get("occurrence_count", 0),
                item.get("name") or "",
                item.get("mode_id") or "",
            )
        )
        token_truncated = False
        if max_tokens and len(token_entries) > max_tokens:
            token_entries = token_entries[:max_tokens]
            token_truncated = True
        token_total_count = len(token_counts)
        token_selected_count = len(token_counts_selected)
        excluded = max(0, token_total_count - token_selected_count)
        omitted = max(0, token_selected_count - len(token_entries))
        if omitted and not token_truncated:
            token_truncated = True
        omitted_occurrences = max(0, token_occurrence_total - token_occurrence_kept)

        ignored_counts = {}
        for callsite_id in callsite_ids_all:
            for ignored in callsite_ignored.get(callsite_id, []):
                key = (ignored.get("reason"), ignored.get("preview"))
                ignored_counts[key] = ignored_counts.get(key, 0) + 1
        ignored_entries = []
        for (reason, preview), count in ignored_counts.items():
            ignored_entries.append(
                {
                    "preview": preview,
                    "reason": reason,
                    "count": count,
                }
            )
        ignored_entries.sort(key=lambda item: (-item.get("count", 0), item.get("preview") or ""))
        ignored_truncated = False
        if max_ignored and len(ignored_entries) > max_ignored:
            ignored_entries = ignored_entries[:max_ignored]
            ignored_truncated = True

        status_counts = {}
        for callsite_id in callsite_ids_all:
            status = (call_args_by_callsite.get(callsite_id, {}) or {}).get("status")
            status_counts[status] = status_counts.get(status, 0) + 1
        status_entries = []
        for status, count in status_counts.items():
            status_entries.append(
                {
                    "status": status,
                    "count": count,
                }
            )
        status_entries.sort(key=lambda item: (-item.get("count", 0), item.get("status") or ""))

        callsite_ids_sorted = sorted(callsite_ids, key=addr_to_int)
        representative_callsite = callsite_ids_sorted[0] if callsite_ids_sorted else None
        token_count = token_selected_count
        strength = "observed" if token_count else "heuristic"
        confidence = _confidence_from_count(token_count)
        evidence_strings = sorted(
            {entry.get("string_id") for entry in token_entries if entry.get("string_id")}
        )
        entry = {
            "function": group.get("function"),
            "callee_names": group.get("callee_names"),
            "compare_callsite_count": group.get("compare_callsite_count", 0),
            "callsite_ids": callsite_ids_sorted,
            "callsites_truncated": callsites_truncated,
            "representative_callsite_id": representative_callsite,
            "dispatch_kind": dispatch_kind,
            "dispatch_kind_strength": dispatch_kind_strength,
            "dispatch_kind_confidence": dispatch_kind_confidence,
            "token_candidates": token_entries,
            "token_candidates_truncated": token_truncated,
            "token_candidate_count": token_count,
            "token_candidate_total_count": token_total_count,
            "excluded_token_count": excluded,
            "token_candidate_occurrence_count": token_occurrence_total,
            "ignored_tokens": ignored_entries,
            "ignored_tokens_truncated": ignored_truncated,
            "omitted_token_count": omitted,
            "omitted_token_occurrence_count": omitted_occurrences,
            "callsite_status_counts": status_entries,
            "strength": strength,
            "confidence": confidence,
            "evidence": {
                "callsites": callsite_ids_sorted,
                "functions": [(group.get("function") or {}).get("address")],
                "strings": evidence_strings,
            },
        }
        if dispatch_kind_basis:
            entry["dispatch_kind_basis"] = dispatch_kind_basis
        dispatch_sites.append(entry)

    dispatch_sites.sort(
        key=lambda item: (
            -item.get("compare_callsite_count", 0),
            addr_to_int((item.get("function") or {}).get("address")),
        )
    )

    payload = {
        "total_dispatch_sites": total_dispatch_sites,
        "selected_dispatch_sites": len(dispatch_sites),
        "truncated": total_dispatch_sites > len(dispatch_sites),
        "max_dispatch_sites": max_dispatch_sites,
        "max_dispatch_site_callsites": max_callsites,
        "max_dispatch_site_tokens": max_tokens,
        "max_dispatch_site_ignored_tokens": max_ignored,
        "selection_strategy": "top_compare_callers_then_token_counts",
        "dispatch_sites": dispatch_sites,
    }
    return payload


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
    entry_names = set(["main", "cmd_main"])
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
