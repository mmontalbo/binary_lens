"""Dispatch-site grouping and selection for mode detection.

This module is intentionally Ghidra-light: it mostly reshapes data already
collected by collectors (CLI compare callsites + callgraph edges) into
per-function "dispatch groups" that can be ranked and truncated deterministically.

The output of these helpers feeds the higher-level mode-candidate and payload
builders, so ordering and truncation behavior should remain stable.
"""

from collections import deque

from export_primitives import addr_to_int


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

