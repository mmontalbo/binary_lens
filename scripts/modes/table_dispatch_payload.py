"""Site and token attachment helpers for table-dispatch mode evidence."""

from export_primitives import addr_to_int
from modes.common import (
    _looks_like_subcommand_token,
    _mode_has_table_dispatch_root,
    _token_kind,
)


def _collect_table_dispatch_site_infos(groups, dispatch_meta_by_func):
    if not groups or not dispatch_meta_by_func:
        return []
    infos = []
    for group in groups:
        func = group.get("function") or {}
        func_addr = func.get("address")
        if not func_addr:
            continue
        meta = dispatch_meta_by_func.get(func_addr)
        if not meta or meta.get("kind") != "table_dispatch":
            continue
        callsites = group.get("callsites") or []
        if not callsites:
            continue
        callsites_sorted = sorted(callsites, key=addr_to_int)
        rep = callsites_sorted[0]
        infos.append(
            {
                "function_id": func_addr,
                "function_name": func.get("name"),
                "compare_callsite_count": group.get("compare_callsite_count", 0),
                "representative_callsite_id": rep,
            }
        )
    return infos


def _attach_table_dispatch_sites(mode_candidates, site_infos):
    if not mode_candidates or not site_infos:
        return False
    updated = False
    for mode in mode_candidates.values():
        if not _mode_has_table_dispatch_root(mode):
            continue
        dispatch_sites = mode.get("dispatch_sites")
        if dispatch_sites is None:
            dispatch_sites = set()
            mode["dispatch_sites"] = dispatch_sites
        dispatch_roots = mode.get("dispatch_roots")
        if dispatch_roots is None:
            dispatch_roots = {}
            mode["dispatch_roots"] = dispatch_roots
        dispatch_site_sources = mode.setdefault("dispatch_site_sources", {})
        for info in site_infos:
            callsite_id = info.get("representative_callsite_id")
            func_id = info.get("function_id")
            if not callsite_id or not func_id:
                continue
            is_new = callsite_id not in dispatch_sites
            dispatch_sites.add(callsite_id)
            if is_new:
                dispatch_site_sources[callsite_id] = "table_dispatch"
                updated = True
            root = dispatch_roots.get(func_id)
            if root is None:
                root = {
                    "function_name": info.get("function_name"),
                    "callsite_ids": set(),
                    "compare_callsite_count": info.get("compare_callsite_count", 0),
                }
                dispatch_roots[func_id] = root
            if not root.get("function_name") and info.get("function_name"):
                root["function_name"] = info.get("function_name")
            root["callsite_ids"].add(callsite_id)
            if "compare_callsite_count" not in root:
                root["compare_callsite_count"] = info.get("compare_callsite_count", 0)
    return updated


def _collect_table_dispatch_tokens(mode_candidates, selected_mode_ids):
    if not mode_candidates or not selected_mode_ids:
        return []
    tokens = []
    seen = set()
    for mode_id in selected_mode_ids:
        mode = mode_candidates.get(mode_id)
        if not mode or not _mode_has_table_dispatch_root(mode):
            continue
        value = mode.get("name")
        if not value or not _looks_like_subcommand_token(value):
            continue
        if value in seen:
            continue
        seen.add(value)
        kind, _kind_basis = _token_kind(value)
        tokens.append(
            {
                "mode_id": mode.get("mode_id") or mode_id,
                "value": value,
                "string_id": mode.get("string_id"),
                "address": mode.get("address"),
                "kind": kind,
                "source": "table_dispatch",
            }
        )
    tokens.sort(key=lambda item: (item.get("value") or "", item.get("mode_id") or ""))
    return tokens
