"""Stable JSON payload builders for mode export.

These helpers build the Milestone 3 "modes" JSON artifacts:
- `modes/index.json` (mode candidate index)
- `modes/dispatch_sites.json` (per-dispatch-function token evidence)

They should remain schema-stable; refactors in this module should avoid altering
field meanings, ordering, or truncation behavior.
"""

from export_bounds import Bounds
from export_primitives import addr_to_int
from modes.common import _source_rank


def _derive_mode_kind(mode, dispatch_kind_by_callsite):
    kind = mode.get("kind")
    if kind == "flag_mode":
        return kind, "token_prefix_dash"
    if not dispatch_kind_by_callsite:
        return kind, mode.get("kind_basis")

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
                    return "argv0", "dispatch_kind:table_dispatch:argv0"
                if argv_index == 1:
                    return "subcommand", "dispatch_kind:table_dispatch:argv1"
                return "subcommand", "dispatch_kind:table_dispatch"
            return mode_kind, "dispatch_kind:%s" % dispatch_kind
    return kind, mode.get("kind_basis")


def _build_modes_index_payload(
    mode_candidates,
    callsite_meta,
    dispatch_kind_by_callsite,
    bounds: Bounds,
):
    max_modes = bounds.optional("max_modes")
    max_sites = bounds.max_mode_dispatch_sites_per_mode
    max_roots = bounds.max_mode_dispatch_roots_per_mode
    max_token_len = bounds.max_mode_token_length
    max_tokens_per_callsite = bounds.max_mode_tokens_per_callsite
    preferred_dispatch_kinds = set(
        [
            "argv0_compare_chain",
            "argv1_compare_chain",
            "table_dispatch",
        ]
    )

    candidate_modes = list(mode_candidates.values())
    total_mode_candidates = len(candidate_modes)

    filtered_modes = []
    for mode in candidate_modes:
        impl_roots = mode.get("implementation_roots") or {}
        derived_kind, _ = _derive_mode_kind(
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

        if mode.get("kind") == "flag_mode" or derived_kind == "flag_mode":
            continue
        if not has_preferred_dispatch_kind:
            continue
        if derived_kind == "unknown":
            continue

        filtered_modes.append(mode)

    filtered_out_modes = max(0, total_mode_candidates - len(filtered_modes))

    modes = []
    for mode in filtered_modes:
        callsite_ids = sorted(mode.get("dispatch_sites") or [], key=addr_to_int)
        dispatch_sites = []
        for callsite_id in callsite_ids:
            dispatch_sites.append(
                {
                    "callsite_id": callsite_id,
                }
            )
        sites_truncated = False
        if max_sites and len(dispatch_sites) > max_sites:
            dispatch_sites = dispatch_sites[:max_sites]
            sites_truncated = True

        root_entries = []
        for func_addr, root in (mode.get("dispatch_roots") or {}).items():
            callsite_count = len(root.get("callsite_ids") or [])
            compare_callsite_count = root.get("compare_callsite_count")
            if compare_callsite_count is None:
                compare_callsite_count = callsite_count
            root_entries.append(
                {
                    "function_id": func_addr,
                    "callsite_count": callsite_count,
                    "compare_callsite_count": compare_callsite_count,
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
        token = {
            "string_id": string_id,
            "address": mode.get("address"),
        }
        if not string_id and name:
            token["value"] = name
        sort_name = name or ""
        kind, kind_basis = _derive_mode_kind(
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
                "sources": sources,
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
            "name": name if not string_id else None,
            "unknown_name": not bool(name or string_id),
            "token": token,
            "kind": kind,
            "dispatch_roots": root_entries,
            "dispatch_roots_truncated": roots_truncated,
            "dispatch_sites": dispatch_sites,
            "dispatch_sites_truncated": sites_truncated,
            "dispatch_site_count": dispatch_site_count,
            "dispatch_root_count": dispatch_root_count,
            "implementation_roots": implementation_roots,
            "implementation_root_count": implementation_root_count,
            "implementation_roots_truncated": impl_roots_truncated,
            "evidence": {
                "strings": evidence_strings,
                "callsites": callsite_ids,
                "functions": sorted((mode.get("dispatch_roots") or {}).keys(), key=addr_to_int),
            },
            "_sort_name": sort_name,
        }
        if kind_basis:
            entry["kind_basis"] = kind_basis
        modes.append(entry)

    modes.sort(
        key=lambda item: (
            -item.get("dispatch_site_count", 0),
            -item.get("dispatch_root_count", 0),
            -item.get("implementation_root_count", 0),
            item.get("_sort_name") or "",
            item.get("mode_id") or "",
        )
    )
    total_modes = len(modes)
    truncated = False
    if max_modes and total_modes > max_modes:
        modes = modes[:max_modes]
        truncated = True

    for entry in modes:
        entry.pop("_sort_name", None)

    selected_mode_ids = set([entry.get("mode_id") for entry in modes if entry.get("mode_id")])

    payload = {
        "total_mode_candidates": total_mode_candidates,
        "filtered_out_modes": filtered_out_modes,
        "total_modes": total_modes,
        "selected_modes": len(modes),
        "truncated": truncated,
        "max_modes": max_modes,
        "max_mode_token_length": max_token_len,
        "max_mode_tokens_per_callsite": max_tokens_per_callsite,
        "max_dispatch_sites_per_mode": max_sites,
        "max_dispatch_roots_per_mode": max_roots,
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
    bounds: Bounds,
    total_dispatch_sites,
):
    max_tokens = bounds.max_mode_dispatch_site_tokens
    max_callsites = bounds.max_mode_dispatch_site_callsites
    max_ignored = bounds.max_mode_dispatch_site_ignored_tokens
    max_dispatch_sites = bounds.max_mode_dispatch_functions

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
            dispatch_kind_basis = dispatch_meta.get("basis")
        else:
            dispatch_kind = "string_compare_chain" if len(callsite_ids) > 1 else "string_compare"
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
            name = token.get("value")
            string_id = token.get("string_id")
            token_entries.append(
                {
                    "mode_id": token.get("mode_id"),
                    "name": name if not string_id else None,
                    "string_id": string_id,
                    "address": token.get("address"),
                    "kind": token.get("kind"),
                    "occurrence_count": count,
                    "_sort_name": name or "",
                }
            )

        token_entries.sort(
            key=lambda item: (
                -item.get("occurrence_count", 0),
                item.get("_sort_name") or "",
                item.get("mode_id") or "",
            )
        )
        for entry in token_entries:
            entry.pop("_sort_name", None)
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
        evidence_strings = sorted(
            {entry.get("string_id") for entry in token_entries if entry.get("string_id")}
        )
        function_id = (group.get("function") or {}).get("address")
        entry = {
            "function_id": function_id,
            "compare_callsite_count": group.get("compare_callsite_count", 0),
            "callsite_ids": callsite_ids_sorted,
            "callsites_truncated": callsites_truncated,
            "representative_callsite_id": representative_callsite,
            "dispatch_kind": dispatch_kind,
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
            "evidence": {
                "callsites": callsite_ids_sorted,
                "functions": [function_id] if function_id else [],
                "strings": evidence_strings,
            },
        }
        if dispatch_kind_basis:
            entry["dispatch_kind_basis"] = dispatch_kind_basis
        dispatch_sites.append(entry)

    dispatch_sites.sort(
        key=lambda item: (
            -item.get("compare_callsite_count", 0),
            addr_to_int(item.get("function_id")),
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
        "dispatch_sites": dispatch_sites,
    }
    return payload
