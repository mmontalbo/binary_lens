"""Stable JSON payload builders for mode export.

These helpers build the Milestone 3 "modes" JSON artifacts:
- `modes/index.json` (mode candidate index + low confidence candidates)
- `modes/dispatch_sites.json` (per-dispatch-function token evidence)

They should remain schema-stable; refactors in this module should avoid altering
field meanings, ordering, or truncation behavior.
"""

from export_primitives import addr_to_int
from modes.common import _confidence_from_count, _source_rank


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

