"""Mode export "surface map" helpers.

The surface map is a compact, high-signal index intended to help downstream users
decide where to start reading mode evidence. This module also contains the small
"callsite_ref" hydration pass that runs after callsite evidence has been written.
"""

from export_bounds import Bounds
from export_primitives import addr_to_int


def attach_mode_callsite_refs(modes_payload, dispatch_sites_payload, callsite_paths):
    for mode in modes_payload.get("modes", []):
        evidence = mode.get("evidence") or {}
        callsite_refs = []
        for entry in mode.get("dispatch_sites", []):
            callsite_id = entry.get("callsite_id")
            if not callsite_id:
                continue
            ref = callsite_paths.get(callsite_id)
            if ref:
                entry["callsite_ref"] = ref
                callsite_refs.append(ref)
        if callsite_refs:
            evidence["callsite_refs"] = callsite_refs
            mode["evidence"] = evidence

    low_confidence = (modes_payload.get("low_confidence_candidates") or {}).get("candidates") or []
    for candidate in low_confidence:
        evidence = candidate.get("evidence") or {}
        callsite_refs = []
        for entry in candidate.get("dispatch_sites", []):
            callsite_id = entry.get("callsite_id")
            if not callsite_id:
                continue
            ref = callsite_paths.get(callsite_id)
            if ref:
                entry["callsite_ref"] = ref
                callsite_refs.append(ref)
        if callsite_refs:
            evidence["callsite_refs"] = callsite_refs
            candidate["evidence"] = evidence

    for entry in dispatch_sites_payload.get("dispatch_sites", []):
        callsite_ids = entry.get("callsite_ids") or []
        callsite_refs = []
        for callsite_id in callsite_ids:
            ref = callsite_paths.get(callsite_id)
            if ref:
                callsite_refs.append(ref)
        if callsite_refs:
            entry["callsite_refs"] = callsite_refs
        representative_callsite = entry.get("representative_callsite_id")
        if representative_callsite:
            entry["representative_callsite_ref"] = callsite_paths.get(representative_callsite)


def build_modes_surface(
    modes_payload,
    dispatch_sites_payload,
    callsite_paths,
    bounds: Bounds,
):
    max_entries = bounds.max_mode_surface_entries or 5

    modes = modes_payload.get("modes", []) if modes_payload else []
    dispatch_sites = (
        dispatch_sites_payload.get("dispatch_sites", []) if dispatch_sites_payload else []
    )

    top_modes = []
    for mode in modes[:max_entries]:
        rep_callsite = None
        for site in mode.get("dispatch_sites", []):
            rep_callsite = site.get("callsite_id")
            break
        entry = {
            "mode_id": mode.get("mode_id"),
            "name": mode.get("name"),
            "dispatch_site_count": mode.get("dispatch_site_count"),
            "dispatch_root_count": mode.get("dispatch_root_count"),
            "dispatch_cluster_score": mode.get("dispatch_cluster_score"),
            "representative_callsite_id": rep_callsite,
            "representative_callsite_ref": callsite_paths.get(rep_callsite)
            if rep_callsite
            else None,
        }
        top_modes.append(entry)

    def _token_candidate_count(site):
        count = site.get("token_candidate_count")
        if count is None:
            count = len(site.get("token_candidates") or [])
        try:
            return int(count)
        except Exception:
            return 0

    top_dispatch_sites = []
    sites_with_tokens = [site for site in dispatch_sites if _token_candidate_count(site) > 0]
    if sites_with_tokens:
        selected_sites = sites_with_tokens
    else:
        selected_sites = dispatch_sites

    for site in selected_sites[:max_entries]:
        rep_callsite = site.get("representative_callsite_id")
        token_candidate_count = _token_candidate_count(site)
        top_dispatch_sites.append(
            {
                "function": site.get("function"),
                "compare_callsite_count": site.get("compare_callsite_count"),
                "token_candidate_count": token_candidate_count,
                "representative_callsite_id": rep_callsite,
                "representative_callsite_ref": site.get("representative_callsite_ref"),
            }
        )

    root_stats = {}
    for mode in modes:
        for root in mode.get("dispatch_roots", []):
            func_id = root.get("function_id")
            if not func_id:
                continue
            stats = root_stats.get(func_id)
            if stats is None:
                stats = {
                    "function": {
                        "address": func_id,
                        "name": root.get("function_name"),
                    },
                    "mode_count": 0,
                    "dispatch_site_count": 0,
                }
                root_stats[func_id] = stats
            stats["mode_count"] += 1
            stats["dispatch_site_count"] += root.get("callsite_count", 0)

    top_dispatch_roots = []
    for stats in sorted(
        root_stats.values(),
        key=lambda item: (
            -item.get("mode_count", 0),
            -item.get("dispatch_site_count", 0),
            addr_to_int((item.get("function") or {}).get("address")),
        ),
    )[:max_entries]:
        top_dispatch_roots.append(stats)

    surface = {}
    if top_modes:
        surface["top_modes"] = top_modes
    if top_dispatch_sites:
        surface["top_dispatch_sites"] = top_dispatch_sites
    if top_dispatch_roots:
        surface["top_dispatch_roots"] = top_dispatch_roots
    if surface:
        surface["index_ref"] = "modes/index.json"
        surface["dispatch_sites_ref"] = "modes/dispatch_sites.json"
        surface["slices_ref"] = "modes/slices.json"
    return surface
