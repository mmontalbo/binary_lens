"""Derive `errors/error_sites.json` payload."""

from errors.common import INT_TYPES, STATUS_EMITTERS
from export_primitives import addr_to_int


def derive_error_sites(messages_payload, exit_callsites_by_func, call_args_cache, options, function_meta_by_addr):
    callsite_imports = {}
    for message in messages_payload.get("messages", []):
        for callsite in message.get("emitting_callsites", []):
            callsite_id = callsite.get("callsite_id")
            if not callsite_id:
                continue
            emitter = callsite.get("emitter_import")
            if emitter:
                callsite_imports[callsite_id] = emitter

    sites = {}
    for message in messages_payload.get("messages", []):
        for callsite in message.get("emitting_callsites", []):
            func_id = callsite.get("function_id")
            if not func_id:
                continue
            site = sites.get(func_id)
            if site is None:
                site = {
                    "function_id": func_id,
                    "function_name": function_meta_by_addr.get(func_id, {}).get("name"),
                    "callsite_ids": [],
                    "imports": set(),
                }
                sites[func_id] = site
            callsite_id = callsite.get("callsite_id")
            if callsite_id:
                site["callsite_ids"].append(callsite_id)
            emitter = callsite.get("emitter_import")
            if emitter:
                site["imports"].add(emitter)

    results = []
    max_callsites = options.get("max_error_site_callsites", 0)
    for site in sites.values():
        all_callsite_ids = sorted(set(site["callsite_ids"]), key=addr_to_int)
        callsite_ids = list(all_callsite_ids)
        if max_callsites and len(callsite_ids) > max_callsites:
            callsite_ids = callsite_ids[:max_callsites]
        imports = sorted(site["imports"])
        severity = "unknown"
        strength = "unknown"
        confidence = "low"
        exit_callsites = exit_callsites_by_func.get(site["function_id"]) if exit_callsites_by_func else None
        direct_exit_callsites = []
        if exit_callsites:
            direct_exit_callsites = sorted(
                {entry.get("callsite_id") for entry in exit_callsites if entry.get("callsite_id")},
                key=addr_to_int,
            )

        status_arg_nonzero = []
        status_arg_zero = []
        status_arg_unknown = []
        for callsite_id in all_callsite_ids:
            emitter = callsite_imports.get(callsite_id)
            if emitter not in STATUS_EMITTERS:
                status_arg_unknown.append(callsite_id)
                continue
            args = call_args_cache.get(callsite_id) or {}
            const_value = args.get("const_args_by_index", {}).get(0)
            if isinstance(const_value, INT_TYPES):
                if int(const_value) == 0:
                    status_arg_zero.append(callsite_id)
                else:
                    status_arg_nonzero.append(callsite_id)
            else:
                status_arg_unknown.append(callsite_id)

        if direct_exit_callsites:
            severity = "fatal"
            strength = "derived"
            confidence = "medium"
        elif status_arg_nonzero:
            severity = "fatal"
            strength = "heuristic"
            confidence = "low"
        elif status_arg_zero:
            severity = "non_fatal"
            strength = "heuristic"
            confidence = "low"

        def cap_callsites(values):
            if not max_callsites:
                return values
            return values[:max_callsites]

        followed_by = {
            "direct_exit_callsites": cap_callsites(direct_exit_callsites),
            "status_arg_nonzero": cap_callsites(status_arg_nonzero),
            "status_arg_zero": cap_callsites(status_arg_zero),
            "unknown": cap_callsites(status_arg_unknown),
        }
        results.append({
            "function_id": site["function_id"],
            "function_name": site.get("function_name"),
            "callsite_ids": callsite_ids,
            "imports": imports,
            "severity": severity,
            "strength": strength,
            "confidence": confidence,
            "followed_by": followed_by,
            "evidence": {
                "callsites": callsite_ids,
                "functions": [site["function_id"]],
            },
        })

    results.sort(key=lambda item: addr_to_int(item.get("function_id")))
    raw_max_sites = options.get("max_error_sites", 0)
    try:
        max_sites = int(raw_max_sites)
    except Exception:
        max_sites = 0
    if max_sites <= 0:
        max_sites = None
    truncated = False
    if max_sites and len(results) > max_sites:
        results = results[:max_sites]
        truncated = True

    payload = {
        "total_sites": len(sites),
        "selected_sites": len(results),
        "truncated": truncated,
        "max_sites": max_sites,
        "max_callsites_per_site": max_callsites,
        "selection_strategy": "grouped_emitter_callsites",
        "sites": results,
    }
    return payload
