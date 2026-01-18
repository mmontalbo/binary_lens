"""Derive `errors/error_sites.json` payload."""

from errors.common import INT_TYPES, STATUS_EMITTERS
from export_bounds import Bounds
from export_primitives import addr_to_int


def derive_error_sites(
    messages_payload,
    exit_callsites_by_func,
    emitter_callsites_by_func,
    call_args_cache,
    bounds: Bounds,
):
    callsite_imports = {}
    callsite_to_function = {}
    for entries in (emitter_callsites_by_func or {}).values():
        if not entries:
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            callsite_id = entry.get("callsite_id")
            func_id = entry.get("function_id")
            if callsite_id and func_id:
                callsite_to_function[callsite_id] = func_id
            emitter = entry.get("emitter_import")
            if callsite_id and emitter:
                callsite_imports[callsite_id] = emitter

    sites = {}
    for message in messages_payload.get("messages", []):
        for callsite_entry in message.get("emitting_callsites", []):
            callsite_id = None
            if isinstance(callsite_entry, str):
                callsite_id = callsite_entry
            elif isinstance(callsite_entry, dict):
                callsite_id = callsite_entry.get("callsite_id")
            if not callsite_id:
                continue
            func_id = callsite_to_function.get(callsite_id)
            if not func_id:
                continue
            site = sites.get(func_id)
            if site is None:
                site = {
                    "function_id": func_id,
                    "callsite_ids": [],
                    "imports": set(),
                }
                sites[func_id] = site
            emitter = callsite_imports.get(callsite_id)
            if emitter:
                site["imports"].add(emitter)
            site["callsite_ids"].append(callsite_id)

    results = []
    max_callsites = bounds.max_error_site_callsites
    for site in sites.values():
        all_callsite_ids = sorted(set(site["callsite_ids"]), key=addr_to_int)
        callsite_ids = list(all_callsite_ids)
        if max_callsites and len(callsite_ids) > max_callsites:
            callsite_ids = callsite_ids[:max_callsites]
        imports = sorted(site["imports"])
        severity = "unknown"
        exit_callsites = exit_callsites_by_func.get(site["function_id"]) if exit_callsites_by_func else None
        direct_exit_callsites = []
        if exit_callsites:
            direct_exit_callsites = sorted(
                {entry.get("callsite_id") for entry in exit_callsites if entry.get("callsite_id")},
                key=addr_to_int,
            )

        status_by_callsite = {}
        has_status_nonzero = False
        has_status_zero = False
        for callsite_id in all_callsite_ids:
            emitter = callsite_imports.get(callsite_id)
            status = "unknown"
            if emitter in STATUS_EMITTERS:
                args = call_args_cache.get(callsite_id) or {}
                const_value = args.get("const_args_by_index", {}).get(0)
                if isinstance(const_value, INT_TYPES):
                    if int(const_value) == 0:
                        status = "status_arg_zero"
                        has_status_zero = True
                    else:
                        status = "status_arg_nonzero"
                        has_status_nonzero = True
            status_by_callsite[callsite_id] = status

        if direct_exit_callsites:
            severity = "fatal"
        elif has_status_nonzero:
            severity = "fatal"
        elif has_status_zero:
            severity = "non_fatal"

        callsites = []
        for callsite_id in callsite_ids:
            callsites.append({
                "callsite_id": callsite_id,
                "status": status_by_callsite.get(callsite_id) or "unknown",
            })
        results.append({
            "callsites": callsites,
            "imports": imports,
            "severity": severity,
        })

    def _site_sort_key(item):
        callsites = item.get("callsites") or []
        if callsites:
            return addr_to_int(callsites[0].get("callsite_id"))
        return -1

    results.sort(key=_site_sort_key)
    max_sites = bounds.optional("max_error_sites")
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
        "sites": results,
    }
    return payload
