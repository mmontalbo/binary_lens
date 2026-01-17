"""Attach callsite reference paths to mode payloads."""


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
