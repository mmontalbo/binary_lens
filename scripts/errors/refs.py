"""Error callsite bookkeeping and evidence reference hydration."""

from export_primitives import addr_to_int


def collect_error_callsites(messages_payload, exit_paths_payload, error_sites_payload):
    callsite_ids = set()
    for message in messages_payload.get("messages", []):
        for entry in message.get("emitting_callsites", []):
            callsite_id = entry.get("callsite_id")
            if callsite_id:
                callsite_ids.add(callsite_id)
    for entry in exit_paths_payload.get("direct_calls", []):
        callsite_id = entry.get("callsite_id")
        if callsite_id:
            callsite_ids.add(callsite_id)
    for site in error_sites_payload.get("sites", []):
        for callsite_id in site.get("callsite_ids", []):
            if callsite_id:
                callsite_ids.add(callsite_id)
    return sorted(callsite_ids, key=addr_to_int)


def attach_callsite_refs(messages_payload, exit_paths_payload, error_sites_payload, callsite_paths):
    if not callsite_paths:
        return
    for message in messages_payload.get("messages", []):
        for entry in message.get("emitting_callsites", []):
            callsite_id = entry.get("callsite_id")
            ref = callsite_paths.get(callsite_id)
            if ref:
                entry["callsite_ref"] = ref

    for entry in exit_paths_payload.get("direct_calls", []):
        callsite_id = entry.get("callsite_id")
        ref = callsite_paths.get(callsite_id)
        if ref:
            entry["callsite_ref"] = ref

    for site in error_sites_payload.get("sites", []):
        refs = []
        for callsite_id in site.get("callsite_ids", []):
            ref = callsite_paths.get(callsite_id)
            if ref:
                refs.append(ref)
        if refs:
            site["callsite_refs"] = refs
