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


def attach_callsite_refs(messages_payload, exit_paths_payload, error_sites_payload, callsites_ref):
    if not callsites_ref:
        return
    if isinstance(messages_payload, dict):
        messages_payload["callsites_ref"] = callsites_ref
    if isinstance(exit_paths_payload, dict):
        exit_paths_payload["callsites_ref"] = callsites_ref
    if isinstance(error_sites_payload, dict):
        error_sites_payload["callsites_ref"] = callsites_ref
