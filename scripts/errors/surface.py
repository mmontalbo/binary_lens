"""Build the compact error surface summary and attach evidence references."""

from export_primitives import addr_to_int


def build_error_surface(messages_payload, exit_paths_payload, error_sites_payload, max_entries=5):
    top_messages = []
    messages = messages_payload.get("messages", []) or []
    if messages:
        bucketed = {}
        for message in messages:
            bucket = message.get("bucket") or "unknown"
            bucketed.setdefault(bucket, []).append(message)
        bucket_order = ["error", "usage", "warn", "diagnostic", "unknown"]
        ordered_buckets = [bucket for bucket in bucket_order if bucket in bucketed]
        ordered_buckets.extend([bucket for bucket in bucketed if bucket not in ordered_buckets])
        bucket_indexes = {bucket: 0 for bucket in ordered_buckets}
        while len(top_messages) < max_entries:
            added = False
            for bucket in ordered_buckets:
                idx = bucket_indexes[bucket]
                if idx >= len(bucketed[bucket]):
                    continue
                message = bucketed[bucket][idx]
                bucket_indexes[bucket] += 1
                callsites = message.get("emitting_callsites") or []
                rep_callsite = callsites[0] if callsites else {}
                top_messages.append({
                    "string_id": message.get("string_id"),
                    "preview": message.get("preview"),
                    "bucket": message.get("bucket"),
                    "representative_callsite_id": rep_callsite.get("callsite_id"),
                })
                added = True
                if len(top_messages) >= max_entries:
                    break
            if not added:
                break

    top_exits = []
    for entry in exit_paths_payload.get("direct_calls", [])[:max_entries]:
        top_exits.append({
            "callsite_id": entry.get("callsite_id"),
            "function": {
                "address": entry.get("function_id"),
                "name": entry.get("function_name"),
            },
            "target": entry.get("target"),
            "exit_code": entry.get("exit_code"),
            "exit_code_strength": entry.get("exit_code_strength"),
        })

    top_emitters = []
    sites = list(error_sites_payload.get("sites", []))
    sites.sort(key=lambda item: (-len(item.get("callsite_ids") or []), addr_to_int(item.get("function_id"))))
    for site in sites[:max_entries]:
        top_emitters.append({
            "function": {
                "address": site.get("function_id"),
                "name": site.get("function_name"),
            },
            "emit_callsite_count": len(site.get("callsite_ids") or []),
        })

    surface = {}
    if top_emitters:
        surface["top_emitting_functions"] = top_emitters
    if top_exits:
        surface["top_exit_paths"] = top_exits
    if top_messages:
        surface["top_message_templates"] = top_messages
    return surface


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
    for entry in exit_paths_payload.get("likely_fatal_patterns", []):
        for callsite_id in entry.get("emitter_callsites", []):
            if callsite_id:
                callsite_ids.add(callsite_id)
        for callsite_id in entry.get("exit_callsites", []):
            if callsite_id:
                callsite_ids.add(callsite_id)
    for site in error_sites_payload.get("sites", []):
        for callsite_id in site.get("callsite_ids", []):
            if callsite_id:
                callsite_ids.add(callsite_id)
    return sorted(callsite_ids, key=addr_to_int)


def attach_callsite_refs(messages_payload, exit_paths_payload, error_sites_payload, error_surface, callsite_paths):
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

    for entry in exit_paths_payload.get("likely_fatal_patterns", []):
        refs = []
        for callsite_id in entry.get("emitter_callsites", []):
            ref = callsite_paths.get(callsite_id)
            if ref:
                refs.append(ref)
        for callsite_id in entry.get("exit_callsites", []):
            ref = callsite_paths.get(callsite_id)
            if ref:
                refs.append(ref)
        if refs:
            entry["callsite_refs"] = refs

    for site in error_sites_payload.get("sites", []):
        refs = []
        for callsite_id in site.get("callsite_ids", []):
            ref = callsite_paths.get(callsite_id)
            if ref:
                refs.append(ref)
        if refs:
            site["callsite_refs"] = refs

    for entry in error_surface.get("top_exit_paths", []):
        callsite_id = entry.get("callsite_id")
        ref = callsite_paths.get(callsite_id)
        if ref:
            entry["callsite_ref"] = ref

    for entry in error_surface.get("top_message_templates", []):
        callsite_id = entry.get("representative_callsite_id")
        ref = callsite_paths.get(callsite_id)
        if ref:
            entry["representative_callsite_ref"] = ref

