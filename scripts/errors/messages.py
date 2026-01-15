"""Derive `errors/messages.json` payload."""

from errors.common import (
    ERROR_BUCKET_EMITTERS,
    ERROR_EMITTER_NAMES,
    WARN_BUCKET_EMITTERS,
    _collect_callsites,
)
from export_collectors import (
    extract_call_args_for_callsites,
    is_printf_format_string,
    is_usage_marker,
)
from export_primitives import addr_to_int

ERROR_KEYWORDS = [
    "error",
    "cannot",
    "can't",
    "could not",
    "failed",
    "invalid",
    "no such file",
    "permission",
    "denied",
    "not found",
    "unrecognized",
    "illegal",
    "unknown",
    "missing",
    "too many",
    "unable",
    "out of memory",
    "overflow",
]

WARN_KEYWORDS = [
    "warning",
    "deprecated",
]

BUCKET_PRIORITY = {
    "usage": 0,
    "error": 1,
    "warn": 2,
    "diagnostic": 3,
    "unknown": 4,
}


def escape_preview(value, limit=160):
    if value is None:
        return ""
    escaped = value.replace("\\", "\\\\")
    escaped = escaped.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
    safe = []
    for ch in escaped:
        code = ord(ch)
        if 32 <= code <= 126:
            safe.append(ch)
        else:
            safe.append("\\u%04x" % code)
    preview = "".join(safe)
    if limit and len(preview) > limit:
        preview = preview[: max(0, limit - 3)] + "..."
    return preview


def _keyword_hit(value, keywords):
    lowered = value.lower()
    for token in keywords:
        if token in lowered:
            return True
    return False


def is_usage_message(value, tags):
    if "usage" in tags:
        return True
    if value is None:
        return False
    return is_usage_marker(value)


def bucket_for_emitter(emitter_import):
    if emitter_import in ERROR_BUCKET_EMITTERS:
        return "error"
    if emitter_import in WARN_BUCKET_EMITTERS:
        return "warn"
    return None


def build_candidate_entry(string_id, value, tags, ref_count=0, address=None):
    if not value:
        return None
    return {
        "string_id": string_id,
        "value": value,
        "preview": escape_preview(value),
        "bucket": classify_message_bucket(value, tags),
        "ref_count": ref_count,
        "address": address,
    }


def merge_emitter_bucket(current, incoming):
    if incoming == "error":
        return "error"
    if incoming == "warn":
        if current != "error":
            return "warn"
    return current


def record_observed_emitter_bucket(observed_map, string_id, emitter_bucket, value, tags):
    if not emitter_bucket or is_usage_message(value, tags):
        return
    observed_map[string_id] = merge_emitter_bucket(observed_map.get(string_id), emitter_bucket)


def append_link(links_by_string, string_id, entry):
    links_by_string.setdefault(string_id, []).append(entry)


def dedupe_links(links):
    seen_links = set()
    unique_links = []
    for link in links:
        key = (link.get("callsite_id"), link.get("link_strength"))
        if key in seen_links:
            continue
        seen_links.add(key)
        unique_links.append(link)
    return unique_links


def sort_links(links, max_callsites):
    def link_sort_key(item):
        return (
            0 if item.get("link_strength") == "observed" else 1,
            addr_to_int(item.get("callsite_id")),
        )

    links_sorted = sorted(links, key=link_sort_key)
    if max_callsites:
        links_sorted = links_sorted[:max_callsites]
    return links_sorted


def classify_message_bucket(value, tags):
    if value is None:
        return "unknown"
    if is_usage_message(value, tags):
        return "usage"
    if _keyword_hit(value, WARN_KEYWORDS):
        return "warn"
    if _keyword_hit(value, ERROR_KEYWORDS):
        return "error"
    if "format" in tags or is_printf_format_string(value):
        if value.endswith("\n"):
            return "diagnostic"
    return "unknown"


def is_error_candidate(value, tags):
    if value is None or len(value) < 3:
        return False
    if is_usage_message(value, tags):
        return True
    if _keyword_hit(value, WARN_KEYWORDS) or _keyword_hit(value, ERROR_KEYWORDS):
        return True
    if "format" in tags or is_printf_format_string(value):
        if value.endswith("\n"):
            return True
    return False


def _build_string_xrefs(string_refs_by_func):
    xrefs = {}
    for func_id, string_ids in string_refs_by_func.items():
        for string_id in string_ids:
            bucket = xrefs.get(string_id)
            if bucket is None:
                bucket = set()
                xrefs[string_id] = bucket
            bucket.add(func_id)
    return xrefs


def derive_error_messages(
    program,
    monitor,
    strings,
    string_addr_map_all,
    string_refs_by_func,
    call_edges,
    function_meta_by_addr,
    string_tags_by_id,
    options,
    call_args_cache=None,
):
    if call_args_cache is None:
        call_args_cache = {}
    candidates = {}
    string_meta_by_id = {}
    for entry in strings:
        string_id = entry.get("id")
        value = entry.get("value")
        if not string_id or not value:
            continue
        string_meta_by_id[string_id] = entry
        tags = string_tags_by_id.get(string_id) or set()
        if not is_error_candidate(value, tags):
            continue
        candidate = build_candidate_entry(
            string_id,
            value,
            tags,
            ref_count=entry.get("ref_count", 0),
            address=entry.get("address"),
        )
        if candidate:
            candidates[string_id] = candidate

    emitter_callsites, emitter_callsites_by_func = _collect_callsites(
        call_edges,
        function_meta_by_addr,
        ERROR_EMITTER_NAMES,
    )
    emitter_callsites_total = len(emitter_callsites)
    candidate_ids = set(candidates.keys())
    candidate_func_ids = set()
    for func_id, refs in string_refs_by_func.items():
        for string_id in refs:
            if string_id in candidate_ids:
                candidate_func_ids.add(func_id)
                break

    candidate_callsites = []
    for callsite in emitter_callsites:
        func_id = callsite.get("function_id")
        if func_id not in candidate_func_ids:
            continue
        candidate_callsites.append(callsite)

    max_callsites = options.get("max_error_message_callsites", 0)
    considered_callsites = candidate_callsites
    truncated_emitters = False
    if max_callsites and len(considered_callsites) > max_callsites:
        considered_callsites = considered_callsites[:max_callsites]
        truncated_emitters = True

    callsite_ids = []
    for entry in considered_callsites:
        callsite_id = entry.get("callsite_id")
        if callsite_id and callsite_id not in call_args_cache:
            callsite_ids.append(callsite_id)

    if callsite_ids:
        call_args_cache.update(
            extract_call_args_for_callsites(
                program,
                callsite_ids,
                monitor,
                purpose="export_errors.derive_error_messages",
            )
        )

    observed = {}
    links_by_string = {}
    for callsite in considered_callsites:
        callsite_id = callsite.get("callsite_id")
        if not callsite_id:
            continue
        args = call_args_cache.get(callsite_id) or {}
        string_args = args.get("string_args", [])
        if not string_args:
            continue
        emitter_bucket = bucket_for_emitter(callsite.get("emitter_import"))
        for entry in string_args:
            address = entry.get("address")
            if not address:
                continue
            string_id = string_addr_map_all.get(address)
            if not string_id or string_id not in candidate_ids:
                continue
            meta = string_meta_by_id.get(string_id, {})
            value = meta.get("value") or entry.get("value")
            tags = string_tags_by_id.get(string_id) or set()
            record_observed_emitter_bucket(observed, string_id, emitter_bucket, value, tags)
            append_link(links_by_string, string_id, {
                "callsite_id": callsite_id,
                "function_id": callsite.get("function_id"),
                "function_name": callsite.get("function_name"),
                "emitter_import": callsite.get("emitter_import"),
                "link_strength": "observed",
                "confidence": "high",
            })

    xrefs = _build_string_xrefs(string_refs_by_func)
    for string_id in candidate_ids:
        if string_id in links_by_string:
            continue
        funcs = sorted(xrefs.get(string_id, []), key=addr_to_int)
        if not funcs:
            continue
        func_id = funcs[0]
        callsites = emitter_callsites_by_func.get(func_id) or []
        for callsite in callsites[:1]:
            append_link(links_by_string, string_id, {
                "callsite_id": callsite.get("callsite_id"),
                "function_id": callsite.get("function_id"),
                "function_name": callsite.get("function_name"),
                "emitter_import": callsite.get("emitter_import"),
                "link_strength": "xref",
                "confidence": "low",
            })

    messages = []
    max_functions = options.get("max_error_message_functions", 10)
    for string_id, candidate in candidates.items():
        value = candidate.get("value")
        tags = string_tags_by_id.get(string_id) or set()
        links = links_by_string.get(string_id, [])
        links = dedupe_links(links)
        links = sort_links(links, max_callsites)
        if not links:
            continue
        emitting_funcs = []
        seen_funcs = set()
        for link in links:
            func_id = link.get("function_id")
            if not func_id or func_id in seen_funcs:
                continue
            emitting_funcs.append({
                "function_id": func_id,
                "function_name": link.get("function_name"),
            })
            seen_funcs.add(func_id)
            if max_functions and len(emitting_funcs) >= max_functions:
                break

        callsite_entries = []
        for link in links:
            callsite_entries.append({
                "callsite_id": link.get("callsite_id"),
                "function_id": link.get("function_id"),
                "function_name": link.get("function_name"),
                "emitter_import": link.get("emitter_import"),
                "link_strength": link.get("link_strength"),
                "confidence": link.get("confidence"),
            })

        emitter_bucket = observed.get(string_id)
        strength = "heuristic"
        confidence = "low"
        if emitter_bucket:
            strength = "observed"
            confidence = "high"

        bucket = classify_message_bucket(value, tags)
        if emitter_bucket and bucket != "usage":
            bucket = merge_emitter_bucket(bucket, emitter_bucket)

        messages.append({
            "string_id": string_id,
            "string_address": candidate.get("address"),
            "preview": candidate.get("preview"),
            "bucket": bucket,
            "strength": strength,
            "confidence": confidence,
            "ref_count": candidate.get("ref_count", 0),
            "emitter_bucket": emitter_bucket,
            "emitting_functions": emitting_funcs,
            "emitting_callsites": callsite_entries,
            "tags": sorted(tags),
            "evidence": {
                "strings": [string_id],
                "callsites": [entry.get("callsite_id") for entry in callsite_entries if entry.get("callsite_id")],
                "functions": [entry.get("function_id") for entry in emitting_funcs if entry.get("function_id")],
            },
        })

    observed_scan = None
    if observed:
        observed_scan = {
            "observed_bucket_counts": {
                bucket: sum(1 for value in observed.values() if value == bucket)
                for bucket in sorted(set(observed.values()))
            },
        }

    def message_sort_key(item):
        return (
            BUCKET_PRIORITY.get(item.get("bucket"), 99),
            0 if item.get("strength") == "observed" else 1,
            -len(item.get("emitting_callsites") or []),
            -len(item.get("emitting_functions") or []),
            addr_to_int(item.get("string_address")),
        )

    messages.sort(key=message_sort_key)
    max_messages = options.get("max_error_messages", 0)
    truncated = False
    if max_messages and len(messages) > max_messages:
        messages = messages[:max_messages]
        truncated = True

    payload = {
        "total_candidates": len(candidates),
        "selected_messages": len(messages),
        "truncated": truncated,
        "max_messages": max_messages,
        "max_callsites_per_message": max_callsites,
        "max_functions_per_message": options.get("max_error_message_functions", 10),
        "emitter_callsites_total": emitter_callsites_total,
        "emitter_callsites_considered": len(considered_callsites),
        "emitter_callsites_truncated": truncated_emitters,
        "selection_strategy": "heuristic_candidates_then_callsite_linked",
        "messages": messages,
    }
    if observed_scan is not None:
        payload["observed_scan"] = observed_scan
    return payload, emitter_callsites_by_func, call_args_cache
