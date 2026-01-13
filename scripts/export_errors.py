from export_collectors import (
    extract_call_args_for_callsites,
    is_printf_format_string,
    is_usage_marker,
)
from export_primitives import addr_to_int, normalize_symbol_name

try:
    INT_TYPES = (int, long)
except NameError:
    INT_TYPES = (int,)

ERROR_EMITTER_NAMES = set([
    "fprintf",
    "printf",
    "dprintf",
    "vfprintf",
    "vprintf",
    "vdprintf",
    "fputs",
    "puts",
    "putc",
    "putchar",
    "perror",
    "strerror",
    "strerror_r",
    "strerrorname_np",
    "error",
    "error_at_line",
    "verror",
    "verror_at_line",
    "warn",
    "warnx",
    "vwarn",
    "vwarnx",
    "err",
    "errx",
    "verr",
    "verrx",
])

ERROR_BUCKET_EMITTERS = set([
    "error",
    "error_at_line",
    "verror",
    "verror_at_line",
    "err",
    "errx",
    "verr",
    "verrx",
    "perror",
])

WARN_BUCKET_EMITTERS = set([
    "warn",
    "warnx",
    "vwarn",
    "vwarnx",
])

STATUS_EMITTERS = set([
    "error",
    "error_at_line",
    "verror",
    "verror_at_line",
])

EXIT_CALL_NAMES = set([
    "exit",
    "_exit",
    "abort",
])

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


def normalize_import_name(name):
    base = normalize_symbol_name(name)
    if not base:
        return None
    base = base.lstrip("_")
    if base.startswith("GI_"):
        base = base[3:]
    if base.endswith("_chk"):
        base = base[:-4]
    return base.lower()


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


def _collect_callsites(call_edges, function_meta_by_addr, name_set):
    callsites = []
    callsites_by_func = {}
    for edge in call_edges:
        callsite_id = edge.get("callsite")
        if not callsite_id:
            continue
        target = edge.get("to") or {}
        name_norm = normalize_import_name(target.get("name"))
        if not name_norm or name_norm not in name_set:
            continue
        from_addr = (edge.get("from") or {}).get("address")
        if not from_addr:
            continue
        meta = function_meta_by_addr.get(from_addr, {})
        if meta.get("is_external") or meta.get("is_thunk"):
            continue
        entry = {
            "callsite_id": callsite_id,
            "function_id": from_addr,
            "function_name": meta.get("name") or (edge.get("from") or {}).get("function"),
            "emitter_import": name_norm,
            "target": target,
        }
        callsites.append(entry)
        bucket = callsites_by_func.get(from_addr)
        if bucket is None:
            bucket = []
            callsites_by_func[from_addr] = bucket
        bucket.append(entry)
    for bucket in callsites_by_func.values():
        bucket.sort(key=lambda item: addr_to_int(item.get("callsite_id")))
    callsites.sort(key=lambda item: addr_to_int(item.get("callsite_id")))
    return callsites, callsites_by_func


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
    if candidate_ids:
        for func_id, string_ids in string_refs_by_func.items():
            if not string_ids:
                continue
            if not candidate_ids.isdisjoint(string_ids):
                candidate_func_ids.add(func_id)
    max_emitters = options.get("max_error_emitter_callsites", 0)
    if candidate_func_ids:
        preferred_callsites = []
        other_callsites = []
        for callsite in emitter_callsites:
            if callsite.get("function_id") in candidate_func_ids:
                preferred_callsites.append(callsite)
            else:
                other_callsites.append(callsite)
        considered_callsites = preferred_callsites + other_callsites
    else:
        considered_callsites = emitter_callsites
    truncated_emitters = False
    if max_emitters and len(considered_callsites) > max_emitters:
        considered_callsites = considered_callsites[:max_emitters]
        truncated_emitters = True
    callsite_ids = [entry.get("callsite_id") for entry in considered_callsites if entry.get("callsite_id")]
    missing_callsites = [callsite_id for callsite_id in callsite_ids if callsite_id not in call_args_cache]
    if missing_callsites:
        call_args_cache.update(
            extract_call_args_for_callsites(program, missing_callsites, monitor)
        )
    links_by_string = {}
    observed_strings = set()
    observed_emitter_bucket = {}
    for callsite in considered_callsites:
        callsite_id = callsite["callsite_id"]
        args = call_args_cache.get(callsite_id) or {}
        emitter_import = callsite.get("emitter_import")
        emitter_bucket = bucket_for_emitter(emitter_import)
        for arg in args.get("string_args", []):
            string_id = string_addr_map_all.get(arg.get("address"))
            if not string_id:
                continue
            value = arg.get("value")
            tags = string_tags_by_id.get(string_id) or set()
            if string_id not in candidates:
                meta_entry = string_meta_by_id.get(string_id)
                if meta_entry:
                    value = meta_entry.get("value") or value
                    candidate = build_candidate_entry(
                        string_id,
                        value,
                        tags,
                        ref_count=meta_entry.get("ref_count", 0),
                        address=meta_entry.get("address"),
                    )
                else:
                    if emitter_bucket not in ("error", "warn"):
                        continue
                    if not value:
                        continue
                    candidate = build_candidate_entry(
                        string_id,
                        value,
                        tags,
                        ref_count=0,
                        address=arg.get("address"),
                    )
                if candidate:
                    candidates[string_id] = candidate
            meta = candidates.get(string_id)
            if not meta:
                continue
            value = meta.get("value") or value
            record_observed_emitter_bucket(
                observed_emitter_bucket,
                string_id,
                emitter_bucket,
                value,
                tags,
            )
            entry = {
                "callsite_id": callsite_id,
                "function_id": callsite["function_id"],
                "function_name": callsite.get("function_name"),
                "emitter_import": callsite["emitter_import"],
                "link_strength": "observed",
                "confidence": "high",
            }
            append_link(links_by_string, string_id, entry)
            observed_strings.add(string_id)

    for string_id, bucket in observed_emitter_bucket.items():
        meta = candidates.get(string_id)
        if not meta:
            continue
        value = meta.get("value")
        tags = string_tags_by_id.get(string_id) or set()
        if is_usage_message(value, tags):
            continue
        meta["bucket"] = bucket

    string_xrefs = _build_string_xrefs(string_refs_by_func)
    max_callsites = options.get("max_error_message_callsites", 5)
    for string_id, meta in candidates.items():
        if string_id in observed_strings:
            continue
        if meta.get("bucket") not in ("error", "warn", "usage"):
            continue
        for func_id in sorted(string_xrefs.get(string_id, []), key=addr_to_int):
            callsites = emitter_callsites_by_func.get(func_id)
            if not callsites:
                continue
            for callsite in callsites:
                append_link(links_by_string, string_id, {
                    "callsite_id": callsite["callsite_id"],
                    "function_id": callsite["function_id"],
                    "function_name": callsite.get("function_name"),
                    "emitter_import": callsite["emitter_import"],
                    "link_strength": "heuristic",
                    "confidence": "low",
                })
                if len(links_by_string.get(string_id, [])) >= max_callsites:
                    break
            if len(links_by_string.get(string_id, [])) >= max_callsites:
                break

    messages = []
    for string_id, meta in candidates.items():
        links = links_by_string.get(string_id) or []
        links = dedupe_links(links)
        if not links:
            continue
        observed = any(link.get("link_strength") == "observed" for link in links)
        strength = "observed" if observed else "heuristic"
        confidence = "high" if observed else "low"
        imports = set()
        function_counts = {}
        for link in links:
            imports.add(link.get("emitter_import"))
            func_id = link.get("function_id")
            if not func_id:
                continue
            function_counts[func_id] = function_counts.get(func_id, 0) + 1
        functions = []
        for func_id, count in function_counts.items():
            func_meta = function_meta_by_addr.get(func_id, {})
            functions.append({
                "function_id": func_id,
                "function_name": func_meta.get("name"),
                "callsite_count": count,
            })
        functions.sort(
            key=lambda item: (-item.get("callsite_count", 0), addr_to_int(item.get("function_id")))
        )
        max_funcs = options.get("max_error_message_functions", 10)
        if max_funcs:
            functions = functions[:max_funcs]
        links_sorted = sort_links(links, max_callsites)
        messages.append({
            "string_id": string_id,
            "string_address": meta.get("address"),
            "preview": meta.get("preview"),
            "bucket": meta.get("bucket"),
            "related_imports": sorted(imports),
            "emitting_functions": functions,
            "emitting_callsites": links_sorted,
            "strength": strength,
            "confidence": confidence,
            "evidence": {
                "strings": [string_id],
                "callsites": sorted({link.get("callsite_id") for link in links if link.get("callsite_id")}),
                "functions": sorted(function_counts.keys(), key=addr_to_int),
            },
        })

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
    return payload, emitter_callsites_by_func, call_args_cache


def derive_exit_paths(
    program,
    monitor,
    call_edges,
    function_meta_by_addr,
    options,
    call_args_cache=None,
    emitter_callsites_by_func=None,
):
    if call_args_cache is None:
        call_args_cache = {}
    exit_callsites, exit_callsites_by_func = _collect_callsites(
        call_edges,
        function_meta_by_addr,
        EXIT_CALL_NAMES,
    )
    direct_calls = []
    exit_callsite_ids = [entry.get("callsite_id") for entry in exit_callsites if entry.get("callsite_id")]
    missing_exit_callsites = [callsite_id for callsite_id in exit_callsite_ids if callsite_id not in call_args_cache]
    if missing_exit_callsites:
        call_args_cache.update(
            extract_call_args_for_callsites(program, missing_exit_callsites, monitor)
        )
    for callsite in exit_callsites:
        callsite_id = callsite["callsite_id"]
        args = call_args_cache.get(callsite_id) or {}
        exit_code = None
        code_strength = "unknown"
        if callsite.get("emitter_import") in ("exit",):
            const_value = args.get("const_args_by_index", {}).get(0)
            if isinstance(const_value, INT_TYPES):
                exit_code = int(const_value)
                code_strength = "observed"
        direct_calls.append({
            "callsite_id": callsite_id,
            "function_id": callsite["function_id"],
            "function_name": callsite.get("function_name"),
            "target": callsite.get("target"),
            "exit_code": exit_code,
            "exit_code_strength": code_strength,
            "strength": "observed",
            "confidence": "high",
            "evidence": {
                "callsites": [callsite_id],
                "functions": [callsite.get("function_id")],
            },
        })
    direct_calls.sort(key=lambda item: addr_to_int(item.get("callsite_id")))
    max_exit_paths = options.get("max_exit_paths", 0)
    truncated = False
    if max_exit_paths and len(direct_calls) > max_exit_paths:
        direct_calls = direct_calls[:max_exit_paths]
        truncated = True

    likely_fatal = []
    if emitter_callsites_by_func:
        for func_id, exit_calls in exit_callsites_by_func.items():
            if func_id not in emitter_callsites_by_func:
                continue
            emit_calls = emitter_callsites_by_func.get(func_id) or []
            if not emit_calls:
                continue
            likely_fatal.append({
                "pattern": "emit_and_exit_same_function",
                "function_id": func_id,
                "emitter_callsites": [entry.get("callsite_id") for entry in emit_calls],
                "exit_callsites": [entry.get("callsite_id") for entry in exit_calls],
                "strength": "heuristic",
                "confidence": "low",
                "evidence": {
                    "callsites": sorted(
                        {entry.get("callsite_id") for entry in emit_calls + exit_calls if entry.get("callsite_id")},
                        key=addr_to_int,
                    ),
                    "functions": [func_id],
                },
            })
    likely_fatal.sort(key=lambda item: addr_to_int(item.get("function_id")))
    max_patterns = options.get("max_exit_patterns", 0)
    if max_patterns and len(likely_fatal) > max_patterns:
        likely_fatal = likely_fatal[:max_patterns]

    payload = {
        "total_exit_calls": len(exit_callsites),
        "selected_exit_calls": len(direct_calls),
        "truncated": truncated,
        "max_exit_calls": max_exit_paths,
        "selection_strategy": "direct_calls_to_exit_abort",
        "direct_calls": direct_calls,
        "likely_fatal_patterns": likely_fatal,
    }
    return payload, exit_callsites_by_func, call_args_cache


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
    max_sites = options.get("max_error_sites", 0)
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
