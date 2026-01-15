"""Derive `errors/messages.json` payload."""

from __future__ import annotations

from typing import Any, Mapping, MutableMapping, Sequence

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

StringId = str
FunctionId = str
CallsiteId = str
Address = str

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


def _collect_initial_candidates(strings, string_tags_by_id):
    """Select initial message candidates from the global string table.

    This phase is heuristic-only; observed callsite scanning may add more
    candidates later.
    """
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
    return candidates, string_meta_by_id


def _collect_candidate_function_ids(string_refs_by_func, candidate_ids):
    """Return functions that reference at least one candidate string."""
    candidate_func_ids = set()
    if not candidate_ids:
        return candidate_func_ids
    for func_id, string_ids in string_refs_by_func.items():
        if not string_ids:
            continue
        if not candidate_ids.isdisjoint(string_ids):
            candidate_func_ids.add(func_id)
    return candidate_func_ids


def _prioritize_emitter_callsites(emitter_callsites, candidate_func_ids, max_emitters):
    """Return emitters to scan, prioritizing functions with candidate strings."""
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
    return considered_callsites, truncated_emitters


def _parse_int_option(options: Mapping[str, Any], key: str) -> int:
    try:
        return int(options.get(key) or 0)
    except Exception:
        return 0


def _process_observed_callsites(
    callsite_entries: Sequence[dict[str, Any]],
    *,
    program: Any,
    monitor: Any,
    candidates: MutableMapping[StringId, dict[str, Any]],
    string_meta_by_id: Mapping[StringId, dict[str, Any]],
    string_addr_map_all: Mapping[Address, StringId],
    string_tags_by_id: Mapping[StringId, set[str]],
    call_args_cache: MutableMapping[CallsiteId, dict[str, Any]],
    links_by_string: MutableMapping[StringId, list[dict[str, Any]]],
    observed_strings: set[StringId],
    observed_emitter_bucket: MutableMapping[StringId, str],
) -> None:
    """Populate observed links by reading call arguments for emitter callsites.

    This is the only phase that consults `program`/`monitor` via PyGhidra.
    """
    if not callsite_entries:
        return
    callsite_ids = [entry.get("callsite_id") for entry in callsite_entries if entry.get("callsite_id")]
    missing_callsites = [callsite_id for callsite_id in callsite_ids if callsite_id not in call_args_cache]
    if missing_callsites:
        call_args_cache.update(
            extract_call_args_for_callsites(
                program,
                missing_callsites,
                monitor,
                purpose="export_errors.derive_error_messages",
            )
        )
    for callsite in callsite_entries:
        callsite_id = callsite.get("callsite_id")
        if not callsite_id:
            continue
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
                "function_id": callsite.get("function_id"),
                "function_name": callsite.get("function_name"),
                "emitter_import": callsite.get("emitter_import"),
                "link_strength": "observed",
                "confidence": "high",
            }
            append_link(links_by_string, string_id, entry)
            observed_strings.add(string_id)


def _scan_observed_callsites(
    considered_callsites: Sequence[dict[str, Any]],
    *,
    program: Any,
    monitor: Any,
    candidates: MutableMapping[StringId, dict[str, Any]],
    string_meta_by_id: Mapping[StringId, dict[str, Any]],
    string_addr_map_all: Mapping[Address, StringId],
    string_tags_by_id: Mapping[StringId, set[str]],
    call_args_cache: MutableMapping[CallsiteId, dict[str, Any]],
    candidate_func_ids: set[FunctionId],
    function_meta_by_addr: Mapping[FunctionId, dict[str, Any]] | None,
    links_by_string: MutableMapping[StringId, list[dict[str, Any]]],
    observed_strings: set[StringId],
    observed_emitter_bucket: MutableMapping[StringId, str],
    max_observed_strings: int,
    max_observed_callsites: int,
    max_observed_functions: int,
    auto_observed_limits: bool,
) -> dict[str, Any] | None:
    """Scan a subset of emitter callsites and attach observed callsite links.

    `observed_scan` is only emitted when auto-limits are enabled or scanning is
    truncated via explicit limits.
    """
    apply_observed_limits = bool(max_observed_strings or max_observed_callsites or max_observed_functions)
    if not apply_observed_limits:
        _process_observed_callsites(
            considered_callsites,
            program=program,
            monitor=monitor,
            candidates=candidates,
            string_meta_by_id=string_meta_by_id,
            string_addr_map_all=string_addr_map_all,
            string_tags_by_id=string_tags_by_id,
            call_args_cache=call_args_cache,
            links_by_string=links_by_string,
            observed_strings=observed_strings,
            observed_emitter_bucket=observed_emitter_bucket,
        )
        return None

    callsites_by_func = {}
    func_order = []
    seen_funcs = set()
    considered_callsite_count = 0
    for callsite in considered_callsites:
        callsite_id = callsite.get("callsite_id")
        func_id = callsite.get("function_id")
        if not callsite_id or not func_id:
            continue
        considered_callsite_count += 1
        bucket = callsites_by_func.get(func_id)
        if bucket is None:
            bucket = []
            callsites_by_func[func_id] = bucket
        bucket.append(callsite)
        if func_id not in seen_funcs:
            seen_funcs.add(func_id)
            func_order.append(func_id)

    if func_order:

        def func_sort_key(func_id: FunctionId) -> tuple[int, int, int]:
            priority = 0 if func_id in candidate_func_ids else 1
            meta = function_meta_by_addr.get(func_id) if function_meta_by_addr else None
            size = (meta or {}).get("size")
            try:
                size = int(size)
            except Exception:
                size = 0
            return (priority, size, addr_to_int(func_id))

        func_order.sort(key=func_sort_key)

    if max_observed_callsites and max_observed_callsites > considered_callsite_count:
        max_observed_callsites = considered_callsite_count
    if max_observed_functions and max_observed_functions > len(func_order):
        max_observed_functions = len(func_order)

    observed_callsites_scanned = 0
    observed_functions_scanned = 0
    batch = []
    batch_callsite_limit = 100
    stop_reason = None
    for func_id in func_order:
        if max_observed_functions and observed_functions_scanned >= max_observed_functions:
            stop_reason = "max_observed_functions"
            break
        callsites = callsites_by_func.get(func_id) or []
        if not callsites:
            continue
        if max_observed_callsites:
            remaining = max_observed_callsites - observed_callsites_scanned
            if remaining <= 0:
                stop_reason = "max_observed_callsites"
                break
            if len(callsites) > remaining:
                callsites = callsites[:remaining]
        observed_functions_scanned += 1
        observed_callsites_scanned += len(callsites)
        batch.extend(callsites)
        if len(batch) >= batch_callsite_limit:
            _process_observed_callsites(
                batch,
                program=program,
                monitor=monitor,
                candidates=candidates,
                string_meta_by_id=string_meta_by_id,
                string_addr_map_all=string_addr_map_all,
                string_tags_by_id=string_tags_by_id,
                call_args_cache=call_args_cache,
                links_by_string=links_by_string,
                observed_strings=observed_strings,
                observed_emitter_bucket=observed_emitter_bucket,
            )
            batch = []
            if max_observed_strings and len(observed_strings) >= max_observed_strings:
                stop_reason = "max_observed_strings"
                break

    if batch and stop_reason != "max_observed_strings":
        _process_observed_callsites(
            batch,
            program=program,
            monitor=monitor,
            candidates=candidates,
            string_meta_by_id=string_meta_by_id,
            string_addr_map_all=string_addr_map_all,
            string_tags_by_id=string_tags_by_id,
            call_args_cache=call_args_cache,
            links_by_string=links_by_string,
            observed_strings=observed_strings,
            observed_emitter_bucket=observed_emitter_bucket,
        )
    if stop_reason is None and max_observed_strings and len(observed_strings) >= max_observed_strings:
        stop_reason = "max_observed_strings"

    if not (auto_observed_limits or stop_reason is not None):
        return None

    return {
        "callsites_scanned": observed_callsites_scanned,
        "functions_scanned": observed_functions_scanned,
        "unique_strings_found": len(observed_strings),
        "stop_reason": stop_reason or "complete",
        "auto_limits": bool(auto_observed_limits),
    }


def _apply_observed_emitter_buckets(candidates, observed_emitter_bucket, string_tags_by_id):
    """Override candidate buckets based on observed error/warn emitters."""
    for string_id, bucket in observed_emitter_bucket.items():
        meta = candidates.get(string_id)
        if not meta:
            continue
        value = meta.get("value")
        tags = string_tags_by_id.get(string_id) or set()
        if is_usage_message(value, tags):
            continue
        meta["bucket"] = bucket


def _add_heuristic_links(
    candidates,
    *,
    observed_strings,
    links_by_string,
    max_callsites,
    string_xrefs,
    emitter_callsites_by_func,
) -> None:
    """Best-effort link candidates to nearby emitter callsites without arg recovery."""
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
                append_link(
                    links_by_string,
                    string_id,
                    {
                        "callsite_id": callsite["callsite_id"],
                        "function_id": callsite["function_id"],
                        "function_name": callsite.get("function_name"),
                        "emitter_import": callsite["emitter_import"],
                        "link_strength": "heuristic",
                        "confidence": "low",
                    },
                )
                if len(links_by_string.get(string_id, [])) >= max_callsites:
                    break
            if len(links_by_string.get(string_id, [])) >= max_callsites:
                break


def _build_messages(
    candidates,
    *,
    links_by_string,
    function_meta_by_addr,
    max_callsites,
    max_funcs,
):
    """Build message entries from candidates + linked callsites.

    Link ordering/truncation is intentionally stable for diff-friendly packs.
    """
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
            functions.append(
                {
                    "function_id": func_id,
                    "function_name": func_meta.get("name"),
                    "callsite_count": count,
                }
            )
        functions.sort(
            key=lambda item: (-item.get("callsite_count", 0), addr_to_int(item.get("function_id")))
        )
        if max_funcs:
            functions = functions[:max_funcs]
        links_sorted = sort_links(links, max_callsites)
        messages.append(
            {
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
                    "callsites": sorted(
                        {link.get("callsite_id") for link in links if link.get("callsite_id")}
                    ),
                    "functions": sorted(function_counts.keys(), key=addr_to_int),
                },
            }
        )
    return messages


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
    """Compute `errors/messages.json` and supporting error-emitter link state."""
    if call_args_cache is None:
        call_args_cache = {}
    candidates, string_meta_by_id = _collect_initial_candidates(strings, string_tags_by_id)

    emitter_callsites, emitter_callsites_by_func = _collect_callsites(
        call_edges,
        function_meta_by_addr,
        ERROR_EMITTER_NAMES,
    )
    emitter_callsites_total = len(emitter_callsites)
    candidate_ids = set(candidates.keys())
    candidate_func_ids = _collect_candidate_function_ids(string_refs_by_func, candidate_ids)

    max_emitters = options.get("max_error_emitter_callsites", 0)
    considered_callsites, truncated_emitters = _prioritize_emitter_callsites(
        emitter_callsites, candidate_func_ids, max_emitters
    )

    links_by_string = {}
    observed_strings = set()
    observed_emitter_bucket = {}
    max_observed_strings = _parse_int_option(options, "max_error_observed_strings")
    max_observed_callsites = _parse_int_option(options, "max_error_observed_callsites")
    max_observed_functions = _parse_int_option(options, "max_error_observed_functions")

    auto_observed_limits = False
    if not (max_observed_strings or max_observed_callsites or max_observed_functions):
        if len(considered_callsites) >= 1500:
            auto_observed_limits = True
            max_messages_budget = options.get("max_error_messages", 0)
            if max_messages_budget:
                max_observed_strings = int(max_messages_budget)
                max_observed_callsites = max(200, int(max_observed_strings * 4))
                max_observed_functions = max(50, int(max_observed_strings * 1.25))
            else:
                max_observed_callsites = 800
                max_observed_functions = 250

    observed_scan = _scan_observed_callsites(
        considered_callsites,
        program=program,
        monitor=monitor,
        candidates=candidates,
        string_meta_by_id=string_meta_by_id,
        string_addr_map_all=string_addr_map_all,
        string_tags_by_id=string_tags_by_id,
        call_args_cache=call_args_cache,
        candidate_func_ids=candidate_func_ids,
        function_meta_by_addr=function_meta_by_addr,
        links_by_string=links_by_string,
        observed_strings=observed_strings,
        observed_emitter_bucket=observed_emitter_bucket,
        max_observed_strings=max_observed_strings,
        max_observed_callsites=max_observed_callsites,
        max_observed_functions=max_observed_functions,
        auto_observed_limits=auto_observed_limits,
    )

    _apply_observed_emitter_buckets(candidates, observed_emitter_bucket, string_tags_by_id)

    string_xrefs = _build_string_xrefs(string_refs_by_func)
    max_callsites = options.get("max_error_message_callsites", 5)
    _add_heuristic_links(
        candidates,
        observed_strings=observed_strings,
        links_by_string=links_by_string,
        max_callsites=max_callsites,
        string_xrefs=string_xrefs,
        emitter_callsites_by_func=emitter_callsites_by_func,
    )

    max_funcs = options.get("max_error_message_functions", 10)
    messages = _build_messages(
        candidates,
        links_by_string=links_by_string,
        function_meta_by_addr=function_meta_by_addr,
        max_callsites=max_callsites,
        max_funcs=max_funcs,
    )

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
        "max_functions_per_message": max_funcs,
        "emitter_callsites_total": emitter_callsites_total,
        "emitter_callsites_considered": len(considered_callsites),
        "emitter_callsites_truncated": truncated_emitters,
        "selection_strategy": "heuristic_candidates_then_callsite_linked",
        "messages": messages,
    }
    if observed_scan is not None:
        payload["observed_scan"] = observed_scan
    return payload, emitter_callsites_by_func, call_args_cache
