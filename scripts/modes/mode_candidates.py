"""Token extraction and aggregation for mode candidates.

Given selected dispatch groups (functions containing CLI compare callsites) and
string arguments recovered at those callsites, build:
- per-callsite token candidates (for diagnostics / dispatch_sites payloads)
- per-token mode candidates (for modes/index payloads)
"""

from modes.common import (
    _escape_preview,
    _mode_id,
    _token_candidate,
    _token_kind,
)


def _build_mode_candidates(
    groups,
    call_args_by_callsite,
    string_addr_map_all,
    max_token_len,
    max_tokens_per_callsite,
    min_token_len,
):
    mode_candidates = {}
    callsite_tokens = {}
    callsite_ignored = {}
    callsite_token_stats = {}

    for group in groups:
        func = group.get("function") or {}
        func_addr = func.get("address")
        func_name = func.get("name")
        for callsite_id in group.get("callsites") or []:
            args = call_args_by_callsite.get(callsite_id, {})
            tokens = []
            ignored = []
            candidate_count = 0
            kept_count = 0
            for entry in args.get("string_args", []):
                value = entry.get("value")
                token_value, reason = _token_candidate(value, min_token_len, max_token_len)
                if token_value is None:
                    ignored.append(
                        {
                            "preview": _escape_preview(value),
                            "reason": reason,
                            "address": entry.get("address"),
                            "length": len(value) if value is not None else 0,
                            "callsite_id": callsite_id,
                        }
                    )
                    continue
                candidate_count += 1
                if max_tokens_per_callsite and len(tokens) >= max_tokens_per_callsite:
                    continue
                address = entry.get("address")
                string_id = string_addr_map_all.get(address)
                mode_id = _mode_id(string_id, address, token_value)
                kind, kind_strength, kind_confidence = _token_kind(token_value)
                token_entry = {
                    "mode_id": mode_id,
                    "value": token_value,
                    "address": address,
                    "string_id": string_id,
                    "kind": kind,
                    "kind_strength": kind_strength,
                    "kind_confidence": kind_confidence,
                }
                tokens.append(token_entry)
                kept_count += 1

                mode = mode_candidates.get(mode_id)
                if mode is None:
                    mode = {
                        "mode_id": mode_id,
                        "name": token_value,
                        "string_id": string_id,
                        "address": address,
                        "kind": kind,
                        "kind_strength": kind_strength,
                        "kind_confidence": kind_confidence,
                        "dispatch_sites": set(),
                        "dispatch_roots": {},
                    }
                    mode_candidates[mode_id] = mode
                mode["dispatch_sites"].add(callsite_id)
                roots = mode["dispatch_roots"]
                root = roots.get(func_addr)
                if root is None:
                    root = {
                        "function_name": func_name,
                        "callsite_ids": set(),
                        "compare_callsite_count": group.get("compare_callsite_count", 0),
                    }
                    roots[func_addr] = root
                root["callsite_ids"].add(callsite_id)
                if "compare_callsite_count" not in root:
                    root["compare_callsite_count"] = group.get("compare_callsite_count", 0)

            if tokens:
                callsite_tokens[callsite_id] = tokens
            if ignored:
                callsite_ignored[callsite_id] = ignored
            if candidate_count:
                callsite_token_stats[callsite_id] = {
                    "candidate_count": candidate_count,
                    "kept_count": kept_count,
                    "truncated": candidate_count > kept_count,
                }

    return mode_candidates, callsite_tokens, callsite_ignored, callsite_token_stats

