"""Shared callsite scanning helpers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Mapping

from export_primitives import addr_to_int
from symbols import MatchResult

MatchFn = Callable[[str | None], MatchResult | None]


@dataclass(frozen=True)
class CallsiteMatch:
    callsite_id: str
    function_id: str
    function_name: str | None
    callee_name: str | None
    callee_normalized: str | None
    match_key: str | None
    match_kind: str | None
    target: Mapping[str, object]


def collect_callsite_matches(
    call_edges,
    function_meta_by_addr,
    match_fn: MatchFn,
    *,
    require_external: bool = True,
):
    matches = []
    matches_by_func = {}
    for edge in call_edges:
        callsite_id = edge.get("callsite")
        if not callsite_id:
            continue
        target = edge.get("to") or {}
        if require_external and not target.get("external"):
            continue
        match = match_fn(target.get("name"))
        if match is None:
            continue
        from_addr = (edge.get("from") or {}).get("address")
        if not from_addr:
            continue
        meta = function_meta_by_addr.get(from_addr, {}) if function_meta_by_addr else {}
        if meta.get("is_external") or meta.get("is_thunk"):
            continue
        entry = CallsiteMatch(
            callsite_id=callsite_id,
            function_id=from_addr,
            function_name=meta.get("name") or (edge.get("from") or {}).get("function"),
            callee_name=target.get("name"),
            callee_normalized=match.normalized,
            match_key=match.canonical,
            match_kind=match.kind,
            target=target,
        )
        matches.append(entry)
        bucket = matches_by_func.get(from_addr)
        if bucket is None:
            bucket = []
            matches_by_func[from_addr] = bucket
        bucket.append(entry)
    for bucket in matches_by_func.values():
        bucket.sort(key=lambda item: addr_to_int(item.callsite_id))
    matches.sort(key=lambda item: addr_to_int(item.callsite_id))
    return matches, matches_by_func
