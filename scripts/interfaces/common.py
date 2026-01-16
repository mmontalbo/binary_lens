"""Shared helpers for interface surface extraction."""

from __future__ import annotations

from typing import Any

from export_primitives import addr_to_int

MAX_VALUE_LENGTH = 160


def truncate_value(value: str | None, limit: int = MAX_VALUE_LENGTH) -> str | None:
    if value is None:
        return None
    if limit and len(value) > limit:
        return value[: max(0, limit - 3)] + "..."
    return value


def _unique_by_address(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen = set()
    unique = []
    for entry in entries:
        addr = entry.get("address")
        key = addr or entry.get("value")
        if key in seen:
            continue
        seen.add(key)
        unique.append(entry)
    return unique


def _string_args_by_index(args: dict[str, Any]) -> tuple[dict[int, list[dict[str, Any]]], list[dict[str, Any]]]:
    indexed: dict[int, list[dict[str, Any]]] = {}
    unindexed: list[dict[str, Any]] = []
    for entry in args.get("string_args", []) or []:
        idx = entry.get("index")
        if idx is None:
            unindexed.append(entry)
        else:
            indexed.setdefault(idx, []).append(entry)
    return indexed, unindexed


def string_candidates_for_index(
    args: dict[str, Any],
    index: int,
    string_addr_map_all: dict[str, str] | None,
    *,
    value_limit: int = MAX_VALUE_LENGTH,
) -> list[dict[str, Any]]:
    indexed, unindexed = _string_args_by_index(args)
    candidates = list(indexed.get(index, []))
    if not candidates and len(unindexed) == 1:
        candidates = list(unindexed)
    entries = []
    for entry in candidates:
        addr = entry.get("address")
        value = truncate_value(entry.get("value"), value_limit)
        string_id = string_addr_map_all.get(addr) if (string_addr_map_all and addr) else None
        value_entry = {
            "status": "known",
            "address": addr,
            "string_id": string_id,
            "value": value,
            "arg_index": index,
        }
        source = entry.get("source")
        if source:
            value_entry["source"] = source
        provider_callsite_id = entry.get("provider_callsite_id")
        if provider_callsite_id:
            value_entry["provider_callsite_id"] = provider_callsite_id
        entries.append(value_entry)
    entries = _unique_by_address(entries)
    entries.sort(key=lambda item: addr_to_int(item.get("address")))
    return entries


def unknown_value() -> dict[str, Any]:
    return {"status": "unknown"}


def const_value_for_index(
    args: dict[str, Any],
    index: int,
) -> tuple[dict[str, Any], bool]:
    const_args = args.get("const_args_by_index", {}) or {}
    if index in const_args:
        return (
            {
                "status": "known",
                "value": const_args.get(index),
                "arg_index": index,
            },
            True,
        )
    return ({"status": "unknown"}, False)
