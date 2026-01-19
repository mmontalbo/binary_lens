"""Callsite id helpers."""

from __future__ import annotations

from typing import Any, Iterable, Mapping, Sequence

from utils.text import as_str

DEFAULT_CALLSITE_KEYS: tuple[str, ...] = ("callsite_id", "callsite")


def callsite_id_from_entry(
    entry: Any,
    *,
    keys: Sequence[str] = DEFAULT_CALLSITE_KEYS,
) -> str | None:
    if isinstance(entry, str):
        return as_str(entry)
    if isinstance(entry, Mapping):
        for key in keys:
            value = as_str(entry.get(key))
            if value:
                return value
    return None


def callsite_ids_from_entries(
    entries: Iterable[Any] | None,
    *,
    keys: Sequence[str] = DEFAULT_CALLSITE_KEYS,
) -> list[str]:
    if not entries:
        return []
    callsite_ids: list[str] = []
    for entry in entries:
        callsite_id = callsite_id_from_entry(entry, keys=keys)
        if callsite_id:
            callsite_ids.append(callsite_id)
    return callsite_ids


def function_id_from_entry(entry: Any) -> str | None:
    if isinstance(entry, Mapping):
        return as_str(entry.get("address"))
    return as_str(entry)


def callsite_to_function_map(callsites: Any) -> dict[str, str]:
    mapping: dict[str, str] = {}
    if isinstance(callsites, Mapping):
        records = callsites.get("callsites")
        if isinstance(records, list):
            for record in records:
                if not isinstance(record, Mapping):
                    continue
                callsite_id = callsite_id_from_entry(record, keys=("callsite", "callsite_id"))
                func_id = function_id_from_entry(record.get("from"))
                if callsite_id and func_id:
                    mapping[callsite_id] = func_id
            return mapping
        for callsite_id, record in callsites.items():
            if not callsite_id or not isinstance(record, Mapping):
                continue
            func_id = function_id_from_entry(record.get("from"))
            if func_id:
                mapping[callsite_id] = func_id
        return mapping
    if isinstance(callsites, list):
        for record in callsites:
            if not isinstance(record, Mapping):
                continue
            callsite_id = callsite_id_from_entry(record, keys=("callsite", "callsite_id"))
            func_id = function_id_from_entry(record.get("from"))
            if callsite_id and func_id:
                mapping[callsite_id] = func_id
    return mapping
