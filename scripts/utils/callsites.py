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
