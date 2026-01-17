"""Name-based heuristics for mode dispatch (explicitly gated).

The actual symbol-name patterns live in `scripts/wordlists/name_hints_default.json`
so they are explicit and configurable.
"""

from __future__ import annotations

from typing import Any

from export_bounds import Bounds
from wordlists.name_hints import load_name_hints, name_hints_enabled


def use_name_heuristics(bounds: Bounds | dict[str, Any]) -> bool:
    return name_hints_enabled(bounds)


def entry_name_candidates(bounds: Bounds | dict[str, Any]) -> set[str]:
    hints = load_name_hints(bounds)
    names = set(hints.entry_function_names_always)
    if use_name_heuristics(bounds):
        names.update(hints.entry_function_names_enabled)
    return names


def is_cmd_handler_name(name: str | None, bounds: Bounds | dict[str, Any] | None = None) -> bool:
    if not name:
        return False
    hints = load_name_hints(bounds)
    if name in hints.handler_exclude_names:
        return False
    for prefix in hints.handler_prefixes:
        if name.startswith(prefix):
            return True
    return False


def prefer_cmd_table_roots(table_roots, bounds: Bounds | dict[str, Any]) -> bool:
    if not use_name_heuristics(bounds):
        return False
    hints = load_name_hints(bounds)
    prefixes = hints.handler_prefixes
    if not prefixes:
        return False
    for root in table_roots:
        func_name = root.get("function_name") or ""
        for prefix in prefixes:
            if func_name.startswith(prefix):
                return True
    return False
