"""Name-based heuristics for mode dispatch (explicitly gated)."""

from __future__ import annotations

from typing import Any

from export_bounds import Bounds


def _resolve_heuristics_flag(source: Any) -> bool:
    value = 1
    if isinstance(source, Bounds):
        value = source.enable_mode_name_heuristics
    elif isinstance(source, dict):
        value = source.get("enable_mode_name_heuristics", 1)
    try:
        return int(value) != 0
    except Exception:
        return bool(value)


def use_name_heuristics(bounds: Bounds | dict[str, Any]) -> bool:
    return _resolve_heuristics_flag(bounds)


def entry_name_candidates(bounds: Bounds | dict[str, Any]) -> set[str]:
    names = {"main"}
    if use_name_heuristics(bounds):
        names.add("cmd_main")
    return names


def is_cmd_handler_name(name: str | None) -> bool:
    if not name:
        return False
    if name == "cmd_main":
        return False
    return name.startswith("cmd_")


def prefer_cmd_table_roots(table_roots, bounds: Bounds | dict[str, Any]) -> bool:
    if not use_name_heuristics(bounds):
        return False
    for root in table_roots:
        if (root.get("function_name") or "").startswith("cmd_"):
            return True
    return False
