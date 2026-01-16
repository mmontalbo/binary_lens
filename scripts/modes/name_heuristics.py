"""Name-based heuristics for mode dispatch (explicitly gated)."""

from __future__ import annotations


def use_name_heuristics(options) -> bool:
    value = 1
    if isinstance(options, dict):
        value = options.get("enable_mode_name_heuristics", 1)
    try:
        return int(value) != 0
    except Exception:
        return bool(value)


def entry_name_candidates(options) -> set[str]:
    names = {"main"}
    if use_name_heuristics(options):
        names.add("cmd_main")
    return names


def is_cmd_handler_name(name: str | None) -> bool:
    if not name:
        return False
    if name == "cmd_main":
        return False
    return name.startswith("cmd_")


def prefer_cmd_table_roots(table_roots, options) -> bool:
    if not use_name_heuristics(options):
        return False
    for root in table_roots:
        if (root.get("function_name") or "").startswith("cmd_"):
            return True
    return False
