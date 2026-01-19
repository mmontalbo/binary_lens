"""Shared helpers for mode export.

These helpers are intentionally small and mostly independent from Ghidra APIs so
they can be reused across the different mode-export subsystems (candidate
collection, table dispatch, payload shaping) without creating import cycles.
"""

from export_primitives import addr_id


def _c_string_literal(value):
    if value is None:
        return None
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _source_rank(sources):
    if not sources:
        return 0
    if "table_dispatch" in sources:
        return 3
    if "compare_chain_handler" in sources:
        return 2
    if "compare_chain_assignment" in sources:
        return 2
    if "compare_chain" in sources:
        return 1
    return 0


def _mode_has_table_dispatch_root(mode):
    for root in (mode.get("implementation_roots") or {}).values():
        if "table_dispatch" in (root.get("sources") or set()):
            return True
    return False


def _mode_id(string_id, address, value):
    if string_id:
        return string_id
    if address:
        return addr_id("mode", address)
    if value:
        safe = []
        for ch in value:
            if ch.isalnum():
                safe.append(ch)
            else:
                safe.append("_")
        slug = "".join(safe).strip("_")
        if not slug:
            slug = "token"
        if len(slug) > 24:
            slug = slug[:24]
        return "mode_%s" % slug
    return "mode_unknown"


def _token_kind(value):
    if value and value.startswith("-"):
        return "flag_mode", "token_prefix_dash"
    return "unknown", None


def _token_candidate(value, min_len, max_len):
    if value is None:
        return None, "empty"
    length = len(value)
    if length < min_len:
        return None, "too_short"
    if max_len and length > max_len:
        return None, "too_long"
    for ch in value:
        if ch.isspace():
            return None, "whitespace"
        code = ord(ch)
        if code < 32 or code > 126:
            return None, "non_printable"
    return value, None


def _looks_like_subcommand_token(value):
    if not value or len(value) < 2:
        return False
    if value.startswith("-"):
        return False
    for ch in value:
        if ch.islower() or ch.isdigit() or ch in "-_":
            continue
        return False
    return True


def _add_implementation_root(mode, func_id, func_name, source, evidence=None):
    if not func_id:
        return
    roots = mode.get("implementation_roots")
    if roots is None:
        roots = {}
        mode["implementation_roots"] = roots
    root = roots.get(func_id)
    if root is None:
        root = {
            "function_name": func_name,
            "sources": set(),
            "table_entry_addresses": set(),
            "compare_callsites": set(),
            "handler_callsites": set(),
            "string_ids": set(),
            "string_addresses": set(),
        }
        roots[func_id] = root
    if not root.get("function_name") and func_name:
        root["function_name"] = func_name
    root["sources"].add(source)
    if not evidence:
        return
    if evidence.get("table_entry_address"):
        root["table_entry_addresses"].add(evidence.get("table_entry_address"))
    if evidence.get("compare_callsite_id"):
        root["compare_callsites"].add(evidence.get("compare_callsite_id"))
    if evidence.get("handler_callsite_id"):
        root["handler_callsites"].add(evidence.get("handler_callsite_id"))
    if evidence.get("string_id"):
        root["string_ids"].add(evidence.get("string_id"))
    if evidence.get("string_address"):
        root["string_addresses"].add(evidence.get("string_address"))
