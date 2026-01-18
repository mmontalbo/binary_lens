"""Build mode-scoped contract views from existing pack payloads."""

from __future__ import annotations

import re
from typing import Any, Mapping

from export_bounds import Bounds
from export_primitives import addr_filename, addr_to_int
from outputs.io import pack_path
from wordlists.name_hints import load_name_hints, name_hints_enabled

MAX_ENV_ENTRIES = 12
MAX_OUTPUT_ENTRIES = 12
MAX_ERROR_SITE_ENTRIES = 10
MAX_MESSAGE_ENTRIES = 10
MAX_EXIT_ENTRIES = 10
MAX_USAGE_ENTRIES = 6
MAX_CALLSITE_REFS = 3
MAX_HELP_PRINTERS = 6
MAX_HELP_STRING_IDS = 4


def _as_str(value: Any) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _as_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    return None


def _safe_component(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "_", value.strip())
    return cleaned or "item"


def _unique(values: list[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        ordered.append(value)
    return ordered


def _mode_name_in_function(func_name: str, mode_name: str) -> bool:
    if not func_name or not mode_name:
        return False
    pattern = r"(?:^|[^A-Za-z0-9])%s(?:$|[^A-Za-z0-9])" % re.escape(mode_name)
    return re.search(pattern, func_name) is not None


def _collect_function_ids(roots: list[Mapping[str, Any]]) -> list[str]:
    func_ids: list[str] = []
    for root in roots:
        func_id = _as_str(root.get("function_id"))
        if func_id:
            func_ids.append(func_id)
    func_ids = _unique(func_ids)
    func_ids.sort(key=addr_to_int)
    return func_ids


def _option_spellings(option: Mapping[str, Any]) -> str:
    spellings: list[str] = []
    short_name = _as_str(option.get("short_name"))
    if short_name:
        spellings.append(f"-{short_name}")
    long_name = _as_str(option.get("long_name"))
    if long_name:
        spellings.append(f"--{long_name}")
    if not spellings:
        return "unknown"
    if len(spellings) == 1:
        return spellings[0]
    return " / ".join(spellings)


def _truncate(entries: list[Any], max_entries: int) -> tuple[list[Any], bool]:
    if max_entries <= 0 or len(entries) <= max_entries:
        return entries, False
    return entries[:max_entries], True


def _callsite_ids_for_message(message: Mapping[str, Any]) -> list[str]:
    callsite_ids: list[str] = []
    for entry in message.get("emitting_callsites") or []:
        callsite_id = _as_str(entry.get("callsite_id"))
        if callsite_id:
            callsite_ids.append(callsite_id)
    return _unique(callsite_ids)


def _function_ids_for_message(message: Mapping[str, Any]) -> list[str]:
    func_ids: list[str] = []
    for entry in message.get("emitting_functions") or []:
        func_id = entry.get("function_id") if isinstance(entry, Mapping) else None
        func_id = _as_str(func_id)
        if func_id:
            func_ids.append(func_id)
    return _unique(func_ids)


def _sort_entries_by_callsite(entries: list[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    return sorted(entries, key=lambda item: addr_to_int(_as_str(item.get("callsite_id"))))


def _format_table(headers: list[str], rows: list[list[str]]) -> str:
    if not rows:
        return ""
    header_line = "| " + " | ".join(headers) + " |"
    divider_line = "| " + " | ".join("---" for _ in headers) + " |"
    body = "\n".join("| " + " | ".join(row) + " |" for row in rows)
    return "\n".join([header_line, divider_line, body])


def _format_truncated(value: Any) -> str:
    if value is True:
        return "true"
    if value is False:
        return "false"
    return "unknown"


def _format_list(values: list[str], *, empty: str = "none") -> str:
    if not values:
        return empty
    return ", ".join(values)


def _is_help_marker_value(value: Any) -> bool:
    if not isinstance(value, str) or not value:
        return False
    lowered = value.lower()
    if "usage:" in lowered:
        return True
    if "--help" in value:
        return True
    if "try '" in lowered or "try \"" in lowered:
        return True
    if "options:" in lowered or "options\n" in lowered:
        return True
    if "report bugs" in lowered or "reporting bugs" in lowered:
        return True
    return False


def _has_usage_tag(tags: Any) -> bool:
    if not tags:
        return False
    if isinstance(tags, set):
        return "usage" in tags
    if isinstance(tags, (list, tuple)):
        return "usage" in tags
    return False


def _help_marker_string_ids(
    string_tags_by_id: Mapping[str, Any] | None,
    string_value_by_id: Mapping[str, Any] | None,
) -> set[str]:
    marker_ids: set[str] = set()
    for string_id, tags in (string_tags_by_id or {}).items():
        if _has_usage_tag(tags):
            marker_ids.add(string_id)
    for string_id, value in (string_value_by_id or {}).items():
        if _is_help_marker_value(value):
            marker_ids.add(string_id)
    return marker_ids


def _parse_loop_function_ids(cli_parse_loops_payload: Mapping[str, Any] | None) -> dict[str, str]:
    parse_loops = (
        cli_parse_loops_payload.get("parse_loops", [])
        if isinstance(cli_parse_loops_payload, Mapping)
        else []
    )
    parse_loop_by_id: dict[str, str] = {}
    for loop in parse_loops:
        if not isinstance(loop, Mapping):
            continue
        loop_id = _as_str(loop.get("id"))
        func = loop.get("function") if isinstance(loop.get("function"), Mapping) else {}
        func_id = _as_str(func.get("address"))
        if loop_id and func_id:
            parse_loop_by_id[loop_id] = func_id
    return parse_loop_by_id


def _format_function_evidence_refs(func_id: str, exported_function_ids: set[str] | None) -> str:
    func_filename = addr_filename("f", func_id, "json")
    function_ref = pack_path("functions", func_filename)
    decomp_ref = pack_path("evidence", "decomp", func_filename)
    if exported_function_ids is not None and func_id not in exported_function_ids:
        return "not exported due to bounds"
    return f"`{function_ref}` / `{decomp_ref}`"


def _build_callgraph_neighbors(callgraph_payload: Mapping[str, Any] | None) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    forward: dict[str, set[str]] = {}
    reverse: dict[str, set[str]] = {}
    edges = callgraph_payload.get("edges", []) if isinstance(callgraph_payload, Mapping) else []
    for edge in edges:
        if not isinstance(edge, Mapping):
            continue
        from_entry = edge.get("from") if isinstance(edge.get("from"), Mapping) else {}
        to_entry = edge.get("to") if isinstance(edge.get("to"), Mapping) else {}
        from_addr = _as_str(from_entry.get("address"))
        to_addr = _as_str(to_entry.get("address"))
        if not from_addr or not to_addr:
            continue
        if to_entry.get("external") or to_addr.startswith("EXTERNAL:"):
            continue
        forward.setdefault(from_addr, set()).add(to_addr)
        reverse.setdefault(to_addr, set()).add(from_addr)
    return forward, reverse


def _env_var_value(entry: Mapping[str, Any]) -> str:
    var = entry.get("var")
    if not isinstance(var, Mapping):
        return "unknown"
    if var.get("status") != "known":
        return "unknown"
    return _as_str(var.get("value")) or "unknown"


def _template_status(entry: Mapping[str, Any]) -> tuple[int, int]:
    templates = entry.get("templates")
    if not isinstance(templates, list):
        return 0, 1
    known = sum(1 for tmpl in templates if isinstance(tmpl, Mapping) and tmpl.get("status") == "known")
    unknown = sum(1 for tmpl in templates if isinstance(tmpl, Mapping) and tmpl.get("status") != "known")
    return known, unknown


def build_contract_views(
    modes_payload: Mapping[str, Any] | None,
    modes_slices_payload: Mapping[str, Any] | None,
    cli_options_payload: Mapping[str, Any] | None,
    cli_parse_loops_payload: Mapping[str, Any] | None,
    interfaces_payloads: Mapping[str, Any] | None,
    error_messages_payload: Mapping[str, Any] | None,
    error_sites_payload: Mapping[str, Any] | None,
    exit_paths_payload: Mapping[str, Any] | None,
    string_tags_by_id: Mapping[str, Any] | None,
    string_value_by_id: Mapping[str, Any] | None,
    string_refs_by_func: Mapping[str, Any] | None,
    callgraph_payload: Mapping[str, Any] | None,
    function_meta_by_addr: Mapping[str, Any] | None,
    exported_function_ids: set[str] | None = None,
    *,
    name_hints_source: Bounds | Mapping[str, Any] | None = None,
) -> tuple[dict[str, Any], dict[str, str]]:
    modes = modes_payload.get("modes", []) if isinstance(modes_payload, Mapping) else []
    slices = modes_slices_payload.get("slices", []) if isinstance(modes_slices_payload, Mapping) else []
    slices_by_id = {
        entry.get("mode_id"): entry for entry in slices if isinstance(entry, Mapping) and entry.get("mode_id")
    }
    options_list = cli_options_payload.get("options", []) if isinstance(cli_options_payload, Mapping) else []
    parse_loops_total = None
    if isinstance(cli_parse_loops_payload, Mapping):
        parse_loops_total = _as_int(cli_parse_loops_payload.get("total_parse_loops"))

    string_tags_by_id = string_tags_by_id or {}
    string_value_by_id = string_value_by_id or {}
    string_refs_by_func = string_refs_by_func or {}
    function_meta_by_addr = function_meta_by_addr or {}
    name_hints = load_name_hints(name_hints_source)
    use_name_hints = name_hints_enabled(name_hints_source)
    help_marker_string_ids = _help_marker_string_ids(string_tags_by_id, string_value_by_id)
    help_string_functions: dict[str, list[str]] = {}
    for func_id, string_ids in string_refs_by_func.items():
        func_id = _as_str(func_id)
        if not func_id or not string_ids:
            continue
        matched = []
        for string_id in string_ids:
            string_id = _as_str(string_id)
            if string_id and string_id in help_marker_string_ids:
                matched.append(string_id)
        if matched:
            matched = _unique(sorted(matched))
            help_string_functions[func_id] = matched

    parse_loop_by_id = _parse_loop_function_ids(cli_parse_loops_payload)
    callgraph_forward, callgraph_reverse = _build_callgraph_neighbors(callgraph_payload)

    interfaces_payloads = interfaces_payloads or {}
    env_entries = (
        interfaces_payloads.get("env", {}).get("entries", [])
        if isinstance(interfaces_payloads.get("env"), Mapping)
        else []
    )
    output_entries = (
        interfaces_payloads.get("output", {}).get("entries", [])
        if isinstance(interfaces_payloads.get("output"), Mapping)
        else []
    )

    messages = error_messages_payload.get("messages", []) if isinstance(error_messages_payload, Mapping) else []
    message_by_id: dict[str, Mapping[str, Any]] = {}
    messages_by_function: dict[str, list[Mapping[str, Any]]] = {}
    usage_message_function_ids: set[str] = set()
    for message in messages:
        if not isinstance(message, Mapping):
            continue
        bucket = _as_str(message.get("bucket")) or "unknown"
        msg_id = _as_str(message.get("string_id")) or _as_str(message.get("string_address"))
        if msg_id and msg_id not in message_by_id:
            message_by_id[msg_id] = message
        for func_id in _function_ids_for_message(message):
            messages_by_function.setdefault(func_id, []).append(message)
            if bucket == "usage":
                usage_message_function_ids.add(func_id)

    error_sites = error_sites_payload.get("sites", []) if isinstance(error_sites_payload, Mapping) else []
    error_sites_by_function: dict[str, list[Mapping[str, Any]]] = {}
    for site in error_sites:
        if not isinstance(site, Mapping):
            continue
        func_id = _as_str(site.get("function_id"))
        if not func_id:
            continue
        error_sites_by_function.setdefault(func_id, []).append(site)

    exit_calls = exit_paths_payload.get("direct_calls", []) if isinstance(exit_paths_payload, Mapping) else []
    exit_by_callsite: dict[str, Mapping[str, Any]] = {}
    exit_by_function: dict[str, list[Mapping[str, Any]]] = {}
    for entry in exit_calls:
        if not isinstance(entry, Mapping):
            continue
        callsite_id = _as_str(entry.get("callsite_id"))
        func_id = _as_str(entry.get("function_id"))
        if callsite_id:
            exit_by_callsite[callsite_id] = entry
        if func_id:
            exit_by_function.setdefault(func_id, []).append(entry)

    env_by_function: dict[str, list[Mapping[str, Any]]] = {}
    for entry in env_entries:
        if not isinstance(entry, Mapping):
            continue
        func_id = _as_str(entry.get("function_id"))
        if func_id:
            env_by_function.setdefault(func_id, []).append(entry)

    output_by_function: dict[str, list[Mapping[str, Any]]] = {}
    for entry in output_entries:
        if not isinstance(entry, Mapping):
            continue
        func_id = _as_str(entry.get("function_id"))
        if func_id:
            output_by_function.setdefault(func_id, []).append(entry)

    docs: dict[str, str] = {}
    contract_entries: list[dict[str, Any]] = []

    for mode in modes:
        if not isinstance(mode, Mapping):
            continue
        mode_id = _as_str(mode.get("mode_id"))
        if not mode_id:
            continue
        mode_name = _as_str(mode.get("name")) or "(unknown)"
        slice_entry = slices_by_id.get(mode_id, {})

        implementation_roots = mode.get("implementation_roots") or []
        if not isinstance(implementation_roots, list):
            implementation_roots = []

        scope_roots = implementation_roots
        scope_basis = "implementation_roots"
        if not scope_roots:
            roots = slice_entry.get("root_functions") if isinstance(slice_entry, Mapping) else None
            if isinstance(roots, list) and roots:
                scope_roots = roots
                scope_basis = "mode_slice_roots"
        if not scope_roots:
            roots = mode.get("dispatch_roots")
            if isinstance(roots, list) and roots:
                scope_roots = roots
                scope_basis = "dispatch_roots"

        scope_function_ids = _collect_function_ids(scope_roots)

        # Options section.
        option_scope = slice_entry.get("option_scope") if isinstance(slice_entry, Mapping) else {}
        option_scope_kind = _as_str(option_scope.get("kind")) or "unknown"
        option_scope_basis = _as_str(option_scope.get("basis")) or "unknown"
        parse_loop_ids = option_scope.get("parse_loop_ids") if isinstance(option_scope, Mapping) else None
        cleaned_loop_ids: list[str] = []
        for loop_id in parse_loop_ids or []:
            loop_id = _as_str(loop_id)
            if loop_id:
                cleaned_loop_ids.append(loop_id)
        parse_loop_ids = cleaned_loop_ids

        has_mode_local_parse_loops = bool(parse_loop_ids) and option_scope_kind == "mode_scoped"
        if parse_loops_total == 0:
            has_mode_local_parse_loops = False

        mode_option_entries: list[Mapping[str, Any]] = []
        if has_mode_local_parse_loops:
            loop_set = set(parse_loop_ids)
            for option in options_list:
                if not isinstance(option, Mapping):
                    continue
                option_loop_ids = option.get("parse_loop_ids")
                if not isinstance(option_loop_ids, list):
                    continue
                if any(loop_id in loop_set for loop_id in option_loop_ids):
                    mode_option_entries.append(option)

        option_ids: list[str] = []
        option_rows: list[list[str]] = []
        unknown_arg_count = 0
        unknown_spellings = 0
        for option in mode_option_entries:
            opt_id = _as_str(option.get("id")) or "unknown"
            option_ids.append(opt_id)
            spellings = _option_spellings(option)
            has_arg = _as_str(option.get("has_arg")) or "unknown"
            if has_arg == "unknown":
                unknown_arg_count += 1
            if spellings == "unknown":
                unknown_spellings += 1
            option_rows.append([f"`{opt_id}`", f"`{spellings}`", f"`{has_arg}`"])

        option_scope_notes: list[str] = []
        if option_scope_kind in ("global", "unknown"):
            option_scope_notes.append("option scope is not localized to this mode")
        if parse_loops_total == 0:
            option_scope_notes.append("cli/parse_loops.json is empty; scoping is uncertain")
        if not parse_loop_ids and parse_loops_total not in (0, None):
            option_scope_notes.append("no parse loop ids available to localize options")
        if has_mode_local_parse_loops and not mode_option_entries and options_list:
            option_scope_notes.append("no options matched mode parse loops; cli/options may be truncated")

        # Environment variables.
        env_scoped_entries: list[Mapping[str, Any]] = []
        for func_id in scope_function_ids:
            env_scoped_entries.extend(env_by_function.get(func_id, []))
        env_scoped_entries = _sort_entries_by_callsite(env_scoped_entries)

        env_scope_kind = "mode_scoped" if env_scoped_entries else "global_or_unknown"
        env_scope_note = (
            "scoped by root function overlap"
            if env_scoped_entries
            else "no root overlap; listing global candidates"
        )
        env_full_candidates = env_scoped_entries or env_entries
        env_total_count = len(env_full_candidates)
        env_unknown_count = sum(
            1 for entry in env_full_candidates if _env_var_value(entry) == "unknown"
        )
        env_candidates, env_truncated = _truncate(env_full_candidates, MAX_ENV_ENTRIES)

        # Output templates.
        output_scoped_entries: list[Mapping[str, Any]] = []
        for func_id in scope_function_ids:
            output_scoped_entries.extend(output_by_function.get(func_id, []))
        output_scoped_entries = _sort_entries_by_callsite(output_scoped_entries)

        output_scope_kind = "mode_scoped" if output_scoped_entries else "global_or_unknown"
        output_scope_note = (
            "scoped by root function overlap"
            if output_scoped_entries
            else "no root overlap; listing global candidates"
        )
        output_full_candidates = output_scoped_entries or output_entries
        output_total_count = len(output_full_candidates)
        output_unknown_template_entries = 0
        output_unknown_channel_entries = 0
        for entry in output_full_candidates:
            channel = entry.get("channel") if isinstance(entry.get("channel"), Mapping) else {}
            channel_status = _as_str(channel.get("status")) or "unknown"
            if channel_status != "known":
                output_unknown_channel_entries += 1
            known_templates, _unknown_templates = _template_status(entry)
            if known_templates == 0:
                output_unknown_template_entries += 1

        output_candidates, output_truncated = _truncate(output_full_candidates, MAX_OUTPUT_ENTRIES)
        output_rows: list[list[str]] = []
        for entry in output_candidates:
            callsite_id = _as_str(entry.get("callsite_id")) or "unknown"
            operation = _as_str(entry.get("operation")) or "unknown"
            channel = entry.get("channel") if isinstance(entry.get("channel"), Mapping) else {}
            channel_kind = _as_str(channel.get("kind")) or "unknown"
            channel_status = _as_str(channel.get("status")) or "unknown"
            known_templates, unknown_templates = _template_status(entry)
            templates_summary = f"known={known_templates}, unknown={unknown_templates}"
            output_rows.append(
                [f"`{callsite_id}`", f"`{operation}`", f"`{channel_kind}`", f"`{templates_summary}`"]
            )

        # Help/usage evidence.
        parse_loop_function_ids: list[str] = []
        for loop_id in parse_loop_ids:
            func_id = parse_loop_by_id.get(loop_id)
            if func_id:
                parse_loop_function_ids.append(func_id)
        parse_loop_function_ids = _unique(parse_loop_function_ids)
        proximity_roots = set(scope_function_ids) | set(parse_loop_function_ids)
        called_by_roots: set[str] = set()
        calls_roots: set[str] = set()
        for root_id in proximity_roots:
            called_by_roots.update(callgraph_forward.get(root_id, set()))
            calls_roots.update(callgraph_reverse.get(root_id, set()))

        help_candidate_map: dict[str, dict[str, Any]] = {}
        adjacency_candidates = set(proximity_roots) | called_by_roots | calls_roots
        for func_id in adjacency_candidates:
            if func_id in help_string_functions:
                entry = help_candidate_map.setdefault(func_id, {"signals": set(), "string_ids": []})
                entry["signals"].add("usage_strings")
                entry["string_ids"].extend(help_string_functions.get(func_id, []))
            if func_id in usage_message_function_ids:
                entry = help_candidate_map.setdefault(func_id, {"signals": set(), "string_ids": []})
                entry["signals"].add("usage_messages")

        if not help_candidate_map:
            for func_id, string_ids in help_string_functions.items():
                entry = help_candidate_map.setdefault(func_id, {"signals": set(), "string_ids": []})
                entry["signals"].add("usage_strings")
                entry["string_ids"].extend(string_ids)
            for func_id in usage_message_function_ids:
                entry = help_candidate_map.setdefault(func_id, {"signals": set(), "string_ids": []})
                entry["signals"].add("usage_messages")

        if not help_candidate_map and function_meta_by_addr and use_name_hints:
            for func_id in proximity_roots:
                func_meta = function_meta_by_addr.get(func_id, {})
                func_name = _as_str(func_meta.get("name")) or ""
                if not func_name:
                    continue
                lowered = func_name.lower()
                if any(lowered.startswith(prefix.lower()) for prefix in name_hints.help_function_prefixes) or any(
                    keyword.lower() in lowered for keyword in name_hints.help_function_keywords
                ):
                    entry = help_candidate_map.setdefault(func_id, {"signals": set(), "string_ids": []})
                    entry["signals"].add("name_heuristic")

        mode_name_lower = mode_name.lower() if mode_name and mode_name != "(unknown)" else ""
        help_candidates: list[tuple[int, dict[str, Any]]] = []
        for func_id, info in help_candidate_map.items():
            if func_id in scope_function_ids:
                proximity = "root_function"
            elif func_id in parse_loop_function_ids:
                proximity = "parse_loop_function"
            elif func_id in called_by_roots:
                proximity = "callee_of_root"
            elif func_id in calls_roots:
                proximity = "caller_of_root"
            else:
                proximity = "unscoped"
            signals = set(info.get("signals", []))
            string_ids = _unique(info.get("string_ids", []))
            score = 1
            if proximity in ("root_function", "parse_loop_function"):
                score += 3
            elif proximity in ("callee_of_root", "caller_of_root"):
                score += 2
            if "usage_strings" in signals:
                score += 1
            if "usage_messages" in signals:
                score += 1
            func_name = _as_str((function_meta_by_addr.get(func_id, {}) or {}).get("name")) or ""
            func_name_lower = func_name.lower() if func_name else ""
            if (
                use_name_hints
                and mode_name_lower
                and func_name_lower
                and _mode_name_in_function(func_name_lower, mode_name_lower)
                and (
                    any(
                        func_name_lower.startswith(prefix.lower())
                        for prefix in name_hints.help_function_prefixes
                    )
                    or any(
                        keyword.lower() in func_name_lower
                        for keyword in name_hints.help_function_keywords
                    )
                )
            ):
                signals.add("name_heuristic")
                score += 2
            help_candidates.append(
                (
                    score,
                    {
                        "function_id": func_id,
                        "proximity": proximity,
                        "string_ids": string_ids,
                    },
                )
            )
        help_candidates.sort(
            key=lambda item: (-item[0], addr_to_int(item[1].get("function_id")))
        )
        help_candidates, help_candidates_truncated = _truncate(
            help_candidates, MAX_HELP_PRINTERS
        )

        # Help/usage messages.
        usage_messages: list[Mapping[str, Any]] = []
        seen_usage_ids: set[str] = set()
        for func_id in scope_function_ids:
            for message in messages_by_function.get(func_id, []):
                if _as_str(message.get("bucket")) != "usage":
                    continue
                msg_id = _as_str(message.get("string_id")) or _as_str(message.get("string_address"))
                if msg_id:
                    if msg_id in seen_usage_ids:
                        continue
                    seen_usage_ids.add(msg_id)
                usage_messages.append(message)
        usage_messages, usage_truncated = _truncate(usage_messages, MAX_USAGE_ENTRIES)
        usage_note = None
        if not usage_messages and messages:
            usage_note = "no usage messages scoped to this mode"

        # Diagnostics messages.
        top_messages = slice_entry.get("top_messages") if isinstance(slice_entry, Mapping) else []
        message_candidates: list[str] = []
        if isinstance(top_messages, list):
            for msg_id in top_messages:
                msg_id = _as_str(msg_id)
                if msg_id:
                    message_candidates.append(msg_id)
        if not message_candidates:
            for func_id in scope_function_ids:
                for message in messages_by_function.get(func_id, []):
                    msg_id = _as_str(message.get("string_id")) or _as_str(message.get("string_address"))
                    if msg_id:
                        message_candidates.append(msg_id)
        message_candidates = _unique(message_candidates)
        message_total_count = len(message_candidates)
        message_candidates, message_truncated = _truncate(message_candidates, MAX_MESSAGE_ENTRIES)
        message_entries: list[tuple[str, Mapping[str, Any] | None]] = []
        for msg_id in message_candidates:
            message_entries.append((msg_id, message_by_id.get(msg_id)))

        # Error sites.
        error_site_candidates: list[Mapping[str, Any]] = []
        for func_id in scope_function_ids:
            error_site_candidates.extend(error_sites_by_function.get(func_id, []))
        error_site_candidates = _sort_entries_by_callsite(error_site_candidates)
        error_site_total_count = len(error_site_candidates)
        error_site_unknown_severity = sum(
            1
            for entry in error_site_candidates
            if _as_str(entry.get("severity")) in (None, "unknown")
        )
        error_site_candidates, error_sites_truncated = _truncate(
            error_site_candidates, MAX_ERROR_SITE_ENTRIES
        )

        # Exit paths.
        exit_candidates: list[Mapping[str, Any]] = []
        top_exit_paths = slice_entry.get("top_exit_paths") if isinstance(slice_entry, Mapping) else []
        if isinstance(top_exit_paths, list) and top_exit_paths:
            for callsite_id in top_exit_paths:
                callsite_id = _as_str(callsite_id)
                if callsite_id and callsite_id in exit_by_callsite:
                    exit_candidates.append(exit_by_callsite[callsite_id])
        if not exit_candidates:
            for func_id in scope_function_ids:
                exit_candidates.extend(exit_by_function.get(func_id, []))
        exit_candidates = _sort_entries_by_callsite(exit_candidates)
        exit_total_count = len(exit_candidates)
        exit_unknown_code = sum(1 for entry in exit_candidates if entry.get("exit_code") is None)
        exit_candidates, exit_truncated = _truncate(exit_candidates, MAX_EXIT_ENTRIES)

        callsites_ref = _as_str((modes_payload or {}).get("callsites_ref")) or "evidence/callsites.json"

        # Build Markdown document.
        lines: list[str] = [
            f"# Contract: {mode_name}",
            "",
            "## Identity",
            f"- mode_id: `{mode_id}`",
            f"- name: `{mode_name}`",
            f"- kind: `{_as_str(mode.get('kind')) or 'unknown'}`",
        ]
        kind_basis = _as_str(mode.get("kind_basis"))
        if kind_basis:
            lines.append(f"- kind_basis: `{kind_basis}`")
        lines.extend(
            [
                "- source: `modes/index.json`",
                f"- callsites_ref: `{callsites_ref}`",
                "",
                "## Implementation roots (modes/index.json)",
                f"- root_count: `{len(implementation_roots)}`",
                f"- truncated: `{_format_truncated(mode.get('implementation_roots_truncated'))}`",
            ]
        )

        if implementation_roots:
            for root in implementation_roots:
                if not isinstance(root, Mapping):
                    continue
                func_id = _as_str(root.get("function_id")) or "unknown"
                func_name = _as_str(root.get("function_name")) or "unknown"
                sources = root.get("sources") if isinstance(root.get("sources"), list) else []
                sources = [src for src in sources if _as_str(src)]
                source_str = _format_list(sources)
                lines.append(f"- `{func_id}` (`{func_name}`) sources: `{source_str}`")
        else:
            lines.append("- _No implementation roots exported for this mode._")

        parse_loops_total_str = str(parse_loops_total) if parse_loops_total is not None else "unknown"
        lines.extend(
            [
                "",
                "## Inputs",
                "### Options",
                f"- scope: `{option_scope_kind}` (basis: `{option_scope_basis}`)",
                f"- parse_loops: `{_format_list(parse_loop_ids)}` (ref: `cli/parse_loops.json`, total: `{parse_loops_total_str}`)",
                "- options_ref: `cli/options.json`",
            ]
        )
        if not has_mode_local_parse_loops:
            lines.append("- mode_scoped_options: `unknown` (no parser localization)")
            lines.append(f"- unscoped_option_tokens: `{len(options_list)}` (see `cli/options.json`)")
        for note in option_scope_notes:
            lines.append(f"- note: {note}")

        if has_mode_local_parse_loops:
            if option_rows:
                lines.append("")
                lines.append(_format_table(["option_id", "spellings", "has_arg"], option_rows))
            else:
                lines.append("- _No options matched the mode parse loops._")

        lines.extend(
            [
                "",
                "### Environment variables",
                f"- scope: `{env_scope_kind}` (basis: `{scope_basis}`; {env_scope_note})",
                "- entries_ref: `interfaces/env.json`",
            ]
        )
        if env_candidates:
            env_rows: list[list[str]] = []
            for entry in env_candidates:
                callsite_id = _as_str(entry.get("callsite_id")) or "unknown"
                operation = _as_str(entry.get("operation")) or "unknown"
                var_value = _env_var_value(entry)
                func_id = _as_str(entry.get("function_id")) or "unknown"
                env_rows.append(
                    [f"`{var_value}`", f"`{operation}`", f"`{callsite_id}`", f"`{func_id}`"]
                )
            lines.append("")
            lines.append(_format_table(["var", "operation", "callsite_id", "function_id"], env_rows))
            if env_truncated:
                lines.append("- note: env list truncated for readability")
        else:
            lines.append("- _No environment variable evidence exported._")

        lines.extend(
            [
                "",
                "## Outputs and help text",
                "### Output templates",
                f"- scope: `{output_scope_kind}` (basis: `{scope_basis}`; {output_scope_note})",
                "- entries_ref: `interfaces/output.json`",
            ]
        )
        if output_rows:
            lines.append("")
            lines.append(
                _format_table(
                    ["callsite_id", "operation", "channel", "templates"], output_rows
                )
            )
            if output_truncated:
                lines.append("- note: output list truncated for readability")
        else:
            lines.append("- _No output templates exported._")

        help_rows: list[list[str]] = []
        for _score, candidate in help_candidates:
            func_id = _as_str(candidate.get("function_id")) or "unknown"
            func_meta = function_meta_by_addr.get(func_id, {})
            func_name = _as_str(func_meta.get("name")) or "unknown"
            proximity = _as_str(candidate.get("proximity")) or "unknown"
            string_ids = candidate.get("string_ids") or []
            string_ids = string_ids[:MAX_HELP_STRING_IDS]
            string_ids_str = _format_list([f"`{sid}`" for sid in string_ids], empty="none")
            evidence_refs = _format_function_evidence_refs(func_id, exported_function_ids)
            help_rows.append(
                [
                    f"`{func_id}`",
                    f"`{func_name}`",
                    f"`{proximity}`",
                    evidence_refs,
                    string_ids_str,
                ]
            )

        lines.extend(
            [
                "",
                "### Help/usage evidence",
                "- strings_ref: `strings.json`",
                "- messages_ref: `errors/messages.json`",
                "- evidence_ref: `evidence/decomp/`",
                "",
                "#### Help/usage printers",
            ]
        )
        if help_rows:
            lines.append(_format_table(
                ["function_id", "name", "proximity", "evidence_refs", "string_ids"],
                help_rows,
            ))
            if help_candidates_truncated:
                lines.append("- note: help printer list truncated for readability")
        else:
            lines.append("- _No help/usage printer candidates linked to this mode._")

        lines.extend(
            [
                "",
                "#### Usage messages",
                "- entries_ref: `errors/messages.json`",
            ]
        )
        if usage_messages:
            for message in usage_messages:
                msg_id = _as_str(message.get("string_id")) or _as_str(message.get("string_address")) or "unknown"
                refs = _callsite_ids_for_message(message)
                refs = refs[:MAX_CALLSITE_REFS]
                lines.append(
                    f"- `{msg_id}` (callsites: {_format_list([f'`{ref}`' for ref in refs])})"
                )
            if usage_truncated:
                lines.append("- note: usage list truncated for readability")
        else:
            lines.append(f"- _{usage_note or 'No usage/help evidence exported.'}_")

        lines.extend(
            [
                "",
                "## Diagnostics and exits",
                "### Error messages",
                "- entries_ref: `errors/messages.json`",
            ]
        )
        if message_entries:
            for msg_id, message in message_entries:
                bucket = "unknown"
                refs: list[str] = []
                if isinstance(message, Mapping):
                    bucket = _as_str(message.get("bucket")) or "unknown"
                    refs = _callsite_ids_for_message(message)[:MAX_CALLSITE_REFS]
                lines.append(
                    f"- `{msg_id}` (bucket: `{bucket}`, callsites: {_format_list([f'`{ref}`' for ref in refs])})"
                )
            if message_truncated:
                lines.append("- note: message list truncated for readability")
        else:
            lines.append("- _No error messages linked to this mode._")

        lines.extend(
            [
                "",
                "### Error sites",
                "- entries_ref: `errors/error_sites.json`",
            ]
        )
        if error_site_candidates:
            for site in error_site_candidates:
                severity = _as_str(site.get("severity")) or "unknown"
                refs = site.get("callsite_ids") if isinstance(site.get("callsite_ids"), list) else []
                refs = [ref for ref in refs if _as_str(ref)][:MAX_CALLSITE_REFS]
                lines.append(
                    f"- severity: `{severity}`, callsites: {_format_list([f'`{ref}`' for ref in refs])}"
                )
            if error_sites_truncated:
                lines.append("- note: error site list truncated for readability")
        else:
            lines.append("- _No error sites linked to this mode._")

        lines.extend(
            [
                "",
                "### Exit paths",
                "- entries_ref: `errors/exit_paths.json`",
            ]
        )
        if exit_candidates:
            for entry in exit_candidates:
                callsite_id = _as_str(entry.get("callsite_id")) or "unknown"
                exit_code = entry.get("exit_code")
                exit_code_str = "unknown" if exit_code is None else str(exit_code)
                lines.append(f"- `{callsite_id}` (exit_code: `{exit_code_str}`)")
            if exit_truncated:
                lines.append("- note: exit list truncated for readability")
        else:
            lines.append("- _No exit paths linked to this mode._")

        env_truncated_flag = _format_truncated(
            interfaces_payloads.get("env", {}).get("truncated")
            if isinstance(interfaces_payloads.get("env"), Mapping)
            else None
        )
        output_truncated_flag = _format_truncated(
            interfaces_payloads.get("output", {}).get("truncated")
            if isinstance(interfaces_payloads.get("output"), Mapping)
            else None
        )
        messages_truncated_flag = _format_truncated(
            error_messages_payload.get("truncated")
            if isinstance(error_messages_payload, Mapping)
            else None
        )
        error_sites_truncated_flag = _format_truncated(
            error_sites_payload.get("truncated")
            if isinstance(error_sites_payload, Mapping)
            else None
        )
        exit_paths_truncated_flag = _format_truncated(
            exit_paths_payload.get("truncated")
            if isinstance(exit_paths_payload, Mapping)
            else None
        )
        cli_options_truncated_flag = _format_truncated(
            cli_options_payload.get("truncated")
            if isinstance(cli_options_payload, Mapping)
            else None
        )
        cli_parse_loops_truncated_flag = _format_truncated(
            cli_parse_loops_payload.get("truncated")
            if isinstance(cli_parse_loops_payload, Mapping)
            else None
        )

        if has_mode_local_parse_loops:
            options_summary = (
                f"- options: `{len(option_ids)}` listed (parse_loop overlap), "
                f"unknown arg shape: `{unknown_arg_count}`, unknown spellings: `{unknown_spellings}`, "
                f"cli/options truncated: `{cli_options_truncated_flag}`, "
                f"cli/parse_loops truncated: `{cli_parse_loops_truncated_flag}`"
            )
        else:
            options_summary = (
                "- options: `unknown` mode-scoped (no parser localization), "
                f"unscoped tokens: `{len(options_list)}`, "
                f"cli/options truncated: `{cli_options_truncated_flag}`, "
                f"cli/parse_loops truncated: `{cli_parse_loops_truncated_flag}`"
            )

        lines.extend(
            [
                "",
                "## Coverage summary",
                options_summary,
                f"- env: total `{env_total_count}`, listed `{len(env_candidates)}`, unknown vars: `{env_unknown_count}`, interfaces/env truncated: `{env_truncated_flag}`",
                f"- outputs: total `{output_total_count}`, listed `{len(output_candidates)}`, templates unknown: `{output_unknown_template_entries}`, channel unknown: `{output_unknown_channel_entries}`, interfaces/output truncated: `{output_truncated_flag}`",
                f"- diagnostics: messages total `{message_total_count}`, listed `{len(message_entries)}`, errors/messages truncated: `{messages_truncated_flag}`, error sites total `{error_site_total_count}` (listed `{len(error_site_candidates)}`, unknown severity: `{error_site_unknown_severity}`, truncated: `{error_sites_truncated_flag}`), exit paths total `{exit_total_count}` (listed `{len(exit_candidates)}`, unknown codes: `{exit_unknown_code}`, truncated: `{exit_paths_truncated_flag}`)",
            ]
        )

        doc_path = pack_path("contracts", "modes", f"{mode_id}.md")
        docs[doc_path] = "\n".join(lines).strip() + "\n"

        contract_entries.append(
            {
                "mode_id": mode_id,
                "name": mode_name,
                "kind": _as_str(mode.get("kind")) or "unknown",
                "contract_doc_ref": doc_path,
                "mode_index_ref": "modes/index.json",
            }
        )

    contracts_payload = {
        "modes_ref": "modes/index.json",
        "mode_slices_ref": "modes/slices.json",
        "contracts_doc_dir": "contracts/modes",
        "total_modes": len(contract_entries),
        "modes": contract_entries,
    }
    return contracts_payload, docs
