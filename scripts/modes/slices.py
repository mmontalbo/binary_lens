"""Build per-mode "slices" used as a starting point for exploration.

This module is intentionally "late stage" and operates only on already-exported
payloads (modes + CLI surface + optional errors/strings). It should not depend on
Ghidra APIs so it remains easy to read and mechanically refactor.
"""

from export_bounds import Bounds
from export_primitives import addr_to_int
from modes.name_heuristics import prefer_cmd_table_roots


def _root_function_id(root) -> str | None:
    if isinstance(root, dict):
        return root.get("function_id")
    if isinstance(root, str):
        return root
    return None


def _dispatch_root_entries(roots) -> list[dict[str, str]]:
    entries: list[dict[str, str]] = []
    for root in roots or []:
        func_id = _root_function_id(root)
        if func_id:
            entries.append({"function_id": func_id})
    return entries


def _collect_option_ids_from_parse_sites(options_list, func_ids, max_options, parse_loop_by_id):
    if not func_ids or not parse_loop_by_id:
        return []
    option_ids = []
    seen = set()
    for option in options_list:
        opt_id = option.get("id")
        if not opt_id or opt_id in seen:
            continue
        for loop_id in option.get("parse_loop_ids", []):
            func_addr = parse_loop_by_id.get(loop_id)
            if func_addr and func_addr in func_ids:
                option_ids.append(opt_id)
                seen.add(opt_id)
                break
        if max_options and len(option_ids) >= max_options:
            break
    return option_ids


def build_mode_slices(
    modes_payload,
    cli_surface,
    bounds: Bounds,
    string_refs_by_func=None,
    selected_string_ids=None,
    error_messages_payload=None,
    exit_paths_payload=None,
    callsite_to_function=None,
):
    max_slices = bounds.optional("max_mode_slices")
    max_roots = bounds.max_mode_slice_roots
    max_sites = bounds.max_mode_slice_dispatch_sites
    max_options = bounds.max_mode_slice_options
    max_strings = bounds.max_mode_slice_strings
    max_messages = bounds.max_mode_slice_messages
    max_exit_paths = bounds.max_mode_slice_exit_paths

    modes = modes_payload.get("modes", []) if modes_payload else []
    parse_loops = (cli_surface or {}).get("parse_loops", [])
    options_list = (cli_surface or {}).get("options", [])
    string_refs_by_func = string_refs_by_func or {}
    selected_string_ids = selected_string_ids or set()

    callsite_to_function = callsite_to_function or {}
    messages_by_func = {}
    if error_messages_payload:
        for message in error_messages_payload.get("messages", []):
            string_id = message.get("string_id") or message.get("string_address")
            if not string_id:
                continue
            func_ids = []
            for func_entry in message.get("emitting_functions", []):
                func_id = func_entry
                if isinstance(func_entry, dict):
                    func_id = func_entry.get("function_id")
                if func_id:
                    func_ids.append(func_id)
            if not func_ids and callsite_to_function:
                for entry in message.get("emitting_callsites", []) or []:
                    callsite_id = None
                    if isinstance(entry, str):
                        callsite_id = entry
                    elif isinstance(entry, dict):
                        callsite_id = entry.get("callsite_id")
                    if not callsite_id:
                        continue
                    func_id = callsite_to_function.get(callsite_id)
                    if func_id:
                        func_ids.append(func_id)
            for func_id in set(func_ids):
                messages_by_func.setdefault(func_id, []).append(string_id)
    exit_calls_by_func = {}
    if exit_paths_payload:
        for entry in exit_paths_payload.get("direct_calls", []):
            callsite_id = entry.get("callsite_id")
            func_id = entry.get("function_id") or callsite_to_function.get(callsite_id)
            if func_id and callsite_id:
                exit_calls_by_func.setdefault(func_id, []).append(callsite_id)

    parse_loop_by_function = {}
    parse_loop_by_id = {}
    for loop in parse_loops:
        loop_id = loop.get("id")
        func_addr = loop.get("function_id")
        if not func_addr:
            for callsite_id in loop.get("callsite_ids") or []:
                if not callsite_id:
                    continue
                func_addr = callsite_to_function.get(callsite_id)
                if func_addr:
                    break
        if loop_id and func_addr:
            parse_loop_by_function[func_addr] = loop_id
            parse_loop_by_id[loop_id] = func_addr

    options_by_loop_id = {}
    for option in options_list:
        for loop_id in option.get("parse_loop_ids", []):
            options_by_loop_id.setdefault(loop_id, []).append(option.get("id"))

    global_option_ids = [opt.get("id") for opt in options_list if opt.get("id")]
    if max_options:
        global_option_ids = global_option_ids[:max_options]

    slices = []
    for mode in modes:
        implementation_roots = mode.get("implementation_roots") or []
        if implementation_roots:
            root_kind = "implementation"
            roots_sorted = list(implementation_roots)
            table_roots = [
                root for root in roots_sorted if "table_dispatch" in (root.get("sources") or [])
            ]
            if table_roots and prefer_cmd_table_roots(table_roots, bounds):
                roots_sorted = table_roots
        else:
            root_kind = "dispatch_shared"
            roots_sorted = _dispatch_root_entries(mode.get("dispatch_roots", []))
            roots_sorted.sort(key=lambda item: addr_to_int(item.get("function_id")))
        if max_roots and len(roots_sorted) > max_roots:
            roots_sorted = roots_sorted[:max_roots]

        dispatch_sites = mode.get("dispatch_sites", [])
        if max_sites and len(dispatch_sites) > max_sites:
            dispatch_sites = dispatch_sites[:max_sites]

        root_func_ids = set()
        for root in roots_sorted:
            func_id = _root_function_id(root)
            if func_id:
                root_func_ids.add(func_id)

        implementation_func_ids = set()
        if root_kind == "implementation":
            for root in roots_sorted:
                func_id = _root_function_id(root)
                if func_id:
                    implementation_func_ids.add(func_id)

        option_ids = []
        parse_loop_ids = []
        scope_kind = "unknown"
        scope_basis = "no_parse_loop_overlap"

        option_ids = _collect_option_ids_from_parse_sites(
            options_list,
            implementation_func_ids,
            max_options,
            parse_loop_by_id,
        )

        if option_ids:
            parse_loop_ids = sorted(
                {
                    parse_loop_by_function.get(func_id)
                    for func_id in implementation_func_ids
                    if parse_loop_by_function.get(func_id)
                }
            )
            scope_kind = "mode_scoped"
            scope_basis = "option_parse_sites"
        else:
            loop_ids = []
            loop_source = root_kind
            for root in roots_sorted:
                func_id = _root_function_id(root)
                loop_id = parse_loop_by_function.get(func_id)
                if loop_id:
                    loop_ids.append(loop_id)
            if not loop_ids and root_kind == "implementation":
                fallback_roots = mode.get("dispatch_roots", [])
                for root in fallback_roots:
                    func_id = _root_function_id(root)
                    loop_id = parse_loop_by_function.get(func_id)
                    if loop_id:
                        loop_ids.append(loop_id)
                if loop_ids:
                    loop_source = "dispatch"

            if loop_ids:
                parse_loop_ids = sorted(set(loop_ids))
                for loop_id in loop_ids:
                    option_ids.extend(options_by_loop_id.get(loop_id, []))
                scope_kind = "mode_scoped"
                dispatch_root_kinds = ("dispatch", "dispatch_shared")
                if loop_source in dispatch_root_kinds and root_kind in dispatch_root_kinds:
                    scope_basis = "shared_parse_loop_function"
                elif loop_source in dispatch_root_kinds:
                    scope_basis = "dispatch_root_parse_loop"
                else:
                    scope_basis = "implementation_root_parse_loop"
            elif global_option_ids:
                option_ids = list(global_option_ids)
                for loop in parse_loops:
                    loop_id = loop.get("id")
                    if loop_id:
                        parse_loop_ids.append(loop_id)
                    if max_options and len(parse_loop_ids) >= max_options:
                        break
                scope_kind = "global"
                scope_basis = "shared_parse_loops"

        seen_option_ids = set()
        deduped = []
        for opt_id in option_ids:
            if not opt_id or opt_id in seen_option_ids:
                continue
            deduped.append(opt_id)
            seen_option_ids.add(opt_id)
            if max_options and len(deduped) >= max_options:
                break

        top_strings = []
        if root_func_ids:
            string_counts = {}
            for func_id in root_func_ids:
                for string_id in string_refs_by_func.get(func_id, []) or []:
                    if selected_string_ids and string_id not in selected_string_ids:
                        continue
                    string_counts[string_id] = string_counts.get(string_id, 0) + 1
            if string_counts:
                for string_id, _count in sorted(
                    string_counts.items(),
                    key=lambda item: (-item[1], item[0]),
                ):
                    top_strings.append(string_id)
                    if max_strings and len(top_strings) >= max_strings:
                        break

        top_messages = []
        if root_func_ids and messages_by_func:
            message_counts = {}
            for func_id in root_func_ids:
                for string_id in messages_by_func.get(func_id, []) or []:
                    message_counts[string_id] = message_counts.get(string_id, 0) + 1
            for string_id, _count in sorted(
                message_counts.items(),
                key=lambda item: (-item[1], item[0]),
            ):
                top_messages.append(string_id)
                if max_messages and len(top_messages) >= max_messages:
                    break

        top_exit_paths = []
        if root_func_ids and exit_calls_by_func:
            seen_callsites = set()
            for func_id in root_func_ids:
                for callsite_id in exit_calls_by_func.get(func_id, []) or []:
                    if callsite_id in seen_callsites:
                        continue
                    seen_callsites.add(callsite_id)
                    top_exit_paths.append(callsite_id)
            top_exit_paths.sort(key=addr_to_int)
            if max_exit_paths and len(top_exit_paths) > max_exit_paths:
                top_exit_paths = top_exit_paths[:max_exit_paths]

        slice_entry = {
            "mode_id": mode.get("mode_id"),
            "name": mode.get("name"),
            "root_functions": roots_sorted,
            "root_kind": root_kind,
            "dispatch_sites": dispatch_sites,
            "option_scope": {
                "kind": scope_kind,
                "basis": scope_basis,
                "option_ids": deduped,
                "parse_loop_ids": parse_loop_ids,
                "options_ref": "cli/options.json",
                "parse_loops_ref": "cli/parse_loops.json",
            },
        }
        if root_kind == "dispatch_shared" and mode.get("token"):
            slice_entry["token"] = mode.get("token")
        if top_strings:
            slice_entry["top_strings"] = top_strings
            slice_entry["top_strings_ref"] = "strings.json"
        if top_messages:
            slice_entry["top_messages"] = top_messages
            slice_entry["top_messages_ref"] = "errors/messages.json"
        if top_exit_paths:
            slice_entry["top_exit_paths"] = top_exit_paths
            slice_entry["top_exit_paths_ref"] = "errors/exit_paths.json"
        slices.append(slice_entry)

    slices.sort(
        key=lambda item: (
            -len(item.get("dispatch_sites") or []),
            -len(item.get("root_functions") or []),
            item.get("name") or "",
            item.get("mode_id") or "",
        )
    )

    total_slices = len(slices)
    truncated = False

    return {
        "total_modes": len(modes),
        "selected_slices": total_slices,
        "truncated": truncated,
        "max_slices": max_slices,
        "slices": slices,
    }
