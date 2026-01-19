"""CLI-related collection helpers.

This module groups the exporter logic that:
- locates CLI parse loops (getopt/argp style)
- locates string-compare sites used for option/mode selection (strcmp-chain style)
- decodes option tokens and `struct option` longopt tables from memory

All of these are heuristics designed to be stable and bounded; they bias toward
not emitting noisy/ambiguous data.
"""

from collectors.cli_longopts import decode_longopt_table
from collectors.cli_tokens import (
    _is_probable_longopt_name as _is_probable_longopt_name_impl,
)
from collectors.cli_tokens import (
    decode_short_opt_string,
    parse_option_token,
)
from export_primitives import addr_to_int, normalize_symbol_name


def normalize_symbol_names(names):
    return set(normalize_symbol_name(name) for name in names)


CLI_PARSE_SIGNAL_NAMES = set([
    "getopt",
    "getopt_long",
    "__getopt_long",
    "getopt_long_only",
    "argp_parse",
])
CLI_PARSE_SIGNAL_NAMES = normalize_symbol_names(CLI_PARSE_SIGNAL_NAMES)
CLI_COMPARE_SIGNAL_NAMES = set([
    "strcmp",
    "strncmp",
    "strcasecmp",
    "strncasecmp",
])
CLI_COMPARE_SIGNAL_NAMES = normalize_symbol_names(CLI_COMPARE_SIGNAL_NAMES)
def collect_cli_parse_sites(call_edges, function_meta_by_addr):
    parse_sites = []
    sites_by_function = {}
    for edge in call_edges:
        target = edge.get("to") or {}
        name_norm = normalize_symbol_name(target.get("name"))
        if not name_norm or name_norm not in CLI_PARSE_SIGNAL_NAMES:
            continue
        from_addr = (edge.get("from") or {}).get("address")
        if not from_addr:
            continue
        caller_meta = function_meta_by_addr.get(from_addr, {})
        if caller_meta.get("is_external") or caller_meta.get("is_thunk"):
            continue
        callsite = edge.get("callsite")
        entry = {
            "callsite": callsite,
            "callee": target.get("name"),
            "callee_norm": name_norm,
            "caller": {
                "address": from_addr,
                "name": caller_meta.get("name") or (edge.get("from") or {}).get("function"),
            },
        }
        parse_sites.append(entry)

        bucket = sites_by_function.get(from_addr)
        if bucket is None:
            bucket = {
                "function": entry["caller"],
                "callsites": [],
                "callee_names": set(),
            }
            sites_by_function[from_addr] = bucket
        if callsite:
            bucket["callsites"].append(callsite)
        if target.get("name"):
            bucket["callee_names"].add(target.get("name"))

    grouped = []
    for entry in sites_by_function.values():
        entry["callsites"] = sorted(set(entry["callsites"]), key=addr_to_int)
        entry["callee_names"] = sorted(entry["callee_names"])
        grouped.append(entry)
    grouped.sort(key=lambda item: addr_to_int((item.get("function") or {}).get("address")))
    parse_sites.sort(key=lambda item: addr_to_int(item.get("callsite")))
    return parse_sites, grouped


def _is_compare_callee(name_norm):
    if not name_norm:
        return False
    if name_norm in CLI_COMPARE_SIGNAL_NAMES:
        return True
    for token in CLI_COMPARE_SIGNAL_NAMES:
        if token in name_norm:
            return True
    return False


def collect_cli_option_compare_sites(call_edges, function_meta_by_addr, allowed_callers=None):
    compare_sites = []
    for edge in call_edges:
        target = edge.get("to") or {}
        name_norm = normalize_symbol_name(target.get("name"))
        if not _is_compare_callee(name_norm):
            continue
        from_addr = (edge.get("from") or {}).get("address")
        if not from_addr:
            continue
        if allowed_callers is not None and from_addr not in allowed_callers:
            continue
        caller_meta = function_meta_by_addr.get(from_addr, {})
        if caller_meta.get("is_external") or caller_meta.get("is_thunk"):
            continue
        compare_sites.append({
            "callsite": edge.get("callsite"),
            "callee": target.get("name"),
            "callee_id": target.get("address"),
            "callee_norm": name_norm,
            "caller": {
                "address": from_addr,
                "name": caller_meta.get("name") or (edge.get("from") or {}).get("function"),
            },
        })
    compare_sites.sort(key=lambda item: addr_to_int(item.get("callsite")))
    return compare_sites


def _is_probable_longopt_name(value):
    return _is_probable_longopt_name_impl(value)


def build_cli_parse_details(
    program,
    parse_sites,
    call_args_by_callsite,
    string_addr_map_all,
    max_longopt_entries,
):
    details_by_callsite = {}
    for site in parse_sites:
        callsite = site.get("callsite")
        if not callsite:
            continue
        args = call_args_by_callsite.get(callsite, {})
        detail = {
            "callsite": callsite,
            "caller": site.get("caller"),
            "callee": site.get("callee"),
            "callee_norm": site.get("callee_norm"),
            "args_status": args.get("status"),
            "optstring": None,
            "longopts": None,
        }

        # Choose the densest optstring/longopts table to reduce noise per callsite.
        best_short = None
        best_short_count = 0
        for entry in args.get("string_args", []):
            options = decode_short_opt_string(entry.get("value"))
            if len(options) > best_short_count:
                best_short_count = len(options)
                best_short = {
                    "address": entry.get("address"),
                    "value": entry.get("value"),
                    "options": options,
                }
        if best_short and best_short_count > 0:
            best_short["string_id"] = string_addr_map_all.get(best_short.get("address"))
            detail["optstring"] = best_short

        best_long = None
        best_long_count = 0
        for addr_text in args.get("data_args", []):
            table = decode_longopt_table(program, addr_text, max_longopt_entries)
            entries = table.get("entries", [])
            count = 0
            for entry in entries:
                if entry.get("name"):
                    count += 1
            if count > best_long_count:
                best_long_count = count
                best_long = table
        if best_long and best_long.get("entries"):
            for entry in best_long["entries"]:
                name_addr = entry.get("name_address")
                if name_addr:
                    entry["string_id"] = string_addr_map_all.get(name_addr)
            detail["longopts"] = best_long

        details_by_callsite[callsite] = detail
    return details_by_callsite


def build_cli_compare_details(compare_sites, call_args_by_callsite, string_addr_map_all):
    details_by_callsite = {}
    for site in compare_sites:
        callsite = site.get("callsite")
        if not callsite:
            continue
        args = call_args_by_callsite.get(callsite, {})
        option_tokens = []
        seen = set()
        # Direct string compares are noisy; only keep tokens that look like CLI options.
        for entry in args.get("string_args", []):
            token = parse_option_token(entry.get("value"))
            if not token:
                continue
            address = entry.get("address")
            string_id = string_addr_map_all.get(address)
            key = (token.get("long_name"), token.get("short_name"), token.get("has_arg"), address)
            if key in seen:
                continue
            seen.add(key)
            token["address"] = address
            token["string_id"] = string_id
            token["value"] = entry.get("value")
            option_tokens.append(token)
        if not option_tokens:
            continue
        details_by_callsite[callsite] = {
            "callsite": callsite,
            "caller": site.get("caller"),
            "callee": site.get("callee"),
            "callee_norm": site.get("callee_norm"),
            "args_status": args.get("status"),
            "option_tokens": option_tokens,
        }
    return details_by_callsite
