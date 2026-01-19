"""Pipeline helpers for CLI-related collection work.

This is intentionally *not* the core CLI collection logic (that lives in
`scripts/collectors/cli.py`). Instead, this module wires together the collector
primitives needed by the export pipeline (batch call-arg recovery, compare-site
scoping, and parse-site enrichment).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from collectors.call_args import extract_call_args_for_callsites
from collectors.cli import (
    build_cli_compare_details,
    build_cli_parse_details,
    collect_cli_option_compare_sites,
    collect_cli_parse_sites,
)
from collectors.cli_tokens import parse_option_token
from export_bounds import Bounds


@dataclass(frozen=True)
class CliInputs:
    parse_groups: list[dict[str, Any]]
    parse_details_by_callsite: dict[str, Any]
    compare_details_by_callsite: dict[str, Any]
    parse_callsite_ids: list[str]
    compare_callsite_ids: list[str]


def collect_cli_inputs(
    program: Any,
    bounds: Bounds,
    call_edges_all: list[dict[str, Any]],
    function_meta_by_addr: dict[str, Any],
    string_addr_map_all: dict[str, Any],
    string_refs_by_func: dict[str, set[str]],
    strings: list[dict[str, Any]],
    monitor: Any,
) -> CliInputs:
    parse_sites, parse_groups = collect_cli_parse_sites(call_edges_all, function_meta_by_addr)

    parse_callsite_ids: list[str] = []
    for entry in parse_sites:
        callsite = entry.get("callsite")
        if callsite:
            parse_callsite_ids.append(callsite)

    # Restrict compare-site scanning to functions that reference option-like strings.
    option_token_string_ids: set[str] = set()
    for entry in strings:
        token = parse_option_token(entry.get("value"))
        if token:
            string_id = entry.get("id")
            if string_id:
                option_token_string_ids.add(string_id)

    option_token_callers: set[str] = set()
    if option_token_string_ids:
        for func_addr, string_ids in string_refs_by_func.items():
            if string_ids & option_token_string_ids:
                option_token_callers.add(func_addr)

    compare_sites = collect_cli_option_compare_sites(
        call_edges_all,
        function_meta_by_addr,
        option_token_callers if option_token_callers else None,
    )

    compare_callsite_ids: list[str] = []
    for entry in compare_sites:
        callsite = entry.get("callsite")
        if callsite:
            compare_callsite_ids.append(callsite)

    callsite_ids = list(dict.fromkeys(parse_callsite_ids + compare_callsite_ids))
    # Resolve call arguments in batches to avoid repeated per-callsite decompilation.
    call_args_by_callsite = extract_call_args_for_callsites(
        program,
        callsite_ids,
        monitor,
        purpose="binary_lens_export.collect_cli_inputs",
    )

    parse_details_by_callsite = build_cli_parse_details(
        program,
        parse_sites,
        call_args_by_callsite,
        string_addr_map_all,
        bounds.max_cli_longopt_entries,
    )

    compare_details_by_callsite = build_cli_compare_details(
        compare_sites,
        call_args_by_callsite,
        string_addr_map_all,
    )

    return CliInputs(
        parse_groups=parse_groups,
        parse_details_by_callsite=parse_details_by_callsite,
        compare_details_by_callsite=compare_details_by_callsite,
        parse_callsite_ids=parse_callsite_ids,
        compare_callsite_ids=compare_callsite_ids,
    )
