"""Collection stage for the context pack export pipeline."""

from __future__ import annotations

from typing import Any

from collectors.callgraph import build_function_meta, collect_call_edges, collect_functions
from collectors.imports import collect_imports
from collectors.strings import collect_string_refs_by_func, collect_strings
from errors.exits import derive_exit_paths
from errors.messages import derive_error_messages
from errors.refs import collect_error_callsites
from errors.sites import derive_error_sites
from export_bounds import Bounds
from interfaces.surface import build_interfaces_index_payload, collect_interfaces
from modes.candidates import collect_mode_candidates
from outputs.payloads import build_binary_info
from pipeline.cli import collect_cli_inputs
from pipeline.phases import phase
from pipeline.types import CollectedData


def collect_pipeline_inputs(
    program: Any,
    bounds: Bounds,
    monitor: Any,
    profiler: Any,
) -> CollectedData:
    with phase(profiler, "collect_strings"):
        binary_info, hashes = build_binary_info(program)
        imports = collect_imports(program)
        (
            strings,
            _string_addr_map_selected,
            total_strings,
            strings_truncated,
            string_addr_map_all,
            string_tags_by_id,
            string_bucket_counts,
            string_bucket_limits,
        ) = collect_strings(program, bounds.max_strings)
    selected_string_ids = set([entry["id"] for entry in strings])
    string_value_by_id = {}
    for entry in strings:
        string_value_by_id[entry["id"]] = entry.get("value")

    with phase(profiler, "collect_functions"):
        functions = collect_functions(program)
        function_meta_by_addr = build_function_meta(functions)
        listing = program.getListing()
        string_refs_by_func = collect_string_refs_by_func(
            listing,
            functions,
            string_addr_map_all,
            monitor,
        )

    with phase(profiler, "collect_call_edges"):
        call_edges_all, callsite_records, call_edge_stats = collect_call_edges(program, functions, monitor)

    with phase(profiler, "collect_cli_parse_compare"):
        cli_inputs = collect_cli_inputs(
            program,
            bounds,
            call_edges_all,
            function_meta_by_addr,
            string_addr_map_all,
            string_refs_by_func,
            strings,
            monitor,
        )

    with phase(profiler, "collect_errors"):
        error_messages_payload, emitter_callsites_by_func, call_args_cache = derive_error_messages(
            program,
            monitor,
            strings,
            string_addr_map_all,
            string_refs_by_func,
            call_edges_all,
            function_meta_by_addr,
            string_tags_by_id,
            bounds,
        )
        exit_paths_payload, exit_callsites_by_func, call_args_cache = derive_exit_paths(
            program,
            monitor,
            call_edges_all,
            function_meta_by_addr,
            bounds,
            call_args_cache=call_args_cache,
            emitter_callsites_by_func=emitter_callsites_by_func,
        )
        error_sites_payload = derive_error_sites(
            error_messages_payload,
            exit_callsites_by_func,
            emitter_callsites_by_func,
            call_args_cache,
            bounds,
        )
    error_callsite_ids = collect_error_callsites(
        error_messages_payload, exit_paths_payload, error_sites_payload
    )

    with phase(profiler, "collect_interfaces"):
        interfaces_payloads, interface_callsite_ids, call_args_cache = collect_interfaces(
            program,
            call_edges_all,
            function_meta_by_addr,
            string_addr_map_all,
            bounds,
            monitor,
            call_args_cache=call_args_cache,
        )
        interfaces_index_payload = build_interfaces_index_payload(interfaces_payloads)

    with phase(profiler, "collect_modes"):
        modes_payload, mode_callsite_ids = collect_mode_candidates(
            program,
            call_edges_all,
            function_meta_by_addr,
            string_addr_map_all,
            bounds,
            monitor,
        )

    return CollectedData(
        binary_info=binary_info,
        hashes=hashes,
        imports=imports,
        strings=strings,
        selected_string_ids=selected_string_ids,
        string_value_by_id=string_value_by_id,
        total_strings=total_strings,
        strings_truncated=strings_truncated,
        string_addr_map_all=string_addr_map_all,
        string_tags_by_id=string_tags_by_id,
        string_bucket_counts=string_bucket_counts,
        string_bucket_limits=string_bucket_limits,
        functions=functions,
        function_meta_by_addr=function_meta_by_addr,
        string_refs_by_func=string_refs_by_func,
        call_edges_all=call_edges_all,
        callsite_records=callsite_records,
        call_edge_stats=call_edge_stats,
        cli_inputs=cli_inputs,
        error_messages_payload=error_messages_payload,
        exit_paths_payload=exit_paths_payload,
        error_sites_payload=error_sites_payload,
        error_callsite_ids=error_callsite_ids,
        interfaces_payloads=interfaces_payloads,
        interfaces_index_payload=interfaces_index_payload,
        interface_callsite_ids=interface_callsite_ids,
        modes_payload=modes_payload,
        mode_callsite_ids=mode_callsite_ids,
    )
