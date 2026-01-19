"""Collection stage for the context pack export pipeline."""

from __future__ import annotations

from dataclasses import dataclass
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


@dataclass(frozen=True)
class BinaryCollection:
    binary_info: dict[str, Any]
    hashes: dict[str, Any]
    imports: list[dict[str, Any]]


@dataclass(frozen=True)
class StringCollection:
    strings: list[dict[str, Any]]
    selected_string_ids: set[str]
    string_value_by_id: dict[str, Any]
    total_strings: int
    strings_truncated: bool
    string_addr_map_all: dict[str, Any]
    string_tags_by_id: dict[str, Any]
    string_bucket_counts: dict[str, Any]
    string_bucket_limits: dict[str, Any]


@dataclass(frozen=True)
class FunctionCollection:
    functions: list[Any]
    function_meta_by_addr: dict[str, Any]
    string_refs_by_func: dict[str, set[str]]


@dataclass(frozen=True)
class CallEdgeCollection:
    call_edges_all: list[dict[str, Any]]
    callsite_records: dict[str, Any]
    call_edge_stats: dict[str, Any]


@dataclass(frozen=True)
class ErrorCollection:
    error_messages_payload: dict[str, Any]
    exit_paths_payload: dict[str, Any]
    error_sites_payload: dict[str, Any]
    error_callsite_ids: list[str]
    call_args_cache: Any


@dataclass(frozen=True)
class InterfaceCollection:
    interfaces_payloads: dict[str, Any]
    interfaces_index_payload: dict[str, Any]
    interface_callsite_ids: list[str]
    call_args_cache: Any


@dataclass(frozen=True)
class ModeCollection:
    modes_payload: dict[str, Any]
    mode_callsite_ids: list[str]


def _collect_binary_and_strings(
    program: Any,
    bounds: Bounds,
    monitor: Any,
    profiler: Any,
) -> tuple[BinaryCollection, StringCollection]:
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
    selected_string_ids = {entry["id"] for entry in strings}
    string_value_by_id = {entry["id"]: entry.get("value") for entry in strings}
    return (
        BinaryCollection(binary_info=binary_info, hashes=hashes, imports=imports),
        StringCollection(
            strings=strings,
            selected_string_ids=selected_string_ids,
            string_value_by_id=string_value_by_id,
            total_strings=total_strings,
            strings_truncated=strings_truncated,
            string_addr_map_all=string_addr_map_all,
            string_tags_by_id=string_tags_by_id,
            string_bucket_counts=string_bucket_counts,
            string_bucket_limits=string_bucket_limits,
        ),
    )


def _collect_functions(
    program: Any,
    string_addr_map_all: dict[str, Any],
    monitor: Any,
    profiler: Any,
) -> FunctionCollection:
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
    return FunctionCollection(
        functions=functions,
        function_meta_by_addr=function_meta_by_addr,
        string_refs_by_func=string_refs_by_func,
    )


def _collect_call_edges(
    program: Any,
    functions: list[Any],
    monitor: Any,
    profiler: Any,
) -> CallEdgeCollection:
    with phase(profiler, "collect_call_edges"):
        call_edges_all, callsite_records, call_edge_stats = collect_call_edges(
            program,
            functions,
            monitor,
        )
    return CallEdgeCollection(
        call_edges_all=call_edges_all,
        callsite_records=callsite_records,
        call_edge_stats=call_edge_stats,
    )


def _collect_cli_inputs(
    program: Any,
    bounds: Bounds,
    call_edges_all: list[dict[str, Any]],
    function_meta_by_addr: dict[str, Any],
    string_addr_map_all: dict[str, Any],
    string_refs_by_func: dict[str, set[str]],
    strings: list[dict[str, Any]],
    monitor: Any,
    profiler: Any,
):
    with phase(profiler, "collect_cli_parse_compare"):
        return collect_cli_inputs(
            program,
            bounds,
            call_edges_all,
            function_meta_by_addr,
            string_addr_map_all,
            string_refs_by_func,
            strings,
            monitor,
        )


def _collect_errors(
    program: Any,
    monitor: Any,
    strings: list[dict[str, Any]],
    string_addr_map_all: dict[str, Any],
    string_refs_by_func: dict[str, set[str]],
    call_edges_all: list[dict[str, Any]],
    function_meta_by_addr: dict[str, Any],
    string_tags_by_id: dict[str, Any],
    bounds: Bounds,
    profiler: Any,
) -> ErrorCollection:
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
        error_messages_payload,
        exit_paths_payload,
        error_sites_payload,
    )
    return ErrorCollection(
        error_messages_payload=error_messages_payload,
        exit_paths_payload=exit_paths_payload,
        error_sites_payload=error_sites_payload,
        error_callsite_ids=error_callsite_ids,
        call_args_cache=call_args_cache,
    )


def _collect_interfaces(
    program: Any,
    call_edges_all: list[dict[str, Any]],
    function_meta_by_addr: dict[str, Any],
    string_addr_map_all: dict[str, Any],
    bounds: Bounds,
    monitor: Any,
    call_args_cache: Any,
    profiler: Any,
) -> InterfaceCollection:
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
    return InterfaceCollection(
        interfaces_payloads=interfaces_payloads,
        interfaces_index_payload=interfaces_index_payload,
        interface_callsite_ids=interface_callsite_ids,
        call_args_cache=call_args_cache,
    )


def _collect_modes(
    program: Any,
    call_edges_all: list[dict[str, Any]],
    function_meta_by_addr: dict[str, Any],
    string_addr_map_all: dict[str, Any],
    bounds: Bounds,
    monitor: Any,
    profiler: Any,
) -> ModeCollection:
    with phase(profiler, "collect_modes"):
        modes_payload, mode_callsite_ids = collect_mode_candidates(
            program,
            call_edges_all,
            function_meta_by_addr,
            string_addr_map_all,
            bounds,
            monitor,
        )
    return ModeCollection(modes_payload=modes_payload, mode_callsite_ids=mode_callsite_ids)


def collect_pipeline_inputs(
    program: Any,
    bounds: Bounds,
    monitor: Any,
    profiler: Any,
) -> CollectedData:
    binary, strings = _collect_binary_and_strings(program, bounds, monitor, profiler)
    functions = _collect_functions(program, strings.string_addr_map_all, monitor, profiler)
    call_edges = _collect_call_edges(program, functions.functions, monitor, profiler)
    cli_inputs = _collect_cli_inputs(
        program,
        bounds,
        call_edges.call_edges_all,
        functions.function_meta_by_addr,
        strings.string_addr_map_all,
        functions.string_refs_by_func,
        strings.strings,
        monitor,
        profiler,
    )
    errors = _collect_errors(
        program,
        monitor,
        strings.strings,
        strings.string_addr_map_all,
        functions.string_refs_by_func,
        call_edges.call_edges_all,
        functions.function_meta_by_addr,
        strings.string_tags_by_id,
        bounds,
        profiler,
    )
    interfaces = _collect_interfaces(
        program,
        call_edges.call_edges_all,
        functions.function_meta_by_addr,
        strings.string_addr_map_all,
        bounds,
        monitor,
        errors.call_args_cache,
        profiler,
    )
    modes = _collect_modes(
        program,
        call_edges.call_edges_all,
        functions.function_meta_by_addr,
        strings.string_addr_map_all,
        bounds,
        monitor,
        profiler,
    )

    return CollectedData(
        binary_info=binary.binary_info,
        hashes=binary.hashes,
        imports=binary.imports,
        strings=strings.strings,
        selected_string_ids=strings.selected_string_ids,
        string_value_by_id=strings.string_value_by_id,
        total_strings=strings.total_strings,
        strings_truncated=strings.strings_truncated,
        string_addr_map_all=strings.string_addr_map_all,
        string_tags_by_id=strings.string_tags_by_id,
        string_bucket_counts=strings.string_bucket_counts,
        string_bucket_limits=strings.string_bucket_limits,
        functions=functions.functions,
        function_meta_by_addr=functions.function_meta_by_addr,
        string_refs_by_func=functions.string_refs_by_func,
        call_edges_all=call_edges.call_edges_all,
        callsite_records=call_edges.callsite_records,
        call_edge_stats=call_edges.call_edge_stats,
        cli_inputs=cli_inputs,
        error_messages_payload=errors.error_messages_payload,
        exit_paths_payload=errors.exit_paths_payload,
        error_sites_payload=errors.error_sites_payload,
        error_callsite_ids=errors.error_callsite_ids,
        interfaces_payloads=interfaces.interfaces_payloads,
        interfaces_index_payload=interfaces.interfaces_index_payload,
        interface_callsite_ids=interfaces.interface_callsite_ids,
        modes_payload=modes.modes_payload,
        mode_callsite_ids=modes.mode_callsite_ids,
    )
