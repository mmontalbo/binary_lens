"""Collection stage for the context pack export pipeline."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from collectors.call_args import extract_call_args_for_callsites
from collectors.callgraph import build_function_meta, collect_call_edges, collect_functions
from collectors.strings import collect_string_refs_by_func, collect_strings
from export_bounds import Bounds
from export_primitives import addr_to_int
from outputs.payloads import build_binary_info
from pipeline.phases import phase
from pipeline.types import CollectedData
from symbols import IMPORT_SYMBOL_POLICY, normalize_symbol_name

LENS_CALL_ARG_TARGETS = {
    "getenv",
    "secure_getenv",
    "getenv_s",
    "fprintf",
    "printf",
    "vfprintf",
    "vprintf",
    "puts",
    "fputs",
    "exit",
    "exit_group",
    "abort",
}

_LENS_CALL_ARG_TARGETS_NORMALIZED: set[str] = set()
for _name in LENS_CALL_ARG_TARGETS:
    _normalized = normalize_symbol_name(_name, policy=IMPORT_SYMBOL_POLICY)
    if _normalized:
        _LENS_CALL_ARG_TARGETS_NORMALIZED.add(_normalized)


@dataclass(frozen=True)
class BinaryCollection:
    binary_info: dict[str, Any]
    hashes: dict[str, Any]


@dataclass(frozen=True)
class StringCollection:
    strings: list[dict[str, Any]]
    selected_string_ids: set[str]
    string_value_by_id: dict[str, Any]
    total_strings: int
    strings_truncated: bool
    string_addr_map_all: dict[str, Any]
    string_tags_by_id: dict[str, Any]


@dataclass(frozen=True)
class FunctionCollection:
    functions: list[Any]
    function_meta_by_addr: dict[str, Any]
    string_refs_by_func: dict[str, set[str]]


@dataclass(frozen=True)
class CallEdgeCollection:
    call_edges_all: list[dict[str, Any]]
    callsite_records: dict[str, Any]


def _collect_binary_and_strings(
    program: Any,
    bounds: Bounds,
    monitor: Any,
    profiler: Any,
) -> tuple[BinaryCollection, StringCollection]:
    with phase(profiler, "collect_strings"):
        binary_info, hashes = build_binary_info(program)
        (
            strings,
            _string_addr_map_selected,
            total_strings,
            strings_truncated,
            string_addr_map_all,
            string_tags_by_id,
            _string_bucket_counts,
            _string_bucket_limits,
        ) = collect_strings(program, bounds.max_strings)
    selected_string_ids = {entry["id"] for entry in strings}
    string_value_by_id = {entry["id"]: entry.get("value") for entry in strings}
    return (
        BinaryCollection(binary_info=binary_info, hashes=hashes),
        StringCollection(
            strings=strings,
            selected_string_ids=selected_string_ids,
            string_value_by_id=string_value_by_id,
            total_strings=total_strings,
            strings_truncated=strings_truncated,
            string_addr_map_all=string_addr_map_all,
            string_tags_by_id=string_tags_by_id,
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
        call_edges_all, callsite_records, _call_edge_stats = collect_call_edges(
            program,
            functions,
            monitor,
        )
    return CallEdgeCollection(
        call_edges_all=call_edges_all,
        callsite_records=callsite_records,
    )


def _collect_call_args_for_lenses(
    program: Any,
    call_edges_all: list[dict[str, Any]],
    monitor: Any,
    call_args_cache: dict[str, Any] | None,
):
    if call_args_cache is None:
        call_args_cache = {}
    if not call_edges_all:
        return call_args_cache
    callsite_ids: list[str] = []
    seen = set(call_args_cache)
    for edge in call_edges_all:
        callsite_id = edge.get("callsite")
        if not callsite_id or callsite_id in seen:
            continue
        target = edge.get("to") or {}
        target_name = target.get("name") if isinstance(target, dict) else None
        normalized = normalize_symbol_name(target_name, policy=IMPORT_SYMBOL_POLICY)
        if normalized and normalized in _LENS_CALL_ARG_TARGETS_NORMALIZED:
            callsite_ids.append(callsite_id)
            seen.add(callsite_id)
    if not callsite_ids:
        return call_args_cache
    callsite_ids.sort(key=addr_to_int)
    call_args_cache.update(
        extract_call_args_for_callsites(
            program,
            callsite_ids,
            monitor,
            purpose="binary_lens_export.collect_call_args_for_lenses",
        )
    )
    return call_args_cache


def collect_pipeline_inputs(
    program: Any,
    bounds: Bounds,
    monitor: Any,
    profiler: Any,
) -> CollectedData:
    call_args_cache: dict[str, Any] = {}
    binary, strings = _collect_binary_and_strings(program, bounds, monitor, profiler)
    functions = _collect_functions(program, strings.string_addr_map_all, monitor, profiler)
    call_edges = _collect_call_edges(program, functions.functions, monitor, profiler)
    call_args_cache = _collect_call_args_for_lenses(
        program,
        call_edges.call_edges_all,
        monitor,
        call_args_cache,
    )

    return CollectedData(
        binary_info=binary.binary_info,
        hashes=binary.hashes,
        strings=strings.strings,
        selected_string_ids=strings.selected_string_ids,
        string_value_by_id=strings.string_value_by_id,
        total_strings=strings.total_strings,
        strings_truncated=strings.strings_truncated,
        string_addr_map_all=strings.string_addr_map_all,
        string_tags_by_id=strings.string_tags_by_id,
        functions=functions.functions,
        function_meta_by_addr=functions.function_meta_by_addr,
        string_refs_by_func=functions.string_refs_by_func,
        call_edges_all=call_edges.call_edges_all,
        callsite_records=call_edges.callsite_records,
        call_args_by_callsite=call_args_cache,
    )
