"""Derivation stage for the context pack export pipeline (pack format v2)."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from collectors.callgraph import (
    build_callgraph_nodes,
    build_function_metrics,
    build_signal_set,
    select_call_edges,
    select_full_functions,
)
from derivations.accelerators import build_callsites_by_id
from export_bounds import Bounds
from export_config import (
    BINARY_LENS_VERSION,
    CALLGRAPH_SIGNAL_RULES,
    FORMAT_VERSION,
)
from export_primitives import addr_str, addr_to_int
from outputs.payloads import build_manifest, build_pack_index_payload
from pipeline.phases import phase
from pipeline.types import CollectedData, DerivedPayloads, FactTable


def _addr_sort_key(value: str | None) -> int:
    return addr_to_int(value)


def _function_id(func: Any) -> str | None:
    try:
        return addr_str(func.getEntryPoint())
    except Exception:
        return None


def _parse_evidence_include_ids(value: Any) -> list[str]:
    if value is None:
        return []
    items: list[str] = []
    if isinstance(value, (list, tuple, set)):
        sources = value
    else:
        sources = [value]
    for source in sources:
        if source is None:
            continue
        text = str(source)
        if not text.strip():
            continue
        items.extend(re.split(r"[,\s]+", text.strip()))
    return [item for item in items if item]


def _compile_evidence_name_regex(value: Any) -> tuple[str | None, re.Pattern | None, str | None]:
    if value is None:
        return None, None, None
    pattern = str(value).strip()
    if not pattern:
        return None, None, None
    try:
        return pattern, re.compile(pattern), None
    except re.error as exc:
        return pattern, None, str(exc)


def _sort_functions_by_addr(funcs: list[Any]) -> list[Any]:
    return sorted(
        funcs,
        key=lambda func: (_addr_sort_key(_function_id(func)), _function_id(func) or ""),
    )


def _apply_evidence_hints(
    functions: list[Any],
    base_selection: list[Any],
    max_count: int,
    *,
    include_name_regex: str | None,
    name_regex: re.Pattern | None,
    include_function_ids: list[str],
    regex_error: str | None,
) -> tuple[list[Any], dict[str, Any] | None]:
    if not include_name_regex and not include_function_ids and not regex_error:
        return base_selection, None

    funcs_by_addr_int: dict[int, Any] = {}
    for func in functions:
        func_id = _function_id(func)
        if not func_id:
            continue
        funcs_by_addr_int[_addr_sort_key(func_id)] = func

    requested_ids = sorted(
        set(include_function_ids),
        key=lambda item: (_addr_sort_key(item), str(item)),
    )
    missing_ids: list[str] = []
    invalid_ids: list[str] = []
    matched_by_id: list[Any] = []
    for raw_id in requested_ids:
        addr_int = _addr_sort_key(raw_id)
        if addr_int < 0:
            invalid_ids.append(raw_id)
            continue
        func = funcs_by_addr_int.get(addr_int)
        if func is None:
            missing_ids.append(raw_id)
            continue
        matched_by_id.append(func)

    matched_by_name: list[Any] = []
    if include_name_regex and regex_error is None and name_regex is not None:
        for func in functions:
            try:
                name = func.getName()
            except Exception:
                name = None
            if isinstance(name, str) and name_regex.search(name):
                matched_by_name.append(func)

    seen_ids: set[str] = set()
    hint_funcs: list[Any] = []
    for func in matched_by_id + matched_by_name:
        func_id = _function_id(func)
        if not func_id or func_id in seen_ids:
            continue
        seen_ids.add(func_id)
        hint_funcs.append(func)

    hint_funcs = _sort_functions_by_addr(hint_funcs)
    base_order = base_selection

    selected: list[Any] = []
    selected_ids: set[str] = set()
    applied_hint_ids: list[str] = []

    def _maybe_add(func: Any, *, is_hint: bool) -> None:
        if len(selected) >= max_count:
            return
        func_id = _function_id(func)
        if not func_id or func_id in selected_ids:
            return
        selected.append(func)
        selected_ids.add(func_id)
        if is_hint:
            applied_hint_ids.append(func_id)

    for func in hint_funcs:
        _maybe_add(func, is_hint=True)
    for func in base_order:
        _maybe_add(func, is_hint=False)

    hint_truncated = len(hint_funcs) > max_count
    hints_payload: dict[str, Any] = {
        "include_function_ids": requested_ids,
        "applied_function_ids": sorted(applied_hint_ids, key=_addr_sort_key),
        "missing_function_ids": sorted(missing_ids, key=_addr_sort_key),
    }
    if include_name_regex:
        hints_payload["include_name_regex"] = include_name_regex
    if invalid_ids:
        hints_payload["invalid_function_ids"] = sorted(invalid_ids)
    if regex_error:
        hints_payload["include_name_regex_error"] = regex_error
    if hint_truncated:
        hints_payload["truncated"] = True
        hints_payload["max_full_functions"] = max_count
    return selected, hints_payload


def _collect_callsite_ids(
    call_edges: list[dict[str, Any]],
    call_args_by_callsite: Mapping[str, Any] | None,
) -> list[str]:
    callsite_ids: set[str] = set()
    for edge in call_edges:
        callsite = edge.get("callsite")
        if isinstance(callsite, str) and callsite.strip():
            callsite_ids.add(callsite.strip())
    if isinstance(call_args_by_callsite, Mapping):
        for callsite in call_args_by_callsite.keys():
            if isinstance(callsite, str) and callsite.strip():
                callsite_ids.add(callsite.strip())
    return sorted(callsite_ids, key=_addr_sort_key)


def _build_callgraph_nodes_table(
    callgraph_nodes: list[dict[str, Any]],
    function_meta_by_addr: Mapping[str, Any],
    external_addrs: set[str] | None = None,
) -> FactTable:
    rows: list[dict[str, Any]] = []
    for node in callgraph_nodes:
        if not isinstance(node, Mapping):
            continue
        function_id = node.get("address")
        if not isinstance(function_id, str) or not function_id.strip():
            continue
        meta = function_meta_by_addr.get(function_id, {}) if isinstance(function_meta_by_addr, Mapping) else {}
        is_external = meta.get("is_external")
        if is_external is None and external_addrs and function_id in external_addrs:
            is_external = True
        row = {
            "function_id": function_id,
            "name": meta.get("name") or node.get("name"),
            "signature": meta.get("signature") or node.get("signature"),
            "is_external": is_external,
            "is_thunk": meta.get("is_thunk"),
            "size": meta.get("size"),
        }
        rows.append(row)
    rows.sort(key=lambda entry: _addr_sort_key(entry.get("function_id")))
    schema = [
        ("function_id", "string"),
        ("name", "string"),
        ("signature", "string"),
        ("is_external", "bool"),
        ("is_thunk", "bool"),
        ("size", "int64"),
    ]
    return FactTable(
        name="callgraph_nodes",
        rows=rows,
        primary_key=["function_id"],
        schema=schema,
        description="Function nodes (address, name, signature metadata).",
    )


def _build_call_edges_table(call_edges: list[dict[str, Any]]) -> FactTable:
    rows: list[dict[str, Any]] = []
    for edge in call_edges:
        if not isinstance(edge, Mapping):
            continue
        callsite_id = edge.get("callsite")
        from_entry = edge.get("from") or {}
        to_entry = edge.get("to") or {}
        from_function_id = from_entry.get("address") if isinstance(from_entry, Mapping) else None
        to_function_id = to_entry.get("address") if isinstance(to_entry, Mapping) else None
        if not (
            isinstance(callsite_id, str)
            and isinstance(from_function_id, str)
            and isinstance(to_function_id, str)
        ):
            continue
        rows.append(
            {
                "from_function_id": from_function_id,
                "to_function_id": to_function_id,
                "callsite_id": callsite_id,
            }
        )
    rows.sort(
        key=lambda entry: (
            _addr_sort_key(entry.get("from_function_id")),
            _addr_sort_key(entry.get("callsite_id")),
            _addr_sort_key(entry.get("to_function_id")),
        )
    )
    schema = [
        ("from_function_id", "string"),
        ("to_function_id", "string"),
        ("callsite_id", "string"),
    ]
    return FactTable(
        name="call_edges",
        rows=rows,
        primary_key=["from_function_id", "callsite_id", "to_function_id"],
        schema=schema,
        description="Callgraph edges with callsite witnesses.",
    )


def _build_callsites_table(
    callsite_records: Mapping[str, Any],
    callsite_ids: list[str],
    callsites_by_id: Mapping[str, Any],
) -> FactTable:
    rows: list[dict[str, Any]] = []
    for callsite_id in callsite_ids:
        record = callsite_records.get(callsite_id, {}) if isinstance(callsite_records, Mapping) else {}
        from_entry = record.get("from") if isinstance(record, Mapping) else None
        from_function_id = from_entry.get("address") if isinstance(from_entry, Mapping) else None
        instruction = record.get("instruction") if isinstance(record, Mapping) else None
        arg_status = None
        if isinstance(callsites_by_id, Mapping):
            arg_status = (callsites_by_id.get(callsite_id) or {}).get("arg_recovery_status")
        rows.append(
            {
                "callsite_id": callsite_id,
                "from_function_id": from_function_id,
                "instruction": instruction,
                "arg_recovery_status": arg_status,
            }
        )
    rows.sort(key=lambda entry: _addr_sort_key(entry.get("callsite_id")))
    schema = [
        ("callsite_id", "string"),
        ("from_function_id", "string"),
        ("instruction", "string"),
        ("arg_recovery_status", "string"),
    ]
    return FactTable(
        name="callsites",
        rows=rows,
        primary_key=["callsite_id"],
        schema=schema,
        description="Callsite inventory with owning function and instruction.",
    )


def _build_callsite_arg_observations_table(
    callsites_by_id: Mapping[str, Any],
    callsite_ids: set[str],
) -> FactTable:
    rows: list[dict[str, Any]] = []
    for callsite_id, record in callsites_by_id.items() if isinstance(callsites_by_id, Mapping) else []:
        if callsite_ids and callsite_id not in callsite_ids:
            continue
        observations = record.get("arg_observations") if isinstance(record, Mapping) else None
        if not isinstance(observations, list):
            continue
        for idx, obs in enumerate(observations):
            if not isinstance(obs, Mapping):
                continue
            row = {
                "observation_id": f"{callsite_id}:{idx}",
                "callsite_id": callsite_id,
                "arg_index": obs.get("index"),
                "kind": obs.get("kind"),
                "status": obs.get("status"),
                "basis": obs.get("basis"),
                "string_id": obs.get("string_id"),
                "string_value": None,
                "int_value": None,
                "address": obs.get("address"),
                "name": obs.get("name"),
                "provider_callsite_id": obs.get("provider_callsite_id"),
            }
            value = obs.get("value")
            if isinstance(value, int):
                row["int_value"] = value
            elif value is not None:
                row["string_value"] = value
            rows.append(row)
    rows.sort(
        key=lambda entry: (
            _addr_sort_key(entry.get("callsite_id")),
            entry.get("arg_index") if isinstance(entry.get("arg_index"), int) else 1_000_000,
            str(entry.get("kind") or ""),
            str(entry.get("basis") or ""),
            str(entry.get("observation_id") or ""),
        )
    )
    schema = [
        ("observation_id", "string"),
        ("callsite_id", "string"),
        ("arg_index", "int64"),
        ("kind", "string"),
        ("status", "string"),
        ("basis", "string"),
        ("string_id", "string"),
        ("string_value", "string"),
        ("int_value", "int64"),
        ("address", "string"),
        ("name", "string"),
        ("provider_callsite_id", "string"),
    ]
    return FactTable(
        name="callsite_arg_observations",
        rows=rows,
        primary_key=["observation_id"],
        schema=schema,
        description="Recovered constant arguments by callsite and arg index.",
    )


def _build_strings_table(
    strings: list[dict[str, Any]],
    string_tags_by_id: Mapping[str, Any],
) -> FactTable:
    rows: list[dict[str, Any]] = []
    for entry in strings:
        if not isinstance(entry, Mapping):
            continue
        string_id = entry.get("id")
        value = entry.get("value")
        if not isinstance(string_id, str) or not isinstance(value, str):
            continue
        tags = string_tags_by_id.get(string_id) if isinstance(string_tags_by_id, Mapping) else None
        tags_list = sorted(list(tags)) if isinstance(tags, (set, list, tuple)) else []
        row = {
            "string_id": string_id,
            "value": value,
            "address": entry.get("address"),
            "length": entry.get("length"),
            "ref_count": entry.get("ref_count"),
            "data_type": entry.get("data_type"),
            "tags": tags_list,
        }
        rows.append(row)
    rows.sort(key=lambda entry: _addr_sort_key(entry.get("address")))
    schema = [
        ("string_id", "string"),
        ("value", "string"),
        ("address", "string"),
        ("length", "int64"),
        ("ref_count", "int64"),
        ("data_type", "string"),
        ("tags", "list<string>"),
    ]
    return FactTable(
        name="strings",
        rows=rows,
        primary_key=["string_id"],
        schema=schema,
        description="Selected string inventory with metadata and tags.",
    )


def derive_payloads(
    collected: CollectedData,
    bounds: Bounds,
    profiler: Any,
    *,
    options: Mapping[str, Any] | None = None,
) -> DerivedPayloads:
    with phase(profiler, "derive_function_metrics"):
        metrics_by_addr = build_function_metrics(
            collected.functions,
            collected.call_edges_all,
            collected.string_refs_by_func,
            collected.string_tags_by_id,
        )
        full_functions = select_full_functions(
            collected.functions,
            metrics_by_addr,
            bounds.max_full_functions,
        )
        include_name_regex, name_regex, regex_error = _compile_evidence_name_regex(
            (options or {}).get("evidence_include_name_regex")
        )
        include_function_ids = _parse_evidence_include_ids(
            (options or {}).get("evidence_include_function_ids")
        )
        full_functions, evidence_hints = _apply_evidence_hints(
            collected.functions,
            full_functions,
            bounds.max_full_functions,
            include_name_regex=include_name_regex,
            name_regex=name_regex,
            include_function_ids=include_function_ids,
            regex_error=regex_error,
        )

    with phase(profiler, "derive_callgraph"):
        signal_set = build_signal_set(CALLGRAPH_SIGNAL_RULES)
        call_edges, total_edges, truncated_edges = select_call_edges(
            collected.call_edges_all,
            signal_set,
            bounds.max_call_edges,
        )
        external_addrs = {
            edge.get("to", {}).get("address")
            for edge in call_edges
            if isinstance(edge, Mapping)
            and isinstance(edge.get("to"), Mapping)
            and edge.get("to", {}).get("external") is True
            and isinstance(edge.get("to", {}).get("address"), str)
        }
        callgraph_nodes = build_callgraph_nodes(call_edges, collected.function_meta_by_addr)

    with phase(profiler, "derive_callsites"):
        callsite_ids = _collect_callsite_ids(call_edges, collected.call_args_by_callsite)
        callsites_by_id = build_callsites_by_id(
            collected.callsite_records,
            call_args_by_callsite=collected.call_args_by_callsite,
            string_addr_map_all=collected.string_addr_map_all,
            selected_string_ids=collected.selected_string_ids,
        )
        callsite_id_set = set(callsite_ids)

    with phase(profiler, "derive_facts"):
        callsite_arg_table = _build_callsite_arg_observations_table(callsites_by_id, callsite_id_set)
        fact_tables = [
            _build_callgraph_nodes_table(
                callgraph_nodes,
                collected.function_meta_by_addr,
                external_addrs=external_addrs,
            ),
            _build_call_edges_table(call_edges),
            _build_callsites_table(collected.callsite_records, callsite_ids, callsites_by_id),
            callsite_arg_table,
            _build_strings_table(collected.strings, collected.string_tags_by_id),
        ]
        callsite_arg_count = len(callsite_arg_table.rows)

    coverage_summary = {
        "full_functions": {
            "total": len(collected.functions),
            "selected": len(full_functions),
            "truncated": len(collected.functions) > bounds.max_full_functions,
            "max": bounds.max_full_functions,
        },
        "callgraph_edges": {
            "total": total_edges,
            "selected": len(call_edges),
            "truncated": truncated_edges,
            "max": bounds.optional("max_call_edges"),
        },
        "callgraph_nodes": {
            "total": None,
            "selected": len(callgraph_nodes),
            "truncated": None,
            "max": None,
        },
        "callsites": {
            "total": len(collected.callsite_records),
            "selected": len(callsite_ids),
            "truncated": len(callsite_ids) < len(collected.callsite_records),
            "max": None,
        },
        "callsite_arg_observations": {
            "total": None,
            "selected": callsite_arg_count,
            "truncated": None,
            "max": None,
        },
        "strings": {
            "total": collected.total_strings,
            "selected": len(collected.strings),
            "truncated": collected.strings_truncated,
            "max": bounds.optional("max_strings"),
        },
    }

    manifest = build_manifest(
        bounds,
        collected.hashes,
        BINARY_LENS_VERSION,
        FORMAT_VERSION,
        binary_info=collected.binary_info,
        coverage_summary=coverage_summary,
        evidence_hints=evidence_hints,
    )
    pack_index_payload = build_pack_index_payload(FORMAT_VERSION)
    return DerivedPayloads(
        full_functions=full_functions,
        facts=fact_tables,
        pack_index_payload=pack_index_payload,
        manifest=manifest,
        evidence_hints=evidence_hints,
    )
