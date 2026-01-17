"""Derivation stage for the context pack export pipeline."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from collectors.callgraph import (
    build_function_metrics,
    build_signal_set,
    collect_function_calls,
    select_call_edges,
    select_full_functions,
    select_index_functions,
    summarize_functions,
)
from contracts.views import build_contract_views
from derivations.cli_surface import attach_cli_callsite_refs, derive_cli_surface
from errors.refs import attach_callsite_refs
from export_bounds import Bounds
from export_config import BINARY_LENS_VERSION, CALLGRAPH_SIGNAL_RULES, FORMAT_VERSION
from export_primitives import addr_str, addr_to_int
from interfaces.surface import attach_interface_callsite_refs
from modes.refs import attach_mode_callsite_refs
from modes.slices import build_mode_slices
from outputs.pack_docs import build_pack_markdown_docs
from outputs.payloads import (
    build_callgraph_payload,
    build_cli_options_payload,
    build_cli_parse_loops_payload,
    build_index_payload,
    build_manifest,
    build_pack_index_payload,
    build_pack_readme,
    build_strings_payload,
)
from outputs.sharding import build_sharded_list_index
from outputs.writers import build_callsite_records
from pipeline.phases import phase
from pipeline.types import CollectedData, DerivedPayloads


def _collect_callsite_values(value: Any, callsite_ids: set[str]) -> None:
    if isinstance(value, str):
        cleaned = value.strip()
        if cleaned:
            callsite_ids.add(cleaned)
        return
    if isinstance(value, list):
        for entry in value:
            _collect_callsite_values(entry, callsite_ids)
        return
    if isinstance(value, Mapping):
        _collect_callsite_ids(value, callsite_ids)


def _collect_callsite_ids(value: Any, callsite_ids: set[str]) -> None:
    if isinstance(value, Mapping):
        for key, entry in value.items():
            if isinstance(key, str) and "callsite" in key and "ref" not in key:
                _collect_callsite_values(entry, callsite_ids)
                continue
            _collect_callsite_ids(entry, callsite_ids)
        return
    if isinstance(value, list):
        for entry in value:
            _collect_callsite_ids(entry, callsite_ids)


def _collect_exported_callsites(*payloads: Any) -> list[str]:
    callsite_ids: set[str] = set()
    for payload in payloads:
        _collect_callsite_ids(payload, callsite_ids)
    return sorted(callsite_ids, key=addr_to_int)


def derive_payloads(
    collected: CollectedData,
    bounds: Bounds,
    profiler: Any,
) -> DerivedPayloads:
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
    index_functions = select_index_functions(
        collected.functions,
        full_functions,
        bounds.max_functions_index,
    )

    summaries = summarize_functions(collected.functions, index_functions, full_functions)

    signal_set = build_signal_set(CALLGRAPH_SIGNAL_RULES)
    call_edges, total_edges, truncated_edges = select_call_edges(
        collected.call_edges_all,
        signal_set,
        bounds.max_call_edges,
    )
    with phase(profiler, "derive_cli_surface"):
        cli_surface = derive_cli_surface(
            collected.cli_inputs.parse_groups,
            collected.cli_inputs.parse_details_by_callsite,
            collected.cli_inputs.compare_details_by_callsite,
            {},
            bounds,
            collected.cli_inputs.check_sites_by_flag_addr,
        )
    with phase(profiler, "build_mode_slices"):
        modes_slices_payload = build_mode_slices(
            collected.modes_payload,
            cli_surface,
            bounds,
            string_refs_by_func=collected.string_refs_by_func,
            selected_string_ids=collected.selected_string_ids,
            error_messages_payload=collected.error_messages_payload,
            exit_paths_payload=collected.exit_paths_payload,
        )

    callsite_evidence_mode = (bounds.get("callsite_evidence") or "referenced").strip().lower()
    if callsite_evidence_mode == "all":
        # Ensure CLI evidence callsites are serialized even if they fall outside edge caps.
        extra_callsites = (
            collected.cli_inputs.parse_callsite_ids
            + collected.cli_inputs.compare_callsite_ids
            + collected.error_callsite_ids
            + collected.mode_callsite_ids
            + collected.interface_callsite_ids
        )
        callsite_paths, callsite_evidence = build_callsite_records(
            collected.callsite_records,
            call_edges,
            extra_callsites=extra_callsites,
        )
    else:
        required_callsites = _collect_exported_callsites(
            cli_surface,
            collected.error_messages_payload,
            collected.exit_paths_payload,
            collected.error_sites_payload,
            collected.interfaces_payloads,
            collected.modes_payload,
            collected.dispatch_sites_payload,
            modes_slices_payload,
        )
        callsite_paths, callsite_evidence = build_callsite_records(
            collected.callsite_records,
            call_edges,
            callsite_ids=required_callsites,
        )

    attach_callsite_refs(
        collected.error_messages_payload,
        collected.exit_paths_payload,
        collected.error_sites_payload,
        callsite_paths,
    )
    attach_mode_callsite_refs(collected.modes_payload, collected.dispatch_sites_payload, callsite_paths)
    attach_interface_callsite_refs(collected.interfaces_payloads, callsite_paths)
    attach_cli_callsite_refs(cli_surface, callsite_paths)

    callgraph = build_callgraph_payload(
        call_edges,
        total_edges,
        truncated_edges,
        bounds,
        collected.call_edge_stats,
    )

    calls_by_func = collect_function_calls(call_edges)

    cli_options_payload = build_cli_options_payload(
        cli_surface.get("options", []),
        cli_surface.get("total_options", 0),
        cli_surface.get("options_truncated", False),
        bounds,
    )
    cli_parse_loops_payload = build_cli_parse_loops_payload(
        cli_surface.get("parse_loops", []),
        cli_surface.get("total_parse_loops", 0),
        cli_surface.get("parse_loops_truncated", False),
        bounds,
    )
    cli_parse_loops_index, cli_parse_loops_shards = build_sharded_list_index(
        cli_parse_loops_payload,
        list_key="parse_loops",
        shard_dir="cli/parse_loops",
        item_id_key="id",
        item_kind="cli_parse_loops",
    )
    modes_slices_index, modes_slices_shards = build_sharded_list_index(
        modes_slices_payload,
        list_key="slices",
        shard_dir="modes/slices",
        item_id_key="mode_id",
        item_kind="mode_slices",
    )

    strings_payload = build_strings_payload(
        collected.strings,
        collected.total_strings,
        collected.strings_truncated,
        bounds,
        collected.string_bucket_counts,
        collected.string_bucket_limits,
    )
    strings_index, strings_shards = build_sharded_list_index(
        strings_payload,
        list_key="strings",
        shard_dir="strings",
        item_id_key=None,
        item_kind="strings",
    )
    callgraph_index, callgraph_shards = build_sharded_list_index(
        callgraph,
        list_key="edges",
        shard_dir="callgraph/edges",
        item_id_key=None,
        item_kind="callgraph_edges",
    )
    cli_options_index, cli_options_shards = build_sharded_list_index(
        cli_options_payload,
        list_key="options",
        shard_dir="cli/options",
        item_id_key=None,
        item_kind="cli_options",
    )
    error_messages_index, error_messages_shards = build_sharded_list_index(
        collected.error_messages_payload,
        list_key="messages",
        shard_dir="errors/messages",
        item_id_key=None,
        item_kind="error_messages",
    )
    exit_paths_index, exit_paths_shards = build_sharded_list_index(
        collected.exit_paths_payload,
        list_key="direct_calls",
        shard_dir="errors/exit_paths",
        item_id_key=None,
        item_kind="exit_calls",
    )
    error_sites_index, error_sites_shards = build_sharded_list_index(
        collected.error_sites_payload,
        list_key="sites",
        shard_dir="errors/error_sites",
        item_id_key=None,
        item_kind="error_sites",
    )
    interfaces_env_index, interfaces_env_shards = build_sharded_list_index(
        collected.interfaces_payloads.get("env", {}),
        list_key="entries",
        shard_dir="interfaces/env",
        item_id_key=None,
        item_kind="interfaces_env",
    )
    interfaces_fs_index, interfaces_fs_shards = build_sharded_list_index(
        collected.interfaces_payloads.get("fs", {}),
        list_key="entries",
        shard_dir="interfaces/fs",
        item_id_key=None,
        item_kind="interfaces_fs",
    )
    interfaces_process_index, interfaces_process_shards = build_sharded_list_index(
        collected.interfaces_payloads.get("process", {}),
        list_key="entries",
        shard_dir="interfaces/process",
        item_id_key=None,
        item_kind="interfaces_process",
    )
    interfaces_net_index, interfaces_net_shards = build_sharded_list_index(
        collected.interfaces_payloads.get("net", {}),
        list_key="entries",
        shard_dir="interfaces/net",
        item_id_key=None,
        item_kind="interfaces_net",
    )
    interfaces_output_index, interfaces_output_shards = build_sharded_list_index(
        collected.interfaces_payloads.get("output", {}),
        list_key="entries",
        shard_dir="interfaces/output",
        item_id_key=None,
        item_kind="interfaces_output",
    )
    index_payload = build_index_payload(
        collected.functions,
        full_functions,
        index_functions,
        summaries,
        bounds,
    )
    functions_index, functions_index_shards = build_sharded_list_index(
        index_payload,
        list_key="functions",
        shard_dir="functions/index",
        item_id_key=None,
        item_kind="functions_index",
    )
    coverage_summary = {
        "strings": {
            "total": strings_payload.get("total_strings"),
            "selected": len(strings_payload.get("strings") or []),
            "truncated": strings_payload.get("truncated"),
            "max": strings_payload.get("max_strings"),
        },
        "functions_index": {
            "total": index_payload.get("total_functions"),
            "selected": len(index_payload.get("functions") or []),
            "truncated": index_payload.get("truncated"),
            "max": index_payload.get("max_functions"),
        },
        "full_functions": {
            "selected": len(index_payload.get("full_functions") or []),
            "truncated": len(collected.functions) > bounds.max_full_functions,
            "max": bounds.max_full_functions,
        },
        "callgraph_edges": {
            "total": callgraph.get("total_edges"),
            "selected": callgraph.get("selected_edges"),
            "truncated": callgraph.get("truncated"),
            "max": callgraph.get("max_edges"),
        },
        "cli_options": {
            "total": cli_options_payload.get("total_options"),
            "selected": cli_options_payload.get("selected_options"),
            "truncated": cli_options_payload.get("truncated"),
            "max": cli_options_payload.get("max_options"),
        },
        "cli_parse_loops": {
            "total": cli_parse_loops_payload.get("total_parse_loops"),
            "selected": cli_parse_loops_payload.get("selected_parse_loops"),
            "truncated": cli_parse_loops_payload.get("truncated"),
            "max": cli_parse_loops_payload.get("max_parse_loops"),
        },
        "modes_index": {
            "total": collected.modes_payload.get("total_modes"),
            "selected": collected.modes_payload.get("selected_modes"),
            "truncated": collected.modes_payload.get("truncated"),
            "max": collected.modes_payload.get("max_modes"),
        },
        "mode_dispatch_sites": {
            "total": collected.dispatch_sites_payload.get("total_dispatch_sites"),
            "selected": collected.dispatch_sites_payload.get("selected_dispatch_sites"),
            "truncated": collected.dispatch_sites_payload.get("truncated"),
            "max": collected.dispatch_sites_payload.get("max_dispatch_sites"),
        },
        "mode_slices": {
            "total": modes_slices_payload.get("total_modes"),
            "selected": modes_slices_payload.get("selected_slices"),
            "truncated": modes_slices_payload.get("truncated"),
            "max": modes_slices_payload.get("max_slices"),
        },
        "interfaces_env": {
            "total": collected.interfaces_payloads.get("env", {}).get("total_candidates"),
            "selected": len(collected.interfaces_payloads.get("env", {}).get("entries") or []),
            "truncated": collected.interfaces_payloads.get("env", {}).get("truncated"),
            "max": collected.interfaces_payloads.get("env", {}).get("max_entries"),
        },
        "interfaces_fs": {
            "total": collected.interfaces_payloads.get("fs", {}).get("total_candidates"),
            "selected": len(collected.interfaces_payloads.get("fs", {}).get("entries") or []),
            "truncated": collected.interfaces_payloads.get("fs", {}).get("truncated"),
            "max": collected.interfaces_payloads.get("fs", {}).get("max_entries"),
        },
        "interfaces_process": {
            "total": collected.interfaces_payloads.get("process", {}).get("total_candidates"),
            "selected": len(collected.interfaces_payloads.get("process", {}).get("entries") or []),
            "truncated": collected.interfaces_payloads.get("process", {}).get("truncated"),
            "max": collected.interfaces_payloads.get("process", {}).get("max_entries"),
        },
        "interfaces_net": {
            "total": collected.interfaces_payloads.get("net", {}).get("total_candidates"),
            "selected": len(collected.interfaces_payloads.get("net", {}).get("entries") or []),
            "truncated": collected.interfaces_payloads.get("net", {}).get("truncated"),
            "max": collected.interfaces_payloads.get("net", {}).get("max_entries"),
        },
        "interfaces_output": {
            "total": collected.interfaces_payloads.get("output", {}).get("total_candidates"),
            "selected": len(collected.interfaces_payloads.get("output", {}).get("entries") or []),
            "truncated": collected.interfaces_payloads.get("output", {}).get("truncated"),
            "max": collected.interfaces_payloads.get("output", {}).get("max_entries"),
        },
        "error_messages": {
            "total": collected.error_messages_payload.get("total_candidates"),
            "selected": collected.error_messages_payload.get("selected_messages"),
            "truncated": collected.error_messages_payload.get("truncated"),
            "max": collected.error_messages_payload.get("max_messages"),
        },
        "error_sites": {
            "total": collected.error_sites_payload.get("total_sites"),
            "selected": collected.error_sites_payload.get("selected_sites"),
            "truncated": collected.error_sites_payload.get("truncated"),
            "max": collected.error_sites_payload.get("max_sites"),
        },
        "exit_calls": {
            "total": collected.exit_paths_payload.get("total_exit_calls"),
            "selected": collected.exit_paths_payload.get("selected_exit_calls"),
            "truncated": collected.exit_paths_payload.get("truncated"),
            "max": collected.exit_paths_payload.get("max_exit_calls"),
        },
    }

    manifest = build_manifest(
        bounds,
        collected.hashes,
        BINARY_LENS_VERSION,
        FORMAT_VERSION,
        binary_info=collected.binary_info,
        coverage_summary=coverage_summary,
    )
    pack_index_payload = build_pack_index_payload(FORMAT_VERSION)
    pack_readme = build_pack_readme()
    pack_docs = build_pack_markdown_docs(
        pack_index=pack_index_payload,
        manifest=manifest,
        binary_info=collected.binary_info,
        modes=collected.modes_payload,
        interfaces_index=collected.interfaces_index_payload,
        interfaces=collected.interfaces_payloads,
        cli_options=cli_options_payload,
        error_messages=collected.error_messages_payload,
    )
    exported_function_ids = {
        addr
        for func in full_functions
        if (addr := addr_str(func.getEntryPoint())) is not None
    }
    contracts_payload, contract_docs = build_contract_views(
        collected.modes_payload,
        modes_slices_payload,
        cli_options_payload,
        cli_parse_loops_payload,
        collected.interfaces_payloads,
        collected.error_messages_payload,
        collected.error_sites_payload,
        collected.exit_paths_payload,
        collected.string_tags_by_id,
        collected.string_value_by_id,
        collected.string_refs_by_func,
        callgraph,
        collected.function_meta_by_addr,
        exported_function_ids,
        name_hints_source=bounds,
    )
    contracts_index, contracts_shards = build_sharded_list_index(
        contracts_payload,
        list_key="modes",
        shard_dir="contracts/index",
        item_id_key="mode_id",
        item_kind="mode_contracts",
    )

    return DerivedPayloads(
        full_functions=full_functions,
        calls_by_func=calls_by_func,
        callsite_evidence=callsite_evidence,
        cli_options_index=cli_options_index,
        cli_parse_loops_index=cli_parse_loops_index,
        modes_slices_index=modes_slices_index,
        strings_index=strings_index,
        callgraph_index=callgraph_index,
        error_messages_index=error_messages_index,
        exit_paths_index=exit_paths_index,
        error_sites_index=error_sites_index,
        interfaces_env_index=interfaces_env_index,
        interfaces_fs_index=interfaces_fs_index,
        interfaces_process_index=interfaces_process_index,
        interfaces_net_index=interfaces_net_index,
        interfaces_output_index=interfaces_output_index,
        functions_index=functions_index,
        contracts_index=contracts_index,
        cli_parse_loops_shards=cli_parse_loops_shards,
        modes_slices_shards=modes_slices_shards,
        strings_shards=strings_shards,
        callgraph_shards=callgraph_shards,
        cli_options_shards=cli_options_shards,
        error_messages_shards=error_messages_shards,
        exit_paths_shards=exit_paths_shards,
        error_sites_shards=error_sites_shards,
        interfaces_env_shards=interfaces_env_shards,
        interfaces_fs_shards=interfaces_fs_shards,
        interfaces_process_shards=interfaces_process_shards,
        interfaces_net_shards=interfaces_net_shards,
        interfaces_output_shards=interfaces_output_shards,
        contracts_shards=contracts_shards,
        functions_index_shards=functions_index_shards,
        pack_index_payload=pack_index_payload,
        manifest=manifest,
        pack_readme=pack_readme,
        pack_docs=pack_docs,
        contract_docs=contract_docs,
    )
