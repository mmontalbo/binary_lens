from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class CollectedData:
    """Raw collection outputs used by later derivation and writing stages."""

    binary_info: dict[str, Any]
    hashes: dict[str, Any]
    imports: list[dict[str, Any]]
    strings: list[dict[str, Any]]
    selected_string_ids: set[str]
    string_value_by_id: dict[str, Any]
    total_strings: int
    strings_truncated: bool
    string_addr_map_all: dict[str, Any]
    string_tags_by_id: dict[str, Any]
    string_bucket_counts: dict[str, Any]
    string_bucket_limits: dict[str, Any]
    functions: list[Any]
    function_meta_by_addr: dict[str, Any]
    string_refs_by_func: dict[str, set[str]]
    call_edges_all: list[dict[str, Any]]
    callsite_records: dict[str, Any]
    call_edge_stats: dict[str, Any]
    cli_inputs: Any
    error_messages_payload: dict[str, Any]
    exit_paths_payload: dict[str, Any]
    error_sites_payload: dict[str, Any]
    error_callsite_ids: list[str]
    interfaces_payloads: dict[str, Any]
    interfaces_index_payload: dict[str, Any]
    interface_callsite_ids: list[str]
    modes_payload: dict[str, Any]
    dispatch_sites_payload: dict[str, Any]
    mode_callsite_ids: list[str]


@dataclass
class DerivedPayloads:
    """Derived payloads and shards ready for writing."""

    full_functions: list[Any]
    calls_by_func: dict[str, Any]
    callsites_index: dict[str, Any]
    callsites_shards: dict[str, Any]
    cli_options_index: dict[str, Any]
    cli_parse_loops_index: dict[str, Any]
    modes_slices_index: dict[str, Any]
    strings_index: dict[str, Any]
    callgraph_index: dict[str, Any]
    callgraph_nodes_index: dict[str, Any]
    error_messages_index: dict[str, Any]
    exit_paths_index: dict[str, Any]
    error_sites_index: dict[str, Any]
    interfaces_env_index: dict[str, Any]
    interfaces_fs_index: dict[str, Any]
    interfaces_process_index: dict[str, Any]
    interfaces_net_index: dict[str, Any]
    interfaces_output_index: dict[str, Any]
    functions_index: dict[str, Any]
    contracts_index: dict[str, Any]
    cli_parse_loops_shards: dict[str, Any]
    modes_slices_shards: dict[str, Any]
    strings_shards: dict[str, Any]
    callgraph_shards: dict[str, Any]
    callgraph_nodes_shards: dict[str, Any]
    cli_options_shards: dict[str, Any]
    error_messages_shards: dict[str, Any]
    exit_paths_shards: dict[str, Any]
    error_sites_shards: dict[str, Any]
    interfaces_env_shards: dict[str, Any]
    interfaces_fs_shards: dict[str, Any]
    interfaces_process_shards: dict[str, Any]
    interfaces_net_shards: dict[str, Any]
    interfaces_output_shards: dict[str, Any]
    contracts_shards: dict[str, Any]
    functions_index_shards: dict[str, Any]
    pack_index_payload: dict[str, Any]
    manifest: dict[str, Any]
    pack_readme: str
    pack_docs: dict[str, str]
    contract_docs: dict[str, str]
