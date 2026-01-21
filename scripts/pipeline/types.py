from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class FactTable:
    """Parquet fact table definition for pack format v2."""

    name: str
    rows: list[dict[str, Any]]
    primary_key: list[str]
    schema: list[tuple[str, str]]
    version: str = "v1"
    description: str | None = None


@dataclass
class CollectedData:
    """Raw collection outputs used by later derivation and writing stages."""

    binary_info: dict[str, Any]
    hashes: dict[str, Any]
    strings: list[dict[str, Any]]
    selected_string_ids: set[str]
    string_value_by_id: dict[str, Any]
    total_strings: int
    strings_truncated: bool
    string_addr_map_all: dict[str, Any]
    string_tags_by_id: dict[str, Any]
    functions: list[Any]
    function_meta_by_addr: dict[str, Any]
    string_refs_by_func: dict[str, set[str]]
    call_edges_all: list[dict[str, Any]]
    callsite_records: dict[str, Any]
    call_args_by_callsite: dict[str, Any]


@dataclass
class DerivedPayloads:
    """Derived payloads ready for writing (pack format v2)."""

    full_functions: list[Any]
    facts: list[FactTable]
    pack_index_payload: dict[str, Any]
    manifest: dict[str, Any]
    evidence_hints: dict[str, Any] | None = None
