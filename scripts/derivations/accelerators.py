"""Derived helpers for callsite argument observations."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from export_primitives import addr_to_int
from utils.text import as_str, string_ref_status


def _string_id_for_address(
    address: str | None,
    string_addr_map_all: Mapping[str, str] | None,
    selected_string_ids: set[str] | None,
) -> str | None:
    if not address or not string_addr_map_all:
        return None
    string_id = string_addr_map_all.get(address)
    if not string_id:
        return None
    if selected_string_ids is not None and string_id not in selected_string_ids:
        return None
    return string_id


def _arg_index(value: Any) -> int | None:
    if isinstance(value, int):
        return value
    return None


def _build_call_arg_observations(
    args: Mapping[str, Any],
    string_addr_map_all: Mapping[str, str] | None,
    selected_string_ids: set[str] | None,
) -> list[dict[str, Any]]:
    observations: list[dict[str, Any]] = []

    for entry in args.get("string_args", []) or []:
        if not isinstance(entry, Mapping):
            continue
        address = as_str(entry.get("address"))
        value = entry.get("value")
        string_id = _string_id_for_address(address, string_addr_map_all, selected_string_ids)
        status = string_ref_status(string_id, address, value=value)
        source = as_str(entry.get("source"))
        basis = f"string_{source}" if source else "string_direct"
        obs = {
            "kind": "string",
            "index": _arg_index(entry.get("index")),
            "status": status,
            "basis": basis,
        }
        if string_id:
            obs["string_id"] = string_id
        else:
            if address:
                obs["address"] = address
            if value is not None:
                obs["value"] = value
        provider_callsite_id = as_str(entry.get("provider_callsite_id"))
        if provider_callsite_id:
            obs["provider_callsite_id"] = provider_callsite_id
        observations.append(obs)

    const_args = args.get("const_args_by_index") or {}
    if isinstance(const_args, Mapping):
        for index, value in const_args.items():
            obs = {
                "kind": "int",
                "index": _arg_index(index),
                "status": "known" if isinstance(value, int) else "unknown",
                "basis": "const_int",
            }
            if isinstance(value, int):
                obs["value"] = value
            observations.append(obs)

    data_args = args.get("data_args_by_index") or {}
    if isinstance(data_args, Mapping):
        for index, values in data_args.items():
            if not isinstance(values, list):
                continue
            for addr in values:
                address = as_str(addr)
                if not address:
                    continue
                observations.append(
                    {
                        "kind": "address",
                        "index": _arg_index(index),
                        "status": "known",
                        "basis": "data_address",
                        "address": address,
                    }
                )

    symbol_args = args.get("symbol_args_by_index") or {}
    if isinstance(symbol_args, Mapping):
        for index, values in symbol_args.items():
            if not isinstance(values, list):
                continue
            for entry in values:
                if not isinstance(entry, Mapping):
                    continue
                name = as_str(entry.get("name"))
                address = as_str(entry.get("address"))
                if not name and not address:
                    continue
                obs = {
                    "kind": "symbol",
                    "index": _arg_index(index),
                    "status": "known" if (name or address) else "unknown",
                    "basis": "symbol",
                }
                if name:
                    obs["name"] = name
                if address:
                    obs["address"] = address
                observations.append(obs)

    def _obs_sort_key(obs: Mapping[str, Any]) -> tuple[int, str, int, str]:
        idx = obs.get("index")
        idx_key = idx if isinstance(idx, int) else 1_000_000
        kind = as_str(obs.get("kind")) or ""
        if kind in ("string", "address"):
            addr = as_str(obs.get("address")) or as_str(obs.get("string_id")) or ""
            return (idx_key, kind, addr_to_int(addr), addr)
        if kind == "int":
            value = obs.get("value")
            return (idx_key, kind, value if isinstance(value, int) else -1, "")
        name = as_str(obs.get("name")) or ""
        return (idx_key, kind, -1, name)

    observations.sort(key=_obs_sort_key)
    return observations


def build_callsites_by_id(
    callsite_records: Mapping[str, Any],
    *,
    call_args_by_callsite: Mapping[str, Any] | None = None,
    string_addr_map_all: Mapping[str, str] | None = None,
    selected_string_ids: set[str] | None = None,
) -> dict[str, Any]:
    def _addr_from_entry(entry: Any) -> str | None:
        if isinstance(entry, Mapping):
            return as_str(entry.get("address"))
        return as_str(entry)

    mapping: dict[str, Any] = {}
    if not isinstance(callsite_records, Mapping):
        return mapping
    for callsite_key, record in callsite_records.items():
        if not isinstance(record, Mapping):
            continue
        callsite_id = as_str(record.get("callsite")) or as_str(callsite_key)
        if not callsite_id:
            continue
        from_addr = _addr_from_entry(record.get("from"))
        targets = record.get("targets")
        target_set: set[str] = set()
        if isinstance(targets, list):
            for target in targets:
                addr = _addr_from_entry(target)
                if addr:
                    target_set.add(addr)
        mapping[callsite_id] = {
            "from": from_addr,
            "targets": sorted(target_set, key=addr_to_int),
        }

    if isinstance(call_args_by_callsite, Mapping):
        for callsite_id, args in call_args_by_callsite.items():
            callsite_key = as_str(callsite_id)
            if not callsite_key or not isinstance(args, Mapping):
                continue
            record = mapping.get(callsite_key)
            if record is None:
                record = {"from": None, "targets": []}
                mapping[callsite_key] = record
            status = as_str(args.get("status"))
            observations = _build_call_arg_observations(
                args,
                string_addr_map_all,
                selected_string_ids,
            )
            if status:
                record["arg_recovery_status"] = status
            if status or observations:
                record["arg_observations"] = observations
    return mapping
