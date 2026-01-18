"""Interface surface extraction and payload construction."""

from __future__ import annotations

from typing import Any

from collectors.call_args import extract_call_args_for_callsites
from collectors.callsites import collect_callsite_matches
from export_bounds import Bounds
from export_config import FORMAT_VERSION
from export_primitives import addr_to_int
from interfaces.common import (
    const_value_for_index,
    string_candidates_for_index,
    unknown_value,
)
from interfaces.definitions import SURFACE_ORDER, SURFACE_SPECS, OperationSpec
from symbols import IMPORT_SYMBOL_POLICY, build_alias_map, match_signal, normalize_symbol_name

SURFACE_MAX_KEYS = {
    "env": "max_interface_env",
    "fs": "max_interface_fs",
    "process": "max_interface_process",
    "net": "max_interface_net",
    "output": "max_interface_output",
}

CHK_INSERTION_INDEX = {
    "printf": 0,
    "vprintf": 0,
    "fprintf": 1,
    "vfprintf": 1,
    "dprintf": 1,
    "vdprintf": 1,
}

XSTAT_VARIANTS = {
    "xstat",
    "xstat64",
    "lxstat",
    "lxstat64",
}


def _callee_base_name(callee_name: str | None) -> str | None:
    if not callee_name:
        return None
    return callee_name.split("@", 1)[0].lstrip("_").lower() or None


def _operation_matcher(operations, aliases):
    name_map = {}
    for name in operations:
        normalized = normalize_symbol_name(name, policy=IMPORT_SYMBOL_POLICY)
        if normalized:
            name_map[normalized] = name
    alias_map = build_alias_map(aliases, policy=IMPORT_SYMBOL_POLICY) if aliases else {}

    def _match(name):
        return match_signal(
            name,
            name_map=name_map,
            alias_map=alias_map,
            policy=IMPORT_SYMBOL_POLICY,
            allow_substring=False,
        )

    return _match


def _select_matches(call_edges, function_meta_by_addr, operations, aliases):
    matcher = _operation_matcher(operations, aliases)
    matches, _matches_by_func = collect_callsite_matches(
        call_edges,
        function_meta_by_addr,
        matcher,
        require_external=False,
    )
    matches.sort(key=lambda item: addr_to_int(item.callsite_id))
    return matches


def _shift_index(index: int | None, shift_from: int, shift_by: int) -> int | None:
    if index is None:
        return None
    if index >= shift_from:
        return index + shift_by
    return index


def _shift_spec(spec: OperationSpec, shift_from: int, shift_by: int) -> OperationSpec:
    return OperationSpec(
        name=spec.name,
        string_arg_indices=tuple(
            _shift_index(idx, shift_from, shift_by) for idx in spec.string_arg_indices
        ),
        var_arg_index=_shift_index(spec.var_arg_index, shift_from, shift_by),
        flags_arg_index=_shift_index(spec.flags_arg_index, shift_from, shift_by),
        mode_arg_index=_shift_index(spec.mode_arg_index, shift_from, shift_by),
        fd_arg_index=_shift_index(spec.fd_arg_index, shift_from, shift_by),
        stream_arg_index=_shift_index(spec.stream_arg_index, shift_from, shift_by),
        channel_kind=spec.channel_kind,
        port_arg_index=_shift_index(spec.port_arg_index, shift_from, shift_by),
    )


def _apply_chk_shift(spec: OperationSpec, callee_base: str | None) -> OperationSpec:
    if not callee_base or not callee_base.endswith("_chk"):
        return spec
    shift_from = CHK_INSERTION_INDEX.get(callee_base[:-4])
    if shift_from is None:
        return spec
    return _shift_spec(spec, shift_from, 1)


def _apply_xstat_shift(surface: str, spec: OperationSpec, callee_base: str | None) -> OperationSpec:
    if surface != "fs" or callee_base not in XSTAT_VARIANTS:
        return spec
    # __xstat/__lxstat insert a leading version arg.
    return _shift_spec(spec, 0, 1)


def _adjust_spec_for_callee(surface: str, spec: OperationSpec, callee_name: str | None) -> OperationSpec:
    callee_base = _callee_base_name(callee_name)
    spec = _apply_chk_shift(spec, callee_base)
    return _apply_xstat_shift(surface, spec, callee_base)


def _build_string_list(
    args: dict[str, Any],
    indices: tuple[int, ...],
    string_addr_map_all: dict[str, str] | None,
) -> tuple[list[dict[str, Any]], bool]:
    values: list[dict[str, Any]] = []
    used_arg = False
    if indices:
        for index in indices:
            candidates = string_candidates_for_index(args, index, string_addr_map_all)
            if candidates:
                values.extend(candidates)
                used_arg = True
            else:
                values.append(unknown_value())
    else:
        values.append(unknown_value())
    return values, used_arg


def _build_single_string(
    args: dict[str, Any],
    index: int | None,
    string_addr_map_all: dict[str, str] | None,
) -> tuple[dict[str, Any], bool]:
    if index is None:
        return unknown_value(), False
    candidates = string_candidates_for_index(args, index, string_addr_map_all)
    if candidates:
        return candidates[0], True
    return unknown_value(), False


def _port_value(
    args: dict[str, Any],
    index: int | None,
    string_addr_map_all: dict[str, str] | None,
) -> tuple[dict[str, Any], bool]:
    if index is None:
        return {"status": "unknown"}, False
    const_entry, used_const = const_value_for_index(args, index)
    if used_const:
        return const_entry, True
    for entry in string_candidates_for_index(args, index, string_addr_map_all):
        value = entry.get("value")
        if isinstance(value, str) and value.isdigit():
            try:
                return (
                    {
                        "status": "known",
                        "value": int(value),
                        "arg_index": index,
                    },
                    True,
                )
            except Exception:
                continue
    return {"status": "unknown"}, False


def _channel_from_fixed_kind(spec: OperationSpec) -> tuple[dict[str, Any], bool] | None:
    if spec.channel_kind in ("stdout", "stderr"):
        return {"status": "known", "kind": spec.channel_kind}, False
    return None


def _channel_from_stream_arg(spec: OperationSpec, args: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    if spec.stream_arg_index is None:
        return {"status": "unknown", "kind": "unknown"}, False
    symbol_args = args.get("symbol_args_by_index", {}) or {}
    entries = symbol_args.get(spec.stream_arg_index, []) or []
    for entry in entries:
        name = entry.get("name")
        if not name:
            continue
        lowered = name.lower()
        if "stderr" in lowered:
            return {"status": "known", "kind": "stderr"}, True
        if "stdout" in lowered:
            return {"status": "known", "kind": "stdout"}, True
    return {"status": "unknown", "kind": "unknown"}, False


def _channel_from_fd_arg(spec: OperationSpec, args: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    const_args = args.get("const_args_by_index", {}) or {}
    if spec.fd_arg_index not in const_args:
        return {"status": "unknown", "kind": "unknown"}, False
    fd_value = const_args.get(spec.fd_arg_index)
    if fd_value == 1:
        return {"status": "known", "kind": "stdout", "fd": fd_value}, True
    if fd_value == 2:
        return {"status": "known", "kind": "stderr", "fd": fd_value}, True
    return {"status": "known", "kind": "fd", "fd": fd_value}, True


def _channel_value(spec: OperationSpec, args: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    fixed = _channel_from_fixed_kind(spec)
    if fixed is not None:
        return fixed
    if spec.fd_arg_index is None:
        return _channel_from_stream_arg(spec, args)
    return _channel_from_fd_arg(spec, args)


def _build_entry(
    surface: str,
    spec,
    match,
    args: dict[str, Any],
    string_addr_map_all: dict[str, str] | None,
) -> tuple[dict[str, Any], bool]:
    spec = _adjust_spec_for_callee(surface, spec, match.callee_name)
    has_known_arg = False
    entry: dict[str, Any] = {
        "callsite_id": match.callsite_id,
        "function_id": match.function_id,
        "callee": {
            "name": match.callee_name,
            "normalized_name": match.callee_normalized,
        },
        "operation": spec.name,
        "arg_recovery_status": args.get("status") or "unknown",
    }

    if surface == "env":
        var_entry, used_arg = _build_single_string(
            args, spec.var_arg_index, string_addr_map_all
        )
        entry["var"] = var_entry
        has_known_arg = used_arg
    elif surface == "fs":
        paths, used_paths = _build_string_list(
            args, spec.string_arg_indices, string_addr_map_all
        )
        if spec.flags_arg_index is None:
            flags, used_flags = {"status": "unknown"}, False
        else:
            flags, used_flags = const_value_for_index(args, spec.flags_arg_index)
        if spec.mode_arg_index is None:
            mode, used_mode = {"status": "unknown"}, False
        else:
            mode, used_mode = const_value_for_index(args, spec.mode_arg_index)
        entry["paths"] = paths
        entry["flags"] = flags
        entry["mode"] = mode
        has_known_arg = used_paths or used_flags or used_mode
    elif surface == "process":
        commands, used_commands = _build_string_list(
            args, spec.string_arg_indices, string_addr_map_all
        )
        entry["commands"] = commands
        has_known_arg = used_commands
    elif surface == "net":
        hosts, used_hosts = _build_string_list(
            args, spec.string_arg_indices, string_addr_map_all
        )
        port, used_port = _port_value(args, spec.port_arg_index, string_addr_map_all)
        entry["hosts"] = hosts
        entry["ports"] = port
        has_known_arg = used_hosts or used_port
    elif surface == "output":
        templates, used_templates = _build_string_list(
            args, spec.string_arg_indices, string_addr_map_all
        )
        channel, used_channel = _channel_value(spec, args)
        entry["templates"] = templates
        entry["channel"] = channel
        has_known_arg = used_templates or used_channel
    else:
        entry["details"] = {}

    return entry, has_known_arg


def _resolve_call_args(
    program,
    callsite_ids,
    monitor,
    call_args_cache,
    purpose: str,
):
    if call_args_cache is None:
        call_args_cache = {}
    missing = [callsite_id for callsite_id in callsite_ids if callsite_id not in call_args_cache]
    if missing:
        call_args_cache.update(
            extract_call_args_for_callsites(
                program,
                missing,
                monitor,
                purpose=purpose,
            )
        )
    return call_args_cache


def _surface_payload(entries, total_candidates: int, max_entries: int | None) -> dict[str, Any]:
    truncated = False
    selected = entries
    if max_entries is not None and max_entries >= 0:
        if len(selected) > max_entries:
            selected = selected[:max_entries]
            truncated = True
        elif total_candidates > max_entries:
            truncated = True
    return {
        "schema_version": FORMAT_VERSION,
        "max_entries": max_entries,
        "total_candidates": total_candidates,
        "truncated": truncated,
        "entries": selected,
    }


def collect_interfaces(
    program,
    call_edges,
    function_meta_by_addr,
    string_addr_map_all,
    bounds: Bounds,
    monitor=None,
    *,
    call_args_cache=None,
):
    if call_args_cache is None:
        call_args_cache = {}
    surfaces = {}
    all_callsite_ids = []
    for surface in SURFACE_ORDER:
        operations, aliases = SURFACE_SPECS[surface]
        matches = _select_matches(call_edges, function_meta_by_addr, operations, aliases)
        total_candidates = len(matches)
        max_key = SURFACE_MAX_KEYS.get(surface, "")
        max_entries = bounds.optional(max_key) if max_key else None

        selected = matches if max_entries is None else matches[:max_entries]
        callsite_ids = [match.callsite_id for match in selected]
        if callsite_ids:
            call_args_cache = _resolve_call_args(
                program,
                callsite_ids,
                monitor,
                call_args_cache,
                purpose=f"interfaces.collect.{surface}",
            )
        entries = []
        for match in selected:
            spec = operations.get(match.match_key)
            if spec is None:
                continue
            args = (call_args_cache or {}).get(match.callsite_id, {}) or {}
            entry, _has_known = _build_entry(
                surface,
                spec,
                match,
                args,
                string_addr_map_all,
            )
            entries.append(entry)
        entries.sort(
            key=lambda item: (
                addr_to_int(item.get("callsite_id")),
                item.get("operation") or "",
            )
        )
        surfaces[surface] = _surface_payload(entries, total_candidates, max_entries)
        all_callsite_ids.extend(callsite_ids)
    all_callsite_ids = sorted(set(all_callsite_ids), key=addr_to_int)
    return surfaces, all_callsite_ids, call_args_cache


def build_interfaces_index_payload(surfaces: dict[str, dict[str, Any]]) -> dict[str, Any]:
    entries = []
    for name in SURFACE_ORDER:
        payload = surfaces.get(name, {})
        max_entries = payload.get("max_entries")
        if isinstance(max_entries, bool):
            max_entries = None
        entries.append(
            {
                "name": name,
                "path": f"interfaces/{name}.json",
                "entry_count": len(payload.get("entries") or []),
                "total_candidates": payload.get("total_candidates", 0),
                "truncated": payload.get("truncated", False),
                "max_entries": max_entries,
            }
        )
    return {
        "schema_version": FORMAT_VERSION,
        "surfaces": entries,
    }


def attach_interface_callsite_refs(surfaces: dict[str, dict[str, Any]], callsites_ref: str) -> None:
    if not callsites_ref:
        return
    for payload in surfaces.values():
        if isinstance(payload, dict):
            payload["callsites_ref"] = callsites_ref
