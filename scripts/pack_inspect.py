from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from export_settings import EXPORT_SETTINGS_SCHEMA, normalize_settings

CAPABILITY_SCHEMA = {"name": "binary_lens_pack_capabilities", "version": "v1"}
REASON_ENUM = {
    "disabled",
    "dependency_disabled",
    "budget_exhausted",
    "not_supported",
    "error",
}


def _read_json(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text())
    except Exception:
        return None
    if isinstance(payload, dict):
        return payload
    return None


def _table_counts(pack_summary: Mapping[str, Any] | None) -> dict[str, int]:
    counts: dict[str, int] = {}
    if not isinstance(pack_summary, Mapping):
        return counts
    facts = pack_summary.get("facts")
    if not isinstance(facts, Mapping):
        return counts
    tables = facts.get("tables")
    if not isinstance(tables, list):
        return counts
    for entry in tables:
        if not isinstance(entry, Mapping):
            continue
        name = entry.get("name")
        row_count = entry.get("row_count")
        if isinstance(name, str) and isinstance(row_count, int):
            counts[name] = row_count
    return counts


def _artifact_reason(
    *,
    enabled: bool,
    requested: bool | None,
    present: bool,
    budget_zero: bool,
) -> str | None:
    if present:
        return None
    if not enabled:
        if requested:
            return "dependency_disabled"
        return "disabled"
    if budget_zero:
        return "budget_exhausted"
    return "not_supported"


def _export_settings_from_manifest(manifest: Mapping[str, Any] | None) -> dict[str, Any]:
    if not isinstance(manifest, Mapping):
        return {"schema": dict(EXPORT_SETTINGS_SCHEMA)}
    export_config = manifest.get("export_config")
    if not isinstance(export_config, Mapping):
        return {"schema": dict(EXPORT_SETTINGS_SCHEMA)}
    resolved = export_config.get("resolved")
    if isinstance(resolved, Mapping):
        return normalize_settings(resolved)
    return {"schema": dict(EXPORT_SETTINGS_SCHEMA)}


def _requested_settings_from_manifest(manifest: Mapping[str, Any] | None) -> dict[str, Any]:
    if not isinstance(manifest, Mapping):
        return {"schema": dict(EXPORT_SETTINGS_SCHEMA)}
    export_config = manifest.get("export_config")
    if not isinstance(export_config, Mapping):
        return {"schema": dict(EXPORT_SETTINGS_SCHEMA)}
    requested = export_config.get("requested")
    if isinstance(requested, Mapping):
        return normalize_settings(requested)
    return {"schema": dict(EXPORT_SETTINGS_SCHEMA)}


def build_capability_report(pack_root: Path) -> dict[str, Any]:
    manifest = _read_json(pack_root / "manifest.json")
    pack_summary = _read_json(pack_root / "pack_summary.json")
    binary_name = None
    format_version = None
    export_config_digest = None
    if isinstance(manifest, Mapping):
        name = manifest.get("binary_name")
        if isinstance(name, str) and name.strip():
            binary_name = name.strip()
        fmt = manifest.get("format_version")
        if isinstance(fmt, str) and fmt.strip():
            format_version = fmt.strip()
        export_config_digest = manifest.get("export_config_digest")
        if not export_config_digest:
            export_config = manifest.get("export_config")
            if isinstance(export_config, Mapping):
                export_config_digest = export_config.get("export_config_digest")
    bounds = {}
    if isinstance(manifest, Mapping):
        bounds = manifest.get("bounds") or {}
    coverage = {}
    if isinstance(manifest, Mapping):
        coverage = manifest.get("coverage_summary") or {}
    table_counts = _table_counts(pack_summary)

    resolved = _export_settings_from_manifest(manifest)
    requested = _requested_settings_from_manifest(manifest)

    artifacts = {}

    strings_count = table_counts.get("strings", 0)
    strings_budget = bounds.get("max_strings")
    strings_enabled = bool(resolved.get("artifacts", {}).get("strings", True))
    strings_requested = requested.get("artifacts", {}).get("strings")
    strings_present = bool(strings_enabled and strings_count > 0)
    strings_truncated = bool((coverage.get("strings") or {}).get("truncated"))
    artifacts["strings"] = {
        "present": strings_present,
        "reason_missing": _artifact_reason(
            enabled=strings_enabled,
            requested=bool(strings_requested) if strings_requested is not None else None,
            present=strings_present,
            budget_zero=strings_budget == 0,
        ),
        "bounded": strings_budget is not None,
        "truncated": strings_truncated,
        "budget_used": {
            "selected": strings_count,
            "max": strings_budget,
        },
    }

    call_edges_count = table_counts.get("call_edges", 0)
    call_edges_budget = bounds.get("max_call_edges")
    callgraph_enabled = bool(resolved.get("artifacts", {}).get("callgraph", True))
    callgraph_requested = requested.get("artifacts", {}).get("callgraph")
    callgraph_present = bool(callgraph_enabled and call_edges_count > 0)
    callgraph_truncated = bool((coverage.get("callgraph_edges") or {}).get("truncated"))
    artifacts["callgraph"] = {
        "present": callgraph_present,
        "reason_missing": _artifact_reason(
            enabled=callgraph_enabled,
            requested=bool(callgraph_requested) if callgraph_requested is not None else None,
            present=callgraph_present,
            budget_zero=call_edges_budget == 0,
        ),
        "bounded": call_edges_budget is not None,
        "truncated": callgraph_truncated,
        "budget_used": {
            "selected": call_edges_count,
            "max": call_edges_budget,
        },
    }

    call_args_count = table_counts.get("callsite_arg_observations", 0)
    call_args_budget = resolved.get("call_args", {}).get("max_callsites")
    call_args_enabled = bool(resolved.get("artifacts", {}).get("call_args", True))
    call_args_requested = requested.get("artifacts", {}).get("call_args")
    call_args_present = bool(call_args_enabled and call_args_count > 0)
    call_args_truncated = bool(
        call_args_budget is not None and call_args_count >= int(call_args_budget)
    )
    artifacts["call_args"] = {
        "present": call_args_present,
        "reason_missing": _artifact_reason(
            enabled=call_args_enabled,
            requested=bool(call_args_requested) if call_args_requested is not None else None,
            present=call_args_present,
            budget_zero=call_args_budget == 0,
        ),
        "bounded": call_args_budget is not None,
        "truncated": call_args_truncated,
        "budget_used": {
            "observations": call_args_count,
            "max_callsites": call_args_budget,
        },
    }

    evidence_summary = pack_summary.get("evidence") if isinstance(pack_summary, Mapping) else {}
    evidence_entries = 0
    evidence_truncated = False
    if isinstance(evidence_summary, Mapping):
        evidence_entries = evidence_summary.get("entry_count") or 0
        evidence_truncated = bool(evidence_summary.get("has_truncated_entries"))
    evidence_enabled = bool(resolved.get("artifacts", {}).get("evidence_decomp", True))
    evidence_requested = requested.get("artifacts", {}).get("evidence_decomp")
    evidence_present = bool(evidence_enabled and evidence_entries > 0)
    max_full_functions = bounds.get("max_full_functions")
    max_decomp_lines = bounds.get("max_decomp_lines")
    full_funcs = coverage.get("full_functions") or {}
    full_funcs_selected = full_funcs.get("selected") if isinstance(full_funcs, Mapping) else None
    artifacts["evidence_decomp"] = {
        "present": evidence_present,
        "reason_missing": _artifact_reason(
            enabled=evidence_enabled,
            requested=bool(evidence_requested) if evidence_requested is not None else None,
            present=evidence_present,
            budget_zero=(max_full_functions == 0),
        ),
        "bounded": True,
        "truncated": evidence_truncated or bool(full_funcs.get("truncated")),
        "budget_used": {
            "functions": full_funcs_selected,
            "max_functions": max_full_functions,
            "max_decomp_lines": max_decomp_lines,
            "entries": evidence_entries,
        },
    }

    return {
        "schema": dict(CAPABILITY_SCHEMA),
        "pack_root": str(pack_root),
        "manifest_ref": "manifest.json",
        "binary_name": binary_name,
        "format_version": format_version,
        "export_config_digest": export_config_digest,
        "binary_hashes": manifest.get("binary_hashes") if isinstance(manifest, Mapping) else None,
        "artifacts": artifacts,
    }
