from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from export_config import (
    DEFAULT_DECOMPILE_TIMEOUT_SECONDS,
    DEFAULT_MAX_CALL_EDGES,
    DEFAULT_MAX_DECOMP_LINES,
    DEFAULT_MAX_FULL_FUNCTIONS,
    DEFAULT_MAX_STRINGS,
)

CONFIG_SCHEMA = {"name": "binary_lens_config", "version": "v1"}
REQUESTS_SCHEMA = {"name": "binary_lens_requests", "version": "v1"}
PLAN_SCHEMA = {"name": "binary_lens_export_plan", "version": "v1"}
EXPORT_SETTINGS_SCHEMA = {"name": "binary_lens_export_settings", "version": "v1"}
EXPORT_CONFIG_SCHEMA = {"name": "binary_lens_export_config", "version": "v1"}
EXPORT_EXPLAIN_SCHEMA = {"name": "binary_lens_export_explain", "version": "v1"}

_SPLIT_RE = re.compile(r"[,\s]+")


@dataclass(frozen=True)
class ExportSettings:
    requested: dict[str, Any]
    resolved: dict[str, Any]
    implied: list[dict[str, Any]]
    options: dict[str, Any]


def _normalize_bool(value: Any, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    if isinstance(value, (int, float)):
        return bool(value)
    lowered = str(value).strip().lower()
    if lowered in ("1", "true", "yes", "on"):
        return True
    if lowered in ("0", "false", "no", "off"):
        return False
    return default


def _normalize_int(value: Any, default: int | None) -> int | None:
    if value is None:
        return default
    try:
        return int(value)
    except Exception:
        return default


def _normalize_string(value: Any, default: str) -> str:
    if value is None:
        return default
    text = str(value).strip()
    return text


def _normalize_string_list(value: Any) -> list[str]:
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
        text = str(source).strip()
        if not text:
            continue
        items.extend(_SPLIT_RE.split(text))
    cleaned = [item for item in (item.strip() for item in items) if item]
    return sorted(set(cleaned))


def _ensure_schema(payload: Mapping[str, Any], expected: Mapping[str, str], label: str) -> None:
    schema = payload.get("schema")
    if not isinstance(schema, Mapping):
        raise ValueError(f"{label} missing schema")
    name = schema.get("name")
    version = schema.get("version")
    if name != expected.get("name") or version != expected.get("version"):
        raise ValueError(
            f"{label} schema mismatch: expected {expected.get('name')} {expected.get('version')}"
        )


def _ensure_keys(payload: Mapping[str, Any], allowed: set[str], label: str) -> None:
    extra = set(payload.keys()) - allowed
    if extra:
        raise ValueError(f"{label} has unknown keys: {', '.join(sorted(extra))}")


def default_settings() -> dict[str, Any]:
    return {
        "schema": dict(EXPORT_SETTINGS_SCHEMA),
        "artifacts": {
            "strings": True,
            "callgraph": True,
            "call_args": True,
            "evidence_decomp": True,
        },
        "budgets": {
            "max_full_functions": DEFAULT_MAX_FULL_FUNCTIONS,
            "max_strings": DEFAULT_MAX_STRINGS,
            "max_call_edges": DEFAULT_MAX_CALL_EDGES,
            "max_decomp_lines": DEFAULT_MAX_DECOMP_LINES,
        },
        "timeouts": {
            "decompile_seconds": DEFAULT_DECOMPILE_TIMEOUT_SECONDS,
        },
        "analysis_profile": "full",
        "profile": False,
        "evidence": {
            "decomp": {
                "include_name_regex": "",
                "include_function_ids": [],
            }
        },
        "call_args": {
            "targets": {
                "function_ids": [],
                "symbol_names": [],
            },
            "max_callsites": None,
        },
    }


def normalize_settings(payload: Mapping[str, Any]) -> dict[str, Any]:
    defaults = default_settings()
    normalized = {
        "schema": dict(EXPORT_SETTINGS_SCHEMA),
        "artifacts": dict(defaults["artifacts"]),
        "budgets": dict(defaults["budgets"]),
        "timeouts": dict(defaults["timeouts"]),
        "analysis_profile": defaults["analysis_profile"],
        "profile": defaults["profile"],
        "evidence": {
            "decomp": dict(defaults["evidence"]["decomp"]),
        },
        "call_args": {
            "targets": dict(defaults["call_args"]["targets"]),
            "max_callsites": defaults["call_args"]["max_callsites"],
        },
    }

    if not isinstance(payload, Mapping):
        return normalized

    artifacts = payload.get("artifacts")
    if isinstance(artifacts, Mapping):
        for key in normalized["artifacts"]:
            if key in artifacts:
                normalized["artifacts"][key] = _normalize_bool(
                    artifacts.get(key), normalized["artifacts"][key]
                )

    budgets = payload.get("budgets")
    if isinstance(budgets, Mapping):
        for key in normalized["budgets"]:
            if key in budgets:
                normalized["budgets"][key] = _normalize_int(
                    budgets.get(key), normalized["budgets"][key]
                )

    timeouts = payload.get("timeouts")
    if isinstance(timeouts, Mapping):
        if "decompile_seconds" in timeouts:
            normalized["timeouts"]["decompile_seconds"] = _normalize_int(
                timeouts.get("decompile_seconds"),
                normalized["timeouts"]["decompile_seconds"],
            )

    if "analysis_profile" in payload:
        normalized["analysis_profile"] = _normalize_string(
            payload.get("analysis_profile"),
            normalized["analysis_profile"],
        )
    if "profile" in payload:
        normalized["profile"] = _normalize_bool(
            payload.get("profile"),
            normalized["profile"],
        )

    evidence = payload.get("evidence")
    if isinstance(evidence, Mapping):
        decomp = evidence.get("decomp")
        if isinstance(decomp, Mapping):
            if "include_name_regex" in decomp:
                normalized["evidence"]["decomp"]["include_name_regex"] = _normalize_string(
                    decomp.get("include_name_regex"),
                    normalized["evidence"]["decomp"]["include_name_regex"],
                )
            if "include_function_ids" in decomp:
                normalized["evidence"]["decomp"]["include_function_ids"] = _normalize_string_list(
                    decomp.get("include_function_ids")
                )

    call_args = payload.get("call_args")
    if isinstance(call_args, Mapping):
        targets = call_args.get("targets")
        if isinstance(targets, Mapping):
            if "function_ids" in targets:
                normalized["call_args"]["targets"]["function_ids"] = _normalize_string_list(
                    targets.get("function_ids")
                )
            if "symbol_names" in targets:
                normalized["call_args"]["targets"]["symbol_names"] = _normalize_string_list(
                    targets.get("symbol_names")
                )
        if "max_callsites" in call_args:
            normalized["call_args"]["max_callsites"] = _normalize_int(
                call_args.get("max_callsites"), normalized["call_args"]["max_callsites"]
            )
    return normalized


def parse_config(payload: Mapping[str, Any]) -> dict[str, Any]:
    _ensure_schema(payload, CONFIG_SCHEMA, "config")
    _ensure_keys(
        payload,
        {"schema", "artifacts", "budgets", "timeouts", "advanced"},
        "config",
    )
    advanced = payload.get("advanced")
    if advanced is not None and not isinstance(advanced, Mapping):
        raise ValueError("config.advanced must be an object")
    if isinstance(advanced, Mapping):
        _ensure_keys(advanced, {"analysis_profile", "profile", "evidence", "call_args"}, "config.advanced")
    artifacts = payload.get("artifacts")
    budgets = payload.get("budgets")
    timeouts = payload.get("timeouts")
    if artifacts is not None and not isinstance(artifacts, Mapping):
        raise ValueError("config.artifacts must be an object")
    if budgets is not None and not isinstance(budgets, Mapping):
        raise ValueError("config.budgets must be an object")
    if timeouts is not None and not isinstance(timeouts, Mapping):
        raise ValueError("config.timeouts must be an object")

    evidence = advanced.get("evidence") if isinstance(advanced, Mapping) else None
    call_args = advanced.get("call_args") if isinstance(advanced, Mapping) else None
    analysis_profile = advanced.get("analysis_profile") if isinstance(advanced, Mapping) else None
    profile = advanced.get("profile") if isinstance(advanced, Mapping) else None

    if evidence is not None and not isinstance(evidence, Mapping):
        raise ValueError("config.advanced.evidence must be an object")
    if call_args is not None and not isinstance(call_args, Mapping):
        raise ValueError("config.advanced.call_args must be an object")
    overlay: dict[str, Any] = {}
    if isinstance(artifacts, Mapping):
        overlay["artifacts"] = {
            key: _normalize_bool(artifacts.get(key), True)
            for key in ("strings", "callgraph", "call_args", "evidence_decomp")
            if key in artifacts
        }
    if isinstance(budgets, Mapping):
        overlay["budgets"] = {
            key: _normalize_int(budgets.get(key), None)
            for key in ("max_full_functions", "max_strings", "max_call_edges", "max_decomp_lines")
            if key in budgets
        }
    if isinstance(timeouts, Mapping) and "decompile_seconds" in timeouts:
        overlay["timeouts"] = {
            "decompile_seconds": _normalize_int(timeouts.get("decompile_seconds"), None)
        }
    if analysis_profile is not None:
        overlay["analysis_profile"] = _normalize_string(analysis_profile, "full")
    if profile is not None:
        overlay["profile"] = _normalize_bool(profile, False)
    if isinstance(evidence, Mapping):
        _ensure_keys(evidence, {"decomp"}, "config.advanced.evidence")
        decomp = evidence.get("decomp")
        if decomp is not None and not isinstance(decomp, Mapping):
            raise ValueError("config.advanced.evidence.decomp must be an object")
        if isinstance(decomp, Mapping):
            _ensure_keys(
                decomp,
                {"include_name_regex", "include_function_ids"},
                "config.advanced.evidence.decomp",
            )
            overlay["evidence"] = {
                "decomp": {
                    key: (
                        _normalize_string(decomp.get(key), "")
                        if key == "include_name_regex"
                        else _normalize_string_list(decomp.get(key))
                    )
                    for key in ("include_name_regex", "include_function_ids")
                    if key in decomp
                }
            }
    if isinstance(call_args, Mapping):
        _ensure_keys(call_args, {"targets", "max_callsites"}, "config.advanced.call_args")
        targets = call_args.get("targets")
        if targets is not None and not isinstance(targets, Mapping):
            raise ValueError("config.advanced.call_args.targets must be an object")
        if isinstance(targets, Mapping):
            _ensure_keys(targets, {"function_ids", "symbol_names"}, "config.advanced.call_args.targets")
        call_args_overlay: dict[str, Any] = {}
        if isinstance(targets, Mapping):
            target_overlay = {}
            if "function_ids" in targets:
                target_overlay["function_ids"] = _normalize_string_list(targets.get("function_ids"))
            if "symbol_names" in targets:
                target_overlay["symbol_names"] = _normalize_string_list(targets.get("symbol_names"))
            if target_overlay:
                call_args_overlay["targets"] = target_overlay
        if "max_callsites" in call_args:
            call_args_overlay["max_callsites"] = _normalize_int(call_args.get("max_callsites"), None)
        if call_args_overlay:
            overlay["call_args"] = call_args_overlay
    return overlay


def parse_requests(payload: Mapping[str, Any]) -> dict[str, Any]:
    _ensure_schema(payload, REQUESTS_SCHEMA, "requests")
    _ensure_keys(payload, {"schema", "evidence", "call_args"}, "requests")
    evidence = payload.get("evidence")
    call_args = payload.get("call_args")
    if evidence is not None and not isinstance(evidence, Mapping):
        raise ValueError("requests.evidence must be an object")
    if call_args is not None and not isinstance(call_args, Mapping):
        raise ValueError("requests.call_args must be an object")
    overlay: dict[str, Any] = {"schema": dict(REQUESTS_SCHEMA)}
    if isinstance(evidence, Mapping):
        _ensure_keys(evidence, {"decomp"}, "requests.evidence")
        decomp = evidence.get("decomp")
        if decomp is not None and not isinstance(decomp, Mapping):
            raise ValueError("requests.evidence.decomp must be an object")
        if isinstance(decomp, Mapping):
            _ensure_keys(decomp, {"include_function_ids"}, "requests.evidence.decomp")
            overlay["evidence"] = {
                "decomp": {
                    "include_function_ids": _normalize_string_list(
                        decomp.get("include_function_ids")
                    )
                }
            }
    if isinstance(call_args, Mapping):
        _ensure_keys(call_args, {"targets", "max_callsites"}, "requests.call_args")
        targets = call_args.get("targets")
        if targets is not None and not isinstance(targets, Mapping):
            raise ValueError("requests.call_args.targets must be an object")
        if isinstance(targets, Mapping):
            _ensure_keys(targets, {"function_ids", "symbol_names"}, "requests.call_args.targets")
        call_args_overlay: dict[str, Any] = {}
        if isinstance(targets, Mapping):
            target_overlay = {}
            if "function_ids" in targets:
                target_overlay["function_ids"] = _normalize_string_list(targets.get("function_ids"))
            if "symbol_names" in targets:
                target_overlay["symbol_names"] = _normalize_string_list(targets.get("symbol_names"))
            if target_overlay:
                call_args_overlay["targets"] = target_overlay
        if "max_callsites" in call_args:
            call_args_overlay["max_callsites"] = _normalize_int(call_args.get("max_callsites"), None)
        if call_args_overlay:
            overlay["call_args"] = call_args_overlay
    return overlay


def parse_export_plan(payload: Mapping[str, Any]) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    _ensure_schema(payload, PLAN_SCHEMA, "export_plan")
    _ensure_keys(payload, {"schema", "config", "requests"}, "export_plan")
    config_payload = payload.get("config")
    requests_payload = payload.get("requests")
    config = None
    requests = None
    if isinstance(config_payload, Mapping):
        config = parse_config(config_payload)
    elif config_payload is not None:
        raise ValueError("export_plan.config must be an object")
    if isinstance(requests_payload, Mapping):
        requests = parse_requests(requests_payload)
    elif requests_payload is not None:
        raise ValueError("export_plan.requests must be an object")
    return config, requests


def _merge_requests(base: dict[str, Any], requests: dict[str, Any]) -> dict[str, Any]:
    merged = normalize_settings(base)
    evidence = requests.get("evidence", {}) if isinstance(requests, Mapping) else {}
    call_args = requests.get("call_args", {}) if isinstance(requests, Mapping) else {}

    decomp = evidence.get("decomp") if isinstance(evidence, Mapping) else None
    if isinstance(decomp, Mapping):
        func_ids = _normalize_string_list(decomp.get("include_function_ids"))
        if func_ids:
            merged_ids = set(merged["evidence"]["decomp"]["include_function_ids"])
            merged_ids.update(func_ids)
            merged["evidence"]["decomp"]["include_function_ids"] = sorted(merged_ids)

    targets = call_args.get("targets") if isinstance(call_args, Mapping) else None
    if isinstance(targets, Mapping):
        func_ids = _normalize_string_list(targets.get("function_ids"))
        if func_ids:
            merged_ids = set(merged["call_args"]["targets"]["function_ids"])
            merged_ids.update(func_ids)
            merged["call_args"]["targets"]["function_ids"] = sorted(merged_ids)
        names = _normalize_string_list(targets.get("symbol_names"))
        if names:
            merged_names = set(merged["call_args"]["targets"]["symbol_names"])
            merged_names.update(names)
            merged["call_args"]["targets"]["symbol_names"] = sorted(merged_names)
    if isinstance(call_args, Mapping) and "max_callsites" in call_args:
        requested_max = _normalize_int(call_args.get("max_callsites"), None)
        current_max = merged["call_args"]["max_callsites"]
        if requested_max is not None and (current_max is None or requested_max > current_max):
            merged["call_args"]["max_callsites"] = requested_max
    return merged


def _merge_overrides(base: dict[str, Any], overrides: dict[str, Any]) -> dict[str, Any]:
    merged = normalize_settings(base)
    if not isinstance(overrides, Mapping) or not overrides:
        return merged

    def _merge_section(current: Mapping[str, Any], update: Mapping[str, Any]) -> dict[str, Any]:
        merged_section = dict(current)
        for sub_key, sub_value in update.items():
            if isinstance(sub_value, Mapping) and isinstance(merged_section.get(sub_key), Mapping):
                nested = dict(merged_section.get(sub_key) or {})
                nested.update(sub_value)
                merged_section[sub_key] = nested
            else:
                merged_section[sub_key] = sub_value
        return merged_section

    for key in ("artifacts", "budgets", "timeouts", "evidence", "call_args"):
        section = overrides.get(key)
        if isinstance(section, Mapping):
            current = merged.get(key, {}) if isinstance(merged.get(key), Mapping) else {}
            merged[key] = _merge_section(current, section)
    if "analysis_profile" in overrides:
        merged["analysis_profile"] = overrides["analysis_profile"]
    if "profile" in overrides:
        merged["profile"] = overrides["profile"]
    return merged


def _apply_dependencies(settings: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    resolved = normalize_settings(settings)
    implied: list[dict[str, Any]] = []

    def _set(path: str, current: bool, desired: bool, reason: str) -> bool:
        if current == desired:
            return current
        implied.append({"setting": path, "from": current, "to": desired, "reason": reason})
        return desired

    evidence = resolved["evidence"]["decomp"]
    evidence_requested = bool(
        evidence.get("include_function_ids") or evidence.get("include_name_regex")
    )
    if evidence_requested:
        resolved["artifacts"]["evidence_decomp"] = _set(
            "artifacts.evidence_decomp",
            resolved["artifacts"]["evidence_decomp"],
            True,
            "evidence_requested",
        )

    call_args = resolved["call_args"]
    call_args_requested = bool(
        call_args.get("max_callsites")
        or call_args.get("targets", {}).get("function_ids")
        or call_args.get("targets", {}).get("symbol_names")
    )
    if call_args_requested:
        resolved["artifacts"]["call_args"] = _set(
            "artifacts.call_args",
            resolved["artifacts"]["call_args"],
            True,
            "call_args_requested",
        )
    if resolved["artifacts"]["call_args"]:
        resolved["artifacts"]["callgraph"] = _set(
            "artifacts.callgraph",
            resolved["artifacts"]["callgraph"],
            True,
            "call_args_dependency",
        )

    return resolved, implied


def resolve_settings(
    *,
    config: Mapping[str, Any] | None = None,
    requests: Mapping[str, Any] | None = None,
    plan: Mapping[str, Any] | None = None,
    cli_overrides: Mapping[str, Any] | None = None,
    base_settings: Mapping[str, Any] | None = None,
) -> ExportSettings:
    base = normalize_settings(base_settings or {})
    requested = normalize_settings(base)

    if plan:
        config_from_plan, requests_from_plan = parse_export_plan(plan)
        if config_from_plan:
            requested = _merge_overrides(requested, config_from_plan)
        if requests_from_plan:
            requested = _merge_requests(requested, requests_from_plan)

    if config:
        requested = _merge_overrides(requested, parse_config(config))
    if requests:
        requested = _merge_requests(requested, parse_requests(requests))
    if cli_overrides:
        requested = _merge_overrides(requested, cli_overrides)

    resolved, implied = _apply_dependencies(requested)
    options = build_options(resolved)
    return ExportSettings(
        requested=requested,
        resolved=resolved,
        implied=implied,
        options=options,
    )


def build_options(settings: Mapping[str, Any]) -> dict[str, Any]:
    normalized = normalize_settings(settings)
    evidence = normalized["evidence"]["decomp"]
    return {
        "profile": 1 if normalized["profile"] else 0,
        "analysis_profile": normalized["analysis_profile"],
        "evidence_include_name_regex": evidence.get("include_name_regex") or "",
        "evidence_include_function_ids": evidence.get("include_function_ids") or [],
        "max_full_functions": normalized["budgets"]["max_full_functions"],
        "max_strings": normalized["budgets"]["max_strings"],
        "max_call_edges": normalized["budgets"]["max_call_edges"],
        "max_decomp_lines": normalized["budgets"]["max_decomp_lines"],
        "artifact_strings": normalized["artifacts"]["strings"],
        "artifact_callgraph": normalized["artifacts"]["callgraph"],
        "artifact_call_args": normalized["artifacts"]["call_args"],
        "artifact_evidence_decomp": normalized["artifacts"]["evidence_decomp"],
        "call_args_targets": normalized["call_args"]["targets"],
        "call_args_max_callsites": normalized["call_args"]["max_callsites"],
        "decompile_timeout_seconds": normalized["timeouts"]["decompile_seconds"],
    }


def load_json_file(path: str | Path) -> dict[str, Any]:
    payload = json.loads(Path(path).read_text())
    if not isinstance(payload, dict):
        raise ValueError(f"JSON file is not an object: {path}")
    return payload


def parse_legacy_kv_pairs(pairs: list[str]) -> tuple[dict[str, Any], list[str]]:
    overrides: dict[str, Any] = {}
    unknown: list[str] = []
    for pair in pairs:
        if "=" not in pair:
            continue
        key, value = pair.split("=", 1)
        key = key.strip()
        if key in (
            "max_full_functions",
            "max_strings",
            "max_call_edges",
            "max_decomp_lines",
        ):
            overrides.setdefault("budgets", {})[key] = _normalize_int(value, None)
        elif key in (
            "artifact_strings",
            "artifact_callgraph",
            "artifact_call_args",
            "artifact_evidence_decomp",
        ):
            artifacts = overrides.setdefault("artifacts", {})
            artifacts[key.replace("artifact_", "")] = _normalize_bool(value, True)
        elif key == "analysis_profile":
            overrides["analysis_profile"] = _normalize_string(value, "full")
        elif key == "profile":
            overrides["profile"] = _normalize_bool(value, False)
        elif key == "evidence_include_name_regex":
            overrides.setdefault("evidence", {}).setdefault("decomp", {})[
                "include_name_regex"
            ] = _normalize_string(value, "")
        elif key == "evidence_include_function_ids":
            overrides.setdefault("evidence", {}).setdefault("decomp", {})[
                "include_function_ids"
            ] = _normalize_string_list(value)
        elif key == "decompile_timeout_seconds":
            overrides.setdefault("timeouts", {})["decompile_seconds"] = _normalize_int(value, None)
        else:
            unknown.append(key)
    return overrides, unknown


def build_export_explain_payload(settings: ExportSettings) -> dict[str, Any]:
    payload = {
        "schema": dict(EXPORT_EXPLAIN_SCHEMA),
        "requested": settings.requested,
        "resolved": settings.resolved,
        "implied": settings.implied,
    }
    return payload


def build_export_config_digest(
    resolved_settings: Mapping[str, Any],
    *,
    binary_hashes: Mapping[str, Any] | None,
    ghidra_version: str | None,
    tool_info: Mapping[str, Any] | None,
) -> str:
    payload = {
        "resolved_settings": normalize_settings(resolved_settings),
        "binary_hashes": dict(binary_hashes or {}),
        "ghidra_version": ghidra_version,
        "tool": dict(tool_info or {}),
    }
    normalized = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def build_export_config_payload(
    requested: Mapping[str, Any] | None,
    resolved: Mapping[str, Any] | None,
) -> dict[str, Any] | None:
    if not isinstance(requested, Mapping) and not isinstance(resolved, Mapping):
        return None
    payload: dict[str, Any] = {
        "schema": dict(EXPORT_CONFIG_SCHEMA),
    }
    if isinstance(requested, Mapping):
        payload["requested"] = normalize_settings(requested)
    if isinstance(resolved, Mapping):
        payload["resolved"] = normalize_settings(resolved)
    return payload


def build_export_config_record(
    requested: Mapping[str, Any] | None,
    resolved: Mapping[str, Any] | None,
    *,
    binary_hashes: Mapping[str, Any] | None,
    ghidra_version: str | None,
    tool_info: Mapping[str, Any] | None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    export_payload = build_export_config_payload(requested, resolved)
    if export_payload:
        payload["export_config"] = export_payload
    if isinstance(resolved, Mapping):
        payload["export_config_digest"] = build_export_config_digest(
            resolved,
            binary_hashes=binary_hashes,
            ghidra_version=ghidra_version,
            tool_info=tool_info,
        )
    return payload


def load_pack_base_settings(pack_root: str | Path) -> dict[str, Any] | None:
    manifest_path = Path(pack_root) / "manifest.json"
    if not manifest_path.is_file():
        return None
    try:
        payload = json.loads(manifest_path.read_text())
    except Exception:
        return None
    if not isinstance(payload, Mapping):
        return None
    export_config = payload.get("export_config")
    if not isinstance(export_config, Mapping):
        return None
    resolved = export_config.get("resolved")
    if isinstance(resolved, Mapping):
        return normalize_settings(resolved)
    requested = export_config.get("requested")
    if isinstance(requested, Mapping):
        return normalize_settings(requested)
    return None
