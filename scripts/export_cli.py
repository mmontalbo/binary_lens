"""Argument parsing helpers for the Ghidra exporter script.

Ghidra scripts receive a flat list of strings. The exporter keeps parsing logic
lightweight by supporting:
- `-h/--help` to print usage
- a positional output directory
- `key=value` overrides for export bounds
- JSON config/request/plan inputs for structured exports
"""

from __future__ import annotations

import os
from pathlib import Path

from export_bounds import BOUND_OPTION_DEFAULTS, Bounds
from export_settings import (
    ExportSettings,
    load_json_file,
    load_pack_base_settings,
    parse_legacy_kv_pairs,
    resolve_settings,
)


def _resolve_pack_root(path: str) -> str:
    candidate = Path(path)
    if candidate.is_dir():
        if (candidate / "manifest.json").is_file():
            return str(candidate)
        nested = candidate / "binary.lens"
        if (nested / "manifest.json").is_file():
            return str(nested)
    return path


def parse_args(args: list[str]) -> tuple[str | None, ExportSettings | None, bool, bool]:
    legacy_pairs: list[str] = []
    out_dir: str | None = None
    show_help = False
    explain = False
    config_path: str | None = None
    requests_path: str | None = None
    plan_path: str | None = None
    from_pack: str | None = None

    idx = 0
    while idx < len(args):
        arg = args[idx]
        idx += 1
        if arg in ("-h", "--help"):
            show_help = True
            continue
        if arg in ("--explain", "--dry-run"):
            explain = True
            continue
        if arg in ("--config", "--requests", "--plan", "--from-pack", "--binary"):
            if idx >= len(args):
                print("Missing value for %s" % arg)
                show_help = True
                break
            value = args[idx]
            idx += 1
            if arg == "--config":
                config_path = value
            elif arg == "--requests":
                requests_path = value
            elif arg == "--plan":
                plan_path = value
            elif arg == "--from-pack":
                from_pack = value
            continue
        if arg == "--in-place":
            continue
        if arg.startswith("--config="):
            config_path = arg.split("=", 1)[1]
            continue
        if arg.startswith("--requests="):
            requests_path = arg.split("=", 1)[1]
            continue
        if arg.startswith("--plan="):
            plan_path = arg.split("=", 1)[1]
            continue
        if arg.startswith("--from-pack="):
            from_pack = arg.split("=", 1)[1]
            continue
        if "=" in arg:
            key, value = arg.split("=", 1)
            if key == "out_dir":
                out_dir = value
                continue
            legacy_pairs.append(arg)
            continue
        if out_dir is None:
            out_dir = arg

    if show_help:
        return out_dir, None, show_help, explain

    cli_overrides, unknown = parse_legacy_kv_pairs(legacy_pairs)
    for key in unknown:
        print("Unknown option: %s" % key)

    config_payload = None
    requests_payload = None
    plan_payload = None
    try:
        if config_path:
            config_payload = load_json_file(config_path)
        if requests_path:
            requests_payload = load_json_file(requests_path)
        if plan_path:
            plan_payload = load_json_file(plan_path)
    except Exception as exc:
        print("Failed to read config inputs: %s" % exc)
        raise SystemExit(1)

    base_settings = None
    if from_pack:
        base_settings = load_pack_base_settings(_resolve_pack_root(from_pack))

    try:
        settings = resolve_settings(
            config=config_payload,
            requests=requests_payload,
            plan=plan_payload,
            cli_overrides=cli_overrides,
            base_settings=base_settings,
        )
    except Exception as exc:
        print("Failed to resolve export settings: %s" % exc)
        raise SystemExit(1)
    bounds = Bounds.from_options(settings.options)
    settings.options.update(bounds.to_options())
    return out_dir, settings, show_help, explain


def print_usage():
    print("Binary Lens exporter")
    print("Usage:")
    print("  <script> <out_dir> [options] [key=value ...]")
    print("Options:")
    print("  profile=0|1")
    print("  analysis_profile=full|minimal|none")
    print("  evidence_include_name_regex=<regex>")
    print("  evidence_include_function_ids=<addr>[,<addr>...]")
    print("  artifact_strings=0|1")
    print("  artifact_callgraph=0|1")
    print("  artifact_call_args=0|1")
    print("  artifact_evidence_decomp=0|1")
    print("  decompile_timeout_seconds=<int>")
    print("  --config <config.json>")
    print("  --requests <requests.json>")
    print("  --plan <export_plan.json>")
    print("  --from-pack <pack_root>")
    print("  --explain | --dry-run")
    for key, default in BOUND_OPTION_DEFAULTS:
        print("  %s=%d" % (key, default))


def resolve_pack_root(out_dir: str) -> str:
    if out_dir.endswith(".lens") or out_dir.endswith("binary.lens"):
        return out_dir
    return os.path.join(out_dir, "binary.lens")
