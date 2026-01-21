"""Argument parsing helpers for the Ghidra exporter script.

Ghidra scripts receive a flat list of strings. The exporter keeps parsing logic
lightweight by supporting:
- `-h/--help` to print usage
- a positional output directory
- `key=value` overrides for export bounds
"""

from __future__ import annotations

import os
from typing import Any

from export_bounds import BOUND_OPTION_DEFAULTS, Bounds


def _default_options() -> dict[str, Any]:
    options: dict[str, Any] = {
        "profile": 0,
        "analysis_profile": "full",
    }
    for key, default in BOUND_OPTION_DEFAULTS:
        options[key] = default
    return options


def parse_args(args: list[str]) -> tuple[str | None, dict[str, Any], bool]:
    options = _default_options()
    out_dir: str | None = None
    show_help = False

    for arg in args:
        if arg in ("-h", "--help"):
            show_help = True
            continue
        # Accept key=value overrides to keep headless invocation simple.
        if "=" in arg:
            key, value = arg.split("=", 1)
            if key == "out_dir":
                out_dir = value
                continue
            if key == "profile":
                try:
                    options[key] = int(value)
                except Exception:
                    lowered = (value or "").strip().lower()
                    options[key] = 1 if lowered in ("1", "true", "yes", "on") else 0
                continue
            if key == "analysis_profile":
                options[key] = (value or "").strip() or "full"
                continue
            if key in options:
                try:
                    options[key] = int(value)
                except Exception:
                    print("Invalid value for %s: %s" % (key, value))
            else:
                print("Unknown option: %s" % key)
        else:
            if out_dir is None:
                out_dir = arg

    bounds = Bounds.from_options(options)
    options.update(bounds.to_options())
    return out_dir, options, show_help


def print_usage():
    print("Binary Lens exporter")
    print("Usage:")
    print("  <script> <out_dir> [key=value ...]")
    print("Options:")
    print("  profile=0|1")
    print("  analysis_profile=full|minimal|none")
    for key, default in BOUND_OPTION_DEFAULTS:
        print("  %s=%d" % (key, default))


def resolve_pack_root(out_dir: str) -> str:
    if out_dir.endswith(".lens") or out_dir.endswith("binary.lens"):
        return out_dir
    return os.path.join(out_dir, "binary.lens")
