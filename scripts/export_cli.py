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

from export_config import (
    DEFAULT_ENABLE_MODE_NAME_HEURISTICS,
    DEFAULT_MAX_CALL_EDGES,
    DEFAULT_MAX_CALLS_PER_FUNCTION,
    DEFAULT_MAX_CLI_CALLSITES_PER_PARSE_LOOP,
    DEFAULT_MAX_CLI_CHECK_SITES,
    DEFAULT_MAX_CLI_FLAG_VARS,
    DEFAULT_MAX_CLI_LONGOPT_ENTRIES,
    DEFAULT_MAX_CLI_OPTION_EVIDENCE,
    DEFAULT_MAX_CLI_OPTIONS,
    DEFAULT_MAX_CLI_PARSE_LOOPS,
    DEFAULT_MAX_CLI_PARSE_SITES_PER_OPTION,
    DEFAULT_MAX_DECOMP_LINES,
    DEFAULT_MAX_ERROR_EMITTER_CALLSITES,
    DEFAULT_MAX_ERROR_MESSAGE_CALLSITES,
    DEFAULT_MAX_ERROR_MESSAGE_FUNCTIONS,
    DEFAULT_MAX_ERROR_MESSAGES,
    DEFAULT_MAX_ERROR_SITE_CALLSITES,
    DEFAULT_MAX_ERROR_SITES,
    DEFAULT_MAX_EXIT_PATHS,
    DEFAULT_MAX_EXIT_PATTERNS,
    DEFAULT_MAX_FULL_FUNCTIONS,
    DEFAULT_MAX_FUNCTIONS_INDEX,
    DEFAULT_MAX_INTERFACE_ENV,
    DEFAULT_MAX_INTERFACE_FS,
    DEFAULT_MAX_INTERFACE_NET,
    DEFAULT_MAX_INTERFACE_OUTPUT,
    DEFAULT_MAX_INTERFACE_PROCESS,
    DEFAULT_MAX_MODE_CALLSITES_PER_FUNCTION,
    DEFAULT_MAX_MODE_DISPATCH_FUNCTIONS,
    DEFAULT_MAX_MODE_DISPATCH_ROOTS_PER_MODE,
    DEFAULT_MAX_MODE_DISPATCH_SITE_CALLSITES,
    DEFAULT_MAX_MODE_DISPATCH_SITE_IGNORED_TOKENS,
    DEFAULT_MAX_MODE_DISPATCH_SITE_TOKENS,
    DEFAULT_MAX_MODE_DISPATCH_SITES_PER_MODE,
    DEFAULT_MAX_MODE_LOW_CONFIDENCE_CANDIDATES,
    DEFAULT_MAX_MODE_SLICE_DISPATCH_SITES,
    DEFAULT_MAX_MODE_SLICE_EXIT_PATHS,
    DEFAULT_MAX_MODE_SLICE_MESSAGES,
    DEFAULT_MAX_MODE_SLICE_OPTIONS,
    DEFAULT_MAX_MODE_SLICE_ROOTS,
    DEFAULT_MAX_MODE_SLICE_STRINGS,
    DEFAULT_MAX_MODE_SLICES,
    DEFAULT_MAX_MODE_SURFACE_ENTRIES,
    DEFAULT_MAX_MODE_TOKEN_LENGTH,
    DEFAULT_MAX_MODE_TOKENS_PER_CALLSITE,
    DEFAULT_MAX_MODES,
    DEFAULT_MAX_STRINGS,
)

BOUND_OPTION_DEFAULTS: tuple[tuple[str, int], ...] = (
    ("max_full_functions", DEFAULT_MAX_FULL_FUNCTIONS),
    ("max_functions_index", DEFAULT_MAX_FUNCTIONS_INDEX),
    ("max_strings", DEFAULT_MAX_STRINGS),
    ("max_call_edges", DEFAULT_MAX_CALL_EDGES),
    ("max_calls_per_function", DEFAULT_MAX_CALLS_PER_FUNCTION),
    ("max_decomp_lines", DEFAULT_MAX_DECOMP_LINES),
    ("max_cli_options", DEFAULT_MAX_CLI_OPTIONS),
    ("max_cli_parse_loops", DEFAULT_MAX_CLI_PARSE_LOOPS),
    ("max_cli_option_evidence", DEFAULT_MAX_CLI_OPTION_EVIDENCE),
    ("max_cli_parse_sites_per_option", DEFAULT_MAX_CLI_PARSE_SITES_PER_OPTION),
    ("max_cli_longopt_entries", DEFAULT_MAX_CLI_LONGOPT_ENTRIES),
    ("max_cli_callsites_per_parse_loop", DEFAULT_MAX_CLI_CALLSITES_PER_PARSE_LOOP),
    ("max_cli_flag_vars", DEFAULT_MAX_CLI_FLAG_VARS),
    ("max_cli_check_sites", DEFAULT_MAX_CLI_CHECK_SITES),
    ("max_error_messages", DEFAULT_MAX_ERROR_MESSAGES),
    ("max_error_message_callsites", DEFAULT_MAX_ERROR_MESSAGE_CALLSITES),
    ("max_error_message_functions", DEFAULT_MAX_ERROR_MESSAGE_FUNCTIONS),
    ("max_exit_paths", DEFAULT_MAX_EXIT_PATHS),
    ("max_exit_patterns", DEFAULT_MAX_EXIT_PATTERNS),
    ("max_error_emitter_callsites", DEFAULT_MAX_ERROR_EMITTER_CALLSITES),
    ("max_error_sites", DEFAULT_MAX_ERROR_SITES),
    ("max_error_site_callsites", DEFAULT_MAX_ERROR_SITE_CALLSITES),
    ("max_mode_dispatch_functions", DEFAULT_MAX_MODE_DISPATCH_FUNCTIONS),
    ("max_mode_callsites_per_function", DEFAULT_MAX_MODE_CALLSITES_PER_FUNCTION),
    ("max_mode_tokens_per_callsite", DEFAULT_MAX_MODE_TOKENS_PER_CALLSITE),
    ("max_mode_token_length", DEFAULT_MAX_MODE_TOKEN_LENGTH),
    ("max_modes", DEFAULT_MAX_MODES),
    ("max_mode_dispatch_sites_per_mode", DEFAULT_MAX_MODE_DISPATCH_SITES_PER_MODE),
    ("max_mode_dispatch_roots_per_mode", DEFAULT_MAX_MODE_DISPATCH_ROOTS_PER_MODE),
    ("max_mode_dispatch_site_callsites", DEFAULT_MAX_MODE_DISPATCH_SITE_CALLSITES),
    ("max_mode_dispatch_site_tokens", DEFAULT_MAX_MODE_DISPATCH_SITE_TOKENS),
    ("max_mode_dispatch_site_ignored_tokens", DEFAULT_MAX_MODE_DISPATCH_SITE_IGNORED_TOKENS),
    ("max_mode_low_confidence_candidates", DEFAULT_MAX_MODE_LOW_CONFIDENCE_CANDIDATES),
    ("max_mode_slices", DEFAULT_MAX_MODE_SLICES),
    ("max_mode_slice_roots", DEFAULT_MAX_MODE_SLICE_ROOTS),
    ("max_mode_slice_dispatch_sites", DEFAULT_MAX_MODE_SLICE_DISPATCH_SITES),
    ("max_mode_slice_options", DEFAULT_MAX_MODE_SLICE_OPTIONS),
    ("max_mode_slice_strings", DEFAULT_MAX_MODE_SLICE_STRINGS),
    ("max_mode_slice_messages", DEFAULT_MAX_MODE_SLICE_MESSAGES),
    ("max_mode_slice_exit_paths", DEFAULT_MAX_MODE_SLICE_EXIT_PATHS),
    ("max_mode_surface_entries", DEFAULT_MAX_MODE_SURFACE_ENTRIES),
    ("enable_mode_name_heuristics", DEFAULT_ENABLE_MODE_NAME_HEURISTICS),
    ("max_interface_env", DEFAULT_MAX_INTERFACE_ENV),
    ("max_interface_fs", DEFAULT_MAX_INTERFACE_FS),
    ("max_interface_process", DEFAULT_MAX_INTERFACE_PROCESS),
    ("max_interface_net", DEFAULT_MAX_INTERFACE_NET),
    ("max_interface_output", DEFAULT_MAX_INTERFACE_OUTPUT),
)


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

    # Ensure the index always includes all fully exported functions.
    if options["max_full_functions"] > options["max_functions_index"]:
        options["max_functions_index"] = options["max_full_functions"]

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
