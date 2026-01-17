"""Bounds parsing and normalization for exporter limits."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

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

BOUND_KEYS = tuple(key for key, _default in BOUND_OPTION_DEFAULTS)
MANIFEST_BOUND_KEYS = tuple(key for key in BOUND_KEYS if key != "enable_mode_name_heuristics")
UNBOUNDED_KEYS = {
    "max_functions_index",
    "max_strings",
    "max_call_edges",
    "max_cli_options",
    "max_cli_parse_loops",
    "max_error_messages",
    "max_exit_paths",
    "max_error_sites",
    "max_modes",
    "max_mode_slices",
    "max_interface_env",
    "max_interface_fs",
    "max_interface_process",
    "max_interface_net",
    "max_interface_output",
}


def _parse_int(value: Any, default: int) -> int:
    if value is None:
        return default
    try:
        return int(value)
    except Exception:
        return default


@dataclass(frozen=True)
class Bounds:
    """Normalized exporter bounds with defaults and legacy option passthrough."""

    max_full_functions: int
    max_functions_index: int
    max_strings: int
    max_call_edges: int
    max_calls_per_function: int
    max_decomp_lines: int
    max_cli_options: int
    max_cli_parse_loops: int
    max_cli_option_evidence: int
    max_cli_parse_sites_per_option: int
    max_cli_longopt_entries: int
    max_cli_callsites_per_parse_loop: int
    max_cli_flag_vars: int
    max_cli_check_sites: int
    max_error_messages: int
    max_error_message_callsites: int
    max_error_message_functions: int
    max_exit_paths: int
    max_exit_patterns: int
    max_error_emitter_callsites: int
    max_error_sites: int
    max_error_site_callsites: int
    max_mode_dispatch_functions: int
    max_mode_callsites_per_function: int
    max_mode_tokens_per_callsite: int
    max_mode_token_length: int
    max_modes: int
    max_mode_dispatch_sites_per_mode: int
    max_mode_dispatch_roots_per_mode: int
    max_mode_dispatch_site_callsites: int
    max_mode_dispatch_site_tokens: int
    max_mode_dispatch_site_ignored_tokens: int
    max_mode_low_confidence_candidates: int
    max_mode_slices: int
    max_mode_slice_roots: int
    max_mode_slice_dispatch_sites: int
    max_mode_slice_options: int
    max_mode_slice_strings: int
    max_mode_slice_messages: int
    max_mode_slice_exit_paths: int
    max_mode_surface_entries: int
    enable_mode_name_heuristics: int
    max_interface_env: int
    max_interface_fs: int
    max_interface_process: int
    max_interface_net: int
    max_interface_output: int
    _extra: Mapping[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def from_options(cls, options: Mapping[str, Any] | None) -> Bounds:
        if isinstance(options, Bounds):
            return options
        options = options or {}
        values: dict[str, int] = {}
        for key, default in BOUND_OPTION_DEFAULTS:
            values[key] = _parse_int(options.get(key, default), default)

        max_index = values["max_functions_index"]
        if max_index and values["max_full_functions"] > max_index:
            values["max_functions_index"] = values["max_full_functions"]

        extra = {key: value for key, value in options.items() if key not in values}
        return cls(**values, _extra=extra)

    @classmethod
    def defaults(cls) -> Bounds:
        return cls.from_options({})

    def to_options(self) -> dict[str, int]:
        return {key: getattr(self, key) for key in BOUND_KEYS}

    def get(self, key: str, default: Any | None = None) -> Any | None:
        if key in BOUND_KEYS:
            return getattr(self, key)
        return self._extra.get(key, default)

    def optional(self, key: str) -> int | None:
        value = self.get(key)
        if key in UNBOUNDED_KEYS:
            try:
                return int(value) if int(value) > 0 else None
            except Exception:
                return None
        return value

    def as_manifest(self) -> dict[str, int | None]:
        return {
            key: (self.optional(key) if key in UNBOUNDED_KEYS else self.get(key))
            for key in MANIFEST_BOUND_KEYS
        }
