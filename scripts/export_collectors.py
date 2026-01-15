"""Collector entrypoint shim.

Historically, `export_collectors.py` hosted most collection logic (callgraph,
strings, CLI surfaces, callsite argument recovery, etc.). To reduce cognitive
overhead, the implementation has been split into `scripts/collectors/`.

This module intentionally preserves the original import path used by:
- `scripts/binary_lens_export.py` (Ghidra script entrypoint)
- other export subsystems that import collector helpers directly
"""

from collectors.call_args import extract_call_args, extract_call_args_for_callsites
from collectors.callgraph import (
    build_function_import_sets,
    build_function_meta,
    build_function_metrics,
    build_signal_set,
    collect_call_edges,
    collect_flow_summary,
    collect_function_calls,
    collect_functions,
    function_size,
    is_jump_instruction,
    resolve_callee_function,
    select_call_edges,
    select_full_functions,
    select_index_functions,
    summarize_functions,
)
from collectors.cli import (
    CLI_COMPARE_MNEMONICS,
    CLI_COMPARE_SIGNAL_NAMES,
    CLI_PARSE_SIGNAL_NAMES,
    _classify_check_site,
    _is_compare_callee,
    _is_probable_longopt_name,
    build_cli_compare_details,
    build_cli_parse_details,
    collect_cli_option_compare_sites,
    collect_cli_parse_sites,
    collect_flag_check_sites,
    decode_longopt_table,
    decode_short_opt_string,
    normalize_symbol_names,
    parse_option_token,
)
from collectors.ghidra_memory import (
    _align_offset,
    _read_c_string,
    _read_int,
    _read_ptr,
    _read_ptr_with_reloc,
    _resolve_string_at,
    _to_address,
)
from collectors.imports import collect_imports
from collectors.pcode import _resolve_varnode_addr, _resolve_varnode_constant, _varnode_key
from collectors.strings import (
    ENV_VAR_RE,
    classify_string_value,
    collect_function_string_refs,
    collect_string_refs_by_func,
    collect_strings,
    is_env_var_string,
    is_path_like,
    is_printf_format_string,
    is_usage_marker,
)

__all__ = [
    "CLI_COMPARE_MNEMONICS",
    "CLI_COMPARE_SIGNAL_NAMES",
    "CLI_PARSE_SIGNAL_NAMES",
    "ENV_VAR_RE",
    "_align_offset",
    "_classify_check_site",
    "_is_compare_callee",
    "_is_probable_longopt_name",
    "_read_c_string",
    "_read_int",
    "_read_ptr",
    "_read_ptr_with_reloc",
    "_resolve_string_at",
    "_resolve_varnode_addr",
    "_resolve_varnode_constant",
    "_to_address",
    "_varnode_key",
    "build_cli_compare_details",
    "build_cli_parse_details",
    "build_function_import_sets",
    "build_function_meta",
    "build_function_metrics",
    "build_signal_set",
    "classify_string_value",
    "collect_call_edges",
    "collect_cli_option_compare_sites",
    "collect_cli_parse_sites",
    "collect_flag_check_sites",
    "collect_flow_summary",
    "collect_function_calls",
    "collect_function_string_refs",
    "collect_functions",
    "collect_imports",
    "collect_string_refs_by_func",
    "collect_strings",
    "decode_longopt_table",
    "decode_short_opt_string",
    "extract_call_args",
    "extract_call_args_for_callsites",
    "function_size",
    "is_env_var_string",
    "is_jump_instruction",
    "is_path_like",
    "is_printf_format_string",
    "is_usage_marker",
    "normalize_symbol_names",
    "parse_option_token",
    "resolve_callee_function",
    "select_call_edges",
    "select_full_functions",
    "select_index_functions",
    "summarize_functions",
]

