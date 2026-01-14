import os

from export_config import (
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


def parse_args(args):
    options = {
        "profile": 0,
        "analysis_profile": "full",
        "max_full_functions": DEFAULT_MAX_FULL_FUNCTIONS,
        "max_functions_index": DEFAULT_MAX_FUNCTIONS_INDEX,
        "max_strings": DEFAULT_MAX_STRINGS,
        "max_call_edges": DEFAULT_MAX_CALL_EDGES,
        "max_calls_per_function": DEFAULT_MAX_CALLS_PER_FUNCTION,
        "max_decomp_lines": DEFAULT_MAX_DECOMP_LINES,
        "max_cli_options": DEFAULT_MAX_CLI_OPTIONS,
        "max_cli_parse_loops": DEFAULT_MAX_CLI_PARSE_LOOPS,
        "max_cli_option_evidence": DEFAULT_MAX_CLI_OPTION_EVIDENCE,
        "max_cli_parse_sites_per_option": DEFAULT_MAX_CLI_PARSE_SITES_PER_OPTION,
        "max_cli_longopt_entries": DEFAULT_MAX_CLI_LONGOPT_ENTRIES,
        "max_cli_callsites_per_parse_loop": DEFAULT_MAX_CLI_CALLSITES_PER_PARSE_LOOP,
        "max_cli_flag_vars": DEFAULT_MAX_CLI_FLAG_VARS,
        "max_cli_check_sites": DEFAULT_MAX_CLI_CHECK_SITES,
        "max_error_messages": DEFAULT_MAX_ERROR_MESSAGES,
        "max_error_message_callsites": DEFAULT_MAX_ERROR_MESSAGE_CALLSITES,
        "max_error_message_functions": DEFAULT_MAX_ERROR_MESSAGE_FUNCTIONS,
        "max_exit_paths": DEFAULT_MAX_EXIT_PATHS,
        "max_exit_patterns": DEFAULT_MAX_EXIT_PATTERNS,
        "max_error_emitter_callsites": DEFAULT_MAX_ERROR_EMITTER_CALLSITES,
        "max_error_sites": DEFAULT_MAX_ERROR_SITES,
        "max_error_site_callsites": DEFAULT_MAX_ERROR_SITE_CALLSITES,
        "max_mode_dispatch_functions": DEFAULT_MAX_MODE_DISPATCH_FUNCTIONS,
        "max_mode_callsites_per_function": DEFAULT_MAX_MODE_CALLSITES_PER_FUNCTION,
        "max_mode_tokens_per_callsite": DEFAULT_MAX_MODE_TOKENS_PER_CALLSITE,
        "max_mode_token_length": DEFAULT_MAX_MODE_TOKEN_LENGTH,
        "max_modes": DEFAULT_MAX_MODES,
        "max_mode_dispatch_sites_per_mode": DEFAULT_MAX_MODE_DISPATCH_SITES_PER_MODE,
        "max_mode_dispatch_roots_per_mode": DEFAULT_MAX_MODE_DISPATCH_ROOTS_PER_MODE,
        "max_mode_dispatch_site_callsites": DEFAULT_MAX_MODE_DISPATCH_SITE_CALLSITES,
        "max_mode_dispatch_site_tokens": DEFAULT_MAX_MODE_DISPATCH_SITE_TOKENS,
        "max_mode_dispatch_site_ignored_tokens": DEFAULT_MAX_MODE_DISPATCH_SITE_IGNORED_TOKENS,
        "max_mode_low_confidence_candidates": DEFAULT_MAX_MODE_LOW_CONFIDENCE_CANDIDATES,
        "max_mode_slices": DEFAULT_MAX_MODE_SLICES,
        "max_mode_slice_roots": DEFAULT_MAX_MODE_SLICE_ROOTS,
        "max_mode_slice_dispatch_sites": DEFAULT_MAX_MODE_SLICE_DISPATCH_SITES,
        "max_mode_slice_options": DEFAULT_MAX_MODE_SLICE_OPTIONS,
        "max_mode_slice_strings": DEFAULT_MAX_MODE_SLICE_STRINGS,
        "max_mode_slice_messages": DEFAULT_MAX_MODE_SLICE_MESSAGES,
        "max_mode_slice_exit_paths": DEFAULT_MAX_MODE_SLICE_EXIT_PATHS,
        "max_mode_surface_entries": DEFAULT_MAX_MODE_SURFACE_ENTRIES,
    }
    out_dir = None
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
    print("  max_full_functions=%d" % DEFAULT_MAX_FULL_FUNCTIONS)
    print("  max_functions_index=%d" % DEFAULT_MAX_FUNCTIONS_INDEX)
    print("  max_strings=%d" % DEFAULT_MAX_STRINGS)
    print("  max_call_edges=%d" % DEFAULT_MAX_CALL_EDGES)
    print("  max_calls_per_function=%d" % DEFAULT_MAX_CALLS_PER_FUNCTION)
    print("  max_decomp_lines=%d" % DEFAULT_MAX_DECOMP_LINES)
    print("  max_cli_options=%d" % DEFAULT_MAX_CLI_OPTIONS)
    print("  max_cli_parse_loops=%d" % DEFAULT_MAX_CLI_PARSE_LOOPS)
    print("  max_cli_option_evidence=%d" % DEFAULT_MAX_CLI_OPTION_EVIDENCE)
    print("  max_cli_parse_sites_per_option=%d" % DEFAULT_MAX_CLI_PARSE_SITES_PER_OPTION)
    print("  max_cli_longopt_entries=%d" % DEFAULT_MAX_CLI_LONGOPT_ENTRIES)
    print("  max_cli_callsites_per_parse_loop=%d" % DEFAULT_MAX_CLI_CALLSITES_PER_PARSE_LOOP)
    print("  max_cli_flag_vars=%d" % DEFAULT_MAX_CLI_FLAG_VARS)
    print("  max_cli_check_sites=%d" % DEFAULT_MAX_CLI_CHECK_SITES)
    print("  max_error_messages=%d" % DEFAULT_MAX_ERROR_MESSAGES)
    print("  max_error_message_callsites=%d" % DEFAULT_MAX_ERROR_MESSAGE_CALLSITES)
    print("  max_error_message_functions=%d" % DEFAULT_MAX_ERROR_MESSAGE_FUNCTIONS)
    print("  max_exit_paths=%d" % DEFAULT_MAX_EXIT_PATHS)
    print("  max_exit_patterns=%d" % DEFAULT_MAX_EXIT_PATTERNS)
    print("  max_error_emitter_callsites=%d" % DEFAULT_MAX_ERROR_EMITTER_CALLSITES)
    print("  max_error_sites=%d" % DEFAULT_MAX_ERROR_SITES)
    print("  max_error_site_callsites=%d" % DEFAULT_MAX_ERROR_SITE_CALLSITES)
    print("  max_mode_dispatch_functions=%d" % DEFAULT_MAX_MODE_DISPATCH_FUNCTIONS)
    print("  max_mode_callsites_per_function=%d" % DEFAULT_MAX_MODE_CALLSITES_PER_FUNCTION)
    print("  max_mode_tokens_per_callsite=%d" % DEFAULT_MAX_MODE_TOKENS_PER_CALLSITE)
    print("  max_mode_token_length=%d" % DEFAULT_MAX_MODE_TOKEN_LENGTH)
    print("  max_modes=%d" % DEFAULT_MAX_MODES)
    print("  max_mode_dispatch_sites_per_mode=%d" % DEFAULT_MAX_MODE_DISPATCH_SITES_PER_MODE)
    print("  max_mode_dispatch_roots_per_mode=%d" % DEFAULT_MAX_MODE_DISPATCH_ROOTS_PER_MODE)
    print("  max_mode_dispatch_site_callsites=%d" % DEFAULT_MAX_MODE_DISPATCH_SITE_CALLSITES)
    print("  max_mode_dispatch_site_tokens=%d" % DEFAULT_MAX_MODE_DISPATCH_SITE_TOKENS)
    print("  max_mode_dispatch_site_ignored_tokens=%d" % DEFAULT_MAX_MODE_DISPATCH_SITE_IGNORED_TOKENS)
    print("  max_mode_low_confidence_candidates=%d" % DEFAULT_MAX_MODE_LOW_CONFIDENCE_CANDIDATES)
    print("  max_mode_slices=%d" % DEFAULT_MAX_MODE_SLICES)
    print("  max_mode_slice_roots=%d" % DEFAULT_MAX_MODE_SLICE_ROOTS)
    print("  max_mode_slice_dispatch_sites=%d" % DEFAULT_MAX_MODE_SLICE_DISPATCH_SITES)
    print("  max_mode_slice_options=%d" % DEFAULT_MAX_MODE_SLICE_OPTIONS)
    print("  max_mode_slice_strings=%d" % DEFAULT_MAX_MODE_SLICE_STRINGS)
    print("  max_mode_slice_messages=%d" % DEFAULT_MAX_MODE_SLICE_MESSAGES)
    print("  max_mode_slice_exit_paths=%d" % DEFAULT_MAX_MODE_SLICE_EXIT_PATHS)
    print("  max_mode_surface_entries=%d" % DEFAULT_MAX_MODE_SURFACE_ENTRIES)


def resolve_pack_root(out_dir):
    if out_dir.endswith(".lens") or out_dir.endswith("binary.lens"):
        return out_dir
    return os.path.join(out_dir, "binary.lens")
