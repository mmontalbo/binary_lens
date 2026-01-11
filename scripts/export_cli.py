import os

from export_config import (
    DEFAULT_MAX_CALL_EDGES,
    DEFAULT_MAX_CALLS_PER_FUNCTION,
    DEFAULT_MAX_DECOMP_LINES,
    DEFAULT_MAX_FULL_FUNCTIONS,
    DEFAULT_MAX_FUNCTIONS_INDEX,
    DEFAULT_MAX_STRINGS,
)


def parse_args(args):
    options = {
        "max_full_functions": DEFAULT_MAX_FULL_FUNCTIONS,
        "max_functions_index": DEFAULT_MAX_FUNCTIONS_INDEX,
        "max_strings": DEFAULT_MAX_STRINGS,
        "max_call_edges": DEFAULT_MAX_CALL_EDGES,
        "max_calls_per_function": DEFAULT_MAX_CALLS_PER_FUNCTION,
        "max_decomp_lines": DEFAULT_MAX_DECOMP_LINES,
    }
    out_dir = None
    show_help = False

    for arg in args:
        if arg in ("-h", "--help"):
            show_help = True
            continue
        if "=" in arg:
            key, value = arg.split("=", 1)
            if key == "out_dir":
                out_dir = value
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

    if options["max_full_functions"] > options["max_functions_index"]:
        options["max_functions_index"] = options["max_full_functions"]

    return out_dir, options, show_help


def print_usage():
    print("Binary Lens exporter")
    print("Usage:")
    print("  <script> <out_dir> [key=value ...]")
    print("Options:")
    print("  max_full_functions=%d" % DEFAULT_MAX_FULL_FUNCTIONS)
    print("  max_functions_index=%d" % DEFAULT_MAX_FUNCTIONS_INDEX)
    print("  max_strings=%d" % DEFAULT_MAX_STRINGS)
    print("  max_call_edges=%d" % DEFAULT_MAX_CALL_EDGES)
    print("  max_calls_per_function=%d" % DEFAULT_MAX_CALLS_PER_FUNCTION)
    print("  max_decomp_lines=%d" % DEFAULT_MAX_DECOMP_LINES)


def resolve_pack_root(out_dir):
    if out_dir.endswith(".lens") or out_dir.endswith("binary.lens"):
        return out_dir
    return os.path.join(out_dir, "binary.lens")
