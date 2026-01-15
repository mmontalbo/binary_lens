# Binary Lens minimal exporter for Ghidra ProgramDB.
#@author
#@category BinaryLens
#@menupath Tools.BinaryLens.Export Context Pack
#@toolbar

import os
import sys
import traceback

try:
    script_dir = os.path.dirname(os.path.abspath(__file__))
except Exception:
    script_dir = None
if script_dir and script_dir not in sys.path:
    sys.path.insert(0, script_dir)

from export_cli import parse_args, print_usage, resolve_pack_root
from export_outputs import ensure_dir
from export_pipeline import ensure_profiler_enabled, write_context_pack
from ghidra.util import SystemUtilities


def main():
    args = getScriptArgs()
    out_dir, options, show_help = parse_args(args)
    if show_help:
        print_usage()
        return
    if out_dir is None:
        if SystemUtilities.isInHeadlessMode():
            print("Output directory required in headless mode.")
            print_usage()
            return
        out_dir = askDirectory("Binary Lens export directory", "Select").getAbsolutePath()
    pack_root = resolve_pack_root(out_dir)
    profiler = ensure_profiler_enabled(pack_root, options)
    try:
        write_context_pack(
            pack_root,
            currentProgram,
            options,
            monitor,
            profiler=profiler,
            analyze_all=globals().get("analyzeAll"),
        )
    except Exception:
        error_path = os.path.join(pack_root, "export_error.txt")
        try:
            ensure_dir(pack_root)
            handle = open(error_path, "w")
            try:
                handle.write(traceback.format_exc())
            finally:
                handle.close()
        except Exception:
            pass
        print("Binary Lens export failed; see %s" % error_path)
        if profiler is not None:
            try:
                profiler.write_profile()
            except Exception:
                pass
        raise
    print("Binary Lens export complete: %s" % pack_root)


main()
