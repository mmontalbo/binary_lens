# Binary Lens minimal exporter for Ghidra ProgramDB.
#@author
#@category BinaryLens
#@menupath Tools.BinaryLens.Export Context Pack
#@toolbar

from ghidra.util import SystemUtilities
import os

from export_cli import parse_args, print_usage, resolve_pack_root
from export_collectors import (
    build_function_import_sets,
    build_function_meta,
    build_function_metrics,
    build_signal_set,
    collect_call_edges,
    collect_function_calls,
    collect_functions,
    collect_imports,
    collect_string_refs_by_func,
    collect_strings,
    select_call_edges,
    select_full_functions,
    select_index_functions,
    summarize_functions,
)
from export_derivations import build_string_bucket_counts, derive_capabilities, derive_subsystems
from export_config import BINARY_LENS_VERSION, FORMAT_VERSION, CAPABILITY_RULES
from export_outputs import (
    build_binary_info,
    build_callgraph_payload,
    build_index_payload,
    build_manifest,
    build_pack_readme,
    build_strings_payload,
    ensure_dir,
    write_callsite_records,
    write_function_exports,
    write_json,
    write_text,
)


def write_context_pack(pack_root, program, options):
    ensure_dir(pack_root)
    functions_dir = os.path.join(pack_root, "functions")
    evidence_decomp_dir = os.path.join(pack_root, "evidence", "decomp")
    evidence_callsites_dir = os.path.join(pack_root, "evidence", "callsites")
    ensure_dir(functions_dir)
    ensure_dir(evidence_decomp_dir)
    ensure_dir(evidence_callsites_dir)

    binary_info, hashes = build_binary_info(program)
    imports = collect_imports(program)
    (
        strings,
        _string_addr_map_selected,
        total_strings,
        strings_truncated,
        string_addr_map_all,
        string_tags_by_id,
        string_bucket_counts,
        string_bucket_limits,
    ) = collect_strings(program, options["max_strings"])
    selected_string_ids = set([entry["id"] for entry in strings])
    string_value_by_id = {}
    for entry in strings:
        string_value_by_id[entry["id"]] = entry.get("value")

    functions = collect_functions(program)
    function_meta_by_addr = build_function_meta(functions)
    call_edges_all, callsite_records, call_edge_stats = collect_call_edges(program, functions, monitor)

    listing = program.getListing()
    string_refs_by_func = collect_string_refs_by_func(
        listing,
        functions,
        string_addr_map_all,
        monitor,
    )

    metrics_by_addr = build_function_metrics(
        functions, call_edges_all, string_refs_by_func, string_tags_by_id
    )
    import_sets_by_func = build_function_import_sets(call_edges_all)
    string_bucket_counts_by_func = build_string_bucket_counts(string_refs_by_func, string_tags_by_id)

    full_functions = select_full_functions(functions, metrics_by_addr, options["max_full_functions"])
    index_functions = select_index_functions(functions, full_functions, options["max_functions_index"])

    if options["max_full_functions"] > options["max_functions_index"]:
        index_functions = full_functions

    summaries = summarize_functions(functions, index_functions, full_functions)

    signal_set = build_signal_set(CAPABILITY_RULES)
    call_edges, total_edges, truncated_edges = select_call_edges(
        call_edges_all,
        signal_set,
        options["max_call_edges"],
    )
    callsite_paths = write_callsite_records(callsite_records, call_edges, evidence_callsites_dir)
    callgraph = build_callgraph_payload(call_edges, total_edges, truncated_edges, options, call_edge_stats)

    calls_by_func = collect_function_calls(call_edges)

    write_function_exports(
        program,
        full_functions,
        options,
        string_refs_by_func,
        selected_string_ids,
        calls_by_func,
        functions_dir,
        evidence_decomp_dir,
        monitor,
    )

    capabilities = derive_capabilities(
        call_edges,
        callsite_paths,
        function_meta_by_addr,
        metrics_by_addr,
        string_refs_by_func,
        selected_string_ids,
        string_tags_by_id,
        string_value_by_id,
        CAPABILITY_RULES,
    )

    subsystems_payload = derive_subsystems(
        functions,
        function_meta_by_addr,
        metrics_by_addr,
        call_edges_all,
        import_sets_by_func,
        string_bucket_counts_by_func,
    )

    manifest = build_manifest(options, hashes, BINARY_LENS_VERSION, FORMAT_VERSION)
    strings_payload = build_strings_payload(
        strings,
        total_strings,
        strings_truncated,
        options,
        string_bucket_counts,
        string_bucket_limits,
    )
    index_payload = build_index_payload(functions, full_functions, index_functions, summaries, options)
    pack_readme = build_pack_readme()

    write_json(os.path.join(pack_root, "manifest.json"), manifest)
    write_json(os.path.join(pack_root, "binary.json"), binary_info)
    write_json(os.path.join(pack_root, "imports.json"), imports)
    write_json(os.path.join(pack_root, "strings.json"), strings_payload)
    write_json(os.path.join(pack_root, "callgraph.json"), callgraph)
    write_json(os.path.join(pack_root, "capabilities.json"), capabilities)
    write_json(os.path.join(pack_root, "subsystems.json"), subsystems_payload)
    write_json(os.path.join(functions_dir, "index.json"), index_payload)
    write_text(os.path.join(pack_root, "README.md"), pack_readme)


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
    write_context_pack(pack_root, currentProgram, options)
    print("Binary Lens export complete: %s" % pack_root)


main()
