# Binary Lens minimal exporter for Ghidra ProgramDB.
#@author
#@category BinaryLens
#@menupath Tools.BinaryLens.Export Context Pack
#@toolbar

import os

from export_cli import parse_args, print_usage, resolve_pack_root
from export_collectors import (
    build_cli_compare_details,
    build_cli_parse_details,
    build_function_import_sets,
    build_function_meta,
    build_function_metrics,
    build_signal_set,
    collect_call_edges,
    collect_cli_option_compare_sites,
    collect_cli_parse_sites,
    collect_flag_check_sites,
    collect_function_calls,
    collect_functions,
    collect_imports,
    collect_string_refs_by_func,
    collect_strings,
    extract_call_args,
    parse_option_token,
    select_call_edges,
    select_full_functions,
    select_index_functions,
    summarize_functions,
)
from export_config import BINARY_LENS_VERSION, CAPABILITY_RULES, FORMAT_VERSION
from export_derivations import (
    build_string_bucket_counts,
    derive_capabilities,
    derive_cli_surface,
    derive_subsystems,
)
from export_outputs import (
    build_binary_info,
    build_callgraph_payload,
    build_cli_options_payload,
    build_cli_parse_loops_payload,
    build_index_payload,
    build_manifest,
    build_pack_readme,
    build_strings_payload,
    build_surface_map_payload,
    ensure_dir,
    write_callsite_records,
    write_function_exports,
    write_json,
    write_text,
)
from ghidra.util import SystemUtilities


def collect_cli_inputs(
    program,
    options,
    call_edges_all,
    function_meta_by_addr,
    string_addr_map_all,
    string_refs_by_func,
    strings,
):
    parse_sites, parse_groups = collect_cli_parse_sites(call_edges_all, function_meta_by_addr)
    parse_callsite_ids = [entry.get("callsite") for entry in parse_sites if entry.get("callsite")]
    # Resolve call arguments at parse sites to recover optstrings/longopts.
    call_args_by_callsite = {}
    for callsite_id in parse_callsite_ids:
        call_args_by_callsite[callsite_id] = extract_call_args(program, callsite_id, monitor)
    parse_details_by_callsite = build_cli_parse_details(
        program,
        parse_sites,
        call_args_by_callsite,
        string_addr_map_all,
        options.get("max_cli_longopt_entries", 0),
    )
    flag_addresses = set()
    for detail in parse_details_by_callsite.values():
        longopts = detail.get("longopts") or {}
        for entry in longopts.get("entries", []):
            flag_addr = entry.get("flag_address")
            if flag_addr:
                flag_addresses.add(flag_addr)
    check_sites_by_flag_addr = collect_flag_check_sites(
        program,
        sorted(flag_addresses),
        options.get("max_cli_check_sites", 0),
    )

    # Restrict compare-site scanning to functions that reference option-like strings.
    option_token_string_ids = set()
    for entry in strings:
        token = parse_option_token(entry.get("value"))
        if token:
            option_token_string_ids.add(entry.get("id"))
    option_token_callers = set()
    if option_token_string_ids:
        for func_addr, string_ids in string_refs_by_func.items():
            if string_ids & option_token_string_ids:
                option_token_callers.add(func_addr)
    compare_sites = collect_cli_option_compare_sites(
        call_edges_all,
        function_meta_by_addr,
        option_token_callers if option_token_callers else None,
    )
    compare_callsite_ids = [entry.get("callsite") for entry in compare_sites if entry.get("callsite")]
    for callsite_id in compare_callsite_ids:
        if callsite_id in call_args_by_callsite:
            continue
        call_args_by_callsite[callsite_id] = extract_call_args(program, callsite_id, monitor)
    compare_details_by_callsite = build_cli_compare_details(
        compare_sites,
        call_args_by_callsite,
        string_addr_map_all,
    )

    return {
        "parse_groups": parse_groups,
        "parse_details_by_callsite": parse_details_by_callsite,
        "compare_details_by_callsite": compare_details_by_callsite,
        "check_sites_by_flag_addr": check_sites_by_flag_addr,
        "parse_callsite_ids": parse_callsite_ids,
        "compare_callsite_ids": compare_callsite_ids,
    }


def write_context_pack(pack_root, program, options):
    ensure_dir(pack_root)
    functions_dir = os.path.join(pack_root, "functions")
    cli_dir = os.path.join(pack_root, "cli")
    evidence_decomp_dir = os.path.join(pack_root, "evidence", "decomp")
    evidence_callsites_dir = os.path.join(pack_root, "evidence", "callsites")
    ensure_dir(functions_dir)
    ensure_dir(cli_dir)
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
    listing = program.getListing()
    string_refs_by_func = collect_string_refs_by_func(
        listing,
        functions,
        string_addr_map_all,
        monitor,
    )
    call_edges_all, callsite_records, call_edge_stats = collect_call_edges(program, functions, monitor)

    cli_inputs = collect_cli_inputs(
        program,
        options,
        call_edges_all,
        function_meta_by_addr,
        string_addr_map_all,
        string_refs_by_func,
        strings,
    )
    parse_groups = cli_inputs["parse_groups"]
    parse_details_by_callsite = cli_inputs["parse_details_by_callsite"]
    compare_details_by_callsite = cli_inputs["compare_details_by_callsite"]
    check_sites_by_flag_addr = cli_inputs["check_sites_by_flag_addr"]
    parse_callsite_ids = cli_inputs["parse_callsite_ids"]
    compare_callsite_ids = cli_inputs["compare_callsite_ids"]

    metrics_by_addr = build_function_metrics(
        functions, call_edges_all, string_refs_by_func, string_tags_by_id
    )
    import_sets_by_func = build_function_import_sets(call_edges_all)
    string_bucket_counts_by_func = build_string_bucket_counts(string_refs_by_func, string_tags_by_id)

    full_functions = select_full_functions(functions, metrics_by_addr, options["max_full_functions"])
    index_functions = select_index_functions(functions, full_functions, options["max_functions_index"])

    if options["max_full_functions"] > options["max_functions_index"]:
        # Guard against misconfigured bounds; index must include full exports.
        index_functions = full_functions

    summaries = summarize_functions(functions, index_functions, full_functions)

    signal_set = build_signal_set(CAPABILITY_RULES)
    call_edges, total_edges, truncated_edges = select_call_edges(
        call_edges_all,
        signal_set,
        options["max_call_edges"],
    )
    # Ensure CLI evidence callsites are serialized even if they fall outside edge caps.
    extra_callsites = parse_callsite_ids + compare_callsite_ids
    callsite_paths = write_callsite_records(
        callsite_records,
        call_edges,
        evidence_callsites_dir,
        extra_callsites=extra_callsites,
    )
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
    cli_surface = derive_cli_surface(
        parse_groups,
        parse_details_by_callsite,
        compare_details_by_callsite,
        callsite_paths,
        options,
        check_sites_by_flag_addr,
    )
    cli_options_payload = build_cli_options_payload(
        cli_surface.get("options", []),
        cli_surface.get("total_options", 0),
        cli_surface.get("options_truncated", False),
        options,
    )
    cli_parse_loops_payload = build_cli_parse_loops_payload(
        cli_surface.get("parse_loops", []),
        cli_surface.get("total_parse_loops", 0),
        cli_surface.get("parse_loops_truncated", False),
        options,
    )
    surface_map_payload = build_surface_map_payload(cli_surface, options)

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
    write_json(os.path.join(pack_root, "surface_map.json"), surface_map_payload)
    write_json(os.path.join(cli_dir, "options.json"), cli_options_payload)
    write_json(os.path.join(cli_dir, "parse_loops.json"), cli_parse_loops_payload)
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
