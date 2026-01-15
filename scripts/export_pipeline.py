"""End-to-end context pack export pipeline.

`scripts/binary_lens_export.py` is the Ghidra script entrypoint. This module
contains the bulk of the exporter pipeline to keep the Ghidra-script surface
area small and reduce cognitive overhead.
"""

from __future__ import annotations

import os
from contextlib import nullcontext
from typing import Any, Callable

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
    extract_call_args_for_callsites,
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
from export_errors import (
    attach_callsite_refs,
    build_error_surface,
    collect_error_callsites,
    derive_error_messages,
    derive_error_sites,
    derive_exit_paths,
)
from export_modes import (
    attach_mode_callsite_refs,
    build_mode_slices,
    build_modes_surface,
    collect_mode_candidates,
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
from ghidra_analysis import run_program_analysis


def _phase(profiler: Any, name: str):
    if profiler is None:
        return nullcontext()
    try:
        return profiler.phase(name)
    except Exception:
        return nullcontext()


def is_profiling_enabled(options: dict[str, Any]) -> bool:
    try:
        return int(options.get("profile") or 0) == 1
    except Exception:
        return False


def ensure_profiler_enabled(pack_root: str, options: dict[str, Any]):
    if not is_profiling_enabled(options):
        return None
    try:
        from export_profile import ensure_profiler
    except Exception:
        ensure_profiler = None
    if ensure_profiler is None:
        return None
    return ensure_profiler(pack_root, enabled=True)


def collect_cli_inputs(
    program: Any,
    options: dict[str, Any],
    call_edges_all: list[dict[str, Any]],
    function_meta_by_addr: dict[str, Any],
    string_addr_map_all: dict[str, Any],
    string_refs_by_func: dict[str, set[str]],
    strings: list[dict[str, Any]],
    monitor: Any,
) -> dict[str, Any]:
    parse_sites, parse_groups = collect_cli_parse_sites(call_edges_all, function_meta_by_addr)
    parse_callsite_ids = [entry.get("callsite") for entry in parse_sites if entry.get("callsite")]

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

    callsite_ids = list(dict.fromkeys(parse_callsite_ids + compare_callsite_ids))
    # Resolve call arguments in batches to avoid repeated per-callsite decompilation.
    call_args_by_callsite = extract_call_args_for_callsites(
        program,
        callsite_ids,
        monitor,
        purpose="binary_lens_export.collect_cli_inputs",
    )

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


def write_context_pack(
    pack_root: str,
    program: Any,
    options: dict[str, Any],
    monitor: Any,
    *,
    profiler: Any = None,
    analyze_all: Callable[[Any], None] | None = None,
) -> None:
    if profiler is None:
        profiler = ensure_profiler_enabled(pack_root, options)
    profile_enabled = is_profiling_enabled(options)

    ensure_dir(pack_root)
    functions_dir = os.path.join(pack_root, "functions")
    cli_dir = os.path.join(pack_root, "cli")
    errors_dir = os.path.join(pack_root, "errors")
    modes_dir = os.path.join(pack_root, "modes")
    evidence_decomp_dir = os.path.join(pack_root, "evidence", "decomp")
    evidence_callsites_dir = os.path.join(pack_root, "evidence", "callsites")
    ensure_dir(functions_dir)
    ensure_dir(cli_dir)
    ensure_dir(errors_dir)
    ensure_dir(modes_dir)
    ensure_dir(evidence_decomp_dir)
    ensure_dir(evidence_callsites_dir)

    analysis_profile = (options.get("analysis_profile") or "full").strip().lower()
    if profile_enabled or analysis_profile != "full":
        run_program_analysis(
            program,
            analysis_profile,
            monitor,
            profiler=profiler,
            analyze_all=analyze_all,
        )

    with _phase(profiler, "collect_strings"):
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

    with _phase(profiler, "collect_functions"):
        functions = collect_functions(program)
        function_meta_by_addr = build_function_meta(functions)
        listing = program.getListing()
        string_refs_by_func = collect_string_refs_by_func(
            listing,
            functions,
            string_addr_map_all,
            monitor,
        )

    with _phase(profiler, "collect_call_edges"):
        call_edges_all, callsite_records, call_edge_stats = collect_call_edges(program, functions, monitor)

    with _phase(profiler, "collect_cli_parse_compare"):
        cli_inputs = collect_cli_inputs(
            program,
            options,
            call_edges_all,
            function_meta_by_addr,
            string_addr_map_all,
            string_refs_by_func,
            strings,
            monitor,
        )
    parse_groups = cli_inputs["parse_groups"]
    parse_details_by_callsite = cli_inputs["parse_details_by_callsite"]
    compare_details_by_callsite = cli_inputs["compare_details_by_callsite"]
    check_sites_by_flag_addr = cli_inputs["check_sites_by_flag_addr"]
    parse_callsite_ids = cli_inputs["parse_callsite_ids"]
    compare_callsite_ids = cli_inputs["compare_callsite_ids"]

    with _phase(profiler, "collect_errors"):
        error_messages_payload, emitter_callsites_by_func, call_args_cache = derive_error_messages(
            program,
            monitor,
            strings,
            string_addr_map_all,
            string_refs_by_func,
            call_edges_all,
            function_meta_by_addr,
            string_tags_by_id,
            options,
        )
        exit_paths_payload, exit_callsites_by_func, call_args_cache = derive_exit_paths(
            program,
            monitor,
            call_edges_all,
            function_meta_by_addr,
            options,
            call_args_cache=call_args_cache,
            emitter_callsites_by_func=emitter_callsites_by_func,
        )
        error_sites_payload = derive_error_sites(
            error_messages_payload,
            exit_callsites_by_func,
            call_args_cache,
            options,
            function_meta_by_addr,
        )
    error_surface = build_error_surface(error_messages_payload, exit_paths_payload, error_sites_payload)
    error_callsite_ids = collect_error_callsites(
        error_messages_payload, exit_paths_payload, error_sites_payload
    )

    with _phase(profiler, "collect_modes"):
        modes_payload, dispatch_sites_payload, mode_callsite_ids = collect_mode_candidates(
            program,
            call_edges_all,
            function_meta_by_addr,
            string_addr_map_all,
            options,
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
    extra_callsites = parse_callsite_ids + compare_callsite_ids + error_callsite_ids + mode_callsite_ids
    callsite_paths = write_callsite_records(
        callsite_records,
        call_edges,
        evidence_callsites_dir,
        extra_callsites=extra_callsites,
    )
    attach_callsite_refs(
        error_messages_payload,
        exit_paths_payload,
        error_sites_payload,
        error_surface,
        callsite_paths,
    )
    attach_mode_callsite_refs(modes_payload, dispatch_sites_payload, callsite_paths)
    callgraph = build_callgraph_payload(call_edges, total_edges, truncated_edges, options, call_edge_stats)

    calls_by_func = collect_function_calls(call_edges)

    with _phase(profiler, "write_function_exports"):
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
    with _phase(profiler, "derive_cli_surface"):
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
    with _phase(profiler, "build_mode_slices"):
        modes_slices_payload = build_mode_slices(
            modes_payload,
            cli_surface,
            options,
            string_refs_by_func=string_refs_by_func,
            selected_string_ids=selected_string_ids,
            error_messages_payload=error_messages_payload,
            exit_paths_payload=exit_paths_payload,
        )
    with _phase(profiler, "build_surface_map"):
        modes_surface = build_modes_surface(modes_payload, dispatch_sites_payload, callsite_paths, options)
        surface_map_payload = build_surface_map_payload(
            cli_surface,
            options,
            error_surface=error_surface,
            modes_surface=modes_surface,
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

    with _phase(profiler, "write_outputs"):
        write_json(os.path.join(pack_root, "manifest.json"), manifest)
        write_json(os.path.join(pack_root, "binary.json"), binary_info)
        write_json(os.path.join(pack_root, "imports.json"), imports)
        write_json(os.path.join(pack_root, "strings.json"), strings_payload)
        write_json(os.path.join(pack_root, "callgraph.json"), callgraph)
        write_json(os.path.join(pack_root, "capabilities.json"), capabilities)
        write_json(os.path.join(pack_root, "subsystems.json"), subsystems_payload)
        write_json(os.path.join(pack_root, "surface_map.json"), surface_map_payload)
        write_json(os.path.join(errors_dir, "messages.json"), error_messages_payload)
        write_json(os.path.join(errors_dir, "exit_paths.json"), exit_paths_payload)
        write_json(os.path.join(errors_dir, "error_sites.json"), error_sites_payload)
        write_json(os.path.join(modes_dir, "index.json"), modes_payload)
        write_json(os.path.join(modes_dir, "dispatch_sites.json"), dispatch_sites_payload)
        write_json(os.path.join(modes_dir, "slices.json"), modes_slices_payload)
        write_json(os.path.join(cli_dir, "options.json"), cli_options_payload)
        write_json(os.path.join(cli_dir, "parse_loops.json"), cli_parse_loops_payload)
        write_json(os.path.join(functions_dir, "index.json"), index_payload)
        write_text(os.path.join(pack_root, "README.md"), pack_readme)

    if profiler is not None:
        profiler.write_profile()

