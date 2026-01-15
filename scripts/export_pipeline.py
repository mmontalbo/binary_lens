"""End-to-end context pack export pipeline.

`scripts/binary_lens_export.py` is the Ghidra script entrypoint. This module
contains the bulk of the exporter pipeline to keep the Ghidra-script surface
area small and reduce cognitive overhead.
"""

from __future__ import annotations

from contextlib import nullcontext
from typing import Any, Callable

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
    build_pack_index_payload,
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
from pipeline.cli import collect_cli_inputs
from pipeline.layout import PackLayout


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

    layout = PackLayout.from_root(pack_root)
    for dir_path in layout.iter_dirs():
        ensure_dir(dir_path)

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
    parse_groups = cli_inputs.parse_groups
    parse_details_by_callsite = cli_inputs.parse_details_by_callsite
    compare_details_by_callsite = cli_inputs.compare_details_by_callsite
    check_sites_by_flag_addr = cli_inputs.check_sites_by_flag_addr
    parse_callsite_ids = cli_inputs.parse_callsite_ids
    compare_callsite_ids = cli_inputs.compare_callsite_ids

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
        layout.evidence_callsites_dir,
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
            layout.functions_dir,
            layout.evidence_decomp_dir,
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

    strings_payload = build_strings_payload(
        strings,
        total_strings,
        strings_truncated,
        options,
        string_bucket_counts,
        string_bucket_limits,
    )
    index_payload = build_index_payload(functions, full_functions, index_functions, summaries, options)
    coverage_summary = {
        "strings": {
            "total": strings_payload.get("total_strings"),
            "selected": len(strings_payload.get("strings") or []),
            "truncated": strings_payload.get("truncated"),
            "max": strings_payload.get("max_strings"),
        },
        "functions_index": {
            "total": index_payload.get("total_functions"),
            "selected": len(index_payload.get("functions") or []),
            "truncated": index_payload.get("truncated"),
            "max": index_payload.get("max_functions"),
        },
        "full_functions": {
            "selected": len(index_payload.get("full_functions") or []),
            "truncated": len(functions) > options.get("max_full_functions", 0),
            "max": options.get("max_full_functions", 0),
        },
        "callgraph_edges": {
            "total": callgraph.get("total_edges"),
            "selected": callgraph.get("selected_edges"),
            "truncated": callgraph.get("truncated"),
            "max": callgraph.get("max_edges"),
        },
        "cli_options": {
            "total": cli_options_payload.get("total_options"),
            "selected": cli_options_payload.get("selected_options"),
            "truncated": cli_options_payload.get("truncated"),
            "max": cli_options_payload.get("max_options"),
        },
        "cli_parse_loops": {
            "total": cli_parse_loops_payload.get("total_parse_loops"),
            "selected": cli_parse_loops_payload.get("selected_parse_loops"),
            "truncated": cli_parse_loops_payload.get("truncated"),
            "max": cli_parse_loops_payload.get("max_parse_loops"),
        },
        "modes_index": {
            "total": modes_payload.get("total_modes"),
            "selected": modes_payload.get("selected_modes"),
            "truncated": modes_payload.get("truncated"),
            "max": modes_payload.get("max_modes"),
        },
        "mode_dispatch_sites": {
            "total": dispatch_sites_payload.get("total_dispatch_sites"),
            "selected": dispatch_sites_payload.get("selected_dispatch_sites"),
            "truncated": dispatch_sites_payload.get("truncated"),
            "max": dispatch_sites_payload.get("max_dispatch_sites"),
        },
        "mode_slices": {
            "total": modes_slices_payload.get("total_modes"),
            "selected": modes_slices_payload.get("selected_slices"),
            "truncated": modes_slices_payload.get("truncated"),
            "max": modes_slices_payload.get("max_slices"),
        },
        "error_messages": {
            "total": error_messages_payload.get("total_candidates"),
            "selected": error_messages_payload.get("selected_messages"),
            "truncated": error_messages_payload.get("truncated"),
            "max": error_messages_payload.get("max_messages"),
        },
        "error_sites": {
            "total": error_sites_payload.get("total_sites"),
            "selected": error_sites_payload.get("selected_sites"),
            "truncated": error_sites_payload.get("truncated"),
            "max": error_sites_payload.get("max_sites"),
        },
        "exit_calls": {
            "total": exit_paths_payload.get("total_exit_calls"),
            "selected": exit_paths_payload.get("selected_exit_calls"),
            "truncated": exit_paths_payload.get("truncated"),
            "max": exit_paths_payload.get("max_exit_calls"),
        },
    }

    manifest = build_manifest(
        options,
        hashes,
        BINARY_LENS_VERSION,
        FORMAT_VERSION,
        binary_info=binary_info,
        coverage_summary=coverage_summary,
    )
    pack_index_payload = build_pack_index_payload(FORMAT_VERSION)
    pack_readme = build_pack_readme()

    with _phase(profiler, "write_outputs"):
        write_json(layout.root / "index.json", pack_index_payload)
        write_json(layout.root / "manifest.json", manifest)
        write_json(layout.root / "binary.json", binary_info)
        write_json(layout.root / "imports.json", imports)
        write_json(layout.root / "strings.json", strings_payload)
        write_json(layout.root / "callgraph.json", callgraph)
        write_json(layout.root / "capabilities.json", capabilities)
        write_json(layout.root / "subsystems.json", subsystems_payload)
        write_json(layout.root / "surface_map.json", surface_map_payload)
        write_json(layout.errors_dir / "messages.json", error_messages_payload)
        write_json(layout.errors_dir / "exit_paths.json", exit_paths_payload)
        write_json(layout.errors_dir / "error_sites.json", error_sites_payload)
        write_json(layout.modes_dir / "index.json", modes_payload)
        write_json(layout.modes_dir / "dispatch_sites.json", dispatch_sites_payload)
        write_json(layout.modes_dir / "slices.json", modes_slices_payload)
        write_json(layout.cli_dir / "options.json", cli_options_payload)
        write_json(layout.cli_dir / "parse_loops.json", cli_parse_loops_payload)
        write_json(layout.functions_dir / "index.json", index_payload)
        write_text(layout.root / "README.md", pack_readme)

    if profiler is not None:
        profiler.write_profile()
