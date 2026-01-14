# Binary Lens minimal exporter for Ghidra ProgramDB.
#@author
#@category BinaryLens
#@menupath Tools.BinaryLens.Export Context Pack
#@toolbar

import os
import sys
import time
import traceback
from contextlib import nullcontext

try:
    script_dir = os.path.dirname(os.path.abspath(__file__))
except Exception:
    script_dir = None
if script_dir and script_dir not in sys.path:
    sys.path.insert(0, script_dir)

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
from ghidra.util import SystemUtilities


def _phase(profiler, name):
    if profiler is None:
        return nullcontext()
    try:
        return profiler.phase(name)
    except Exception:
        return nullcontext()


def _get_analyzers_options(program):
    group_name = "Analyzers"
    try:
        for name in program.getOptionsNames():
            if str(name).lower() == "analyzers":
                group_name = str(name)
                break
    except Exception:
        pass
    try:
        return group_name, program.getOptions(group_name)
    except Exception:
        return group_name, None


def _task_analyzer_name(task):
    try:
        if hasattr(task, "getAnalyzer"):
            analyzer = task.getAnalyzer()
            if analyzer is not None and hasattr(analyzer, "getName"):
                return str(analyzer.getName())
    except Exception:
        pass
    try:
        fields = task.getClass().getDeclaredFields()
    except Exception:
        fields = None
    if fields is None:
        return None
    for field in fields:
        try:
            field_name = field.getName()
        except Exception:
            continue
        if "analy" not in field_name.lower():
            continue
        try:
            field.setAccessible(True)
            analyzer = field.get(task)
        except Exception:
            continue
        if analyzer is None or not hasattr(analyzer, "getName"):
            continue
        try:
            return str(analyzer.getName())
        except Exception:
            continue
    return None


def _get_task_list_tasks(task_list):
    try:
        fields = task_list.getClass().getDeclaredFields()
    except Exception:
        fields = None
    if fields is None:
        return None
    for field in fields:
        try:
            if field.getName() == "tasks":
                field.setAccessible(True)
                return field.get(task_list)
        except Exception:
            continue
    return None


def _snapshot_task_analyzers(program):
    try:
        from ghidra.app.plugin.core.analysis import AutoAnalysisManager
    except Exception:
        return []
    try:
        manager = AutoAnalysisManager.getAnalysisManager(program)
    except Exception:
        manager = None
    if manager is None:
        return []

    task_array = None
    try:
        for field in manager.getClass().getDeclaredFields():
            if field.getName() == "taskArray":
                field.setAccessible(True)
                task_array = field.get(manager)
                break
    except Exception:
        task_array = None
    if task_array is None:
        return []

    discovered = set()
    for task_list in list(task_array):
        tasks_value = _get_task_list_tasks(task_list)
        if tasks_value is None:
            continue
        try:
            tasks = list(tasks_value)
        except Exception:
            continue
        for task in tasks:
            name = _task_analyzer_name(task)
            if name:
                discovered.add(name)
    return sorted(discovered)


def _snapshot_analyzers(program):
    group_name, analyzers_options = _get_analyzers_options(program)
    snapshot = {
        "status": "ok",
        "analyzers_group": group_name,
        "entries": [],
        "enabled": [],
        "enabled_count": 0,
        "total_count": 0,
    }
    if analyzers_options is None:
        snapshot["status"] = "missing_options_group"
        return snapshot

    try:
        option_names = list(analyzers_options.getOptionNames())
    except Exception:
        option_names = []

    entries = []
    enabled_names = []
    for name in option_names:
        try:
            enabled = analyzers_options.getBoolean(name)
        except Exception:
            continue
        name_text = str(name)
        entries.append({"name": name_text, "enabled": bool(enabled)})
        if enabled:
            enabled_names.append(name_text)

    entries.sort(key=lambda entry: entry.get("name") or "")
    enabled_names.sort()
    snapshot["entries"] = entries
    snapshot["enabled"] = enabled_names
    snapshot["enabled_count"] = len(enabled_names)
    snapshot["total_count"] = len(entries)
    if not entries:
        task_names = _snapshot_task_analyzers(program)
        if task_names:
            snapshot["analyzers_source"] = "analysis_tasks"
            snapshot["entries"] = [{"name": name, "enabled": True} for name in task_names]
            snapshot["enabled"] = task_names
            snapshot["enabled_count"] = len(task_names)
            snapshot["total_count"] = len(task_names)
    return snapshot


def _configure_minimal_analysis(program):
    allowed_patterns = [
        "Disassemble Entry Points",
        "Function Start",
        "Subroutine References",
        "Reference",
        "Data Reference",
        "ASCII Strings",
        "Unicode Strings",
        "Create Address Tables",
        "Decompiler Switch Analysis",
        "Decompiler Parameter ID",
        "Stack",
        "Call-Fixup",
        "Call Convention ID",
        "Function ID",
        "Non-Returning",
        "Shared Return Calls",
        "Variadic Function Signature Override",
    ]
    lowered_allowed = [pattern.lower() for pattern in allowed_patterns]

    def _allow(analyzer_name):
        if not analyzer_name:
            return True
        lowered = analyzer_name.lower()
        return any(pattern in lowered for pattern in lowered_allowed)

    try:
        from ghidra.app.plugin.core.analysis import AutoAnalysisManager
    except Exception:
        AutoAnalysisManager = None

    if AutoAnalysisManager is not None:
        try:
            manager = AutoAnalysisManager.getAnalysisManager(program)
        except Exception:
            manager = None
        if manager is not None:
            task_array = None
            try:
                for field in manager.getClass().getDeclaredFields():
                    if field.getName() == "taskArray":
                        field.setAccessible(True)
                        task_array = field.get(manager)
                        break
            except Exception:
                task_array = None
            if task_array is not None:
                kept_analyzers = set()
                dropped_analyzers = set()
                total_before = 0
                total_after = 0

                for task_list in list(task_array):
                    tasks_value = _get_task_list_tasks(task_list)
                    if tasks_value is None:
                        continue
                    try:
                        tasks = list(tasks_value)
                    except Exception:
                        continue
                    total_before += len(tasks)
                    kept_tasks = []
                    for task in tasks:
                        analyzer_name = _task_analyzer_name(task)
                        if _allow(analyzer_name):
                            kept_tasks.append(task)
                            if analyzer_name:
                                kept_analyzers.add(analyzer_name)
                        elif analyzer_name:
                            dropped_analyzers.add(analyzer_name)
                    try:
                        tasks_value.clear()
                        for task in kept_tasks:
                            tasks_value.add(task)
                    except Exception:
                        pass
                    total_after += len(kept_tasks)

                return {
                    "status": "ok",
                    "allowed_patterns": allowed_patterns,
                    "kept_task_count": total_after,
                    "dropped_task_count": max(0, total_before - total_after),
                    "kept_analyzers": sorted(kept_analyzers),
                    "dropped_analyzers": sorted(dropped_analyzers),
                    "kept_analyzer_count": len(kept_analyzers),
                    "dropped_analyzer_count": len(dropped_analyzers),
                }

    group_name, analyzers_options = _get_analyzers_options(program)
    if analyzers_options is None:
        return {"status": "missing_options_group", "analyzers_group": group_name}

    try:
        option_names = list(analyzers_options.getOptionNames())
    except Exception:
        option_names = []

    kept = set()
    dropped = set()
    changed = 0
    for name in option_names:
        name_text = str(name)
        try:
            current = analyzers_options.getBoolean(name)
        except Exception:
            continue
        lowered = name_text.lower()
        desired = any(pattern in lowered for pattern in lowered_allowed)
        if current != desired:
            try:
                analyzers_options.setBoolean(name, bool(desired))
                changed += 1
            except Exception:
                pass
        if desired:
            kept.add(name_text)
        elif current and not desired:
            dropped.add(name_text)

    kept_list = sorted(kept)
    dropped_list = sorted(dropped)
    return {
        "status": "ok",
        "allowed_patterns": allowed_patterns,
        "analyzers_group": group_name,
        "changed_count": changed,
        "kept_analyzers": kept_list,
        "dropped_analyzers": dropped_list,
        "kept_analyzer_count": len(kept_list),
        "dropped_analyzer_count": len(dropped_list),
    }


def _run_program_analysis(program, analysis_profile, monitor, profiler=None):
    if not analysis_profile:
        analysis_profile = "full"
    analysis_profile = str(analysis_profile).strip().lower() or "full"
    skip_run = analysis_profile in ("none", "reuse")

    try:
        from ghidra.app.plugin.core.analysis import AutoAnalysisManager
    except Exception:
        return {"status": "missing_auto_analysis_manager", "analysis_profile": analysis_profile}

    manager = AutoAnalysisManager.getAnalysisManager(program)
    try:
        manager.initializeOptions()
    except Exception:
        pass
    try:
        manager.registerAnalyzerOptions()
    except Exception:
        pass
    config = {"analysis_profile": analysis_profile, "status": "skipped" if skip_run else "ok"}

    if analysis_profile == "minimal" and not skip_run:
        try:
            manager.reAnalyzeAll(monitor)
        except Exception:
            pass
        if profiler is not None:
            config["before"] = _snapshot_analyzers(program)
        minimal_config = _configure_minimal_analysis(program)
        if profiler is not None:
            config["minimal_config"] = minimal_config
            config["after"] = _snapshot_analyzers(program)
    elif profiler is not None:
        config["analyzers"] = _snapshot_analyzers(program)

    if skip_run:
        if profiler is not None:
            try:
                profiler.set_analysis_snapshot(config)
            except Exception:
                pass
        return config

    start = time.perf_counter()
    run_method = None
    try:
        if analysis_profile == "minimal":
            try:
                analyzeAll(program)  # noqa: F821 - provided by GhidraScript runtime
                run_method = "analyzeAll_pruned"
            except Exception:
                run_method = "auto_analysis_manager_pruned"
                try:
                    if hasattr(manager, "startBackgroundAnalysis"):
                        manager.startBackgroundAnalysis()
                except Exception:
                    pass
                try:
                    manager.startAnalysis(monitor, True)
                except Exception:
                    try:
                        manager.startAnalysis(monitor)
                    except Exception:
                        pass
                try:
                    if hasattr(manager, "waitForAnalysis"):
                        try:
                            manager.waitForAnalysis(None, monitor)
                        except Exception:
                            pass
                    while manager.isAnalyzing():
                        if monitor is not None and monitor.isCancelled():
                            break
                        time.sleep(0.05)
                except Exception:
                    pass
        else:
            try:
                analyzeAll(program)  # noqa: F821 - provided by GhidraScript runtime
                run_method = "analyzeAll"
            except Exception:
                run_method = "auto_analysis_manager"
                try:
                    manager.reAnalyzeAll(monitor)
                except Exception:
                    pass
                try:
                    manager.startAnalysis(monitor)
                except Exception:
                    pass
                try:
                    if hasattr(manager, "waitForAnalysis"):
                        try:
                            manager.waitForAnalysis(None, monitor)
                        except Exception:
                            pass
                    while manager.isAnalyzing():
                        if monitor is not None and monitor.isCancelled():
                            break
                        time.sleep(0.05)
                except Exception:
                    pass
    finally:
        if profiler is not None:
            profiler.add_timing("analysis", time.perf_counter() - start)
    config["run_method"] = run_method
    if profiler is not None:
        try:
            profiler.set_analysis_snapshot(config)
        except Exception:
            pass
    return config


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


def write_context_pack(pack_root, program, options):
    profiler = None
    profile_enabled = False
    try:
        profile_enabled = int(options.get("profile") or 0) == 1
    except Exception:
        profile_enabled = False
    if profile_enabled:
        try:
            from export_profile import ensure_profiler
        except Exception:
            ensure_profiler = None
        if ensure_profiler is not None:
            profiler = ensure_profiler(pack_root, enabled=True)

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
        _run_program_analysis(program, analysis_profile, monitor, profiler=profiler)

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
    profiler = None
    profile_enabled = False
    try:
        profile_enabled = int(options.get("profile") or 0) == 1
    except Exception:
        profile_enabled = False
    if profile_enabled:
        try:
            from export_profile import ensure_profiler
        except Exception:
            ensure_profiler = None
        if ensure_profiler is not None:
            profiler = ensure_profiler(pack_root, enabled=True)
    try:
        write_context_pack(pack_root, currentProgram, options)
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
