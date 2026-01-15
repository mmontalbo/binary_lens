"""Ghidra analysis-control helpers.

This module isolates the "Ghidra glue" needed to:
- snapshot analyzer enablement (for profiling/debugging)
- prune the analyzer set for a lightweight analysis profile
- kick off analysis in both GUI and headless contexts

The returned payloads are JSON-serializable and intended to be written under
`binary.lens/profile/analyzers.json` when profiling is enabled.
"""

from __future__ import annotations

import time
from typing import Any, Callable

AnalyzeAllFn = Callable[[Any], None]


def _get_analyzers_options(program: Any) -> tuple[str, Any | None]:
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


def _task_analyzer_name(task: Any) -> str | None:
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


def _get_task_list_tasks(task_list: Any) -> Any | None:
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


def _snapshot_task_analyzers(program: Any) -> list[str]:
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

    discovered: set[str] = set()
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


def snapshot_analyzers(program: Any) -> dict[str, Any]:
    """Best-effort snapshot of Ghidra analyzers and their enablement state."""

    group_name, analyzers_options = _get_analyzers_options(program)
    snapshot: dict[str, Any] = {
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

    entries: list[dict[str, Any]] = []
    enabled_names: list[str] = []
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


def configure_minimal_analysis(program: Any) -> dict[str, Any]:
    """Prune analyzer execution for `analysis_profile=minimal`.

    This intentionally retains the core analyzers Binary Lens depends on:
    disassembly, function recovery, string discovery, references, and basic
    decompiler cleanup that stabilizes evidence extraction.
    """

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

    def _allow(analyzer_name: str | None) -> bool:
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
                kept_analyzers: set[str] = set()
                dropped_analyzers: set[str] = set()
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
                    kept_tasks: list[Any] = []
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

    kept: set[str] = set()
    dropped: set[str] = set()
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


def run_program_analysis(
    program: Any,
    analysis_profile: str | None,
    monitor: Any,
    *,
    profiler: Any = None,
    analyze_all: AnalyzeAllFn | None = None,
) -> dict[str, Any]:
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
    config: dict[str, Any] = {
        "analysis_profile": analysis_profile,
        "status": "skipped" if skip_run else "ok",
    }

    if analysis_profile == "minimal" and not skip_run:
        try:
            manager.reAnalyzeAll(monitor)
        except Exception:
            pass
        if profiler is not None:
            config["before"] = snapshot_analyzers(program)
        minimal_config = configure_minimal_analysis(program)
        if profiler is not None:
            config["minimal_config"] = minimal_config
            config["after"] = snapshot_analyzers(program)
    elif profiler is not None:
        config["analyzers"] = snapshot_analyzers(program)

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
            if analyze_all is not None:
                try:
                    analyze_all(program)
                    run_method = "analyzeAll_pruned"
                except Exception:
                    run_method = None
            if run_method is None:
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
            if analyze_all is not None:
                try:
                    analyze_all(program)
                    run_method = "analyzeAll"
                except Exception:
                    run_method = None
            if run_method is None:
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

