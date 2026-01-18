"""End-to-end context pack export pipeline.

`scripts/binary_lens_export.py` is the Ghidra script entrypoint. This module
contains the bulk of the exporter pipeline to keep the Ghidra-script surface
area small and reduce cognitive overhead.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any, Callable

from export_bounds import Bounds
from ghidra_analysis import run_program_analysis
from outputs.io import ensure_dir
from pipeline.collect import collect_pipeline_inputs
from pipeline.derive import derive_payloads
from pipeline.layout import PackLayout
from pipeline.write import write_outputs


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


def _clear_pack_root(pack_root: str) -> None:
    root = Path(pack_root)
    if root.is_dir():
        shutil.rmtree(root)
    elif root.exists():
        root.unlink()


def write_context_pack(
    pack_root: str,
    program: Any,
    options: dict[str, Any],
    monitor: Any,
    *,
    profiler: Any = None,
    analyze_all: Callable[[Any], None] | None = None,
) -> None:
    bounds = Bounds.from_options(options)
    options.update(bounds.to_options())
    if profiler is None:
        profiler = ensure_profiler_enabled(pack_root, options)
    profile_enabled = is_profiling_enabled(options)

    _clear_pack_root(pack_root)
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

    collected = collect_pipeline_inputs(program, bounds, monitor, profiler)
    derived = derive_payloads(collected, bounds, profiler)
    write_outputs(program, collected, derived, layout, bounds, monitor, profiler)

    if profiler is not None:
        profiler.write_profile()
