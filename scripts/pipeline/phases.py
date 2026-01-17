"""Profiling phase helpers for the export pipeline."""

from __future__ import annotations

from contextlib import nullcontext
from typing import Any


def phase(profiler: Any, name: str):
    if profiler is None:
        return nullcontext()
    try:
        return profiler.phase(name)
    except Exception:
        return nullcontext()
