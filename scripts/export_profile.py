"""Profiling helpers for the exporter.

When `profile=1` is passed, the exporter writes timing + decompiler statistics
under `binary.lens/profile/`. This output is not part of the milestone goldens,
but is useful for debugging headless runs and tracking exporter hotspots.
"""

from __future__ import annotations

import json
import os
import time
from contextlib import contextmanager
from typing import Any

try:
    from export_primitives import addr_str
except Exception:  # pragma: no cover
    addr_str = None


_ACTIVE_PROFILER: ExportProfiler | None = None
_DECOMPILE_CACHE: dict[str, dict[str, Any]] = {}

def _env_flag(name, default=True):
    value = os.environ.get(name)
    if value is None:
        return bool(default)
    return str(value).strip().lower() not in ("0", "false", "no", "off")


def _env_float(name, default):
    value = os.environ.get(name)
    if value is None:
        return float(default)
    value = str(value).strip()
    if not value:
        return float(default)
    try:
        return float(value)
    except Exception:
        return float(default)


_DECOMPILE_CACHE_ENABLED = _env_flag("BINARY_LENS_DECOMPILE_CACHE", True)

_DECOMPILE_SLOW_GUARD_SECONDS = _env_float("BINARY_LENS_DECOMPILE_SLOW_GUARD_SECONDS", 10.0)
if _DECOMPILE_SLOW_GUARD_SECONDS <= 0:
    _DECOMPILE_SLOW_GUARD_SECONDS = None


def get_profiler():
    return _ACTIVE_PROFILER


def ensure_profiler(pack_root=None, enabled=False):
    global _ACTIVE_PROFILER
    if _ACTIVE_PROFILER is None and enabled:
        _ACTIVE_PROFILER = ExportProfiler(pack_root=pack_root)
    if _ACTIVE_PROFILER is not None and pack_root and not _ACTIVE_PROFILER.pack_root:
        _ACTIVE_PROFILER.pack_root = pack_root
    return _ACTIVE_PROFILER


class ExportProfiler:
    def __init__(self, pack_root=None):
        self.pack_root = pack_root
        self.timings: dict[str, dict[str, Any]] = {}
        self.metadata: dict[str, Any] = {}
        self.analysis: dict[str, Any] = {}
        self._decompile_events: list[dict[str, Any]] = []
        self._decompile_requests: list[dict[str, Any]] = []

    def _function_payload(self, func):
        func_name = None
        func_addr = None
        if func is not None:
            try:
                func_name = func.getName()
            except Exception:
                func_name = None
            try:
                entry = func.getEntryPoint()
            except Exception:
                entry = None
            if entry is not None:
                if addr_str is not None:
                    try:
                        func_addr = addr_str(entry)
                    except Exception:
                        func_addr = None
                if func_addr is None:
                    try:
                        func_addr = str(entry)
                    except Exception:
                        func_addr = None
        return {"name": func_name, "address": func_addr}

    @contextmanager
    def phase(self, name):
        start = time.perf_counter()
        try:
            yield
        finally:
            elapsed = time.perf_counter() - start
            self.add_timing(name, elapsed)

    def add_timing(self, name, seconds):
        if not name:
            return
        if seconds is None:
            return
        entry = self.timings.get(name)
        if entry is None:
            entry = {"seconds": 0.0, "count": 0}
            self.timings[name] = entry
        entry["seconds"] += float(seconds)
        entry["count"] += 1

    def record_decompile(self, func, seconds, purpose=None, timeout_seconds=None):
        if seconds is None:
            return
        event = {
            "seconds": float(seconds),
            "purpose": purpose,
            "timeout_seconds": timeout_seconds,
            "function": self._function_payload(func),
        }
        self._decompile_events.append(event)

    def record_decompile_request(
        self,
        func,
        purpose=None,
        timeout_seconds=None,
        status=None,
    ):
        event = {
            "purpose": purpose,
            "timeout_seconds": timeout_seconds,
            "status": status,
            "function": self._function_payload(func),
        }
        self._decompile_requests.append(event)

    def set_analysis_snapshot(self, snapshot):
        if snapshot is None:
            return
        self.analysis = snapshot

    def write_profile(self):
        if not self.pack_root:
            return
        profile_dir = os.path.join(self.pack_root, "profile")
        try:
            os.makedirs(profile_dir, exist_ok=True)
        except Exception:
            return
        self._write_json(os.path.join(profile_dir, "timings.json"), self._build_timings_payload())
        self._write_json(os.path.join(profile_dir, "decompile.json"), self._build_decompile_payload())
        if self.analysis:
            self._write_json(os.path.join(profile_dir, "analyzers.json"), self.analysis)

    def _build_timings_payload(self):
        return {
            "version": 1,
            "phases": self.timings,
            "metadata": self.metadata,
        }

    def _build_decompile_payload(self, top_n=25):
        samples = [event.get("seconds") for event in self._decompile_events if event.get("seconds") is not None]
        count = len(samples)
        payload = {
            "version": 1,
            "count": count,
            "unique_function_count": 0,
            "duplicate_function_count": 0,
            "duplicate_call_count": 0,
            "by_purpose": [],
            "top_duplicated_functions": [],
            "request_count": 0,
            "request_unique_function_count": 0,
            "request_duplicate_function_count": 0,
            "request_duplicate_call_count": 0,
            "request_by_purpose": [],
            "request_top_duplicated_functions": [],
            "cache_hit_count": 0,
            "skipped_due_to_prior_fail_count": 0,
            "skipped_due_to_prior_slow_count": 0,
            "total_seconds": float(sum(samples)) if samples else 0.0,
            "p50_seconds": None,
            "p95_seconds": None,
            "slowest": [],
        }
        if not samples:
            return payload

        by_purpose = {}
        by_function = {}
        unknown_func_count = 0
        for event in self._decompile_events:
            seconds = event.get("seconds")
            if seconds is None:
                continue
            purpose = event.get("purpose") or "unknown"
            purpose_entry = by_purpose.get(purpose)
            if purpose_entry is None:
                purpose_entry = {"purpose": purpose, "count": 0, "total_seconds": 0.0}
                by_purpose[purpose] = purpose_entry
            purpose_entry["count"] += 1
            purpose_entry["total_seconds"] += float(seconds)

            func = event.get("function") or {}
            addr = func.get("address")
            if not addr:
                unknown_func_count += 1
                continue
            func_entry = by_function.get(addr)
            if func_entry is None:
                func_entry = {
                    "function": {"address": addr, "name": func.get("name")},
                    "count": 0,
                    "total_seconds": 0.0,
                    "purposes": set(),
                }
                by_function[addr] = func_entry
            func_entry["count"] += 1
            func_entry["total_seconds"] += float(seconds)
            func_entry["purposes"].add(purpose)
            if not func_entry["function"].get("name") and func.get("name"):
                func_entry["function"]["name"] = func.get("name")

        payload["by_purpose"] = sorted(
            by_purpose.values(),
            key=lambda item: (-(item.get("total_seconds") or 0.0), item.get("purpose") or ""),
        )

        unique_count = len(by_function)
        duplicate_func_count = 0
        duplicate_call_count = 0
        duplicated = []
        for entry in by_function.values():
            entry_count = int(entry.get("count") or 0)
            if entry_count > 1:
                duplicate_func_count += 1
                duplicate_call_count += entry_count - 1
                duplicated.append(entry)

        payload["unique_function_count"] = unique_count
        payload["duplicate_function_count"] = duplicate_func_count
        payload["duplicate_call_count"] = duplicate_call_count
        if unknown_func_count:
            payload["unknown_function_count"] = int(unknown_func_count)

        duplicated_sorted = sorted(
            duplicated,
            key=lambda item: (
                -(item.get("count") or 0),
                -(item.get("total_seconds") or 0.0),
                item.get("function", {}).get("address") or "",
            ),
        )
        top_dupes = []
        for entry in duplicated_sorted[: max(0, int(top_n))]:
            top_dupes.append(
                {
                    "function": entry.get("function") or {},
                    "count": int(entry.get("count") or 0),
                    "total_seconds": float(entry.get("total_seconds") or 0.0),
                    "purposes": sorted(entry.get("purposes") or []),
                }
            )
        payload["top_duplicated_functions"] = top_dupes

        # Requests include cache hits + slow/fail guard skips.
        request_events = self._decompile_requests or []
        payload["request_count"] = len(request_events)
        if request_events:
            req_by_purpose = {}
            req_by_function = {}
            req_unknown_func_count = 0
            cache_hits = 0
            skip_prior_fail = 0
            skip_prior_slow = 0
            for event in request_events:
                purpose = event.get("purpose") or "unknown"
                purpose_entry = req_by_purpose.get(purpose)
                if purpose_entry is None:
                    purpose_entry = {
                        "purpose": purpose,
                        "count": 0,
                        "cache_hit_count": 0,
                        "skipped_due_to_prior_fail_count": 0,
                        "skipped_due_to_prior_slow_count": 0,
                    }
                    req_by_purpose[purpose] = purpose_entry
                purpose_entry["count"] += 1
                status = event.get("status")
                if status == "cache_hit":
                    cache_hits += 1
                    purpose_entry["cache_hit_count"] += 1
                elif status == "skipped_due_to_prior_fail":
                    skip_prior_fail += 1
                    purpose_entry["skipped_due_to_prior_fail_count"] += 1
                elif status == "skipped_due_to_prior_slow":
                    skip_prior_slow += 1
                    purpose_entry["skipped_due_to_prior_slow_count"] += 1

                func = event.get("function") or {}
                addr = func.get("address")
                if not addr:
                    req_unknown_func_count += 1
                    continue
                func_entry = req_by_function.get(addr)
                if func_entry is None:
                    func_entry = {
                        "function": {"address": addr, "name": func.get("name")},
                        "count": 0,
                        "purposes": set(),
                        "status_counts": {},
                    }
                    req_by_function[addr] = func_entry
                func_entry["count"] += 1
                func_entry["purposes"].add(purpose)
                if status:
                    func_entry["status_counts"][status] = func_entry["status_counts"].get(status, 0) + 1
                if not func_entry["function"].get("name") and func.get("name"):
                    func_entry["function"]["name"] = func.get("name")

            payload["cache_hit_count"] = cache_hits
            payload["skipped_due_to_prior_fail_count"] = skip_prior_fail
            payload["skipped_due_to_prior_slow_count"] = skip_prior_slow

            payload["request_by_purpose"] = sorted(
                req_by_purpose.values(),
                key=lambda item: (-(item.get("count") or 0), item.get("purpose") or ""),
            )
            req_unique_count = len(req_by_function)
            req_duplicate_func_count = 0
            req_duplicate_call_count = 0
            req_duplicated = []
            for entry in req_by_function.values():
                entry_count = int(entry.get("count") or 0)
                if entry_count > 1:
                    req_duplicate_func_count += 1
                    req_duplicate_call_count += entry_count - 1
                    req_duplicated.append(entry)
            payload["request_unique_function_count"] = req_unique_count
            payload["request_duplicate_function_count"] = req_duplicate_func_count
            payload["request_duplicate_call_count"] = req_duplicate_call_count
            if req_unknown_func_count:
                payload["request_unknown_function_count"] = int(req_unknown_func_count)

            req_duplicated_sorted = sorted(
                req_duplicated,
                key=lambda item: (
                    -(item.get("count") or 0),
                    item.get("function", {}).get("address") or "",
                ),
            )
            req_top_dupes = []
            for entry in req_duplicated_sorted[: max(0, int(top_n))]:
                req_top_dupes.append(
                    {
                        "function": entry.get("function") or {},
                        "count": int(entry.get("count") or 0),
                        "purposes": sorted(entry.get("purposes") or []),
                        "status_counts": entry.get("status_counts") or {},
                    }
                )
            payload["request_top_duplicated_functions"] = req_top_dupes

        samples_sorted = sorted(samples)
        payload["p50_seconds"] = _percentile(samples_sorted, 0.50)
        payload["p95_seconds"] = _percentile(samples_sorted, 0.95)
        slowest = sorted(self._decompile_events, key=lambda ev: ev.get("seconds") or 0.0, reverse=True)
        payload["slowest"] = slowest[: max(0, int(top_n))]
        return payload

    def _write_json(self, path, payload):
        try:
            handle = open(path, "w", encoding="utf-8")
        except Exception:
            return
        try:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
        except Exception:
            pass
        finally:
            try:
                handle.close()
            except Exception:
                pass


def _percentile(sorted_samples, fraction):
    if not sorted_samples:
        return None
    if fraction <= 0:
        return float(sorted_samples[0])
    if fraction >= 1:
        return float(sorted_samples[-1])
    idx = int(round((len(sorted_samples) - 1) * float(fraction)))
    idx = max(0, min(len(sorted_samples) - 1, idx))
    return float(sorted_samples[idx])


def profiled_decompile(decomp_interface, func, timeout_seconds, monitor=None, purpose=None):
    profiler = get_profiler()
    cache_key = None
    if _DECOMPILE_CACHE_ENABLED and func is not None:
        entry = None
        try:
            entry = func.getEntryPoint()
        except Exception:
            entry = None
        if entry is not None:
            if addr_str is not None:
                try:
                    cache_key = addr_str(entry)
                except Exception:
                    cache_key = None
            if cache_key is None:
                try:
                    cache_key = str(entry)
                except Exception:
                    cache_key = None

        if cache_key:
            cached = _DECOMPILE_CACHE.get(cache_key)
            if cached is not None:
                status = "cache_hit"
                if cached.get("completed") is False or cached.get("result") is None:
                    status = "skipped_due_to_prior_fail"
                elif cached.get("slow"):
                    status = "skipped_due_to_prior_slow"
                if profiler is not None:
                    profiler.record_decompile_request(
                        func,
                        purpose=purpose,
                        timeout_seconds=timeout_seconds,
                        status=status,
                    )
                return cached.get("result")

    start = time.perf_counter()
    result = None
    try:
        result = decomp_interface.decompileFunction(func, timeout_seconds, monitor)
    except Exception:
        result = None
    elapsed = time.perf_counter() - start
    completed = bool(result and result.decompileCompleted())
    slow = _DECOMPILE_SLOW_GUARD_SECONDS is not None and elapsed > float(_DECOMPILE_SLOW_GUARD_SECONDS)

    if cache_key:
        _DECOMPILE_CACHE[cache_key] = {
            "result": result,
            "completed": completed,
            "seconds": float(elapsed),
            "slow": bool(slow),
        }

    if profiler is not None:
        profiler.record_decompile(
            func,
            elapsed,
            purpose=purpose,
            timeout_seconds=timeout_seconds,
        )
        profiler.record_decompile_request(
            func,
            purpose=purpose,
            timeout_seconds=timeout_seconds,
            status="executed" if completed else "executed_failed",
        )
    return result
