"""Derive `errors/exit_paths.json` payload."""

from collectors.call_args import extract_call_args_for_callsites
from errors.common import EXIT_CALL_NAMES, INT_TYPES, _collect_callsites
from export_bounds import Bounds
from export_config import DEFAULT_MAX_DECOMPILE_FUNCTION_SIZE
from export_primitives import addr_to_int


def derive_exit_paths(
    program,
    monitor,
    call_edges,
    function_meta_by_addr,
    bounds: Bounds,
    call_args_cache=None,
    emitter_callsites_by_func=None,
):
    if call_args_cache is None:
        call_args_cache = {}
    exit_callsites, exit_callsites_by_func = _collect_callsites(
        call_edges,
        function_meta_by_addr,
        EXIT_CALL_NAMES,
    )
    direct_calls = []
    max_exit_call_arg_function_size = DEFAULT_MAX_DECOMPILE_FUNCTION_SIZE
    skipped_large_exit_call_args = 0
    missing_exit_callsites = []
    for callsite in exit_callsites:
        callsite_id = callsite.get("callsite_id")
        if not callsite_id or callsite_id in call_args_cache:
            continue
        if callsite.get("emitter_import") not in ("exit",):
            continue
        func_id = callsite.get("function_id")
        meta = function_meta_by_addr.get(func_id, {}) if function_meta_by_addr else {}
        size = meta.get("size")
        try:
            size = int(size)
        except Exception:
            size = 0
        if size and size > max_exit_call_arg_function_size:
            skipped_large_exit_call_args += 1
            continue
        missing_exit_callsites.append(callsite_id)
    if missing_exit_callsites:
        call_args_cache.update(
            extract_call_args_for_callsites(
                program,
                missing_exit_callsites,
                monitor,
                purpose="export_errors.derive_exit_paths",
            )
        )
    for callsite in exit_callsites:
        callsite_id = callsite["callsite_id"]
        args = call_args_cache.get(callsite_id) or {}
        exit_code = None
        if callsite.get("emitter_import") in ("exit",):
            const_value = args.get("const_args_by_index", {}).get(0)
            if isinstance(const_value, INT_TYPES):
                exit_code = int(const_value)
        direct_calls.append({
            "callsite_id": callsite_id,
            "function_id": callsite["function_id"],
            "target_id": callsite.get("target_id"),
            "exit_code": exit_code,
            "evidence": {
                "callsites": [callsite_id],
                "functions": [callsite.get("function_id")],
            },
        })
    direct_calls.sort(key=lambda item: addr_to_int(item.get("callsite_id")))
    max_exit_paths = bounds.optional("max_exit_paths")
    truncated = False
    if max_exit_paths and len(direct_calls) > max_exit_paths:
        direct_calls = direct_calls[:max_exit_paths]
        truncated = True

    payload = {
        "total_exit_calls": len(exit_callsites),
        "selected_exit_calls": len(direct_calls),
        "truncated": truncated,
        "max_exit_calls": max_exit_paths,
        "direct_calls": direct_calls,
    }
    if skipped_large_exit_call_args:
        payload["exit_code_call_args_skipped_due_to_size"] = skipped_large_exit_call_args
    return payload, exit_callsites_by_func, call_args_cache
