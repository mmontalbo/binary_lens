"""Dispatch classification heuristics for mode detection.

This module assigns a coarse "dispatch_kind" for each selected compare-caller
function (and its compare callsites). The classifications are used for:
- ranking / filtering mode candidates
- enriching the dispatch_sites payload for debugging and analysis

The heuristics intentionally rely on small, cheap signals (token prefixes,
argv index mentions, adjacent table-dispatch roots) to keep analysis stable.
"""

import re

from export_collectors import _to_address
from ghidra.app.decompiler import DecompInterface
from modes.common import _c_string_literal
from modes.ghidra_helpers import _decompile_function_text

_ARGV0_RE = re.compile(r"\bargv\s*\[\s*0\s*\]|\*\s*argv\b|\bargv\s*\+\s*0\b")
_ARGV1_RE = re.compile(r"\bargv\s*\[\s*1\s*\]|\bargv\s*\+\s*1\b")
_SWITCH_RE = re.compile(r"\bswitch\s*\(")


def _detect_argv_index(decomp_text, token_literals):
    if not decomp_text or not token_literals:
        return 0, 0
    argv0_hits = 0
    argv1_hits = 0
    for line in decomp_text.splitlines():
        if not any(literal in line for literal in token_literals):
            continue
        if _ARGV0_RE.search(line):
            argv0_hits += 1
        if _ARGV1_RE.search(line):
            argv1_hits += 1
    return argv0_hits, argv1_hits


def _detect_argv_index_for_callees(decomp_text, callee_names):
    if not decomp_text or not callee_names:
        return 0, 0
    argv0_hits = 0
    argv1_hits = 0
    for line in decomp_text.splitlines():
        if not any(name and name in line for name in callee_names):
            continue
        if _ARGV0_RE.search(line):
            argv0_hits += 1
        if _ARGV1_RE.search(line):
            argv1_hits += 1
    return argv0_hits, argv1_hits


def _classify_dispatch_groups(
    program,
    groups,
    callsite_tokens,
    table_dispatch_funcs=None,
    handler_diversity_by_func=None,
    monitor=None,
):
    dispatch_meta_by_func = {}
    dispatch_meta_by_callsite = {}
    if not groups:
        return dispatch_meta_by_func, dispatch_meta_by_callsite

    func_manager = program.getFunctionManager()
    decomp_iface = DecompInterface()
    decomp_iface.openProgram(program)
    decomp_cache = {}

    for group in groups:
        func = group.get("function") or {}
        func_addr = func.get("address")
        func_name = func.get("name")
        callsite_ids = group.get("callsites") or []
        base_kind = "string_compare_chain" if len(callsite_ids) > 1 else "string_compare"

        token_values = []
        token_literals = []
        seen_values = set()
        dash_count = 0
        for callsite_id in callsite_ids:
            for token in callsite_tokens.get(callsite_id, []):
                value = token.get("value")
                if not value or value in seen_values:
                    continue
                seen_values.add(value)
                token_values.append(value)
                token_literals.append(_c_string_literal(value))
                if value.startswith("-"):
                    dash_count += 1

        decomp_text = None
        if func_addr:
            if func_addr in decomp_cache:
                decomp_text = decomp_cache[func_addr]
            else:
                addr = _to_address(program, func_addr)
                func_obj = func_manager.getFunctionAt(addr) if addr else None
                decomp_text = _decompile_function_text(decomp_iface, func_obj, monitor)
                decomp_cache[func_addr] = decomp_text

        kind = base_kind
        strength = "heuristic"
        confidence = "low"
        basis = "compare_callsite_count"
        argv_index = None
        argv_index_basis = None

        if table_dispatch_funcs and func_addr in table_dispatch_funcs:
            kind = "table_dispatch"
            strength = "derived"
            confidence = "medium"
            basis = "string_table_adjacent_function_ptrs"
            argv0_hits, argv1_hits = _detect_argv_index(decomp_text, token_literals)
            if not (argv0_hits or argv1_hits):
                argv0_hits, argv1_hits = _detect_argv_index_for_callees(
                    decomp_text,
                    group.get("callee_names") or [],
                )
                if argv0_hits or argv1_hits:
                    argv_index_basis = "argv_index_in_compare_lines"
            else:
                argv_index_basis = "argv_index_in_token_lines"
            if argv0_hits or argv1_hits:
                argv_index = 0 if argv0_hits >= argv1_hits else 1
        else:
            flag_ratio = 0.0
            if token_values and dash_count:
                flag_ratio = float(dash_count) / float(len(token_values))
            if flag_ratio >= 0.6:
                kind = "flag_compare_chain"
                confidence = "low"
                basis = "token_prefix_dash"
            else:
                argv0_hits, argv1_hits = _detect_argv_index(decomp_text, token_literals)
                argv_basis = None
                if not (argv0_hits or argv1_hits):
                    argv0_hits, argv1_hits = _detect_argv_index_for_callees(
                        decomp_text,
                        group.get("callee_names") or [],
                    )
                    if argv0_hits or argv1_hits:
                        argv_basis = "argv_index_in_compare_lines"
                else:
                    argv_basis = "argv_index_in_token_lines"
                if argv0_hits or argv1_hits:
                    if argv0_hits >= argv1_hits and argv0_hits > 0:
                        kind = "argv0_compare_chain"
                        confidence = "medium" if argv0_hits > 1 else "low"
                    else:
                        kind = "argv1_compare_chain"
                        confidence = "medium" if argv1_hits > 1 else "low"
                    basis = argv_basis or "argv_index_in_decomp"
                elif handler_diversity_by_func and func_addr:
                    diversity = handler_diversity_by_func.get(func_addr, 0) or 0
                    if diversity >= 8:
                        kind = "argv0_compare_chain"
                        basis = "handler_assignment_diversity"
                        if func_name and func_name == "main":
                            kind = "argv1_compare_chain"
                            basis = "handler_assignment_diversity_in_main"
                        strength = "derived"
                        confidence = "high"
                elif decomp_text and _SWITCH_RE.search(decomp_text):
                    kind = "switch_dispatch"
                    confidence = "low"
                    basis = "switch_in_decomp"

        meta = {
            "kind": kind,
            "strength": strength,
            "confidence": confidence,
            "basis": basis,
        }
        if argv_index is not None:
            meta["argv_index"] = argv_index
            if argv_index_basis:
                meta["argv_index_basis"] = argv_index_basis
        if func_addr:
            dispatch_meta_by_func[func_addr] = meta
        for callsite_id in callsite_ids:
            dispatch_meta_by_callsite[callsite_id] = meta

    return dispatch_meta_by_func, dispatch_meta_by_callsite

