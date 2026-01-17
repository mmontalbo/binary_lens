"""Compare-chain analysis for mode dispatch detection.

Many CLIs implement mode/subcommand dispatch by comparing a token (often argv[1]) and
then either calling a handler directly or assigning a handler function pointer.
This module focuses on extracting candidate handler targets from those post-compare
"chains" so higher-level heuristics can attach implementation roots to modes.
"""

from collectors.pcode import _resolve_varnode_addr
from export_primitives import addr_str, addr_to_int
from export_profile import profiled_decompile
from ghidra.program.model.pcode import PcodeOp
from modes.handlers import _is_ignored_handler_name, _is_usage_like_handler_name


def _build_callsite_maps(call_edges):
    callsites_by_func = {}
    callsite_targets = {}
    callsite_target_seen = {}
    for edge in call_edges:
        callsite = edge.get("callsite")
        if not callsite:
            continue
        from_addr = (edge.get("from") or {}).get("address")
        if from_addr:
            callsites = callsites_by_func.get(from_addr)
            if callsites is None:
                callsites = set()
                callsites_by_func[from_addr] = callsites
            callsites.add(callsite)
        target = edge.get("to") or {}
        target_addr = target.get("address")
        if not target_addr:
            continue
        seen = callsite_target_seen.get(callsite)
        if seen is None:
            seen = set()
            callsite_target_seen[callsite] = seen
        if target_addr in seen:
            continue
        seen.add(target_addr)
        entry = {
            "function_id": target_addr,
            "function_name": target.get("name"),
            "external": target.get("external"),
        }
        callsite_targets.setdefault(callsite, []).append(entry)
    for func_id, callsites in callsites_by_func.items():
        callsites_by_func[func_id] = sorted(callsites, key=addr_to_int)
    return callsites_by_func, callsite_targets


def _collect_compare_chain_targets(callsites_by_func, callsite_targets, compare_callsites_by_func):
    compare_chain = {}
    for func_id, compare_callsites in compare_callsites_by_func.items():
        all_callsites = callsites_by_func.get(func_id, [])
        if not all_callsites:
            continue
        compare_set = set(compare_callsites)
        callsite_index = {callsite: idx for idx, callsite in enumerate(all_callsites)}
        for compare_callsite in compare_callsites:
            start_idx = callsite_index.get(compare_callsite)
            if start_idx is None:
                continue
            handler_callsite = None
            targets = []
            for idx in range(start_idx + 1, len(all_callsites)):
                candidate = all_callsites[idx]
                if candidate in compare_set:
                    break
                targets = callsite_targets.get(candidate, [])
                if not targets:
                    continue
                handler_callsite = candidate
                internal = [target for target in targets if not target.get("external")]
                if internal:
                    targets = internal
                break
            if not handler_callsite or not targets:
                continue
            entry = compare_chain.get(compare_callsite)
            if entry is None:
                entry = {}
                compare_chain[compare_callsite] = entry
            for target in targets:
                func_addr = target.get("function_id")
                if not func_addr:
                    continue
                entry[func_addr] = {
                    "function_id": func_addr,
                    "function_name": target.get("function_name"),
                    "handler_callsite_id": handler_callsite,
                    "external": target.get("external"),
                }
    result = {}
    for callsite_id, entries in compare_chain.items():
        result[callsite_id] = list(entries.values())
    return result


def _varnode_key(varnode):
    if varnode is None:
        return None
    high = None
    try:
        high = varnode.getHigh()
    except Exception:
        high = None
    if high is not None:
        try:
            name = high.getName()
        except Exception:
            name = None
        if name:
            return name
    try:
        return str(varnode)
    except Exception:
        return None


_PCODE_ASSIGNMENT_OPCODES = set(
    [
        PcodeOp.COPY,
        PcodeOp.CAST,
        PcodeOp.INT_ZEXT,
        PcodeOp.INT_SEXT,
        PcodeOp.SUBPIECE,
    ]
)


def _collect_compare_chain_assignments(
    program,
    decomp_iface,
    func_obj,
    compare_callsites,
    monitor=None,
):
    if func_obj is None or not compare_callsites or decomp_iface is None:
        return {}
    try:
        decomp_result = profiled_decompile(
            decomp_iface,
            func_obj,
            30,
            monitor,
            purpose="export_modes._collect_compare_chain_assignments",
        )
    except Exception:
        return {}
    if not decomp_result or not decomp_result.decompileCompleted():
        return {}
    try:
        high_func = decomp_result.getHighFunction()
    except Exception:
        high_func = None
    if high_func is None:
        return {}

    func_manager = program.getFunctionManager()
    events = []
    stats = {}
    try:
        op_iter = high_func.getPcodeOps()
    except Exception:
        op_iter = None
    if op_iter is None:
        return {}
    while op_iter.hasNext():
        if monitor is not None and monitor.isCancelled():
            break
        op = op_iter.next()
        try:
            opcode = op.getOpcode()
        except Exception:
            continue
        if opcode not in _PCODE_ASSIGNMENT_OPCODES:
            continue
        try:
            out_varnode = op.getOutput()
        except Exception:
            out_varnode = None
        if out_varnode is None:
            continue
        try:
            in_varnode = op.getInput(0)
        except Exception:
            continue
        addr = _resolve_varnode_addr(program, in_varnode)
        if addr is None:
            continue
        target_func = func_manager.getFunctionAt(addr)
        if target_func is None:
            continue
        try:
            if target_func.isExternal() or target_func.isThunk():
                continue
        except Exception:
            pass
        try:
            func_name = target_func.getName()
        except Exception:
            func_name = None
        if func_name and _is_ignored_handler_name(func_name):
            continue
        key = _varnode_key(out_varnode)
        if not key:
            continue
        try:
            assign_addr = op.getSeqnum().getTarget()
        except Exception:
            assign_addr = None
        assign_id = addr_str(assign_addr) if assign_addr else None
        if not assign_id:
            continue
        func_id = addr_str(target_func.getEntryPoint())
        if not func_id:
            continue
        usage_like = _is_usage_like_handler_name(func_name)
        events.append(
            {
                "assignment_id": assign_id,
                "function_id": func_id,
                "function_name": func_name,
                "var": key,
                "usage_like": usage_like,
            }
        )
        st = stats.get(key)
        if st is None:
            st = {"unique_non_usage": set(), "unique_all": set(), "count": 0}
            stats[key] = st
        st["count"] += 1
        st["unique_all"].add(func_id)
        if not usage_like:
            st["unique_non_usage"].add(func_id)

    if not events:
        return {}

    # Heuristic: the handler variable is the one that receives the widest variety
    # of non-usage function targets.
    best_key = None
    best_tuple = None
    for key, st in stats.items():
        score = (
            len(st.get("unique_non_usage") or []),
            st.get("count", 0),
            len(st.get("unique_all") or []),
        )
        if best_tuple is None or score > best_tuple:
            best_tuple = score
            best_key = key
    if best_tuple is None or best_tuple[0] < 2:
        return {}

    selected_events = [
        event for event in events if event.get("var") == best_key and not event.get("usage_like")
    ]
    if not selected_events:
        return {}
    selected_events.sort(key=lambda item: addr_to_int(item.get("assignment_id")))

    compare_sorted = sorted(set(compare_callsites), key=addr_to_int)
    compare_ints = [addr_to_int(c) for c in compare_sorted]

    mapping = {}
    idx = 0
    for i, compare_callsite in enumerate(compare_sorted):
        start = compare_ints[i]
        end = compare_ints[i + 1] if i + 1 < len(compare_ints) else None
        while (
            idx < len(selected_events)
            and addr_to_int(selected_events[idx].get("assignment_id")) <= start
        ):
            idx += 1
        j = idx
        candidates = []
        while j < len(selected_events):
            addr_int = addr_to_int(selected_events[j].get("assignment_id"))
            if end is not None and addr_int >= end:
                break
            candidates.append(selected_events[j])
            j += 1
        if not candidates:
            continue
        unique = []
        seen = set()
        for event in candidates:
            func_id = event.get("function_id")
            if not func_id or func_id in seen:
                continue
            seen.add(func_id)
            unique.append(event)
            if len(unique) >= 3:
                break
        if unique:
            mapping[compare_callsite] = unique

    return mapping
