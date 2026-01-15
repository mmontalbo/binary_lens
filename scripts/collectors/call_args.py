"""Recover callsite argument values.

The exporter uses these helpers to pull string/constant arguments from selected
call edges (e.g., `strcmp` dispatch sites, `getopt` parse loops). Resolution is
best-effort and intentionally bounded: a decompile failure should degrade
gracefully rather than failing the overall export.
"""

from collectors.ghidra_memory import _resolve_string_at, _to_address
from collectors.pcode import _resolve_varnode_addr, _resolve_varnode_constant
from export_primitives import addr_str, addr_to_int
from export_profile import profiled_decompile
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.pcode import PcodeOp


def extract_call_args(program, callsite_addr, monitor=None, purpose=None):
    results = extract_call_args_for_callsites(program, [callsite_addr], monitor, purpose=purpose)
    if callsite_addr in results:
        return results[callsite_addr]
    return {
        "callsite": callsite_addr,
        "status": "invalid_address",
        "arg_addrs": [],
        "string_args": [],
        "data_args": [],
        "const_args": [],
        "const_args_by_index": {},
    }


def extract_call_args_for_callsites(program, callsite_addrs, monitor=None, purpose=None):
    results = {}
    if not callsite_addrs:
        return results
    if not purpose:
        purpose = "export_collectors.extract_call_args_for_callsites"

    func_manager = program.getFunctionManager()
    groups = {}
    for callsite_addr in callsite_addrs:
        if not callsite_addr:
            continue
        result = {
            "callsite": callsite_addr,
            "status": "unresolved",
            "arg_addrs": [],
            "string_args": [],
            "data_args": [],
            "const_args": [],
            "const_args_by_index": {},
        }
        results[callsite_addr] = result
        addr = _to_address(program, callsite_addr)
        if addr is None:
            result["status"] = "invalid_address"
            continue
        func = func_manager.getFunctionContaining(addr)
        if func is None:
            result["status"] = "no_function"
            continue
        result["function"] = {
            "address": addr_str(func.getEntryPoint()),
            "name": func.getName(),
        }
        func_id = addr_str(func.getEntryPoint())
        group = groups.get(func_id)
        if group is None:
            group = {
                "function": func,
                "callsites": [],
            }
            groups[func_id] = group
        group["callsites"].append(callsite_addr)

    if not groups:
        return results

    decomp = DecompInterface()
    decomp.openProgram(program)

    for group in groups.values():
        func = group["function"]
        callsites = sorted(set(group["callsites"]), key=addr_to_int)
        callsite_set = set(callsites)
        decomp_result = profiled_decompile(
            decomp,
            func,
            30,
            monitor,
            purpose=purpose,
        )
        if not decomp_result or not decomp_result.decompileCompleted():
            for callsite_id in callsites:
                if results.get(callsite_id, {}).get("status") == "unresolved":
                    results[callsite_id]["status"] = "decompile_failed"
            continue
        high_func = decomp_result.getHighFunction()
        if high_func is None:
            for callsite_id in callsites:
                if results.get(callsite_id, {}).get("status") == "unresolved":
                    results[callsite_id]["status"] = "no_high_function"
            continue

        found = set()
        op_iter = high_func.getPcodeOps()
        while op_iter.hasNext():
            if monitor is not None and monitor.isCancelled():
                for callsite_id in callsites:
                    if results.get(callsite_id, {}).get("status") == "unresolved":
                        results[callsite_id]["status"] = "cancelled"
                break
            op = op_iter.next()
            if op.getOpcode() not in (PcodeOp.CALL, PcodeOp.CALLIND):
                continue
            seq = op.getSeqnum()
            try:
                op_addr = seq.getTarget()
            except Exception:
                op_addr = None
            if op_addr is None:
                continue
            callsite_id = addr_str(op_addr)
            if callsite_id not in callsite_set:
                continue
            result = results.get(callsite_id)
            if result is None:
                continue
            result["status"] = "ok"
            seen_addrs = set()
            for idx in range(1, op.getNumInputs()):
                varnode = op.getInput(idx)
                const_addr = _resolve_varnode_addr(program, varnode)
                if const_addr is not None:
                    addr_text = addr_str(const_addr)
                    if addr_text is None or addr_text in seen_addrs:
                        continue
                    seen_addrs.add(addr_text)
                    result["arg_addrs"].append(addr_text)
                    value = _resolve_string_at(program, const_addr)
                    if value is not None:
                        result["string_args"].append({
                            "address": addr_text,
                            "value": value,
                        })
                    else:
                        result["data_args"].append(addr_text)
                    continue
                const_value = _resolve_varnode_constant(program, varnode)
                if const_value is not None:
                    result["const_args"].append({
                        "index": idx - 1,
                        "value": const_value,
                    })
                    result["const_args_by_index"][idx - 1] = const_value
            found.add(callsite_id)
            if len(found) == len(callsite_set):
                break

        for callsite_id in callsites:
            result = results.get(callsite_id)
            if result is None:
                continue
            if result.get("status") == "unresolved":
                result["status"] = "callsite_not_found"
            if result.get("status") == "ok":
                if (
                    not result.get("string_args")
                    and not result.get("data_args")
                    and not result.get("const_args")
                ):
                    result["status"] = "no_resolved_args"

    return results
