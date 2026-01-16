"""Recover callsite argument values.

The exporter uses these helpers to pull string/constant arguments from selected
call edges (e.g., `strcmp` dispatch sites, `getopt` parse loops). Resolution is
best-effort and intentionally bounded: a decompile failure should degrade
gracefully rather than failing the overall export.
"""

from collectors.ghidra_memory import _resolve_string_at, _to_address
from collectors.pcode import _resolve_varnode_addr, _resolve_varnode_constant, _varnode_key
from export_primitives import addr_str, addr_to_int
from export_profile import profiled_decompile
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.pcode import PcodeOp
from symbols import IMPORT_SYMBOL_POLICY, normalize_symbol_name

GETTEXT_FAMILY_ARG_INDICES = {
    "gettext": (0,),
    "dgettext": (1,),
    "dcgettext": (1,),
    "ngettext": (0, 1),
    "dngettext": (1, 2),
    "dcngettext": (1, 2),
}

GETTEXT_FAMILY_ALIASES = {
    "gettext": ("libintl_gettext",),
    "dgettext": ("libintl_dgettext",),
    "dcgettext": ("libintl_dcgettext",),
    "ngettext": ("libintl_ngettext",),
    "dngettext": ("libintl_dngettext",),
    "dcngettext": ("libintl_dcngettext",),
}


def _build_gettext_name_map():
    name_map = {}
    for canonical in GETTEXT_FAMILY_ARG_INDICES:
        name_map[canonical] = canonical
        for alias in GETTEXT_FAMILY_ALIASES.get(canonical, ()):
            name_map[alias] = canonical
    normalized = {}
    for name, canonical in name_map.items():
        norm = normalize_symbol_name(name, policy=IMPORT_SYMBOL_POLICY)
        if norm:
            normalized[norm] = canonical
    return normalized


GETTEXT_FAMILY_NAME_MAP = _build_gettext_name_map()


def _call_target_name(program, call_op):
    try:
        target = call_op.getInput(0)
    except Exception:
        return None
    if target is None:
        return None
    addr = None
    try:
        addr = target.getAddress()
    except Exception:
        addr = None
    if addr is None:
        try:
            if target.isConstant():
                addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(target.getOffset())
        except Exception:
            addr = None
    if addr is None:
        return None
    try:
        func = program.getFunctionManager().getFunctionAt(addr)
    except Exception:
        func = None
    if func is None:
        try:
            func = program.getFunctionManager().getFunctionContaining(addr)
        except Exception:
            func = None
    if func is not None:
        try:
            return func.getName()
        except Exception:
            return None
    try:
        symbol = program.getSymbolTable().getPrimarySymbol(addr)
    except Exception:
        symbol = None
    if symbol is not None:
        try:
            return symbol.getName()
        except Exception:
            return None
    return None


def _callsite_id_for_op(op):
    try:
        seq = op.getSeqnum()
    except Exception:
        return None
    try:
        target = seq.getTarget()
    except Exception:
        return None
    return addr_str(target)


def _resolve_gettext_strings(program, varnode):
    try:
        def_op = varnode.getDef()
    except Exception:
        def_op = None
    if def_op is None:
        return []
    try:
        if def_op.getOpcode() != PcodeOp.CALL:
            return []
    except Exception:
        return []
    callee_name = _call_target_name(program, def_op)
    canonical = normalize_symbol_name(callee_name, policy=IMPORT_SYMBOL_POLICY) if callee_name else None
    if canonical:
        canonical = GETTEXT_FAMILY_NAME_MAP.get(canonical)
    if not canonical:
        return []
    msg_indices = GETTEXT_FAMILY_ARG_INDICES.get(canonical, ())
    if not msg_indices:
        return []
    provider_callsite_id = _callsite_id_for_op(def_op)
    entries = []
    for msg_index in msg_indices:
        try:
            arg_node = def_op.getInput(msg_index + 1)
        except Exception:
            continue
        const_addr = _resolve_varnode_addr(program, arg_node)
        if const_addr is None:
            continue
        addr_text = addr_str(const_addr)
        value = _resolve_string_at(program, const_addr)
        if value is None:
            continue
        entry = {
            "address": addr_text,
            "value": value,
            "source": "gettext",
        }
        if provider_callsite_id:
            entry["provider_callsite_id"] = provider_callsite_id
        entries.append(entry)
    return entries


def _symbol_name_at(program, addr):
    if addr is None:
        return None
    try:
        symbol = program.getSymbolTable().getPrimarySymbol(addr)
    except Exception:
        symbol = None
    if symbol is not None:
        try:
            name = symbol.getName()
        except Exception:
            name = None
        if name:
            return name
    return None


def _resolve_symbol_entries(program, varnode, const_addr=None, max_depth=4, visited=None):
    entries = []
    seen = set()

    def _add_entry(addr, name):
        addr_text = addr_str(addr)
        if not addr_text or not name:
            return
        key = (addr_text, name)
        if key in seen:
            return
        seen.add(key)
        entries.append({
            "address": addr_text,
            "name": name,
        })

    addr = None
    try:
        if varnode is not None and (varnode.isAddrTied() or varnode.isPersistent()):
            addr = varnode.getAddress()
            if addr is not None:
                try:
                    if addr.isStackAddress():
                        addr = None
                except Exception:
                    addr = None
    except Exception:
        addr = None
    if addr is not None:
        _add_entry(addr, _symbol_name_at(program, addr))
    if const_addr is not None:
        _add_entry(const_addr, _symbol_name_at(program, const_addr))

    if max_depth <= 0 or varnode is None:
        return entries

    if visited is None:
        visited = set()
    key = _varnode_key(varnode)
    if key is None:
        key = id(varnode)
    if key in visited:
        return entries
    visited.add(key)

    try:
        def_op = varnode.getDef()
    except Exception:
        def_op = None
    if def_op is None:
        return entries
    try:
        opcode = def_op.getOpcode()
    except Exception:
        return entries

    def _merge(incoming):
        for entry in incoming:
            _add_entry(entry.get("address"), entry.get("name"))

    if opcode in (
        PcodeOp.COPY,
        PcodeOp.CAST,
        PcodeOp.INT_ZEXT,
        PcodeOp.INT_SEXT,
        PcodeOp.SUBPIECE,
    ):
        _merge(_resolve_symbol_entries(program, def_op.getInput(0), max_depth=max_depth - 1, visited=visited))
    elif opcode == PcodeOp.MULTIEQUAL:
        for idx in range(def_op.getNumInputs()):
            _merge(
                _resolve_symbol_entries(program, def_op.getInput(idx), max_depth=max_depth - 1, visited=visited)
            )
    elif opcode == PcodeOp.LOAD:
        try:
            addr_node = def_op.getInput(1)
        except Exception:
            addr_node = None
        if addr_node is not None:
            load_addr = _resolve_varnode_addr(program, addr_node)
            if load_addr is not None:
                _add_entry(load_addr, _symbol_name_at(program, load_addr))
            _merge(_resolve_symbol_entries(program, addr_node, max_depth=max_depth - 1, visited=visited))
    elif opcode in (
        PcodeOp.INDIRECT,
        PcodeOp.PTRSUB,
        PcodeOp.PTRADD,
        PcodeOp.INT_ADD,
        PcodeOp.INT_SUB,
    ):
        for idx in range(def_op.getNumInputs()):
            _merge(
                _resolve_symbol_entries(program, def_op.getInput(idx), max_depth=max_depth - 1, visited=visited)
            )

    return entries


def _append_indexed_entry(indexed_map, index, value):
    bucket = indexed_map.get(index)
    if bucket is None:
        bucket = []
        indexed_map[index] = bucket
    bucket.append(value)


def _collect_stream_symbol_entries(program, varnode, const_addr, result, arg_index):
    """Recover FILE* symbols for downstream stdout/stderr classification."""

    entries = _resolve_symbol_entries(program, varnode, const_addr)
    if not entries:
        return
    for entry in entries:
        entry["index"] = arg_index
        result["symbol_args"].append(entry)
        _append_indexed_entry(result["symbol_args_by_index"], arg_index, entry)


def _recover_direct_string_arg(program, const_addr, result, arg_index, seen_addrs):
    """Resolve direct string/data references from constant addresses."""

    if const_addr is None:
        return False
    addr_text = addr_str(const_addr)
    if not addr_text or addr_text in seen_addrs:
        return True
    seen_addrs.add(addr_text)
    result["arg_addrs"].append(addr_text)
    value = _resolve_string_at(program, const_addr)
    if value is not None:
        result["string_args"].append({
            "index": arg_index,
            "address": addr_text,
            "value": value,
        })
    else:
        result["data_args"].append(addr_text)
        _append_indexed_entry(result["data_args_by_index"], arg_index, addr_text)
    return True


def _recover_gettext_string_arg(program, varnode, result, arg_index):
    """Recover gettext-family message templates referenced via helper calls."""

    indirect_entries = _resolve_gettext_strings(program, varnode)
    if not indirect_entries:
        return False
    for entry in indirect_entries:
        entry["index"] = arg_index
        result["string_args"].append(entry)
    return True


def _recover_int_constant_arg(program, varnode, result, arg_index):
    const_value = _resolve_varnode_constant(program, varnode)
    if const_value is None:
        return False
    result["const_args"].append({
        "index": arg_index,
        "value": const_value,
    })
    result["const_args_by_index"][arg_index] = const_value
    return True


def _init_callsite_result(callsite_addr):
    return {
        "callsite": callsite_addr,
        "status": "unresolved",
        "arg_addrs": [],
        "string_args": [],
        "data_args": [],
        "data_args_by_index": {},
        "symbol_args": [],
        "symbol_args_by_index": {},
        "const_args": [],
        "const_args_by_index": {},
    }


def _update_status(result, new_status):
    if result.get("status") == "unresolved":
        result["status"] = new_status


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
        "data_args_by_index": {},
        "symbol_args": [],
        "symbol_args_by_index": {},
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
        result = _init_callsite_result(callsite_addr)
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
                _update_status(results.get(callsite_id, {}), "decompile_failed")
            continue
        high_func = decomp_result.getHighFunction()
        if high_func is None:
            for callsite_id in callsites:
                _update_status(results.get(callsite_id, {}), "no_high_function")
            continue

        found = set()
        op_iter = high_func.getPcodeOps()
        while op_iter.hasNext():
            if monitor is not None and monitor.isCancelled():
                for callsite_id in callsites:
                    _update_status(results.get(callsite_id, {}), "cancelled")
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
                arg_index = idx - 1
                const_addr = _resolve_varnode_addr(program, varnode)
                _collect_stream_symbol_entries(program, varnode, const_addr, result, arg_index)
                if _recover_direct_string_arg(program, const_addr, result, arg_index, seen_addrs):
                    continue
                if _recover_gettext_string_arg(program, varnode, result, arg_index):
                    continue
                _recover_int_constant_arg(program, varnode, result, arg_index)
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
