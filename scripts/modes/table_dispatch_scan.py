"""Low-level table-dispatch scanning helpers.

This module contains the Ghidra-memory-facing primitives used by table-dispatch
heuristics:
- find handler targets adjacent to a token string pointer
- parse candidate table records (`{"token", handler_ptr}`-like layouts)
- build fast lookup maps for function-pointer resolution
"""

from export_collectors import _read_ptr_with_reloc, _resolve_string_at, _to_address
from export_primitives import addr_str
from modes.common import _looks_like_subcommand_token, _token_candidate
from modes.handlers import _is_ignored_handler_name


def _collect_table_dispatch_targets(program, string_addr_text, max_refs=8, max_targets=6):
    if not string_addr_text:
        return []
    string_addr = _to_address(program, string_addr_text)
    if string_addr is None:
        return []
    listing = program.getListing()
    ref_manager = program.getReferenceManager()
    func_manager = program.getFunctionManager()
    ptr_size = program.getDefaultPointerSize()
    big_endian = program.getLanguage().isBigEndian()
    targets = []
    seen = set()
    try:
        refs = ref_manager.getReferencesTo(string_addr)
    except Exception:
        refs = None
    if refs is None:
        return []
    ref_count = 0
    while refs.hasNext():
        ref = refs.next()
        from_addr = ref.getFromAddress()
        if from_addr is None:
            continue
        if listing.getInstructionAt(from_addr) is not None:
            continue
        ref_count += 1
        if max_refs and ref_count > max_refs:
            break
        for delta in (ptr_size, -ptr_size):
            try:
                if delta > 0:
                    entry_addr = from_addr.add(delta)
                else:
                    entry_addr = from_addr.subtract(-delta)
            except Exception:
                entry_addr = None
            if entry_addr is None:
                continue
            ptr_val = _read_ptr_with_reloc(program, entry_addr, ptr_size, big_endian)
            if not ptr_val:
                continue
            try:
                ptr_addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(ptr_val)
            except Exception:
                ptr_addr = None
            if ptr_addr is None:
                continue
            try:
                if not program.getMemory().contains(ptr_addr):
                    continue
            except Exception:
                pass
            func = func_manager.getFunctionAt(ptr_addr)
            if func is None:
                continue
            func_id = addr_str(func.getEntryPoint())
            if not func_id or func_id in seen:
                continue
            seen.add(func_id)
            targets.append(
                {
                    "function_id": func_id,
                    "function_name": func.getName(),
                    "table_entry_address": addr_str(from_addr),
                }
            )
            if max_targets and len(targets) >= max_targets:
                return targets
    return targets


def _collect_table_runs(slot_offsets, allowed_strides, min_entries):
    if not slot_offsets:
        return []
    if min_entries and min_entries <= 1:
        min_entries = 2
    slot_offsets = sorted(set(slot_offsets))
    runs = []
    run_start = slot_offsets[0]
    run_stride = None
    run_len = 1
    prev = slot_offsets[0]
    for offset in slot_offsets[1:]:
        diff = offset - prev
        if run_stride is None:
            if diff in allowed_strides:
                run_stride = diff
                run_len = 2
            else:
                run_start = offset
                run_len = 1
            prev = offset
            continue
        if diff == run_stride:
            run_len += 1
            prev = offset
            continue
        if run_len >= (min_entries or 2):
            runs.append(
                {
                    "start_offset": run_start,
                    "stride": run_stride,
                    "length": run_len,
                }
            )
        run_start = offset
        run_stride = None
        run_len = 1
        prev = offset
    if run_stride is not None and run_len >= (min_entries or 2):
        runs.append(
            {
                "start_offset": run_start,
                "stride": run_stride,
                "length": run_len,
            }
        )
    return runs


def _build_func_ptr_map(program):
    if program is None:
        return {}
    func_ptr_map = {}
    func_manager = program.getFunctionManager()
    try:
        funcs_iter = func_manager.getFunctions(True)
        while funcs_iter.hasNext():
            func = funcs_iter.next()
            if func is None:
                continue
            try:
                if func.isExternal() or func.isThunk():
                    continue
            except Exception:
                pass
            entry = func.getEntryPoint()
            if entry is None:
                continue
            func_id = addr_str(entry)
            if not func_id:
                continue
            name = func.getName()
            if name and _is_ignored_handler_name(name):
                continue
            func_ptr_map[entry.getOffset()] = (func_id, name)
    except Exception:
        for func in func_manager.getFunctions(True):
            if func is None:
                continue
            try:
                if func.isExternal() or func.isThunk():
                    continue
            except Exception:
                pass
            entry = func.getEntryPoint()
            if entry is None:
                continue
            func_id = addr_str(entry)
            if not func_id:
                continue
            name = func.getName()
            if name and _is_ignored_handler_name(name):
                continue
            func_ptr_map[entry.getOffset()] = (func_id, name)
    return func_ptr_map


def _resolve_func_ptr(program, func_ptr_val, func_ptr_map, func_manager=None, addr_space=None):
    if not func_ptr_val:
        return None, None
    meta = func_ptr_map.get(func_ptr_val) if func_ptr_map else None
    if meta:
        return meta[0], meta[1]
    if program is None:
        return None, None
    func_manager = func_manager or program.getFunctionManager()
    if addr_space is None:
        try:
            addr_space = program.getAddressFactory().getDefaultAddressSpace()
        except Exception:
            addr_space = None
    if addr_space is None:
        return None, None
    try:
        func_addr = addr_space.getAddress(func_ptr_val)
    except Exception:
        func_addr = None
    if func_addr is None:
        return None, None
    func = func_manager.getFunctionAt(func_addr)
    if func is None:
        func = func_manager.getFunctionContaining(func_addr)
    if func is None:
        return None, None
    try:
        if func.isExternal() or func.isThunk():
            return None, None
    except Exception:
        pass
    func_id = addr_str(func.getEntryPoint())
    func_name = func.getName()
    if func_name and _is_ignored_handler_name(func_name):
        return None, None
    return func_id, func_name


def _parse_table_dispatch_records_at(
    program,
    base_addr,
    stride,
    func_ptr_map,
    string_addr_map_all,
    max_token_len,
    max_entries,
    monitor=None,
):
    if program is None or base_addr is None or not stride:
        return []
    memory = program.getMemory()
    ptr_size = program.getDefaultPointerSize()
    big_endian = program.getLanguage().isBigEndian()
    func_manager = program.getFunctionManager()
    addr_space = program.getAddressFactory().getDefaultAddressSpace()

    records = []
    invalid_run = 0
    for idx in range(max_entries):
        if monitor is not None and monitor.isCancelled():
            break
        try:
            entry_addr = base_addr.add(idx * stride)
        except Exception:
            break
        try:
            if not memory.contains(entry_addr):
                break
        except Exception:
            pass
        str_ptr_val = _read_ptr_with_reloc(program, entry_addr, ptr_size, big_endian)
        func_ptr_val = _read_ptr_with_reloc(program, entry_addr.add(ptr_size), ptr_size, big_endian)
        if not str_ptr_val and not func_ptr_val:
            break
        if not str_ptr_val or not func_ptr_val:
            invalid_run += 1
            if invalid_run >= 2:
                break
            continue
        try:
            str_addr = addr_space.getAddress(str_ptr_val)
        except Exception:
            invalid_run += 1
            if invalid_run >= 3:
                break
            continue
        raw_value = _resolve_string_at(program, str_addr)
        token_value, _reason = _token_candidate(raw_value, 1, max_token_len)
        if token_value is None or not _looks_like_subcommand_token(token_value):
            invalid_run += 1
            if invalid_run >= 3:
                break
            continue
        func_id, func_name = _resolve_func_ptr(
            program,
            func_ptr_val,
            func_ptr_map,
            func_manager=func_manager,
            addr_space=addr_space,
        )
        if not func_id:
            invalid_run += 1
            if invalid_run >= 3:
                break
            continue
        invalid_run = 0

        string_addr_text = addr_str(str_addr)
        string_id = string_addr_map_all.get(string_addr_text) if string_addr_map_all else None
        records.append(
            {
                "token": token_value,
                "string_id": string_id,
                "string_address": string_addr_text,
                "function_id": func_id,
                "function_name": func_name,
                "table_entry_address": addr_str(entry_addr),
                "entry_index": idx,
            }
        )
    return records

