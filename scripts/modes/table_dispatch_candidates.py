"""Table-dispatch candidate discovery.

This module implements several heuristics for finding static token->handler
dispatch tables, prioritized from highest to lowest signal:
- symbol-named tables
- `cmd_` handler references
- string-token references
- raw memory scanning for table-like layouts
"""

from __future__ import annotations

import re

from collectors.ghidra_memory import _read_ptr_with_reloc, _resolve_string_at, _to_address
from export_bounds import Bounds
from export_primitives import addr_str, addr_to_int
from modes.common import (
    _add_implementation_root,
    _looks_like_subcommand_token,
    _mode_id,
    _token_candidate,
)
from modes.name_heuristics import is_cmd_handler_name, use_name_heuristics
from modes.table_dispatch_scan import (
    _build_func_ptr_map,
    _collect_table_dispatch_targets,
    _collect_table_runs,
    _parse_table_dispatch_records_at,
)

_TABLE_DISPATCH_SYMBOL_NAMES = [
    "commands",
    "command_list",
    "command_table",
    "cmds",
    "subcommands",
    "subcommand_table",
]
_TABLE_DISPATCH_SYMBOL_FALLBACK_RE = re.compile(
    r"(?:^|_)(?:command|commands|cmds|subcommand)(?:$|_)", re.I
)


def _iter_symbol_iterator(symbol_iter, max_symbols=None):
    if symbol_iter is None:
        return
    count = 0
    try:
        while symbol_iter.hasNext():
            sym = symbol_iter.next()
            if sym is None:
                continue
            yield sym
            count += 1
            if max_symbols and count >= max_symbols:
                return
    except Exception:
        for sym in symbol_iter:
            if sym is None:
                continue
            yield sym
            count += 1
            if max_symbols and count >= max_symbols:
                return


def _lookup_symbols_by_name(symbol_table, name, max_symbols=None):
    if symbol_table is None or not name:
        return []
    symbols = []
    symbol_iter = None
    try:
        symbol_iter = symbol_table.getSymbols(name)
    except Exception:
        symbol_iter = None
    if symbol_iter is None:
        try:
            symbol_iter = symbol_table.getSymbols(name, None)
        except Exception:
            symbol_iter = None
    for sym in _iter_symbol_iterator(symbol_iter, max_symbols=max_symbols):
        symbols.append(sym)
    return symbols


def _collect_table_dispatch_mode_candidates_from_symbols(
    program,
    function_meta_by_addr,
    string_addr_map_all,
    bounds: Bounds,
    monitor=None,
):
    if not use_name_heuristics(bounds):
        return {}
    if program is None:
        return {}
    max_token_len = bounds.max_mode_token_length or 32
    max_modes = bounds.max_modes or 200
    min_entries = bounds.get("min_table_dispatch_table_entries", 0) or 5
    max_tables = bounds.get("max_table_dispatch_tables", 0) or 4
    max_entries = max(64, min(max_modes * 4, 1024))

    ptr_size = program.getDefaultPointerSize()
    memory = program.getMemory()
    big_endian = program.getLanguage().isBigEndian()

    func_ptr_map = _build_func_ptr_map(program)
    if not func_ptr_map:
        return {}

    symbol_table = program.getSymbolTable()
    candidates = []
    seen_addrs = set()
    for name in _TABLE_DISPATCH_SYMBOL_NAMES:
        for sym in _lookup_symbols_by_name(symbol_table, name, max_symbols=6):
            try:
                addr = sym.getAddress()
            except Exception:
                addr = None
            if addr is None:
                continue
            try:
                if sym.isExternal():
                    continue
            except Exception:
                pass
            try:
                if not memory.contains(addr):
                    continue
            except Exception:
                pass
            addr_text = addr_str(addr)
            if not addr_text or addr_text in seen_addrs:
                continue
            seen_addrs.add(addr_text)
            candidates.append((sym.getName(), addr))
            if max_tables and len(candidates) >= max_tables:
                break
        if max_tables and len(candidates) >= max_tables:
            break

    if not candidates:
        try:
            sym_iter = symbol_table.getAllSymbols(True)
        except Exception:
            sym_iter = None
        for sym in _iter_symbol_iterator(sym_iter, max_symbols=8000):
            if monitor is not None and monitor.isCancelled():
                break
            try:
                sym_name = sym.getName()
            except Exception:
                sym_name = None
            if not sym_name or not _TABLE_DISPATCH_SYMBOL_FALLBACK_RE.search(sym_name):
                continue
            try:
                addr = sym.getAddress()
            except Exception:
                addr = None
            if addr is None:
                continue
            try:
                if sym.isExternal():
                    continue
            except Exception:
                pass
            try:
                if not memory.contains(addr):
                    continue
            except Exception:
                pass
            addr_text = addr_str(addr)
            if not addr_text or addr_text in seen_addrs:
                continue
            seen_addrs.add(addr_text)
            candidates.append((sym_name, addr))
            if max_tables and len(candidates) >= max_tables:
                break

    if not candidates:
        return {}

    stride_candidates = [ptr_size * n for n in (2, 3, 4, 5) if ptr_size * n]
    mode_candidates = {}
    addr_space = program.getAddressFactory().getDefaultAddressSpace()

    for sym_name, sym_addr in candidates:
        if monitor is not None and monitor.isCancelled():
            break
        base_addrs = [sym_addr]
        deref = _read_ptr_with_reloc(program, sym_addr, ptr_size, big_endian)
        if deref:
            try:
                deref_addr = addr_space.getAddress(deref)
            except Exception:
                deref_addr = None
            if deref_addr is not None:
                base_addrs.append(deref_addr)

        best_records = []
        for base_addr in base_addrs:
            for stride in stride_candidates:
                records = _parse_table_dispatch_records_at(
                    program,
                    base_addr,
                    stride,
                    func_ptr_map,
                    string_addr_map_all,
                    max_token_len,
                    max_entries,
                    monitor=monitor,
                )
                if len(records) > len(best_records):
                    best_records = records
        if not best_records or len(best_records) < min_entries:
            continue

        for record in best_records:
            string_id = record.get("string_id")
            string_addr_text = record.get("string_address")
            token_value = record.get("token")
            mode_id = _mode_id(string_id, string_addr_text, token_value)
            mode = mode_candidates.get(mode_id)
            if mode is None:
                mode = {
                    "mode_id": mode_id,
                    "name": token_value,
                    "string_id": string_id,
                    "address": string_addr_text,
                    "kind": "subcommand",
                    "kind_strength": "derived",
                    "kind_confidence": "low",
                    "dispatch_sites": set(),
                    "dispatch_roots": {},
                }
                mode_candidates[mode_id] = mode
            evidence = {
                "table_entry_address": record.get("table_entry_address"),
                "string_id": string_id,
                "string_address": string_addr_text,
            }
            _add_implementation_root(
                mode,
                record.get("function_id"),
                record.get("function_name"),
                "table_dispatch",
                "derived",
                "medium",
                evidence,
            )
            if max_modes and len(mode_candidates) >= max_modes:
                return mode_candidates

    return mode_candidates


def _collect_table_dispatch_mode_candidates_from_memory(
    program,
    function_meta_by_addr,
    string_addr_map_all,
    bounds: Bounds,
    monitor=None,
):
    if program is None:
        return {}
    max_token_len = bounds.max_mode_token_length or 32
    max_modes = bounds.max_modes or 200
    min_entries = bounds.get("min_table_dispatch_table_entries", 0) or 5
    max_tables = bounds.get("max_table_dispatch_tables", 0) or 4

    ptr_size = program.getDefaultPointerSize()
    big_endian = program.getLanguage().isBigEndian()
    memory = program.getMemory()
    default_addr_space = program.getAddressFactory().getDefaultAddressSpace()

    func_ptr_map = _build_func_ptr_map(program)
    if not func_ptr_map:
        return {}

    deltas = (-ptr_size, ptr_size, -2 * ptr_size, 2 * ptr_size)

    entries_by_slot = {}
    seen_pairs = set()
    for block in memory.getBlocks():
        if monitor is not None and monitor.isCancelled():
            break
        try:
            start_off = block.getStart().getOffset()
            end_off = block.getEnd().getOffset()
        except Exception:
            continue
        if start_off is None or end_off is None or end_off <= start_off:
            continue
        off = start_off
        if ptr_size:
            off = ((off + ptr_size - 1) // ptr_size) * ptr_size
        while off <= end_off:
            if monitor is not None and monitor.isCancelled():
                break
            try:
                slot_addr = block.getStart().add(off - start_off)
            except Exception:
                break
            func_ptr_val = _read_ptr_with_reloc(program, slot_addr, ptr_size, big_endian)
            if not func_ptr_val:
                off += ptr_size
                continue
            func_meta = func_ptr_map.get(func_ptr_val)
            if not func_meta:
                off += ptr_size
                continue
            func_id, func_name = func_meta
            for delta in deltas:
                try:
                    if delta > 0:
                        str_slot_addr = slot_addr.add(delta)
                    else:
                        str_slot_addr = slot_addr.subtract(-delta)
                except Exception:
                    continue
                str_ptr_val = _read_ptr_with_reloc(program, str_slot_addr, ptr_size, big_endian)
                if not str_ptr_val:
                    continue
                try:
                    str_ptr_addr = default_addr_space.getAddress(str_ptr_val)
                except Exception:
                    continue
                raw_value = _resolve_string_at(program, str_ptr_addr)
                token_value, _reason = _token_candidate(raw_value, 1, max_token_len)
                if token_value is None:
                    continue
                if not _looks_like_subcommand_token(token_value):
                    continue
                string_addr_text = addr_str(str_ptr_addr)
                pair_key = (string_addr_text, func_id)
                if pair_key in seen_pairs:
                    continue
                seen_pairs.add(pair_key)
                try:
                    slot_offset = str_slot_addr.getOffset()
                except Exception:
                    continue
                string_id = (
                    string_addr_map_all.get(string_addr_text) if string_addr_map_all else None
                )
                record = {
                    "token": token_value,
                    "string_id": string_id,
                    "string_address": string_addr_text,
                    "function_id": func_id,
                    "function_name": func_name,
                    "table_entry_address": addr_str(str_slot_addr),
                }
                entries_by_slot.setdefault(slot_offset, []).append(record)
            off += ptr_size

    if not entries_by_slot:
        return {}

    slot_offsets = sorted(entries_by_slot.keys())
    allowed_strides = set([ptr_size * n for n in (2, 3, 4, 5, 6, 7) if ptr_size * n])
    runs = _collect_table_runs(slot_offsets, allowed_strides, min_entries)
    if not runs:
        return {}
    runs.sort(
        key=lambda item: (
            -item.get("length", 0),
            item.get("start_offset", 0),
            item.get("stride", 0),
        )
    )
    if max_tables and len(runs) > max_tables:
        runs = runs[:max_tables]

    selected_slots = set()
    for run in runs:
        start = run.get("start_offset")
        stride = run.get("stride") or 0
        length = run.get("length") or 0
        if start is None or not stride or length <= 0:
            continue
        for idx in range(length):
            selected_slots.add(start + idx * stride)
    if not selected_slots:
        return {}

    mode_candidates = {}
    for slot_offset in sorted(selected_slots):
        for record in entries_by_slot.get(slot_offset, []) or []:
            string_id = record.get("string_id")
            string_addr_text = record.get("string_address")
            token_value = record.get("token")
            mode_id = _mode_id(string_id, string_addr_text, token_value)
            mode = mode_candidates.get(mode_id)
            if mode is None:
                mode = {
                    "mode_id": mode_id,
                    "name": token_value,
                    "string_id": string_id,
                    "address": string_addr_text,
                    "kind": "subcommand",
                    "kind_strength": "derived",
                    "kind_confidence": "low",
                    "dispatch_sites": set(),
                    "dispatch_roots": {},
                }
                mode_candidates[mode_id] = mode
            _add_implementation_root(
                mode,
                record.get("function_id"),
                record.get("function_name"),
                "table_dispatch",
                "derived",
                "medium",
                {
                    "table_entry_address": record.get("table_entry_address"),
                    "string_id": string_id,
                    "string_address": string_addr_text,
                },
            )
            if max_modes and len(mode_candidates) >= max_modes:
                return mode_candidates

    return mode_candidates


def _collect_table_dispatch_mode_candidates_from_handlers(
    program,
    function_meta_by_addr,
    string_addr_map_all,
    bounds: Bounds,
    monitor=None,
):
    if not use_name_heuristics(bounds):
        return {}
    if program is None or not function_meta_by_addr:
        return {}
    max_token_len = bounds.max_mode_token_length or 32
    max_modes = bounds.max_modes or 200
    max_handlers = max(200, max_modes)
    max_refs_per_handler = 8

    handler_ids = []
    for func_id, meta in (function_meta_by_addr or {}).items():
        name = (meta or {}).get("name") or ""
        if not is_cmd_handler_name(name):
            continue
        handler_ids.append(func_id)
    handler_ids.sort(key=addr_to_int)
    if max_handlers and len(handler_ids) > max_handlers:
        handler_ids = handler_ids[:max_handlers]

    listing = program.getListing()
    ref_manager = program.getReferenceManager()
    memory = program.getMemory()
    ptr_size = program.getDefaultPointerSize()
    big_endian = program.getLanguage().isBigEndian()
    addr_factory = program.getAddressFactory().getDefaultAddressSpace()

    mode_candidates = {}
    for handler_id in handler_ids:
        if monitor is not None and monitor.isCancelled():
            break
        handler_meta = function_meta_by_addr.get(handler_id, {}) if function_meta_by_addr else {}
        handler_name = handler_meta.get("name")
        handler_addr = _to_address(program, handler_id)
        if handler_addr is None:
            continue
        try:
            refs = ref_manager.getReferencesTo(handler_addr)
        except Exception:
            refs = None
        if refs is None:
            continue
        ref_count = 0
        while refs.hasNext():
            ref = refs.next()
            from_addr = ref.getFromAddress()
            if from_addr is None:
                continue
            if listing.getInstructionAt(from_addr) is not None:
                continue
            ref_count += 1
            if max_refs_per_handler and ref_count > max_refs_per_handler:
                break
            for delta in (-ptr_size, ptr_size):
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
                    ptr_addr = addr_factory.getAddress(ptr_val)
                except Exception:
                    ptr_addr = None
                if ptr_addr is None:
                    continue
                try:
                    if not memory.contains(ptr_addr):
                        continue
                except Exception:
                    pass
                raw_value = _resolve_string_at(program, ptr_addr)
                token_value, _reason = _token_candidate(raw_value, 1, max_token_len)
                if token_value is None:
                    continue
                if token_value.startswith("-"):
                    continue
                string_addr_text = addr_str(ptr_addr)
                string_id = (
                    string_addr_map_all.get(string_addr_text) if string_addr_map_all else None
                )
                mode_id = _mode_id(string_id, string_addr_text, token_value)
                mode = mode_candidates.get(mode_id)
                if mode is None:
                    mode = {
                        "mode_id": mode_id,
                        "name": token_value,
                        "string_id": string_id,
                        "address": string_addr_text,
                        "kind": "subcommand",
                        "kind_strength": "derived",
                        "kind_confidence": "low",
                        "dispatch_sites": set(),
                        "dispatch_roots": {},
                    }
                    mode_candidates[mode_id] = mode
                _add_implementation_root(
                    mode,
                    handler_id,
                    handler_name,
                    "table_dispatch",
                    "derived",
                    "medium",
                    {
                        "table_entry_address": addr_str(from_addr),
                        "string_id": string_id,
                        "string_address": string_addr_text,
                    },
                )
            if max_modes and len(mode_candidates) >= max_modes:
                break
        if max_modes and len(mode_candidates) >= max_modes:
            break
    return mode_candidates


def _collect_table_dispatch_mode_candidates_from_strings(
    program,
    string_addr_map_all,
    bounds: Bounds,
    monitor=None,
):
    if program is None or not string_addr_map_all:
        return {}
    max_token_len = bounds.max_mode_token_length or 32
    max_modes = bounds.max_modes or 200
    max_scan_strings = max(2500, max_modes * 40)

    string_addrs = sorted(string_addr_map_all.keys(), key=addr_to_int)
    if max_scan_strings and len(string_addrs) > max_scan_strings:
        string_addrs = string_addrs[:max_scan_strings]

    mode_candidates = {}
    for addr_text in string_addrs:
        if monitor is not None and monitor.isCancelled():
            break
        addr_obj = _to_address(program, addr_text)
        if addr_obj is None:
            continue
        raw_value = _resolve_string_at(program, addr_obj)
        token_value, _reason = _token_candidate(raw_value, 1, max_token_len)
        if token_value is None:
            continue
        if not _looks_like_subcommand_token(token_value):
            continue
        targets = _collect_table_dispatch_targets(
            program,
            addr_text,
            max_refs=6,
            max_targets=4,
        )
        if not targets:
            continue
        string_id = string_addr_map_all.get(addr_text)
        mode_id = _mode_id(string_id, addr_text, token_value)
        mode = mode_candidates.get(mode_id)
        if mode is None:
            mode = {
                "mode_id": mode_id,
                "name": token_value,
                "string_id": string_id,
                "address": addr_text,
                "kind": "subcommand",
                "kind_strength": "derived",
                "kind_confidence": "low",
                "dispatch_sites": set(),
                "dispatch_roots": {},
            }
            mode_candidates[mode_id] = mode
        for target in targets:
            _add_implementation_root(
                mode,
                target.get("function_id"),
                target.get("function_name"),
                "table_dispatch",
                "derived",
                "medium",
                {
                    "table_entry_address": target.get("table_entry_address"),
                    "string_id": string_id,
                    "string_address": addr_text,
                },
            )
        if max_modes and len(mode_candidates) >= max_modes:
            break
    return mode_candidates


def _collect_table_dispatch_mode_candidates(
    program,
    function_meta_by_addr,
    string_addr_map_all,
    bounds: Bounds,
    monitor=None,
):
    if use_name_heuristics(bounds):
        mode_candidates = _collect_table_dispatch_mode_candidates_from_symbols(
            program,
            function_meta_by_addr,
            string_addr_map_all,
            bounds,
            monitor=monitor,
        )
        if mode_candidates:
            return mode_candidates
        mode_candidates = _collect_table_dispatch_mode_candidates_from_handlers(
            program,
            function_meta_by_addr,
            string_addr_map_all,
            bounds,
            monitor=monitor,
        )
        if mode_candidates:
            return mode_candidates
    mode_candidates = _collect_table_dispatch_mode_candidates_from_strings(
        program,
        string_addr_map_all,
        bounds,
        monitor=monitor,
    )
    if mode_candidates:
        return mode_candidates
    return _collect_table_dispatch_mode_candidates_from_memory(
        program,
        function_meta_by_addr,
        string_addr_map_all,
        bounds,
        monitor=monitor,
    )
