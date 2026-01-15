"""Decode `struct option` longopt tables from memory."""

from collectors.cli_tokens import _is_probable_longopt_name
from collectors.ghidra_memory import (
    _align_offset,
    _read_int,
    _read_ptr_with_reloc,
    _resolve_string_at,
    _to_address,
)
from export_primitives import addr_str


def decode_longopt_table(program, base_addr_text, max_entries=128):
    result = {
        "address": base_addr_text,
        "status": "unresolved",
        "entries": [],
        "truncated": False,
    }
    base_addr = _to_address(program, base_addr_text)
    if base_addr is None:
        result["status"] = "invalid_address"
        return result
    memory = program.getMemory()
    ptr_size = program.getDefaultPointerSize()
    big_endian = program.getLanguage().isBigEndian()
    # Use a conservative struct option layout with alignment heuristics.
    has_arg_offset = ptr_size
    flag_offset = _align_offset(ptr_size + 4, ptr_size)
    val_offset = flag_offset + ptr_size
    entry_size = _align_offset(val_offset + 4, ptr_size)
    if entry_size <= 0:
        result["status"] = "invalid_layout"
        return result
    invalid_name_runs = 0

    for idx in range(max_entries):
        entry_addr = base_addr.add(idx * entry_size)
        name_ptr = _read_ptr_with_reloc(program, entry_addr, ptr_size, big_endian)
        if name_ptr is None:
            result["status"] = "read_failed"
            return result
        if name_ptr == 0:
            result["status"] = "ok"
            break
        try:
            name_addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(name_ptr)
        except Exception:
            name_addr = None
        name_value = _resolve_string_at(program, name_addr)
        if name_value is None or not _is_probable_longopt_name(name_value):
            invalid_name_runs += 1
        else:
            invalid_name_runs = 0

        has_arg_addr = entry_addr.add(has_arg_offset)
        has_arg_raw = _read_int(memory, has_arg_addr, 4, big_endian)
        if has_arg_raw == 0:
            has_arg = "no"
        elif has_arg_raw == 1:
            has_arg = "required"
        elif has_arg_raw == 2:
            has_arg = "optional"
        else:
            has_arg = "unknown"

        flag_addr = entry_addr.add(flag_offset)
        flag_ptr = _read_ptr_with_reloc(program, flag_addr, ptr_size, big_endian)
        if flag_ptr:
            try:
                flag_ptr_addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(flag_ptr)
                flag_addr_text = addr_str(flag_ptr_addr)
            except Exception:
                flag_addr_text = None
        else:
            flag_addr_text = None

        val_addr = entry_addr.add(val_offset)
        val_raw = _read_int(memory, val_addr, 4, big_endian)

        entry = {
            "entry_address": addr_str(entry_addr),
            "name": name_value,
            "name_address": addr_str(name_addr) if name_addr else None,
            "has_arg": has_arg,
            "flag_address": flag_addr_text,
            "val": val_raw,
        }
        if entry["name"]:
            result["entries"].append(entry)

        if invalid_name_runs >= 3:
            result["status"] = "invalid_names"
            break

    if len(result["entries"]) >= max_entries:
        result["truncated"] = True
    if result["status"] == "unresolved":
        result["status"] = "ok" if result["entries"] else "no_entries"
    return result

