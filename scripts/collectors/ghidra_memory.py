"""Low-level Ghidra memory/address helpers.

These helpers are intentionally defensive:
- return `None` on best-effort failures (bad addresses, missing memory, JPype edge cases)
- avoid raising exceptions into the export pipeline

They are shared by collectors that need to decode pointers, strings, and
relocation-adjusted table structures.
"""

from ghidra.program.model.data import StringDataInstance


def _to_address(program, addr_text):
    if addr_text is None:
        return None
    try:
        return program.getAddressFactory().getAddress(addr_text)
    except Exception:
        return None


def _align_offset(offset, alignment):
    if alignment <= 0:
        return offset
    return (offset + alignment - 1) // alignment * alignment


def _read_int(memory, addr, size, big_endian):
    if memory is None or addr is None:
        return None
    try:
        size = int(size)
    except Exception:
        return None
    if size <= 0:
        return None

    # Prefer the typed accessors (avoids JPype buffer conversion edge cases).
    try:
        if size == 8 and hasattr(memory, "getLong"):
            return int(memory.getLong(addr)) & 0xFFFFFFFFFFFFFFFF
        if size == 4 and hasattr(memory, "getInt"):
            return int(memory.getInt(addr)) & 0xFFFFFFFF
        if size == 2 and hasattr(memory, "getShort"):
            return int(memory.getShort(addr)) & 0xFFFF
        if size == 1 and hasattr(memory, "getByte"):
            return int(memory.getByte(addr)) & 0xFF
    except Exception:
        pass

    value = 0
    if big_endian:
        for idx in range(size):
            try:
                b = int(memory.getByte(addr.add(idx))) & 0xFF
            except Exception:
                return None
            value = (value << 8) | b
        return value
    for idx in range(size):
        try:
            b = int(memory.getByte(addr.add(idx))) & 0xFF
        except Exception:
            return None
        value |= b << (8 * idx)
    return value


def _read_ptr(memory, addr, ptr_size, big_endian):
    return _read_int(memory, addr, ptr_size, big_endian)


def _read_ptr_with_reloc(program, addr, ptr_size, big_endian):
    memory = program.getMemory()
    raw = _read_ptr(memory, addr, ptr_size, big_endian)
    if raw:
        return raw
    try:
        reloc_table = program.getRelocationTable()
    except Exception:
        reloc_table = None
    if reloc_table is None:
        return raw
    try:
        relocs = reloc_table.getRelocations(addr)
    except Exception:
        relocs = None
    if not relocs:
        return raw
    image_base = None
    for reloc in relocs:
        try:
            data = reloc.getBytes()
        except Exception:
            data = None
        if not data:
            continue
        data_bytes = bytes(data)
        if not data_bytes:
            continue
        addend = int.from_bytes(
            data_bytes[:ptr_size],
            byteorder="big" if big_endian else "little",
            signed=False,
        )
        try:
            reloc_type = reloc.getType()
        except Exception:
            reloc_type = None
        # RELATIVE relocations encode an addend relative to image base.
        if reloc_type == 8:
            if image_base is None:
                try:
                    image_base = program.getImageBase().getOffset()
                except Exception:
                    image_base = 0
            return image_base + addend
        if addend:
            return addend
    return raw


def _read_c_string(program, addr, max_len=128):
    memory = program.getMemory()
    chars = []
    for idx in range(max(0, int(max_len))):
        try:
            cur = addr.add(idx)
        except Exception:
            return None
        try:
            b = int(memory.getByte(cur)) & 0xFF
        except Exception:
            return None
        if b == 0:
            break
        if b < 32 or b > 126:
            return None
        chars.append(chr(b))
    if not chars:
        return None
    return "".join(chars)


def _resolve_string_at(program, addr):
    if addr is None:
        return None
    try:
        if not program.getMemory().contains(addr):
            return None
    except Exception:
        pass
    listing = program.getListing()
    data = listing.getDefinedDataAt(addr)
    if data and StringDataInstance.isString(data):
        try:
            sdi = StringDataInstance.getStringDataInstance(data)
        except Exception:
            sdi = None
        if sdi and sdi != StringDataInstance.NULL_INSTANCE:
            try:
                return sdi.getStringValue()
            except Exception:
                return None
    return _read_c_string(program, addr)
