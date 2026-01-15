"""Best-effort P-code value resolution.

The exporter uses these helpers to recover constant-ish arguments from callsites
without requiring perfect decompilation. All resolution is conservative and
depth-capped to avoid cycles.
"""

from collectors.ghidra_memory import _read_int
from ghidra.program.model.pcode import PcodeOp


def _varnode_key(varnode):
    if varnode is None:
        return None
    try:
        return varnode.getUniqueId()
    except Exception:
        return id(varnode)


def _resolve_varnode_constant(program, varnode, max_depth=6, visited=None):
    # Best-effort constant folding with a depth cap to avoid recursion cycles.
    if varnode is None or max_depth <= 0:
        return None
    if visited is None:
        visited = set()
    key = _varnode_key(varnode)
    if key is not None:
        if key in visited:
            return None
        visited.add(key)
    try:
        if varnode.isConstant():
            return varnode.getOffset()
    except Exception:
        return None

    try:
        def_op = varnode.getDef()
    except Exception:
        def_op = None
    if def_op is None:
        return None
    try:
        opcode = def_op.getOpcode()
    except Exception:
        return None

    if opcode in (
        PcodeOp.COPY,
        PcodeOp.CAST,
        PcodeOp.INT_ZEXT,
        PcodeOp.INT_SEXT,
        PcodeOp.SUBPIECE,
    ):
        return _resolve_varnode_constant(program, def_op.getInput(0), max_depth - 1, visited)

    if opcode == PcodeOp.MULTIEQUAL:
        for idx in range(def_op.getNumInputs()):
            value = _resolve_varnode_constant(program, def_op.getInput(idx), max_depth - 1, visited)
            if value is not None:
                return value
        return None

    if opcode == PcodeOp.PTRSUB:
        base = _resolve_varnode_constant(program, def_op.getInput(0), max_depth - 1, visited)
        offset = _resolve_varnode_constant(program, def_op.getInput(1), max_depth - 1, visited)
        if base is not None and offset is not None:
            return base + offset
        return None

    if opcode == PcodeOp.PTRADD:
        base = _resolve_varnode_constant(program, def_op.getInput(0), max_depth - 1, visited)
        index = _resolve_varnode_constant(program, def_op.getInput(1), max_depth - 1, visited)
        scale = _resolve_varnode_constant(program, def_op.getInput(2), max_depth - 1, visited)
        if base is not None and index is not None and scale is not None:
            return base + (index * scale)
        return None

    if opcode == PcodeOp.INT_ADD:
        left = _resolve_varnode_constant(program, def_op.getInput(0), max_depth - 1, visited)
        right = _resolve_varnode_constant(program, def_op.getInput(1), max_depth - 1, visited)
        if left is not None and right is not None:
            return left + right
        return None

    if opcode == PcodeOp.INT_SUB:
        left = _resolve_varnode_constant(program, def_op.getInput(0), max_depth - 1, visited)
        right = _resolve_varnode_constant(program, def_op.getInput(1), max_depth - 1, visited)
        if left is not None and right is not None:
            return left - right
        return None

    if opcode == PcodeOp.LOAD:
        ptr_val = _resolve_varnode_constant(program, def_op.getInput(1), max_depth - 1, visited)
        if ptr_val is None:
            return None
        try:
            addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(ptr_val)
        except Exception:
            return None
        try:
            if not program.getMemory().contains(addr):
                return None
        except Exception:
            pass
        try:
            size = varnode.getSize()
        except Exception:
            size = 0
        if not size or size <= 0:
            size = program.getDefaultPointerSize()
        big_endian = program.getLanguage().isBigEndian()
        value = _read_int(program.getMemory(), addr, size, big_endian)
        return value

    return None


def _resolve_varnode_addr(program, varnode, max_depth=6):
    try:
        if varnode is not None and (varnode.isAddrTied() or varnode.isPersistent()):
            addr = varnode.getAddress()
            if addr is not None:
                try:
                    if addr.isStackAddress():
                        addr = None
                except Exception:
                    pass
                if addr is not None:
                    try:
                        memory = program.getMemory()
                        if memory.contains(addr):
                            try:
                                size = varnode.getSize()
                            except Exception:
                                size = 0
                            ptr_size = program.getDefaultPointerSize()
                            if size == ptr_size:
                                big_endian = program.getLanguage().isBigEndian()
                                ptr_val = _read_int(memory, addr, ptr_size, big_endian)
                                if ptr_val and ptr_val > 0:
                                    try:
                                        ptr_addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(
                                            ptr_val
                                        )
                                    except Exception:
                                        ptr_addr = None
                                    if ptr_addr is not None:
                                        try:
                                            if memory.contains(ptr_addr):
                                                return ptr_addr
                                        except Exception:
                                            return ptr_addr
                                return None
                            return addr
                    except Exception:
                        return addr
    except Exception:
        pass

    # Fall back to a literal constant if the varnode does not map to memory.
    value = _resolve_varnode_constant(program, varnode, max_depth=max_depth)
    if value is None or value <= 0:
        return None
    try:
        addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(value)
    except Exception:
        return None
    try:
        if not program.getMemory().contains(addr):
            return None
    except Exception:
        pass
    return addr
