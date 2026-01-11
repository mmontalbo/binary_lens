import re

from export_primitives import SALIENCE_TAGS, addr_id, addr_str, addr_to_int, normalize_symbol_name
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.data import StringDataInstance
from ghidra.program.model.pcode import PcodeOp

ENV_VAR_RE = re.compile(r"^[A-Z0-9_]{3,}$")


def normalize_symbol_names(names):
    return set(normalize_symbol_name(name) for name in names)


CLI_PARSE_SIGNAL_NAMES = set([
    "getopt",
    "getopt_long",
    "__getopt_long",
    "getopt_long_only",
    "argp_parse",
])
CLI_PARSE_SIGNAL_NAMES = normalize_symbol_names(CLI_PARSE_SIGNAL_NAMES)
CLI_COMPARE_SIGNAL_NAMES = set([
    "strcmp",
    "strncmp",
    "strcasecmp",
    "strncasecmp",
])
CLI_COMPARE_SIGNAL_NAMES = normalize_symbol_names(CLI_COMPARE_SIGNAL_NAMES)
CLI_COMPARE_MNEMONICS = set([
    "CMP",
    "CMPL",
    "CMPQ",
    "CMPW",
    "CMPB",
    "TEST",
    "TESTL",
    "TESTQ",
    "TESTW",
    "TESTB",
    "TST",
    "CMN",
])


def is_env_var_string(value):
    if value is None:
        return False
    return ENV_VAR_RE.match(value) is not None


def is_usage_marker(value):
    if value is None:
        return False
    lowered = value.lower()
    if "usage:" in lowered:
        return True
    if "--help" in value:
        return True
    if "try '" in lowered or "try \"" in lowered:
        return True
    return False


def is_printf_format_string(value):
    if value is None or "%" not in value:
        return False
    length = len(value)
    idx = 0
    while idx < length:
        if value[idx] != "%":
            idx += 1
            continue
        if idx + 1 < length and value[idx + 1] == "%":
            idx += 2
            continue
        j = idx + 1
        while j < length and value[j] in "#0- +":
            j += 1
        while j < length and value[j].isdigit():
            j += 1
        if j < length and value[j] == ".":
            j += 1
            while j < length and value[j].isdigit():
                j += 1
        while j < length and value[j] in "hljztL":
            j += 1
        if j < length and value[j].isalpha():
            return True
        idx = j + 1
    return False


def is_path_like(value):
    if value is None:
        return False
    return "/" in value or value.startswith("./") or value.startswith("../")


def classify_string_value(value):
    tags = set()
    if is_env_var_string(value):
        tags.add("env_var")
    if is_usage_marker(value):
        tags.add("usage")
    if is_printf_format_string(value):
        tags.add("format")
    if is_path_like(value):
        tags.add("path")
    return tags


def function_size(func):
    try:
        return func.getBody().getNumAddresses()
    except Exception:
        return 0


def collect_imports(program):
    external_manager = program.getExternalManager()
    imports = []
    library_names = []
    try:
        library_names = list(external_manager.getExternalLibraryNames())
    except Exception:
        library_names = []

    for library_name in library_names:
        try:
            loc_iter = external_manager.getExternalLocations(library_name)
        except Exception:
            loc_iter = None
        if loc_iter is None:
            continue
        while loc_iter.hasNext():
            loc = loc_iter.next()
            try:
                symbol = loc.getSymbol()
            except Exception:
                symbol = None
            if symbol:
                name = symbol.getName()
            else:
                try:
                    name = loc.getLabel()
                except Exception:
                    name = None
            entry = {
                "name": name,
                "address": addr_str(loc.getAddress()),
            }
            try:
                entry["library"] = loc.getLibraryName()
            except Exception:
                entry["library"] = library_name
            if symbol:
                entry["symbol_type"] = str(symbol.getSymbolType())
            try:
                func = loc.getFunction()
            except Exception:
                func = None
            if func:
                entry["signature"] = func.getSignature().toString()
            imports.append(entry)

    imports.sort(key=lambda item: (item.get("library") or "", item.get("name") or "", item.get("address") or ""))
    return imports


def collect_strings(program, max_strings):
    listing = program.getListing()
    ref_manager = program.getReferenceManager()
    strings = []
    string_tags_by_id = {}
    data_iter = listing.getDefinedData(True)
    while data_iter.hasNext():
        data = data_iter.next()
        if not StringDataInstance.isString(data):
            continue
        try:
            sdi = StringDataInstance.getStringDataInstance(data)
        except Exception:
            sdi = None
        if sdi is None or sdi == StringDataInstance.NULL_INSTANCE:
            continue
        try:
            value = sdi.getStringValue()
        except Exception:
            value = None
        if value is None:
            continue
        addr = data.getMinAddress()
        ref_iter = ref_manager.getReferencesTo(addr)
        ref_count = 0
        while ref_iter.hasNext():
            ref_iter.next()
            ref_count += 1
        if ref_count == 0:
            continue
        addr_text = addr_str(addr)
        entry = {
            "id": addr_id("s", addr_text),
            "address": addr_text,
            "value": value,
            "length": data.getLength(),
            "ref_count": ref_count,
        }
        try:
            entry["data_type"] = data.getDataType().getDisplayName()
        except Exception:
            entry["data_type"] = None
        string_tags_by_id[entry["id"]] = classify_string_value(value)
        strings.append(entry)

    strings.sort(key=lambda item: (-item.get("ref_count", 0), addr_to_int(item.get("address"))))
    total = len(strings)
    # Bucket selection preserves salient CLI/format/path strings even when boilerplate dominates.
    bucket_limit = min(max_strings // 5, 40)
    bucket_limits = {
        "env_vars": bucket_limit,
        "usage": bucket_limit,
        "format": bucket_limit,
        "path": bucket_limit,
    }
    buckets = {
        "env_vars": [],
        "usage": [],
        "format": [],
        "path": [],
    }
    for entry in strings:
        tags = string_tags_by_id.get(entry["id"], set())
        if "env_var" in tags:
            buckets["env_vars"].append(entry)
        if "usage" in tags:
            buckets["usage"].append(entry)
        if "format" in tags:
            buckets["format"].append(entry)
        if "path" in tags:
            buckets["path"].append(entry)

    selected = []
    selected_ids = set()
    bucket_counts = {}

    def add_bucket(name):
        limit = bucket_limits.get(name, 0)
        count = 0
        for entry in buckets.get(name, []):
            if len(selected) >= max_strings or count >= limit:
                break
            entry_id = entry["id"]
            if entry_id in selected_ids:
                continue
            selected.append(entry)
            selected_ids.add(entry_id)
            count += 1
        bucket_counts[name] = count

    add_bucket("env_vars")
    add_bucket("usage")
    add_bucket("format")
    add_bucket("path")

    for entry in strings:
        if len(selected) >= max_strings:
            break
        entry_id = entry["id"]
        if entry_id in selected_ids:
            continue
        selected.append(entry)
        selected_ids.add(entry_id)

    truncated = total > len(selected)

    string_addr_map_selected = {}
    for entry in selected:
        string_addr_map_selected[entry["address"]] = entry["id"]

    string_addr_map_all = {}
    for entry in strings:
        string_addr_map_all[entry["address"]] = entry["id"]

    return selected, string_addr_map_selected, total, truncated, string_addr_map_all, string_tags_by_id, bucket_counts, bucket_limits


def collect_function_string_refs(listing, func, string_addr_map, monitor=None):
    refs = set()
    instr_iter = listing.getInstructions(func.getBody(), True)
    while instr_iter.hasNext():
        if monitor is not None and monitor.isCancelled():
            break
        instr = instr_iter.next()
        for ref in instr.getReferencesFrom():
            to_addr = addr_str(ref.getToAddress())
            string_id = string_addr_map.get(to_addr)
            if string_id:
                refs.add(string_id)
    return refs


def collect_cli_parse_sites(call_edges, function_meta_by_addr):
    parse_sites = []
    sites_by_function = {}
    for edge in call_edges:
        target = edge.get("to") or {}
        name_norm = normalize_symbol_name(target.get("name"))
        if not name_norm or name_norm not in CLI_PARSE_SIGNAL_NAMES:
            continue
        from_addr = (edge.get("from") or {}).get("address")
        if not from_addr:
            continue
        caller_meta = function_meta_by_addr.get(from_addr, {})
        if caller_meta.get("is_external") or caller_meta.get("is_thunk"):
            continue
        callsite = edge.get("callsite")
        entry = {
            "callsite": callsite,
            "callee": target.get("name"),
            "callee_norm": name_norm,
            "caller": {
                "address": from_addr,
                "name": caller_meta.get("name") or (edge.get("from") or {}).get("function"),
            },
        }
        parse_sites.append(entry)

        bucket = sites_by_function.get(from_addr)
        if bucket is None:
            bucket = {
                "function": entry["caller"],
                "callsites": [],
                "callee_names": set(),
            }
            sites_by_function[from_addr] = bucket
        if callsite:
            bucket["callsites"].append(callsite)
        if target.get("name"):
            bucket["callee_names"].add(target.get("name"))

    grouped = []
    for entry in sites_by_function.values():
        entry["callsites"] = sorted(set(entry["callsites"]), key=addr_to_int)
        entry["callee_names"] = sorted(entry["callee_names"])
        grouped.append(entry)
    grouped.sort(key=lambda item: addr_to_int((item.get("function") or {}).get("address")))
    parse_sites.sort(key=lambda item: addr_to_int(item.get("callsite")))
    return parse_sites, grouped


def _is_compare_callee(name_norm):
    if not name_norm:
        return False
    if name_norm in CLI_COMPARE_SIGNAL_NAMES:
        return True
    for token in CLI_COMPARE_SIGNAL_NAMES:
        if token in name_norm:
            return True
    return False


def collect_cli_option_compare_sites(call_edges, function_meta_by_addr, allowed_callers=None):
    compare_sites = []
    for edge in call_edges:
        target = edge.get("to") or {}
        name_norm = normalize_symbol_name(target.get("name"))
        if not _is_compare_callee(name_norm):
            continue
        from_addr = (edge.get("from") or {}).get("address")
        if not from_addr:
            continue
        if allowed_callers is not None and from_addr not in allowed_callers:
            continue
        caller_meta = function_meta_by_addr.get(from_addr, {})
        if caller_meta.get("is_external") or caller_meta.get("is_thunk"):
            continue
        compare_sites.append({
            "callsite": edge.get("callsite"),
            "callee": target.get("name"),
            "callee_norm": name_norm,
            "caller": {
                "address": from_addr,
                "name": caller_meta.get("name") or (edge.get("from") or {}).get("function"),
            },
        })
    compare_sites.sort(key=lambda item: addr_to_int(item.get("callsite")))
    return compare_sites


def _to_address(program, addr_text):
    if addr_text is None:
        return None
    try:
        return program.getAddressFactory().getAddress(addr_text)
    except Exception:
        return None


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
                                        ptr_addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(ptr_val)
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


def extract_call_args(program, callsite_addr, monitor=None):
    result = {
        "callsite": callsite_addr,
        "status": "unresolved",
        "arg_addrs": [],
        "string_args": [],
        "data_args": [],
    }
    addr = _to_address(program, callsite_addr)
    if addr is None:
        result["status"] = "invalid_address"
        return result
    func = program.getFunctionManager().getFunctionContaining(addr)
    if func is None:
        result["status"] = "no_function"
        return result
    result["function"] = {
        "address": addr_str(func.getEntryPoint()),
        "name": func.getName(),
    }

    decomp = DecompInterface()
    decomp.openProgram(program)
    decomp_result = decomp.decompileFunction(func, 30, monitor)
    if not decomp_result or not decomp_result.decompileCompleted():
        result["status"] = "decompile_failed"
        return result
    high_func = decomp_result.getHighFunction()
    if high_func is None:
        result["status"] = "no_high_function"
        return result

    # Walk pcode to find the exact callsite and resolve constant args.
    op_iter = high_func.getPcodeOps()
    while op_iter.hasNext():
        if monitor is not None and monitor.isCancelled():
            result["status"] = "cancelled"
            return result
        op = op_iter.next()
        if op.getOpcode() not in (PcodeOp.CALL, PcodeOp.CALLIND):
            continue
        seq = op.getSeqnum()
        try:
            op_addr = seq.getTarget()
        except Exception:
            op_addr = None
        if op_addr is None or addr_str(op_addr) != callsite_addr:
            continue
        result["status"] = "ok"
        seen_addrs = set()
        for idx in range(1, op.getNumInputs()):
            varnode = op.getInput(idx)
            const_addr = _resolve_varnode_addr(program, varnode)
            if const_addr is None:
                continue
            addr_text = addr_str(const_addr)
            if addr_text is None:
                continue
            if addr_text in seen_addrs:
                continue
            seen_addrs.add(addr_text)
            result["arg_addrs"].append(addr_text)
            value = _resolve_string_at(program, const_addr)
            if value is not None:
                result["string_args"].append({
                    "address": addr_text,
                    "value": value,
                })
                continue
            result["data_args"].append(addr_text)
        if not result["string_args"] and not result["data_args"]:
            result["status"] = "no_resolved_args"
        return result

    result["status"] = "callsite_not_found"
    return result


def _align_offset(offset, alignment):
    if alignment <= 0:
        return offset
    return (offset + alignment - 1) // alignment * alignment


def _read_int(memory, addr, size, big_endian):
    data = bytearray(size)
    try:
        memory.getBytes(addr, data)
    except Exception:
        return None
    value = 0
    if big_endian:
        for b in data:
            value = (value << 8) | (b & 0xFF)
    else:
        for idx in range(size - 1, -1, -1):
            value = (value << 8) | (data[idx] & 0xFF)
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
    data = bytearray(max_len)
    try:
        memory.getBytes(addr, data)
    except Exception:
        return None
    chars = []
    for b in data:
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


def _is_probable_longopt_name(value):
    if value is None:
        return False
    for ch in value:
        if ch.isalnum():
            continue
        if ch in "_-":
            continue
        return False
    return True


def parse_option_token(value):
    if not value:
        return None
    if any(ch.isspace() for ch in value):
        return None
    if value.startswith("--"):
        name = value[2:]
        if not name:
            return None
        has_arg = "no"
        if name.endswith("="):
            name = name[:-1]
            has_arg = "required"
        if not name or not _is_probable_longopt_name(name):
            return None
        return {
            "long_name": name,
            "short_name": None,
            "has_arg": has_arg,
        }
    if value.startswith("-") and len(value) == 2:
        ch = value[1]
        if not ch.isalnum():
            return None
        return {
            "long_name": None,
            "short_name": ch,
            "has_arg": "no",
        }
    return None


def decode_short_opt_string(value):
    if not value:
        return []
    options = []
    idx = 0
    length = len(value)
    while idx < length:
        ch = value[idx]
        if idx == 0 and ch in (":", "+", "-"):
            idx += 1
            continue
        if ch == ":":
            idx += 1
            continue
        has_arg = "no"
        if idx + 1 < length and value[idx + 1] == ":":
            if idx + 2 < length and value[idx + 2] == ":":
                has_arg = "optional"
                idx += 2
            else:
                has_arg = "required"
                idx += 1
        options.append({
            "short_name": ch,
            "has_arg": has_arg,
        })
        idx += 1
    return options


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


def build_cli_parse_details(
    program,
    parse_sites,
    call_args_by_callsite,
    string_addr_map_all,
    max_longopt_entries,
):
    details_by_callsite = {}
    for site in parse_sites:
        callsite = site.get("callsite")
        if not callsite:
            continue
        args = call_args_by_callsite.get(callsite, {})
        detail = {
            "callsite": callsite,
            "caller": site.get("caller"),
            "callee": site.get("callee"),
            "callee_norm": site.get("callee_norm"),
            "args_status": args.get("status"),
            "optstring": None,
            "longopts": None,
        }

        # Choose the densest optstring/longopts table to reduce noise per callsite.
        best_short = None
        best_short_count = 0
        for entry in args.get("string_args", []):
            options = decode_short_opt_string(entry.get("value"))
            if len(options) > best_short_count:
                best_short_count = len(options)
                best_short = {
                    "address": entry.get("address"),
                    "value": entry.get("value"),
                    "options": options,
                }
        if best_short and best_short_count > 0:
            best_short["string_id"] = string_addr_map_all.get(best_short.get("address"))
            detail["optstring"] = best_short

        best_long = None
        best_long_count = 0
        for addr_text in args.get("data_args", []):
            table = decode_longopt_table(program, addr_text, max_longopt_entries)
            entries = table.get("entries", [])
            count = 0
            for entry in entries:
                if entry.get("name"):
                    count += 1
            if count > best_long_count:
                best_long_count = count
                best_long = table
        if best_long and best_long.get("entries"):
            for entry in best_long["entries"]:
                name_addr = entry.get("name_address")
                if name_addr:
                    entry["string_id"] = string_addr_map_all.get(name_addr)
            detail["longopts"] = best_long

        details_by_callsite[callsite] = detail
    return details_by_callsite


def build_cli_compare_details(compare_sites, call_args_by_callsite, string_addr_map_all):
    details_by_callsite = {}
    for site in compare_sites:
        callsite = site.get("callsite")
        if not callsite:
            continue
        args = call_args_by_callsite.get(callsite, {})
        option_tokens = []
        seen = set()
        # Direct string compares are noisy; only keep tokens that look like CLI options.
        for entry in args.get("string_args", []):
            token = parse_option_token(entry.get("value"))
            if not token:
                continue
            address = entry.get("address")
            string_id = string_addr_map_all.get(address)
            key = (token.get("long_name"), token.get("short_name"), token.get("has_arg"), address)
            if key in seen:
                continue
            seen.add(key)
            token["address"] = address
            token["string_id"] = string_id
            token["value"] = entry.get("value")
            option_tokens.append(token)
        if not option_tokens:
            continue
        details_by_callsite[callsite] = {
            "callsite": callsite,
            "caller": site.get("caller"),
            "callee": site.get("callee"),
            "callee_norm": site.get("callee_norm"),
            "args_status": args.get("status"),
            "option_tokens": option_tokens,
        }
    return details_by_callsite


def _classify_check_site(listing, instr):
    try:
        flow = instr.getFlowType()
    except Exception:
        flow = None
    if flow and flow.isConditional():
        return {
            "strength": "derived",
            "confidence": "medium",
        }
    try:
        mnemonic = instr.getMnemonicString()
    except Exception:
        mnemonic = None
    if mnemonic and mnemonic.upper() in CLI_COMPARE_MNEMONICS:
        try:
            next_instr = listing.getInstructionAfter(instr.getAddress())
        except Exception:
            next_instr = None
        if next_instr is not None:
            try:
                next_flow = next_instr.getFlowType()
            except Exception:
                next_flow = None
            if next_flow and next_flow.isConditional():
                return {
                    "strength": "derived",
                    "confidence": "medium",
                    "branch_address": addr_str(next_instr.getAddress()),
                }
        return {
            "strength": "heuristic",
            "confidence": "low",
        }
    return None


def collect_flag_check_sites(program, flag_addresses, max_sites_per_flag):
    listing = program.getListing()
    ref_manager = program.getReferenceManager()
    func_manager = program.getFunctionManager()
    results = {}
    for addr_text in flag_addresses:
        addr = _to_address(program, addr_text)
        if addr is None:
            continue
        sites = []
        seen = set()
        try:
            ref_iter = ref_manager.getReferencesTo(addr)
        except Exception:
            ref_iter = None
        if ref_iter is None:
            continue
        while ref_iter.hasNext():
            ref = ref_iter.next()
            from_addr = ref.getFromAddress()
            if from_addr is None:
                continue
            from_text = addr_str(from_addr)
            if from_text in seen:
                continue
            instr = listing.getInstructionAt(from_addr)
            if instr is None:
                continue
            # Heuristic: only keep sites that look like conditionals or compares.
            classification = _classify_check_site(listing, instr)
            if classification is None:
                continue
            func = func_manager.getFunctionContaining(from_addr)
            func_entry = None
            func_name = None
            if func:
                func_entry = addr_str(func.getEntryPoint())
                func_name = func.getName()
            site = {
                "address": from_text,
                "function": {
                    "address": func_entry,
                    "name": func_name,
                },
                "instruction": instr.toString(),
                "strength": classification.get("strength"),
                "confidence": classification.get("confidence"),
            }
            branch_addr = classification.get("branch_address")
            if branch_addr:
                site["branch_address"] = branch_addr
            sites.append(site)
            seen.add(from_text)
            if max_sites_per_flag and len(sites) >= max_sites_per_flag:
                break
        if sites:
            results[addr_text] = sites
    return results


def is_jump_instruction(instr):
    try:
        flow = instr.getFlowType()
        if flow.isJump():
            return True
    except Exception:
        pass
    try:
        mnemonic = instr.getMnemonicString()
    except Exception:
        mnemonic = None
    if mnemonic and mnemonic.upper() == "JMP":
        return True
    return False


def build_function_metrics(functions, call_edges, string_refs_by_func, string_tags_by_id):
    in_degree = {}
    out_degree = {}
    import_calls = {}
    import_callees = {}
    for edge in call_edges:
        from_addr = edge.get("from", {}).get("address")
        target = edge.get("to") or {}
        if from_addr is None:
            continue
        if target.get("external"):
            import_calls[from_addr] = import_calls.get(from_addr, 0) + 1
            name_norm = normalize_symbol_name(target.get("name"))
            if name_norm:
                callees = import_callees.get(from_addr)
                if callees is None:
                    callees = set()
                    import_callees[from_addr] = callees
                callees.add(name_norm)
        else:
            out_degree[from_addr] = out_degree.get(from_addr, 0) + 1
            to_addr = target.get("address")
            if to_addr:
                in_degree[to_addr] = in_degree.get(to_addr, 0) + 1

    metrics_by_addr = {}
    for func in functions:
        addr = addr_str(func.getEntryPoint())
        string_refs = string_refs_by_func.get(addr, set())
        salience = 0
        for string_id in string_refs:
            tags = string_tags_by_id.get(string_id)
            if not tags:
                continue
            for tag in tags:
                if tag in SALIENCE_TAGS:
                    salience += 1
                    break
        metrics_by_addr[addr] = {
            "size": function_size(func),
            "import_calls": import_calls.get(addr, 0),
            "import_diversity": len(import_callees.get(addr, set())),
            "string_salience": salience,
            "call_degree": in_degree.get(addr, 0) + out_degree.get(addr, 0),
            "in_degree": in_degree.get(addr, 0),
            "out_degree": out_degree.get(addr, 0),
        }
    return metrics_by_addr


def build_function_import_sets(call_edges):
    import_sets = {}
    for edge in call_edges:
        from_addr = (edge.get("from") or {}).get("address")
        target = edge.get("to") or {}
        if not from_addr or not target.get("external"):
            continue
        name_norm = normalize_symbol_name(target.get("name"))
        if not name_norm:
            continue
        names = import_sets.get(from_addr)
        if names is None:
            names = set()
            import_sets[from_addr] = names
        names.add(name_norm)
    return import_sets


def select_full_functions(functions, metrics_by_addr, max_count):
    internal = [func for func in functions if not func.isExternal() and not func.isThunk()]
    if max_count <= 0:
        return []
    # Mix multiple ranking signals to avoid size-only bias in multicall binaries.
    bucket_size = max(1, max_count // 5)
    selected = []
    selected_addrs = set()

    def metric_sort_key(func, primary, secondary):
        addr = addr_str(func.getEntryPoint())
        metrics = metrics_by_addr.get(addr, {})
        return (
            -metrics.get(primary, 0),
            -metrics.get(secondary, 0),
            -metrics.get("call_degree", 0),
            -metrics.get("string_salience", 0),
            -metrics.get("size", 0),
            addr_to_int(addr),
        )

    def add_from_sorted(sorted_funcs, limit):
        count = 0
        for func in sorted_funcs:
            if len(selected) >= max_count or count >= limit:
                break
            addr = addr_str(func.getEntryPoint())
            if addr in selected_addrs:
                continue
            selected.append(func)
            selected_addrs.add(addr)
            count += 1

    add_from_sorted(
        sorted(internal, key=lambda func: metric_sort_key(func, "import_calls", "import_diversity")),
        bucket_size,
    )
    add_from_sorted(
        sorted(internal, key=lambda func: metric_sort_key(func, "import_diversity", "import_calls")),
        bucket_size,
    )
    add_from_sorted(
        sorted(internal, key=lambda func: metric_sort_key(func, "string_salience", "import_calls")),
        bucket_size,
    )
    add_from_sorted(
        sorted(internal, key=lambda func: metric_sort_key(func, "call_degree", "import_calls")),
        bucket_size,
    )
    add_from_sorted(
        sorted(internal, key=lambda func: metric_sort_key(func, "size", "import_calls")),
        bucket_size,
    )

    def relevance_sort_key(func):
        addr = addr_str(func.getEntryPoint())
        metrics = metrics_by_addr.get(addr, {})
        return (
            -metrics.get("import_calls", 0),
            -metrics.get("import_diversity", 0),
            -metrics.get("string_salience", 0),
            -metrics.get("call_degree", 0),
            -metrics.get("size", 0),
            addr_to_int(addr),
        )

    for func in sorted(internal, key=relevance_sort_key):
        if len(selected) >= max_count:
            break
        addr = addr_str(func.getEntryPoint())
        if addr in selected_addrs:
            continue
        selected.append(func)
        selected_addrs.add(addr)

    return selected


def select_index_functions(functions, full_functions, max_count):
    if max_count <= 0:
        return []
    selected = []
    selected_addrs = set()
    for func in full_functions:
        if len(selected) >= max_count:
            return selected
        addr = addr_str(func.getEntryPoint())
        if addr in selected_addrs:
            continue
        selected.append(func)
        selected_addrs.add(addr)

    ordered = sorted(
        functions,
        key=lambda func: (-function_size(func), func.getEntryPoint().getOffset()),
    )
    for func in ordered:
        if len(selected) >= max_count:
            break
        addr = addr_str(func.getEntryPoint())
        if addr in selected_addrs:
            continue
        selected.append(func)
        selected_addrs.add(addr)

    return selected


def summarize_functions(functions, selected_functions, full_functions):
    summaries = []
    full_addr_set = set([addr_str(func.getEntryPoint()) for func in full_functions])
    selected_addr_set = set([addr_str(func.getEntryPoint()) for func in selected_functions])
    for func in functions:
        addr = addr_str(func.getEntryPoint())
        if addr not in selected_addr_set:
            continue
        try:
            size = func.getBody().getNumAddresses()
        except Exception:
            size = 0
        summary = {
            "name": func.getName(),
            "address": addr,
            "size": size,
            "is_external": func.isExternal(),
            "is_thunk": func.isThunk(),
            "fully_exported": addr in full_addr_set,
        }
        try:
            summary["signature"] = func.getSignature().toString()
        except Exception:
            summary["signature"] = None
        summaries.append(summary)

    summaries.sort(key=lambda item: addr_to_int(item.get("address")))
    return summaries


def resolve_callee_function(func_manager, symbol_table, external_manager, to_addr):
    callee = func_manager.getFunctionAt(to_addr)
    if callee and callee.isThunk():
        try:
            thunked = callee.getThunkedFunction(True)
            if thunked:
                callee = thunked
        except Exception:
            pass
    if callee:
        library = None
        if callee.isExternal():
            try:
                symbol = callee.getSymbol()
                if symbol:
                    ext_loc = external_manager.getExternalLocation(symbol)
                    if ext_loc:
                        library = ext_loc.getLibraryName()
            except Exception:
                library = None
        return {
            "name": callee.getName(),
            "address": addr_str(callee.getEntryPoint()),
            "external": callee.isExternal(),
            "library": library,
        }
    symbol = symbol_table.getPrimarySymbol(to_addr)
    if symbol and symbol.isExternal():
        library = None
        try:
            ext_loc = external_manager.getExternalLocation(symbol)
            if ext_loc:
                library = ext_loc.getLibraryName()
        except Exception:
            library = None
        return {
            "name": symbol.getName(),
            "address": addr_str(to_addr),
            "external": True,
            "library": library,
        }
    return {
        "name": None,
        "address": addr_str(to_addr),
        "external": None,
        "library": None,
    }


def collect_call_edges(program, functions, monitor=None):
    listing = program.getListing()
    func_manager = program.getFunctionManager()
    symbol_table = program.getSymbolTable()
    external_manager = program.getExternalManager()
    edges = []
    callsite_records = {}
    stats = {
        "caller_functions_total": 0,
        "caller_functions_skipped_external": 0,
        "caller_functions_skipped_thunk": 0,
        "call_instructions_total": 0,
        "call_instructions_skipped_jump": 0,
        "edges_emitted": 0,
    }

    for func in functions:
        stats["caller_functions_total"] += 1
        if func.isExternal():
            stats["caller_functions_skipped_external"] += 1
            continue
        if func.isThunk():
            stats["caller_functions_skipped_thunk"] += 1
            continue
        instr_iter = listing.getInstructions(func.getBody(), True)
        while instr_iter.hasNext():
            if monitor is not None and monitor.isCancelled():
                break
            instr = instr_iter.next()
            if not instr.getFlowType().isCall():
                continue
            stats["call_instructions_total"] += 1
            # Drop jump-based thunks so the callgraph reflects real logic.
            if is_jump_instruction(instr):
                stats["call_instructions_skipped_jump"] += 1
                continue
            callsite_addr = addr_str(instr.getAddress())
            refs = instr.getReferencesFrom()
            for ref in refs:
                if not ref.getReferenceType().isCall():
                    continue
                to_addr = ref.getToAddress()
                target = resolve_callee_function(func_manager, symbol_table, external_manager, to_addr)
                edge = {
                    "from": {
                        "function": func.getName(),
                        "address": addr_str(func.getEntryPoint()),
                    },
                    "to": target,
                    "callsite": callsite_addr,
                }
                edges.append(edge)
                stats["edges_emitted"] += 1

                record = callsite_records.get(callsite_addr)
                if record is None:
                    record = {
                        "callsite": callsite_addr,
                        "from": {
                            "function": func.getName(),
                            "address": addr_str(func.getEntryPoint()),
                        },
                        "instruction": instr.toString(),
                        "targets": [],
                    }
                    callsite_records[callsite_addr] = record
                record["targets"].append(target)

    return edges, callsite_records, stats


def collect_flow_summary(listing, func):
    summary = {
        "instruction_count": 0,
        "call_count": 0,
        "branch_count": 0,
        "return_count": 0,
    }
    instr_iter = listing.getInstructions(func.getBody(), True)
    while instr_iter.hasNext():
        instr = instr_iter.next()
        summary["instruction_count"] += 1
        flow = instr.getFlowType()
        if flow.isCall():
            summary["call_count"] += 1
        try:
            if flow.isJump() or flow.isConditional():
                summary["branch_count"] += 1
        except Exception:
            if flow.isJump():
                summary["branch_count"] += 1
        if flow.isTerminal():
            summary["return_count"] += 1
    return summary


def collect_function_calls(call_edges):
    calls_by_func = {}
    for edge in call_edges:
        from_addr = edge["from"]["address"]
        calls = calls_by_func.get(from_addr)
        if calls is None:
            calls = []
            calls_by_func[from_addr] = calls
        calls.append({
            "callsite": edge["callsite"],
            "to": edge["to"],
        })
    return calls_by_func


def collect_functions(program):
    func_manager = program.getFunctionManager()
    functions = []
    func_iter = func_manager.getFunctions(True)
    while func_iter.hasNext():
        functions.append(func_iter.next())
    functions.sort(key=lambda func: func.getEntryPoint().getOffset())
    return functions


def build_function_meta(functions):
    meta = {}
    for func in functions:
        addr = addr_str(func.getEntryPoint())
        meta[addr] = {
            "name": func.getName(),
            "address": addr,
            "is_external": func.isExternal(),
            "is_thunk": func.isThunk(),
        }
    return meta


def collect_string_refs_by_func(listing, functions, string_addr_map_all, monitor=None):
    string_refs_by_func = {}
    for func in functions:
        if func.isExternal():
            continue
        addr = addr_str(func.getEntryPoint())
        string_refs_by_func[addr] = collect_function_string_refs(
            listing, func, string_addr_map_all, monitor
        )
    return string_refs_by_func


def build_signal_set(capability_rules):
    signal_set = set()
    for rule in capability_rules:
        for name in rule["signals"]:
            signal_set.add(normalize_symbol_name(name))
    return signal_set


def select_call_edges(call_edges_all, signal_set, max_edges):
    # Prefer capability signal edges first, then fill with internal calls by order.
    call_edges_all.sort(
        key=lambda item: (
            addr_to_int(item.get("callsite")),
            addr_to_int(item.get("from", {}).get("address")),
            item.get("to", {}).get("name") or "",
        )
    )
    signal_edges = []
    other_edges = []
    for edge in call_edges_all:
        name_norm = normalize_symbol_name((edge.get("to") or {}).get("name"))
        if name_norm and name_norm in signal_set:
            signal_edges.append(edge)
        else:
            other_edges.append(edge)

    call_edges = signal_edges + other_edges

    total_edges = len(call_edges)
    truncated_edges = False
    if total_edges > max_edges:
        call_edges = call_edges[:max_edges]
        truncated_edges = True
    return call_edges, total_edges, truncated_edges
