import re

from ghidra.program.model.data import StringDataInstance

from export_primitives import SALIENCE_TAGS, addr_id, addr_str, addr_to_int, normalize_symbol_name

ENV_VAR_RE = re.compile(r"^[A-Z0-9_]{3,}$")


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
