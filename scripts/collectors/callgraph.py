"""Callgraph and function-level collection helpers."""

from export_primitives import SALIENCE_TAGS, addr_str, addr_to_int, normalize_symbol_name


def function_size(func):
    try:
        return func.getBody().getNumAddresses()
    except Exception:
        return 0


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
        import_set = import_sets.get(from_addr)
        if import_set is None:
            import_set = set()
            import_sets[from_addr] = import_set
        import_set.add(name_norm)
    return import_sets


def select_full_functions(functions, metrics_by_addr, max_count):
    scored = []
    for func in functions:
        addr = addr_str(func.getEntryPoint())
        metrics = metrics_by_addr.get(addr, {})
        score = (
            metrics.get("import_diversity", 0) * 3
            + metrics.get("import_calls", 0)
            + metrics.get("string_salience", 0) * 2
            + metrics.get("call_degree", 0)
        )
        scored.append((score, -metrics.get("size", 0), addr))
    scored.sort(reverse=True)

    selected = []
    selected_addrs = set()
    for _, _, addr in scored:
        if len(selected) >= max_count:
            break
        for func in functions:
            func_addr = addr_str(func.getEntryPoint())
            if func_addr == addr:
                selected.append(func)
                selected_addrs.add(addr)
                break
    return selected


def select_index_functions(functions, full_functions, max_count):
    selected = list(full_functions)
    selected_addrs = set([addr_str(func.getEntryPoint()) for func in full_functions])

    # Prefer entry points to keep the index navigable and stable.
    for func in functions:
        if len(selected) >= max_count:
            break
        if func.isExternal() or func.isThunk():
            continue
        try:
            if func.getEntryPoint() != func.getEntryPoint():
                continue
        except Exception:
            pass
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
            "size": function_size(func),
        }
    return meta


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

