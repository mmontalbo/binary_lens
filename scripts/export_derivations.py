from export_primitives import SALIENCE_TAGS, addr_id, addr_str, addr_to_int, normalize_symbol_name

DEFAULT_MAX_CAPABILITY_FUNCTIONS = 5
DEFAULT_MAX_CAPABILITY_CALLSITE_CLUSTERS = 5
DEFAULT_MAX_CAPABILITY_CALLSITES_PER_CLUSTER = 3
DEFAULT_MAX_CAPABILITY_STRINGS = 8

DEFAULT_MAX_SUBSYSTEMS = 60
DEFAULT_MAX_SUBSYSTEM_REP_FUNCTIONS = 8
DEFAULT_MAX_SUBSYSTEM_IMPORTS = 8
DEFAULT_MAX_SUBSYSTEM_STRING_BUCKETS = 4
DEFAULT_MAX_SUBSYSTEM_CLUSTER_SIZE = 200
DEFAULT_MAX_SUBSYSTEM_STRONG_LINKS = 6

try:
    INT_TYPES = (int, long)
except NameError:
    INT_TYPES = (int,)

OPTION_SIGNALS = set([
    "getopt",
    "getopt_long",
    "__getopt_long",
    "getopt_long_only",
    "argp_parse",
])
FORMAT_SIGNALS = set([
    "printf",
    "fprintf",
    "vprintf",
    "vfprintf",
    "puts",
    "fputs",
    "putchar",
    "sprintf",
    "snprintf",
    "vsprintf",
    "vsnprintf",
    "asprintf",
    "vasprintf",
])
TRAVERSAL_SIGNALS = set([
    "opendir",
    "readdir",
    "readdir64",
])
CALLBACK_SIGNALS = set([
    "ftw",
    "nftw",
])


def classify_role_hint(in_deg, out_deg):
    # Mechanical role hints based on local callgraph shape.
    if in_deg == 0 and out_deg > 0:
        return "entry_like"
    if out_deg == 0 and in_deg > 0:
        return "leaf_worker"
    if out_deg >= max(3, 2 * max(1, in_deg)):
        return "dispatcher_like"
    if in_deg >= max(3, 2 * max(1, out_deg)):
        return "shared_helper"
    if out_deg > in_deg:
        return "dispatcher_like"
    if in_deg > out_deg:
        return "shared_helper"
    return "leaf_worker"


def refine_entry_like_roles(top_functions, role_metrics_by_addr):
    # Enforce a single primary entry-like function per capability for clarity.
    candidates = [fn for fn in top_functions if fn.get("role_hint") == "entry_like"]
    primary_addr = None
    if candidates:
        def score(fn):
            addr = fn.get("address")
            metrics = role_metrics_by_addr.get(addr, {})
            return (
                metrics.get("out_degree", 0),
                metrics.get("callsite_count", 0),
                -metrics.get("in_degree", 0),
                -addr_to_int(addr),
            )

        primary = max(candidates, key=score)
        primary_addr = primary.get("address")
        for fn in top_functions:
            if fn.get("role_hint") != "entry_like":
                continue
            addr = fn.get("address")
            if addr == primary_addr:
                fn["role_hint"] = "primary_entry_like"
                continue
            metrics = role_metrics_by_addr.get(addr, {})
            if metrics.get("in_degree", 0) > metrics.get("out_degree", 0):
                fn["role_hint"] = "shared_helper"
            else:
                fn["role_hint"] = "secondary_entry_like"
    return primary_addr


def infer_shape_hint(matched_signals, top_strings, evidence_clusters, top_functions):
    # Shape hints are coarse, mechanical cues derived from imports, strings, and graph shape.
    matched = set(matched_signals)
    option_signals = set([normalize_symbol_name(name) for name in OPTION_SIGNALS])
    format_signals = set([normalize_symbol_name(name) for name in FORMAT_SIGNALS])
    traversal_signals = set([normalize_symbol_name(name) for name in TRAVERSAL_SIGNALS])
    callback_signals = set([normalize_symbol_name(name) for name in CALLBACK_SIGNALS])
    if matched & option_signals:
        return "option_flag_controlled"
    if matched & callback_signals:
        return "callback_style"
    if matched & traversal_signals:
        return "iterative_traversal"
    if matched & format_signals:
        return "format_string_based"
    for entry in top_strings:
        tags = set(entry.get("tags") or [])
        if "format" in tags:
            return "format_string_based"
    dispatcher_present = any(
        fn.get("role_hint") in ("dispatcher_like",)
        for fn in top_functions
    )
    if len(evidence_clusters) >= 3 and dispatcher_present:
        return "table_driven"
    if len(evidence_clusters) <= 1 and len(top_functions) <= 1:
        return "simple_wrapper"
    if dispatcher_present:
        return "table_driven"
    return "simple_wrapper"


def build_internal_callgraph_adjacency(call_edges):
    # Undirected adjacency supports cheap community-style clustering.
    adjacency = {}
    for edge in call_edges:
        from_addr = (edge.get("from") or {}).get("address")
        target = edge.get("to") or {}
        if not from_addr or target.get("external"):
            continue
        to_addr = target.get("address")
        if not to_addr:
            continue
        neighbors = adjacency.get(from_addr)
        if neighbors is None:
            neighbors = set()
            adjacency[from_addr] = neighbors
        neighbors.add(to_addr)
        reverse = adjacency.get(to_addr)
        if reverse is None:
            reverse = set()
            adjacency[to_addr] = reverse
        reverse.add(from_addr)
    return adjacency


def compute_callgraph_components(addrs, adjacency):
    component_by_addr = {}
    component_count = 0
    for addr in sorted(addrs, key=addr_to_int):
        if addr in component_by_addr:
            continue
        queue = [addr]
        component_by_addr[addr] = component_count
        while queue:
            current = queue.pop()
            for neighbor in adjacency.get(current, []):
                if neighbor in component_by_addr:
                    continue
                component_by_addr[neighbor] = component_count
                queue.append(neighbor)
        component_count += 1
    return component_by_addr, component_count


def build_string_bucket_counts(string_refs_by_func, string_tags_by_id):
    bucket_counts_by_func = {}
    for addr, string_ids in string_refs_by_func.items():
        counts = {}
        for string_id in string_ids:
            tags = string_tags_by_id.get(string_id) or set()
            for tag in tags:
                if tag not in SALIENCE_TAGS:
                    continue
                counts[tag] = counts.get(tag, 0) + 1
        if counts:
            bucket_counts_by_func[addr] = counts
    return bucket_counts_by_func


def derive_subsystems(
    functions,
    function_meta_by_addr,
    metrics_by_addr,
    call_edges,
    import_sets_by_func,
    string_bucket_counts_by_func,
):
    internal_addrs = []
    for func in functions:
        if func.isExternal() or func.isThunk():
            continue
        internal_addrs.append(addr_str(func.getEntryPoint()))

    adjacency = build_internal_callgraph_adjacency(call_edges)
    component_by_addr, _ = compute_callgraph_components(internal_addrs, adjacency)

    # Cluster by callgraph component + import signature + string bucket signature.
    signature_import_limit = min(3, DEFAULT_MAX_SUBSYSTEM_IMPORTS)
    clusters = {}
    for addr in internal_addrs:
        component_id = component_by_addr.get(addr, -1)
        imports = sorted(list(import_sets_by_func.get(addr, set())))
        if signature_import_limit > 0:
            imports = imports[:signature_import_limit]
        import_sig = ",".join(imports) if imports else "none"
        bucket_sig = ",".join(sorted((string_bucket_counts_by_func.get(addr) or {}).keys()))
        if not bucket_sig:
            bucket_sig = "none"
        key = (component_id, import_sig, bucket_sig)
        cluster = clusters.get(key)
        if cluster is None:
            cluster = {
                "component_id": component_id,
                "import_signature": imports,
                "bucket_signature": bucket_sig.split(",") if bucket_sig != "none" else [],
                "functions": [],
            }
            clusters[key] = cluster
        cluster["functions"].append(addr)

    cluster_list = []
    for cluster in clusters.values():
        funcs = sorted(cluster["functions"], key=addr_to_int)
        if len(funcs) <= DEFAULT_MAX_SUBSYSTEM_CLUSTER_SIZE:
            cluster["functions"] = funcs
            cluster_list.append(cluster)
            continue
        for idx in range(0, len(funcs), DEFAULT_MAX_SUBSYSTEM_CLUSTER_SIZE):
            part = {
                "component_id": cluster["component_id"],
                "import_signature": cluster["import_signature"],
                "bucket_signature": cluster["bucket_signature"],
                "functions": funcs[idx : idx + DEFAULT_MAX_SUBSYSTEM_CLUSTER_SIZE],
                "part_index": idx // DEFAULT_MAX_SUBSYSTEM_CLUSTER_SIZE,
            }
            cluster_list.append(part)

    summaries = []
    for cluster in cluster_list:
        funcs = cluster["functions"]
        func_set = set(funcs)
        total_size = 0
        for addr in funcs:
            total_size += metrics_by_addr.get(addr, {}).get("size", 0)

        def rep_sort_key(addr):
            metrics = metrics_by_addr.get(addr, {})
            return (
                -metrics.get("call_degree", 0),
                -metrics.get("import_calls", 0),
                -metrics.get("string_salience", 0),
                -metrics.get("size", 0),
                addr_to_int(addr),
            )

        representative_functions = []
        for addr in sorted(funcs, key=rep_sort_key):
            meta = function_meta_by_addr.get(addr, {})
            metrics = metrics_by_addr.get(addr, {})
            representative_functions.append({
                "address": addr,
                "name": meta.get("name"),
                "size": metrics.get("size", 0),
                "import_calls": metrics.get("import_calls", 0),
                "import_diversity": metrics.get("import_diversity", 0),
                "string_salience": metrics.get("string_salience", 0),
                "call_degree": metrics.get("call_degree", 0),
            })
            if len(representative_functions) >= DEFAULT_MAX_SUBSYSTEM_REP_FUNCTIONS:
                break

        import_counts = {}
        import_call_count = 0
        internal_edges = 0
        outbound_edges = 0
        inbound_edges = 0
        for edge in call_edges:
            from_addr = (edge.get("from") or {}).get("address")
            target = edge.get("to") or {}
            if not from_addr:
                continue
            if target.get("external"):
                if from_addr in func_set:
                    name_norm = normalize_symbol_name(target.get("name"))
                    if name_norm:
                        import_counts[name_norm] = import_counts.get(name_norm, 0) + 1
                    import_call_count += 1
                continue
            to_addr = target.get("address")
            if not to_addr:
                continue
            if from_addr in func_set and to_addr in func_set:
                internal_edges += 1
            elif from_addr in func_set and to_addr not in func_set:
                outbound_edges += 1
            elif from_addr not in func_set and to_addr in func_set:
                inbound_edges += 1

        characteristic_imports = []
        for name, count in sorted(
            import_counts.items(),
            key=lambda item: (-item[1], item[0]),
        ):
            characteristic_imports.append({
                "name": name,
                "count": count,
            })
            if len(characteristic_imports) >= DEFAULT_MAX_SUBSYSTEM_IMPORTS:
                break

        bucket_counts = {}
        for addr in funcs:
            counts = string_bucket_counts_by_func.get(addr, {})
            for bucket, count in counts.items():
                bucket_counts[bucket] = bucket_counts.get(bucket, 0) + count

        characteristic_buckets = []
        for bucket, count in sorted(
            bucket_counts.items(),
            key=lambda item: (-item[1], item[0]),
        ):
            characteristic_buckets.append({
                "bucket": bucket,
                "count": count,
            })
            if len(characteristic_buckets) >= DEFAULT_MAX_SUBSYSTEM_STRING_BUCKETS:
                break

        min_addr = min([addr_to_int(addr) for addr in funcs]) if funcs else -1
        summaries.append({
            "component_id": cluster.get("component_id"),
            "import_signature": cluster.get("import_signature"),
            "bucket_signature": cluster.get("bucket_signature"),
            "function_count": len(funcs),
            "total_size": total_size,
            "min_address": min_addr,
            "functions": funcs,
            "representative_functions": representative_functions,
            "characteristic_imports": characteristic_imports,
            "characteristic_string_buckets": characteristic_buckets,
            "reachability": {
                "internal_edges": internal_edges,
                "outbound_edges": outbound_edges,
                "inbound_edges": inbound_edges,
                "import_calls": import_call_count,
            },
        })

    summaries.sort(
        key=lambda item: (
            -item.get("function_count", 0),
            -item.get("total_size", 0),
            item.get("min_address", 0),
        )
    )

    total_subsystems = len(summaries)
    truncated = False
    if total_subsystems > DEFAULT_MAX_SUBSYSTEMS:
        summaries = summaries[:DEFAULT_MAX_SUBSYSTEMS]
        truncated = True

    for idx, summary in enumerate(summaries):
        summary["id"] = "ss_%03d" % (idx + 1)
        summary.pop("min_address", None)

    func_to_subsystem = {}
    for summary in summaries:
        subsystem_id = summary.get("id")
        for addr in summary.get("functions", []):
            func_to_subsystem[addr] = subsystem_id

    # Track cross-subsystem call edges for directional linkage.
    link_counts = {}
    for edge in call_edges:
        target = edge.get("to") or {}
        if target.get("external"):
            continue
        from_addr = (edge.get("from") or {}).get("address")
        to_addr = target.get("address")
        if not from_addr or not to_addr:
            continue
        from_ss = func_to_subsystem.get(from_addr)
        to_ss = func_to_subsystem.get(to_addr)
        if not from_ss or not to_ss or from_ss == to_ss:
            continue
        pair = (from_ss, to_ss)
        link_counts[pair] = link_counts.get(pair, 0) + 1

    for summary in summaries:
        subsystem_id = summary.get("id")
        outbound = {}
        inbound = {}
        for (from_id, to_id), count in link_counts.items():
            if from_id == subsystem_id:
                outbound[to_id] = outbound.get(to_id, 0) + count
            if to_id == subsystem_id:
                inbound[from_id] = inbound.get(from_id, 0) + count
        linked_ids = set(outbound.keys()) | set(inbound.keys())
        links = []
        for other_id in sorted(linked_ids):
            out_count = outbound.get(other_id, 0)
            in_count = inbound.get(other_id, 0)
            if out_count > 0 and in_count > 0:
                direction = "bidirectional"
            elif out_count > 0:
                direction = "calls_into"
            else:
                direction = "called_by"
            links.append({
                "subsystem_id": other_id,
                "direction": direction,
                "call_edge_count": out_count + in_count,
                "calls_into_count": out_count,
                "called_by_count": in_count,
            })
        links.sort(key=lambda item: (-item.get("call_edge_count", 0), item.get("subsystem_id") or ""))
        if len(links) > DEFAULT_MAX_SUBSYSTEM_STRONG_LINKS:
            links = links[:DEFAULT_MAX_SUBSYSTEM_STRONG_LINKS]
        summary["strong_links"] = links

    for summary in summaries:
        summary.pop("functions", None)

    return {
        "total_subsystems": total_subsystems,
        "selected_subsystems": len(summaries),
        "max_subsystems": DEFAULT_MAX_SUBSYSTEMS,
        "truncated": truncated,
        "selection_strategy": "callgraph_components_imports_string_buckets",
        "subsystems": summaries,
    }


def _merge_has_arg(current, new):
    if not current or current == "unknown":
        return new or "unknown"
    if not new or new == "unknown":
        return current
    if current == new:
        return current
    return "unknown"


def _short_from_val(val):
    if val is None:
        return None
    if not isinstance(val, INT_TYPES):
        return None
    if val <= 0 or val > 127:
        return None
    ch = chr(val)
    if ch.isspace() or ch in (":",):
        return None
    return ch


def _option_identity(long_name, short_name, has_arg):
    has_arg = has_arg or "unknown"
    if long_name:
        return (long_name, short_name, has_arg)
    return (None, short_name, has_arg)


def _init_option(long_name, short_name, has_arg):
    return {
        "long_name": long_name,
        "short_name": short_name,
        "has_arg": has_arg or "unknown",
        "evidence": [],
        "parse_sites": [],
        "flag_vars": [],
        "check_sites": [],
        "parse_loop_ids": [],
    }


def _entry_strength_confidence(entry):
    evidence = entry.get("evidence") or []
    strength = "observed" if any(ev.get("strength") == "observed" for ev in evidence) else "heuristic"
    confidences = [ev.get("confidence") for ev in evidence if ev.get("confidence")]
    confidence = "high" if confidences and all(c == "high" for c in confidences) else "medium"
    return strength, confidence


def _add_parse_site(option, callsite_id, callsite_ref, caller, max_sites):
    seen = option.setdefault("_seen_parse_sites", set())
    if callsite_id in seen:
        return
    seen.add(callsite_id)
    if len(option["parse_sites"]) >= max_sites:
        return
    option["parse_sites"].append({
        "callsite_id": callsite_id,
        "callsite_ref": callsite_ref,
        "function": caller,
        "strength": "observed",
        "confidence": "high",
    })


def _add_parse_loop_id(option, loop_id):
    if not loop_id:
        return
    seen = option.setdefault("_seen_parse_loops", set())
    if loop_id in seen:
        return
    seen.add(loop_id)
    option.setdefault("parse_loop_ids", []).append(loop_id)


def _add_evidence(option, evidence, max_evidence):
    seen = option.setdefault("_seen_evidence", set())
    key = (
        evidence.get("kind"),
        evidence.get("callsite_id"),
        evidence.get("entry_address"),
        evidence.get("optstring_address"),
    )
    if key in seen:
        return
    seen.add(key)
    if len(option["evidence"]) >= max_evidence:
        return
    option["evidence"].append(evidence)


def _add_flag_var(option, flag_addr, entry_addr, name_addr, max_vars):
    seen = option.setdefault("_seen_flag_vars", set())
    if flag_addr in seen:
        return
    seen.add(flag_addr)
    if len(option["flag_vars"]) >= max_vars:
        return
    option["flag_vars"].append({
        "address": flag_addr,
        "entry_address": entry_addr,
        "name_address": name_addr,
        "strength": "observed",
        "confidence": "high",
    })


def _add_check_sites(option, flag_addr, check_sites_by_flag_addr, max_sites):
    sites = check_sites_by_flag_addr.get(flag_addr, [])
    seen = option.setdefault("_seen_check_sites", set())
    for site in sites:
        addr = site.get("address")
        if addr is None or addr in seen:
            continue
        if len(option["check_sites"]) >= max_sites:
            break
        seen.add(addr)
        option["check_sites"].append(site)


def _add_check_site_entry(option, site, max_sites):
    addr = site.get("address")
    if addr is None:
        return
    seen = option.setdefault("_seen_check_sites", set())
    if addr in seen:
        return
    if len(option["check_sites"]) >= max_sites:
        return
    seen.add(addr)
    option["check_sites"].append(site)


def _build_parse_loop_lookup(parse_groups):
    parse_loop_id_by_callsite = {}
    parse_loop_id_by_function = {}
    for idx, group in enumerate(parse_groups, start=1):
        loop_id = "parse_loop_%03d" % idx
        func_addr = (group.get("function") or {}).get("address")
        if func_addr:
            parse_loop_id_by_function[func_addr] = loop_id
        for callsite_id in group.get("callsites") or []:
            if callsite_id:
                parse_loop_id_by_callsite[callsite_id] = loop_id
    return parse_loop_id_by_callsite, parse_loop_id_by_function


def _collect_parse_option_entries(
    parse_details_by_callsite,
    parse_loop_id_by_callsite,
    callsite_paths,
    max_parse_sites,
    max_evidence,
    max_flag_vars,
    max_check_sites,
    check_sites_by_flag_addr,
):
    raw_options = []
    callsite_ids = sorted(parse_details_by_callsite.keys(), key=addr_to_int)
    for callsite_id in callsite_ids:
        detail = parse_details_by_callsite.get(callsite_id)
        if not detail:
            continue
        caller = detail.get("caller")
        callsite_ref = callsite_paths.get(callsite_id)
        loop_id = parse_loop_id_by_callsite.get(callsite_id)
        optstring = detail.get("optstring")
        if optstring:
            for opt in optstring.get("options", []):
                short_name = opt.get("short_name")
                option = _init_option(None, short_name, opt.get("has_arg"))
                _add_parse_site(option, callsite_id, callsite_ref, caller, max_parse_sites)
                _add_parse_loop_id(option, loop_id)
                _add_evidence(
                    option,
                    {
                        "kind": "optstring",
                        "callsite_id": callsite_id,
                        "callsite_ref": callsite_ref,
                        "optstring_address": optstring.get("address"),
                        "string_id": optstring.get("string_id"),
                        "strength": "observed",
                        "confidence": "high",
                    },
                    max_evidence,
                )
                raw_options.append(option)

        longopts = detail.get("longopts")
        if longopts:
            for entry in longopts.get("entries", []):
                long_name = entry.get("name")
                short_name = _short_from_val(entry.get("val"))
                option = _init_option(long_name, short_name, entry.get("has_arg"))
                _add_parse_site(option, callsite_id, callsite_ref, caller, max_parse_sites)
                _add_parse_loop_id(option, loop_id)
                _add_evidence(
                    option,
                    {
                        "kind": "longopt_entry",
                        "callsite_id": callsite_id,
                        "callsite_ref": callsite_ref,
                        "table_address": longopts.get("address"),
                        "entry_address": entry.get("entry_address"),
                        "name_address": entry.get("name_address"),
                        "string_id": entry.get("string_id"),
                        "strength": "observed",
                        "confidence": "high",
                    },
                    max_evidence,
                )
                flag_addr = entry.get("flag_address")
                if flag_addr:
                    _add_flag_var(
                        option,
                        flag_addr,
                        entry.get("entry_address"),
                        entry.get("name_address"),
                        max_flag_vars,
                    )
                    _add_check_sites(option, flag_addr, check_sites_by_flag_addr, max_check_sites)
                raw_options.append(option)
    return raw_options


def _collect_compare_option_entries(
    compare_details_by_callsite,
    parse_loop_id_by_callsite,
    callsite_paths,
    max_parse_sites,
    max_evidence,
):
    raw_options = []
    compare_details_by_callsite = compare_details_by_callsite or {}
    compare_callsite_ids = sorted(compare_details_by_callsite.keys(), key=addr_to_int)
    for callsite_id in compare_callsite_ids:
        detail = compare_details_by_callsite.get(callsite_id)
        if not detail:
            continue
        caller = detail.get("caller")
        callsite_ref = callsite_paths.get(callsite_id)
        loop_id = parse_loop_id_by_callsite.get(callsite_id)
        for token in detail.get("option_tokens", []):
            option = _init_option(
                token.get("long_name"),
                token.get("short_name"),
                token.get("has_arg"),
            )
            _add_parse_site(option, callsite_id, callsite_ref, caller, max_parse_sites)
            _add_parse_loop_id(option, loop_id)
            _add_evidence(
                option,
                {
                    "kind": "direct_compare",
                    "callsite_id": callsite_id,
                    "callsite_ref": callsite_ref,
                    "string_id": token.get("string_id"),
                    "string_address": token.get("address"),
                    "compare_callee": detail.get("callee"),
                    "strength": "observed",
                    "confidence": "high",
                },
                max_evidence,
            )
            raw_options.append(option)
    return raw_options


def _merge_option_entries(raw_options, max_parse_sites, max_evidence, max_flag_vars, max_check_sites):
    # Deduplicate per-option observations across parse loops in multicall binaries.
    options_map = {}
    for entry in raw_options:
        key = _option_identity(entry.get("long_name"), entry.get("short_name"), entry.get("has_arg"))
        option = options_map.get(key)
        if option is None:
            option = _init_option(entry.get("long_name"), entry.get("short_name"), entry.get("has_arg"))
            option["_strengths"] = set()
            option["_confidences"] = set()
            options_map[key] = option
        else:
            if entry.get("long_name") and not option.get("long_name"):
                option["long_name"] = entry.get("long_name")
            if entry.get("short_name") and not option.get("short_name"):
                option["short_name"] = entry.get("short_name")

        for site in entry.get("parse_sites", []):
            _add_parse_site(
                option,
                site.get("callsite_id"),
                site.get("callsite_ref"),
                site.get("function"),
                max_parse_sites,
            )
        for evidence in entry.get("evidence", []):
            _add_evidence(option, evidence, max_evidence)
        for flag_var in entry.get("flag_vars", []):
            _add_flag_var(
                option,
                flag_var.get("address"),
                flag_var.get("entry_address"),
                flag_var.get("name_address"),
                max_flag_vars,
            )
        for site in entry.get("check_sites", []):
            _add_check_site_entry(option, site, max_check_sites)
        for loop_id in entry.get("parse_loop_ids", []):
            _add_parse_loop_id(option, loop_id)
        strength, confidence = _entry_strength_confidence(entry)
        option["_strengths"].add(strength)
        option["_confidences"].add(confidence)

    options_list = list(options_map.values())
    for option in options_list:
        strengths = option.pop("_strengths", set())
        confidences = option.pop("_confidences", set())
        option["strength"] = "observed" if "observed" in strengths else "heuristic"
        option["confidence"] = "high" if confidences and confidences == {"high"} else "medium"
        if option.get("parse_sites"):
            option["parse_sites"].sort(key=lambda item: addr_to_int(item.get("callsite_id")))
        if option.get("parse_loop_ids"):
            option["parse_loop_ids"] = sorted(set(option["parse_loop_ids"]))
        option["_score"] = len(option.get("parse_sites", [])) + len(option.get("evidence", []))

    options_list.sort(
        key=lambda item: (
            -item.get("_score", 0),
            item.get("long_name") or "",
            item.get("short_name") or "",
        )
    )
    return options_list


def _finalize_option_entries(options_list, max_options):
    total_options = len(options_list)
    truncated_options = False
    if max_options > 0 and total_options > max_options:
        options_list = options_list[:max_options]
        truncated_options = True

    for idx, option in enumerate(options_list, start=1):
        option["id"] = "opt_%03d" % idx
        option.pop("_score", None)
        option.pop("_seen_evidence", None)
        option.pop("_seen_parse_sites", None)
        option.pop("_seen_flag_vars", None)
        option.pop("_seen_check_sites", None)
        option.pop("_seen_parse_loops", None)
    return options_list, total_options, truncated_options


def _build_parse_loops(
    parse_groups,
    parse_details_by_callsite,
    callsite_paths,
    parse_loop_id_by_function,
    max_callsites_per_loop,
):
    parse_loops = []
    for group in parse_groups:
        callsites = group.get("callsites") or []
        details = [parse_details_by_callsite.get(cs) for cs in callsites]
        rep_detail = None
        rep_score = -1
        for detail in details:
            if not detail:
                continue
            score = 0
            optstring = detail.get("optstring")
            if optstring:
                score += len(optstring.get("options") or [])
            longopts = detail.get("longopts")
            if longopts:
                score += len(longopts.get("entries") or [])
            if score > rep_score:
                rep_score = score
                rep_detail = detail

        callsite_ids = sorted(set(callsites), key=addr_to_int)
        callsite_refs = []
        for callsite_id in callsite_ids[:max_callsites_per_loop]:
            ref = callsite_paths.get(callsite_id)
            if ref:
                callsite_refs.append(ref)
        entry = {
            "id": parse_loop_id_by_function.get((group.get("function") or {}).get("address")),
            "function": group.get("function"),
            "callee_names": group.get("callee_names"),
            "callsite_count": len(callsite_ids),
            "callsite_ids": callsite_ids[:max_callsites_per_loop],
            "callsites_truncated": len(callsite_ids) > max_callsites_per_loop,
            "callsite_refs": callsite_refs,
        }
        if rep_detail:
            entry["representative_callsite_id"] = rep_detail.get("callsite")
            entry["representative_callsite_ref"] = callsite_paths.get(rep_detail.get("callsite"))
            optstring = rep_detail.get("optstring")
            if optstring:
                entry["optstring"] = {
                    "address": optstring.get("address"),
                    "string_id": optstring.get("string_id"),
                    "option_count": len(optstring.get("options") or []),
                }
            longopts = rep_detail.get("longopts")
            if longopts:
                entries = longopts.get("entries") or []
                entry["longopts"] = {
                    "address": longopts.get("address"),
                    "entry_count": len(entries),
                    "truncated": longopts.get("truncated", False),
                    "entry_addresses": [e.get("entry_address") for e in entries[:3]],
                }
        parse_loops.append(entry)
    return parse_loops


def derive_cli_surface(
    parse_groups,
    parse_details_by_callsite,
    compare_details_by_callsite,
    callsite_paths,
    options,
    check_sites_by_flag_addr,
):
    max_options = options.get("max_cli_options", 0)
    max_parse_loops = options.get("max_cli_parse_loops", 0)
    max_evidence = options.get("max_cli_option_evidence", 0)
    max_parse_sites = options.get("max_cli_parse_sites_per_option", 0)
    max_callsites_per_loop = options.get("max_cli_callsites_per_parse_loop", 0)
    max_flag_vars = options.get("max_cli_flag_vars", 0)
    max_check_sites = options.get("max_cli_check_sites", 0)

    parse_loop_id_by_callsite, parse_loop_id_by_function = _build_parse_loop_lookup(parse_groups)

    raw_options = _collect_parse_option_entries(
        parse_details_by_callsite,
        parse_loop_id_by_callsite,
        callsite_paths,
        max_parse_sites,
        max_evidence,
        max_flag_vars,
        max_check_sites,
        check_sites_by_flag_addr,
    )
    raw_options.extend(
        _collect_compare_option_entries(
            compare_details_by_callsite,
            parse_loop_id_by_callsite,
            callsite_paths,
            max_parse_sites,
            max_evidence,
        )
    )

    options_list = _merge_option_entries(
        raw_options,
        max_parse_sites,
        max_evidence,
        max_flag_vars,
        max_check_sites,
    )
    options_list, total_options, truncated_options = _finalize_option_entries(options_list, max_options)

    parse_loops = _build_parse_loops(
        parse_groups,
        parse_details_by_callsite,
        callsite_paths,
        parse_loop_id_by_function,
        max_callsites_per_loop,
    )
    parse_loops.sort(
        key=lambda item: (
            -item.get("callsite_count", 0),
            addr_to_int((item.get("function") or {}).get("address")),
        )
    )
    total_parse_loops = len(parse_loops)
    truncated_parse_loops = False
    if max_parse_loops > 0 and total_parse_loops > max_parse_loops:
        parse_loops = parse_loops[:max_parse_loops]
        truncated_parse_loops = True

    return {
        "options": options_list,
        "total_options": total_options,
        "options_truncated": truncated_options,
        "parse_loops": parse_loops,
        "total_parse_loops": total_parse_loops,
        "parse_loops_truncated": truncated_parse_loops,
    }


def derive_capabilities(
    call_edges,
    callsite_paths,
    function_meta_by_addr,
    metrics_by_addr,
    string_refs_by_func,
    selected_string_ids,
    string_tags_by_id,
    string_value_by_id,
    capability_rules,
):
    # Capabilities are derived from import-call evidence and localized by callers.
    rules = []
    for rule in capability_rules:
        rules.append({
            "id": rule["id"],
            "name": rule["name"],
            "signals": set([normalize_symbol_name(name) for name in rule["signals"]]),
        })

    capabilities = []
    for rule in rules:
        evidence_refs = {}
        callsite_internal = {}
        matched = set()
        caller_counts = {}
        caller_callsites = {}
        string_counts = {}
        for edge in call_edges:
            target = edge.get("to") or {}
            name = target.get("name")
            name_norm = normalize_symbol_name(name)
            if name_norm and name_norm in rule["signals"]:
                callsite = edge.get("callsite")
                ref = callsite_paths.get(callsite)
                caller = edge.get("from") or {}
                caller_addr = caller.get("address")
                caller_meta = function_meta_by_addr.get(caller_addr, {})
                if caller_meta.get("is_thunk"):
                    continue
                if ref:
                    evidence_refs[callsite] = {
                        "kind": "callsite",
                        "ref": ref,
                        "callee": name,
                    }
                    callsite_internal[callsite] = not caller_meta.get("is_external", False)
                matched.add(name_norm)
                if caller_addr:
                    caller_counts[caller_addr] = caller_counts.get(caller_addr, 0) + 1
                    callsites = caller_callsites.get(caller_addr)
                    if callsites is None:
                        callsites = []
                        caller_callsites[caller_addr] = callsites
                    if callsite:
                        callsites.append(callsite)
                    for string_id in string_refs_by_func.get(caller_addr, set()):
                        if string_id in selected_string_ids:
                            tags = string_tags_by_id.get(string_id) or set()
                            if not tags or not (tags & SALIENCE_TAGS):
                                continue
                            string_counts[string_id] = string_counts.get(string_id, 0) + 1

        count = len(evidence_refs)
        if count == 0:
            continue
        # Confidence scales with callsite evidence volume, capped for weak signals.
        if count == 1:
            confidence = 0.55
        elif count <= 3:
            confidence = 0.7
        elif count <= 6:
            confidence = 0.85
        else:
            confidence = 0.95

        if rule["id"] == "spawns_subprocesses":
            confidence = min(confidence, 0.7)
        if rule["id"] == "uses_network_sockets":
            if count < 3 or len(matched) < 2:
                confidence = min(confidence, 0.55)

        evidence_list = []
        for callsite, evidence in evidence_refs.items():
            evidence_list.append((callsite_internal.get(callsite, False), evidence))
        evidence_list.sort(key=lambda item: (not item[0], item[1].get("ref") or ""))
        evidence_list = [item[1] for item in evidence_list]

        caller_addrs = set(caller_counts.keys())
        slice_in = {}
        slice_out = {}
        if caller_addrs:
            for edge in call_edges:
                target = edge.get("to") or {}
                if target.get("external"):
                    continue
                from_addr = (edge.get("from") or {}).get("address")
                to_addr = target.get("address")
                if from_addr in caller_addrs and to_addr in caller_addrs:
                    slice_out[from_addr] = slice_out.get(from_addr, 0) + 1
                    slice_in[to_addr] = slice_in.get(to_addr, 0) + 1

        top_functions = []
        role_metrics_by_addr = {}
        for addr, count in sorted(
            caller_counts.items(),
            key=lambda item: (-item[1], addr_to_int(item[0])),
        ):
            meta = function_meta_by_addr.get(addr, {})
            if meta.get("is_external") or meta.get("is_thunk"):
                continue
            metrics = metrics_by_addr.get(addr, {})
            if slice_in.get(addr, 0) or slice_out.get(addr, 0):
                in_deg = slice_in.get(addr, 0)
                out_deg = slice_out.get(addr, 0)
            else:
                in_deg = metrics.get("in_degree", 0)
                out_deg = metrics.get("out_degree", 0)
            role_metrics_by_addr[addr] = {
                "in_degree": in_deg,
                "out_degree": out_deg,
                "callsite_count": count,
            }
            top_functions.append({
                "name": meta.get("name"),
                "address": addr,
                "count": count,
                "role_hint": classify_role_hint(in_deg, out_deg),
            })
            if len(top_functions) >= DEFAULT_MAX_CAPABILITY_FUNCTIONS:
                break

        primary_entry_like_addr = refine_entry_like_roles(top_functions, role_metrics_by_addr)

        evidence_clusters = []
        for addr, callsites in caller_callsites.items():
            meta = function_meta_by_addr.get(addr, {})
            if meta.get("is_external") or meta.get("is_thunk"):
                continue
            unique_ids = sorted(set(callsites), key=addr_to_int)
            callsite_refs = []
            for callsite_id in unique_ids:
                ref = callsite_paths.get(callsite_id)
                if ref:
                    callsite_refs.append(ref)
                if len(callsite_refs) >= DEFAULT_MAX_CAPABILITY_CALLSITES_PER_CLUSTER:
                    break
            evidence_clusters.append({
                "cluster_id": addr_id("caller", addr),
                "function": {
                    "name": meta.get("name"),
                    "address": addr,
                },
                "callsite_count": len(unique_ids),
                "callsite_ids": unique_ids[:DEFAULT_MAX_CAPABILITY_CALLSITES_PER_CLUSTER],
                "callsite_refs": callsite_refs,
            })
        evidence_clusters.sort(
            key=lambda item: (-item.get("callsite_count", 0), item.get("function", {}).get("address") or "")
        )
        evidence_clusters = evidence_clusters[:DEFAULT_MAX_CAPABILITY_CALLSITE_CLUSTERS]

        representative_cluster_id = None
        if evidence_clusters:
            def cluster_score(cluster):
                func_addr = (cluster.get("function") or {}).get("address")
                string_tags = set()
                for string_id in string_refs_by_func.get(func_addr, set()):
                    tags = string_tags_by_id.get(string_id) or set()
                    string_tags.update(tags & SALIENCE_TAGS)
                metrics = metrics_by_addr.get(func_addr, {})
                return (
                    cluster.get("callsite_count", 0),
                    len(string_tags),
                    metrics.get("call_degree", 0),
                    -addr_to_int(func_addr),
                )

            best_cluster = max(evidence_clusters, key=cluster_score)
            representative_cluster_id = best_cluster.get("cluster_id")
            for cluster in evidence_clusters:
                cluster["is_representative"] = cluster.get("cluster_id") == representative_cluster_id

        top_strings = []
        for string_id, count in sorted(
            string_counts.items(),
            key=lambda item: (-item[1], item[0]),
        ):
            tags = sorted(list(string_tags_by_id.get(string_id) or set()))
            entry = {
                "id": string_id,
                "count": count,
                "tags": tags,
            }
            value = string_value_by_id.get(string_id)
            if value is not None:
                entry["value"] = value
            top_strings.append(entry)
            if len(top_strings) >= DEFAULT_MAX_CAPABILITY_STRINGS:
                break
        shape_hint = infer_shape_hint(matched, top_strings, evidence_clusters, top_functions)
        localization = {
            "top_functions": top_functions,
            "evidence_clusters": evidence_clusters,
            "top_strings": top_strings,
            "representative_cluster_id": representative_cluster_id,
        }
        if primary_entry_like_addr:
            localization["primary_entry_like"] = {
                "address": primary_entry_like_addr,
                "name": function_meta_by_addr.get(primary_entry_like_addr, {}).get("name"),
            }
        capabilities.append({
            "id": rule["id"],
            "name": rule["name"],
            "scope": "binary",
            "confidence": confidence,
            "shape_hint": shape_hint,
            "evidence": evidence_list,
            "localization": localization,
            "derivation": {
                "type": "import_call_match",
                "signals": sorted(list(rule["signals"])),
                "matched": sorted(list(matched)),
            },
        })

    capabilities.sort(key=lambda item: item.get("id"))
    return capabilities
