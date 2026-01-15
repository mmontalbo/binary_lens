"""Derive subsystem clusters from the internal callgraph."""

from derivations.constants import (
    DEFAULT_MAX_SUBSYSTEM_CLUSTER_SIZE,
    DEFAULT_MAX_SUBSYSTEM_IMPORTS,
    DEFAULT_MAX_SUBSYSTEM_REP_FUNCTIONS,
    DEFAULT_MAX_SUBSYSTEM_STRING_BUCKETS,
    DEFAULT_MAX_SUBSYSTEM_STRONG_LINKS,
    DEFAULT_MAX_SUBSYSTEMS,
)
from export_primitives import addr_str, addr_to_int, normalize_symbol_name


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
