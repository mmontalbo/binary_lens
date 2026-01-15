"""Derive capability (import-signal) lens artifacts."""

from derivations.constants import (
    CALLBACK_SIGNALS,
    DEFAULT_MAX_CAPABILITY_CALLSITE_CLUSTERS,
    DEFAULT_MAX_CAPABILITY_CALLSITES_PER_CLUSTER,
    DEFAULT_MAX_CAPABILITY_FUNCTIONS,
    DEFAULT_MAX_CAPABILITY_STRINGS,
    FORMAT_SIGNALS,
    OPTION_SIGNALS,
    TRAVERSAL_SIGNALS,
)
from export_primitives import SALIENCE_TAGS, addr_id, addr_to_int, normalize_symbol_name


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

