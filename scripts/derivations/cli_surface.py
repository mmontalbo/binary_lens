"""Derive CLI surface artifacts (options + parse loops)."""

from derivations.constants import INT_TYPES
from export_primitives import addr_to_int


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

