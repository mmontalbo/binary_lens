"""Derive CLI surface artifacts (options + parse loops)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from derivations.constants import INT_TYPES
from export_bounds import Bounds
from export_primitives import addr_to_int


@dataclass(frozen=True)
class CliSurfaceBounds:
    max_options: int
    max_parse_loops: int
    max_evidence: int
    max_parse_sites: int
    max_callsites_per_loop: int
    max_flag_vars: int
    max_check_sites: int

    @classmethod
    def from_bounds(cls, bounds: Bounds) -> CliSurfaceBounds:
        return cls(
            max_options=bounds.max_cli_options,
            max_parse_loops=bounds.max_cli_parse_loops,
            max_evidence=bounds.max_cli_option_evidence,
            max_parse_sites=bounds.max_cli_parse_sites_per_option,
            max_callsites_per_loop=bounds.max_cli_callsites_per_parse_loop,
            max_flag_vars=bounds.max_cli_flag_vars,
            max_check_sites=bounds.max_cli_check_sites,
        )


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
        "parse_sites": [],
        "parse_loop_ids": [],
    }


def _add_parse_site(option, callsite_id, caller, max_sites):
    seen = option.setdefault("_seen_parse_sites", set())
    if callsite_id in seen:
        return
    seen.add(callsite_id)
    if len(option["parse_sites"]) >= max_sites:
        return
    option["parse_sites"].append({
        "callsite_id": callsite_id,
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
        cleaned = {key: value for key, value in site.items() if key not in ("strength", "confidence")}
        option["check_sites"].append(cleaned)


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
    cleaned = {key: value for key, value in site.items() if key not in ("strength", "confidence")}
    option["check_sites"].append(cleaned)


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
        loop_id = parse_loop_id_by_callsite.get(callsite_id)
        optstring = detail.get("optstring")
        if optstring:
            for opt in optstring.get("options", []):
                short_name = opt.get("short_name")
                option = _init_option(None, short_name, opt.get("has_arg"))
                _add_parse_site(option, callsite_id, None, max_parse_sites)
                _add_parse_loop_id(option, loop_id)
                raw_options.append(option)

        longopts = detail.get("longopts")
        if longopts:
            for entry in longopts.get("entries", []):
                long_name = entry.get("name")
                short_name = _short_from_val(entry.get("val"))
                option = _init_option(long_name, short_name, entry.get("has_arg"))
                _add_parse_site(option, callsite_id, None, max_parse_sites)
                _add_parse_loop_id(option, loop_id)
                raw_options.append(option)
    return raw_options


def _collect_compare_option_entries(
    compare_details_by_callsite,
    parse_loop_id_by_callsite,
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
        loop_id = parse_loop_id_by_callsite.get(callsite_id)
        for token in detail.get("option_tokens", []):
            option = _init_option(
                token.get("long_name"),
                token.get("short_name"),
                token.get("has_arg"),
            )
            _add_parse_site(option, callsite_id, None, max_parse_sites)
            _add_parse_loop_id(option, loop_id)
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
                None,
                max_parse_sites,
            )
        for loop_id in entry.get("parse_loop_ids", []):
            _add_parse_loop_id(option, loop_id)
    options_list = list(options_map.values())
    for option in options_list:
        if option.get("parse_sites"):
            option["parse_sites"].sort(key=lambda item: addr_to_int(item.get("callsite_id")))
        if option.get("parse_loop_ids"):
            option["parse_loop_ids"] = sorted(set(option["parse_loop_ids"]))

    options_list.sort(
        key=lambda item: (
            -len(item.get("parse_sites") or []),
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
        option.pop("_seen_parse_sites", None)
        option.pop("_seen_parse_loops", None)
    return options_list, total_options, truncated_options


def _build_parse_loops(
    parse_groups,
    parse_details_by_callsite,
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
        entry = {
            "id": parse_loop_id_by_function.get((group.get("function") or {}).get("address")),
            "function": group.get("function"),
            "callee_names": group.get("callee_names"),
            "callsite_count": len(callsite_ids),
            "callsite_ids": callsite_ids[:max_callsites_per_loop],
            "callsites_truncated": len(callsite_ids) > max_callsites_per_loop,
        }
        if rep_detail:
            entry["representative_callsite_id"] = rep_detail.get("callsite")
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


def _finalize_parse_loops(parse_loops, max_parse_loops):
    parse_loops.sort(
        key=lambda item: (
            -item.get("callsite_count", 0),
            addr_to_int((item.get("function") or {}).get("address")),
        )
    )
    total_parse_loops = len(parse_loops)
    truncated_parse_loops = False
    return parse_loops, total_parse_loops, truncated_parse_loops


@dataclass(frozen=True)
class _CliSurfaceDeriver:
    parse_groups: list[dict[str, Any]]
    parse_details_by_callsite: dict[str, Any]
    compare_details_by_callsite: dict[str, Any]
    check_sites_by_flag_addr: dict[str, Any]
    bounds: CliSurfaceBounds

    def derive(self) -> dict[str, Any]:
        parse_loop_id_by_callsite, parse_loop_id_by_function = _build_parse_loop_lookup(self.parse_groups)

        raw_options = _collect_parse_option_entries(
            self.parse_details_by_callsite,
            parse_loop_id_by_callsite,
            self.bounds.max_parse_sites,
            self.bounds.max_evidence,
            self.bounds.max_flag_vars,
            self.bounds.max_check_sites,
            self.check_sites_by_flag_addr,
        )
        raw_options.extend(
            _collect_compare_option_entries(
                self.compare_details_by_callsite,
                parse_loop_id_by_callsite,
                self.bounds.max_parse_sites,
                self.bounds.max_evidence,
            )
        )

        options_list = _merge_option_entries(
            raw_options,
            self.bounds.max_parse_sites,
            self.bounds.max_evidence,
            self.bounds.max_flag_vars,
            self.bounds.max_check_sites,
        )
        options_list, total_options, truncated_options = _finalize_option_entries(
            options_list,
            self.bounds.max_options,
        )

        parse_loops = _build_parse_loops(
            self.parse_groups,
            self.parse_details_by_callsite,
            parse_loop_id_by_function,
            self.bounds.max_callsites_per_loop,
        )
        parse_loops, total_parse_loops, truncated_parse_loops = _finalize_parse_loops(
            parse_loops,
            self.bounds.max_parse_loops,
        )

        return {
            "options": options_list,
            "total_options": total_options,
            "options_truncated": truncated_options,
            "parse_loops": parse_loops,
            "total_parse_loops": total_parse_loops,
            "parse_loops_truncated": truncated_parse_loops,
        }


def derive_cli_surface(
    parse_groups,
    parse_details_by_callsite,
    compare_details_by_callsite,
    bounds: Bounds,
    check_sites_by_flag_addr,
):
    """Derive CLI surface artifacts.

    Invariants:
    - Options are merged across parse sites (multi-call binaries) and then sorted by
      parse-site/evidence counts with stable tie-breakers.
    - `truncated` flags indicate exporter bounds were hit; missing entries may exist.
    """

    cli_bounds = CliSurfaceBounds.from_bounds(bounds)
    return _CliSurfaceDeriver(
        parse_groups=parse_groups or [],
        parse_details_by_callsite=parse_details_by_callsite or {},
        compare_details_by_callsite=compare_details_by_callsite or {},
        check_sites_by_flag_addr=check_sites_by_flag_addr or {},
        bounds=cli_bounds,
    ).derive()
