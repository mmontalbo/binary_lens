"""Derive CLI surface artifacts (options + parse loops)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from derivations.constants import INT_TYPES
from export_bounds import Bounds
from export_primitives import addr_to_int
from utils.text import string_ref_status


@dataclass(frozen=True)
class CliSurfaceBounds:
    max_options: int
    max_parse_sites: int
    max_callsites_per_loop: int

    @classmethod
    def from_bounds(cls, bounds: Bounds) -> CliSurfaceBounds:
        return cls(
            max_options=bounds.max_cli_options,
            max_parse_sites=bounds.max_cli_parse_sites_per_option,
            max_callsites_per_loop=bounds.max_cli_callsites_per_parse_loop,
        )


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
    has_arg = _normalize_has_arg(has_arg)
    if long_name:
        return (long_name, short_name, has_arg)
    return (None, short_name, has_arg)


def _normalize_has_arg(has_arg):
    return has_arg or "unknown"


@dataclass(frozen=True)
class OptionObservation:
    long_name: str | None
    short_name: str | None
    has_arg: str
    callsite_id: str | None
    parse_loop_id: str | None


@dataclass
class OptionAccumulator:
    long_name: str | None
    short_name: str | None
    has_arg: str
    parse_sites: list[str] = field(default_factory=list)
    parse_loop_ids: list[str] = field(default_factory=list)
    _seen_parse_sites: set[str] = field(default_factory=set, repr=False)
    _seen_parse_loops: set[str] = field(default_factory=set, repr=False)

    def merge_names(self, long_name: str | None, short_name: str | None) -> None:
        if long_name and not self.long_name:
            self.long_name = long_name
        if short_name and not self.short_name:
            self.short_name = short_name

    def add_parse_site(self, callsite_id: str | None, max_sites: int) -> None:
        if not callsite_id or callsite_id in self._seen_parse_sites:
            return
        self._seen_parse_sites.add(callsite_id)
        if len(self.parse_sites) >= max_sites:
            return
        self.parse_sites.append(callsite_id)

    def add_parse_loop_id(self, loop_id: str | None) -> None:
        if not loop_id or loop_id in self._seen_parse_loops:
            return
        self._seen_parse_loops.add(loop_id)
        self.parse_loop_ids.append(loop_id)

    def to_payload(self, option_id: str) -> dict[str, Any]:
        return {
            "id": option_id,
            "long_name": self.long_name,
            "short_name": self.short_name,
            "has_arg": self.has_arg,
            "parse_sites": sorted(self.parse_sites, key=addr_to_int),
            "parse_loop_ids": sorted(self.parse_loop_ids),
        }


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
):
    raw_options: list[OptionObservation] = []
    callsite_ids = sorted(parse_details_by_callsite.keys(), key=addr_to_int)
    for callsite_id in callsite_ids:
        detail = parse_details_by_callsite.get(callsite_id)
        if not detail:
            continue
        loop_id = parse_loop_id_by_callsite.get(callsite_id)
        optstring = detail.get("optstring")
        if optstring:
            for opt in optstring.get("options", []):
                raw_options.append(
                    OptionObservation(
                        long_name=None,
                        short_name=opt.get("short_name"),
                        has_arg=_normalize_has_arg(opt.get("has_arg")),
                        callsite_id=callsite_id,
                        parse_loop_id=loop_id,
                    )
                )

        longopts = detail.get("longopts")
        if longopts:
            for entry in longopts.get("entries", []):
                raw_options.append(
                    OptionObservation(
                        long_name=entry.get("name"),
                        short_name=_short_from_val(entry.get("val")),
                        has_arg=_normalize_has_arg(entry.get("has_arg")),
                        callsite_id=callsite_id,
                        parse_loop_id=loop_id,
                    )
                )
    return raw_options


def _collect_compare_option_entries(
    compare_details_by_callsite,
    parse_loop_id_by_callsite,
):
    raw_options: list[OptionObservation] = []
    compare_details_by_callsite = compare_details_by_callsite or {}
    compare_callsite_ids = sorted(compare_details_by_callsite.keys(), key=addr_to_int)
    for callsite_id in compare_callsite_ids:
        detail = compare_details_by_callsite.get(callsite_id)
        if not detail:
            continue
        loop_id = parse_loop_id_by_callsite.get(callsite_id)
        for token in detail.get("option_tokens", []):
            raw_options.append(
                OptionObservation(
                    long_name=token.get("long_name"),
                    short_name=token.get("short_name"),
                    has_arg=_normalize_has_arg(token.get("has_arg")),
                    callsite_id=callsite_id,
                    parse_loop_id=loop_id,
                )
            )
    return raw_options


def _merge_option_entries(raw_options, max_parse_sites):
    # Deduplicate per-option observations across parse loops in multicall binaries.
    options_map = {}
    for entry in raw_options:
        key = _option_identity(entry.long_name, entry.short_name, entry.has_arg)
        option = options_map.get(key)
        if option is None:
            option = OptionAccumulator(entry.long_name, entry.short_name, entry.has_arg)
            options_map[key] = option
        else:
            option.merge_names(entry.long_name, entry.short_name)

        option.add_parse_site(entry.callsite_id, max_parse_sites)
        option.add_parse_loop_id(entry.parse_loop_id)
    options_list = list(options_map.values())

    options_list.sort(
        key=lambda item: (
            -len(item.parse_sites),
            item.long_name or "",
            item.short_name or "",
        )
    )
    return options_list


def _finalize_option_entries(options_list, max_options):
    total_options = len(options_list)
    truncated_options = False
    if max_options > 0 and total_options > max_options:
        options_list = options_list[:max_options]
        truncated_options = True

    payloads = [
        option.to_payload("opt_%03d" % idx) for idx, option in enumerate(options_list, start=1)
    ]
    return payloads, total_options, truncated_options


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
            "callsite_ids": callsite_ids[:max_callsites_per_loop],
            "callsites_truncated": len(callsite_ids) > max_callsites_per_loop,
        }
        if rep_detail:
            optstring = rep_detail.get("optstring")
            if optstring:
                string_id = optstring.get("string_id")
                address = optstring.get("address")
                optstring_entry = {
                    "status": string_ref_status(string_id, address),
                    "option_count": len(optstring.get("options") or []),
                }
                if string_id:
                    optstring_entry["string_id"] = string_id
                elif address:
                    optstring_entry["address"] = address
                entry["optstring"] = optstring_entry
            longopts = rep_detail.get("longopts")
            if longopts:
                entries = longopts.get("entries") or []
                entry["longopts"] = {
                    "address": longopts.get("address"),
                    "truncated": longopts.get("truncated", False),
                    "entry_addresses": [e.get("entry_address") for e in entries[:3]],
                }
        parse_loops.append(entry)
    return parse_loops


def _finalize_parse_loops(parse_loops):
    def _loop_sort_id(item):
        rep_callsite = None
        callsites = item.get("callsite_ids") or []
        if callsites:
            rep_callsite = callsites[0]
        return addr_to_int(rep_callsite)

    parse_loops.sort(
        key=lambda item: (
            -len(item.get("callsite_ids") or []),
            _loop_sort_id(item),
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
    bounds: CliSurfaceBounds

    def derive(self) -> dict[str, Any]:
        parse_loop_id_by_callsite, parse_loop_id_by_function = _build_parse_loop_lookup(self.parse_groups)

        raw_options = _collect_parse_option_entries(
            self.parse_details_by_callsite,
            parse_loop_id_by_callsite,
        )
        raw_options.extend(
            _collect_compare_option_entries(
                self.compare_details_by_callsite,
                parse_loop_id_by_callsite,
            )
        )

        options_list = _merge_option_entries(
            raw_options,
            self.bounds.max_parse_sites,
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
):
    """Derive CLI surface artifacts.

    Invariants:
    - Options are merged across parse sites (multi-call binaries) and then sorted by
      parse-site counts with stable tie-breakers.
    - `truncated` flags indicate exporter bounds were hit; missing entries may exist.
    """

    cli_bounds = CliSurfaceBounds.from_bounds(bounds)
    return _CliSurfaceDeriver(
        parse_groups=parse_groups or [],
        parse_details_by_callsite=parse_details_by_callsite or {},
        compare_details_by_callsite=compare_details_by_callsite or {},
        bounds=cli_bounds,
    ).derive()
