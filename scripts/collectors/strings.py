"""String collection and lightweight classification.

The exporter treats strings as primary evidence, but must keep output bounded and
diff-friendly. Selection is biased toward "salient" buckets (usage markers,
format strings, path-like strings, env var names) so that important CLI surface
strings are retained even when binaries contain lots of boilerplate.
"""

import re

from export_primitives import addr_id, addr_str, addr_to_int
from ghidra.program.model.data import StringDataInstance

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
    if "options:" in lowered or "options\n" in lowered:
        return True
    if "report bugs" in lowered or "reporting bugs" in lowered:
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
    try:
        max_strings = int(max_strings)
    except Exception:
        max_strings = 0

    # Bucket selection preserves salient CLI/format/path strings even when boilerplate dominates.
    bucket_limit = min(max_strings // 5, 40) if max_strings > 0 else 0
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

    bucket_counts = {name: len(entries) for name, entries in buckets.items()}
    if max_strings <= 0 or total <= max_strings:
        selected = list(strings)
        selected_ids = {entry.get("id") for entry in selected if entry.get("id")}
        truncated = False
        # Preserve schema fields while signaling "unbounded" selection.
        bucket_limits = {name: None for name in bucket_limits}
    else:
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

    return (
        selected,
        string_addr_map_selected,
        total,
        truncated,
        string_addr_map_all,
        string_tags_by_id,
        bucket_counts,
        bucket_limits,
    )


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
