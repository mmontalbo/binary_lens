"""Shared helpers/constants for the error/exit lens."""

from export_primitives import addr_to_int, normalize_symbol_name

try:
    INT_TYPES = (int, long)
except NameError:
    INT_TYPES = (int,)

ERROR_EMITTER_NAMES = set([
    "fprintf",
    "printf",
    "dprintf",
    "vfprintf",
    "vprintf",
    "vdprintf",
    "fputs",
    "puts",
    "putc",
    "putchar",
    "perror",
    "strerror",
    "strerror_r",
    "strerrorname_np",
    "error",
    "error_at_line",
    "verror",
    "verror_at_line",
    "warn",
    "warnx",
    "vwarn",
    "vwarnx",
    "err",
    "errx",
    "verr",
    "verrx",
])

ERROR_BUCKET_EMITTERS = set([
    "error",
    "error_at_line",
    "verror",
    "verror_at_line",
    "err",
    "errx",
    "verr",
    "verrx",
    "perror",
])

WARN_BUCKET_EMITTERS = set([
    "warn",
    "warnx",
    "vwarn",
    "vwarnx",
])

STATUS_EMITTERS = set([
    "error",
    "error_at_line",
    "verror",
    "verror_at_line",
])

EXIT_CALL_NAMES = set([
    "exit",
    "_exit",
    "abort",
])


def normalize_import_name(name):
    base = normalize_symbol_name(name)
    if not base:
        return None
    base = base.lstrip("_")
    if base.startswith("GI_"):
        base = base[3:]
    if base.endswith("_chk"):
        base = base[:-4]
    return base.lower()


def _collect_callsites(call_edges, function_meta_by_addr, name_set):
    callsites = []
    callsites_by_func = {}
    for edge in call_edges:
        callsite_id = edge.get("callsite")
        if not callsite_id:
            continue
        target = edge.get("to") or {}
        name_norm = normalize_import_name(target.get("name"))
        if not name_norm or name_norm not in name_set:
            continue
        from_addr = (edge.get("from") or {}).get("address")
        if not from_addr:
            continue
        meta = function_meta_by_addr.get(from_addr, {})
        if meta.get("is_external") or meta.get("is_thunk"):
            continue
        entry = {
            "callsite_id": callsite_id,
            "function_id": from_addr,
            "function_name": meta.get("name") or (edge.get("from") or {}).get("function"),
            "emitter_import": name_norm,
            "target": target,
        }
        callsites.append(entry)
        bucket = callsites_by_func.get(from_addr)
        if bucket is None:
            bucket = []
            callsites_by_func[from_addr] = bucket
        bucket.append(entry)
    for bucket in callsites_by_func.values():
        bucket.sort(key=lambda item: addr_to_int(item.get("callsite_id")))
    callsites.sort(key=lambda item: addr_to_int(item.get("callsite_id")))
    return callsites, callsites_by_func

