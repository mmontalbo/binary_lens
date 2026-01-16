"""Shared helpers/constants for the error/exit lens."""

from export_collectors import collect_callsite_matches
from export_primitives import addr_to_int
from symbols import (
    IMPORT_SYMBOL_POLICY,
    match_signal,
    normalize_name_set,
)
from symbols import (
    normalize_import_name as _normalize_import_name,
)

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
    return _normalize_import_name(name)


def _collect_callsites(call_edges, function_meta_by_addr, name_set):
    normalized = normalize_name_set(name_set, policy=IMPORT_SYMBOL_POLICY)
    name_map = {name: name for name in normalized}

    def _match(name):
        return match_signal(name, name_map=name_map, policy=IMPORT_SYMBOL_POLICY)

    matches, _matches_by_func = collect_callsite_matches(
        call_edges,
        function_meta_by_addr,
        _match,
        require_external=False,
    )
    callsites = []
    callsites_by_func = {}
    for match in matches:
        entry = {
            "callsite_id": match.callsite_id,
            "function_id": match.function_id,
            "function_name": match.function_name,
            "emitter_import": match.match_key or match.callee_normalized,
            "target": match.target,
        }
        callsites.append(entry)
        bucket = callsites_by_func.get(match.function_id)
        if bucket is None:
            bucket = []
            callsites_by_func[match.function_id] = bucket
        bucket.append(entry)
    for bucket in callsites_by_func.values():
        bucket.sort(key=lambda item: addr_to_int(item.get("callsite_id")))
    callsites.sort(key=lambda item: addr_to_int(item.get("callsite_id")))
    return callsites, callsites_by_func
