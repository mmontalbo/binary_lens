"""Error/exit lens entrypoint shim.

Historically, `export_errors.py` hosted Milestone 2's error/exit extraction.
To reduce cognitive overhead, the implementation is now split into the
`scripts/errors/` package.

This module preserves the original import path used by the exporter.
"""

from errors.common import (
    ERROR_BUCKET_EMITTERS,
    ERROR_EMITTER_NAMES,
    EXIT_CALL_NAMES,
    INT_TYPES,
    STATUS_EMITTERS,
    WARN_BUCKET_EMITTERS,
    _collect_callsites,
    normalize_import_name,
)
from errors.exits import derive_exit_paths
from errors.messages import (
    BUCKET_PRIORITY,
    ERROR_KEYWORDS,
    WARN_KEYWORDS,
    _build_string_xrefs,
    _keyword_hit,
    append_link,
    bucket_for_emitter,
    build_candidate_entry,
    classify_message_bucket,
    dedupe_links,
    derive_error_messages,
    escape_preview,
    is_error_candidate,
    is_usage_message,
    merge_emitter_bucket,
    record_observed_emitter_bucket,
    sort_links,
)
from errors.sites import derive_error_sites
from errors.surface import attach_callsite_refs, build_error_surface, collect_error_callsites

__all__ = [
    "BUCKET_PRIORITY",
    "ERROR_BUCKET_EMITTERS",
    "ERROR_EMITTER_NAMES",
    "ERROR_KEYWORDS",
    "EXIT_CALL_NAMES",
    "INT_TYPES",
    "STATUS_EMITTERS",
    "WARN_BUCKET_EMITTERS",
    "WARN_KEYWORDS",
    "_build_string_xrefs",
    "_collect_callsites",
    "_keyword_hit",
    "append_link",
    "attach_callsite_refs",
    "build_candidate_entry",
    "build_error_surface",
    "bucket_for_emitter",
    "classify_message_bucket",
    "collect_error_callsites",
    "dedupe_links",
    "derive_error_messages",
    "derive_error_sites",
    "derive_exit_paths",
    "escape_preview",
    "is_error_candidate",
    "is_usage_message",
    "merge_emitter_bucket",
    "normalize_import_name",
    "record_observed_emitter_bucket",
    "sort_links",
]
