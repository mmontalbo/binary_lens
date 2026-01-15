"""Derivation entrypoint shim.

Historically, `export_derivations.py` contained all logic for derived lenses
(capabilities, subsystems, and CLI surface extraction). The implementation now
lives in the `scripts/derivations/` package to keep modules smaller and more
coherent, while preserving the original import path for the exporter.
"""

from derivations.capabilities import (
    classify_role_hint,
    derive_capabilities,
    infer_shape_hint,
    refine_entry_like_roles,
)
from derivations.cli_surface import (
    _add_check_site_entry,
    _add_check_sites,
    _add_evidence,
    _add_flag_var,
    _add_parse_loop_id,
    _add_parse_site,
    _build_parse_loop_lookup,
    _build_parse_loops,
    _collect_compare_option_entries,
    _collect_parse_option_entries,
    _entry_strength_confidence,
    _finalize_option_entries,
    _init_option,
    _merge_has_arg,
    _merge_option_entries,
    _option_identity,
    _short_from_val,
    derive_cli_surface,
)
from derivations.constants import (
    CALLBACK_SIGNALS,
    DEFAULT_MAX_CAPABILITY_CALLSITE_CLUSTERS,
    DEFAULT_MAX_CAPABILITY_CALLSITES_PER_CLUSTER,
    DEFAULT_MAX_CAPABILITY_FUNCTIONS,
    DEFAULT_MAX_CAPABILITY_STRINGS,
    DEFAULT_MAX_SUBSYSTEM_CLUSTER_SIZE,
    DEFAULT_MAX_SUBSYSTEM_IMPORTS,
    DEFAULT_MAX_SUBSYSTEM_REP_FUNCTIONS,
    DEFAULT_MAX_SUBSYSTEM_STRING_BUCKETS,
    DEFAULT_MAX_SUBSYSTEM_STRONG_LINKS,
    DEFAULT_MAX_SUBSYSTEMS,
    FORMAT_SIGNALS,
    INT_TYPES,
    OPTION_SIGNALS,
    TRAVERSAL_SIGNALS,
)
from derivations.strings import build_string_bucket_counts
from derivations.subsystems import (
    build_internal_callgraph_adjacency,
    compute_callgraph_components,
    derive_subsystems,
)

__all__ = [
    "CALLBACK_SIGNALS",
    "DEFAULT_MAX_CAPABILITY_CALLSITE_CLUSTERS",
    "DEFAULT_MAX_CAPABILITY_CALLSITES_PER_CLUSTER",
    "DEFAULT_MAX_CAPABILITY_FUNCTIONS",
    "DEFAULT_MAX_CAPABILITY_STRINGS",
    "DEFAULT_MAX_SUBSYSTEMS",
    "DEFAULT_MAX_SUBSYSTEM_CLUSTER_SIZE",
    "DEFAULT_MAX_SUBSYSTEM_IMPORTS",
    "DEFAULT_MAX_SUBSYSTEM_REP_FUNCTIONS",
    "DEFAULT_MAX_SUBSYSTEM_STRING_BUCKETS",
    "DEFAULT_MAX_SUBSYSTEM_STRONG_LINKS",
    "FORMAT_SIGNALS",
    "INT_TYPES",
    "OPTION_SIGNALS",
    "TRAVERSAL_SIGNALS",
    "_add_check_site_entry",
    "_add_check_sites",
    "_add_evidence",
    "_add_flag_var",
    "_add_parse_loop_id",
    "_add_parse_site",
    "_build_parse_loop_lookup",
    "_build_parse_loops",
    "_collect_compare_option_entries",
    "_collect_parse_option_entries",
    "_entry_strength_confidence",
    "_finalize_option_entries",
    "_init_option",
    "_merge_has_arg",
    "_merge_option_entries",
    "_option_identity",
    "_short_from_val",
    "build_internal_callgraph_adjacency",
    "build_string_bucket_counts",
    "classify_role_hint",
    "compute_callgraph_components",
    "derive_capabilities",
    "derive_cli_surface",
    "derive_subsystems",
    "infer_shape_hint",
    "refine_entry_like_roles",
]

