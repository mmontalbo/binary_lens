"""Output entrypoint shim.

Historically, `export_outputs.py` hosted payload builders and writer helpers.
To reduce cognitive overhead, the implementation now lives in `scripts/outputs/`,
while preserving the original import path used by the exporter.
"""

from outputs.io import ensure_dir, pack_path, write_json, write_text
from outputs.payloads import (
    build_binary_info,
    build_callgraph_payload,
    build_cli_options_payload,
    build_cli_parse_loops_payload,
    build_index_payload,
    build_manifest,
    build_pack_readme,
    build_strings_payload,
    build_surface_map_payload,
    get_program_hashes,
    maybe_call,
)
from outputs.writers import write_callsite_records, write_function_exports

__all__ = [
    "build_binary_info",
    "build_callgraph_payload",
    "build_cli_options_payload",
    "build_cli_parse_loops_payload",
    "build_index_payload",
    "build_manifest",
    "build_pack_readme",
    "build_strings_payload",
    "build_surface_map_payload",
    "ensure_dir",
    "get_program_hashes",
    "maybe_call",
    "pack_path",
    "write_callsite_records",
    "write_function_exports",
    "write_json",
    "write_text",
]
