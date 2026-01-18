from __future__ import annotations

import os
import platform
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from export_bounds import Bounds
from export_primitives import addr_str
from ghidra.framework import Application


def maybe_call(obj, method_name):
    try:
        method = getattr(obj, method_name)
    except Exception:
        return None
    try:
        return method()
    except Exception:
        return None


def get_program_hashes(program):
    hashes = {}
    sha256 = maybe_call(program, "getExecutableSHA256")
    if sha256:
        hashes["sha256"] = sha256
    md5 = maybe_call(program, "getExecutableMD5")
    if md5:
        hashes["md5"] = md5
    return hashes


def build_binary_info(program):
    language = program.getLanguage()
    compiler = program.getCompilerSpec()
    info = {
        "name": program.getName(),
        "executable_format": program.getExecutableFormat(),
        "language": {
            "id": str(language.getLanguageID()),
            "processor": str(language.getProcessor()),
            "endian": "big" if language.isBigEndian() else "little",
        },
        "compiler_spec": str(compiler.getCompilerSpecID()),
        "default_pointer_size": program.getDefaultPointerSize(),
        "image_base": addr_str(program.getImageBase()),
        "address_range": {
            "min": addr_str(program.getMinAddress()),
            "max": addr_str(program.getMaxAddress()),
        },
    }
    executable_path = maybe_call(program, "getExecutablePath")
    if executable_path:
        info["executable_path"] = str(executable_path)
    hashes = get_program_hashes(program)
    if hashes:
        info["hashes"] = hashes
    return info, hashes


def build_callgraph_payload(
    call_edges,
    total_edges,
    truncated_edges,
    bounds: Bounds,
    call_edge_stats,
    *,
    nodes_ref: str | None = None,
    nodes_total: int | None = None,
):
    payload = {
        "total_edges": total_edges,
        "selected_edges": len(call_edges),
        "truncated": truncated_edges,
        "max_edges": bounds.optional("max_call_edges"),
        "metrics": call_edge_stats,
        "edges": call_edges,
    }
    if nodes_ref:
        payload["nodes_ref"] = nodes_ref
    if nodes_total is not None:
        payload["nodes_total"] = nodes_total
    return payload


def build_callgraph_nodes_payload(nodes):
    return {
        "total_nodes": len(nodes),
        "nodes": nodes,
    }


def build_cli_options_payload(options_list, total_options, truncated, bounds: Bounds):
    return {
        "total_options": total_options,
        "selected_options": len(options_list),
        "truncated": truncated,
        "max_options": bounds.optional("max_cli_options"),
        "options": options_list,
    }


def build_cli_parse_loops_payload(parse_loops, total_parse_loops, truncated, bounds: Bounds):
    selected = len(parse_loops)
    if not isinstance(total_parse_loops, int) or total_parse_loops < selected:
        total_parse_loops = selected
    return {
        "total_parse_loops": total_parse_loops,
        "selected_parse_loops": selected,
        "truncated": False,
        "max_parse_loops": bounds.optional("max_cli_parse_loops"),
        "parse_loops": parse_loops,
    }


@dataclass(frozen=True)
class ExportCreatedAt:
    iso8601: str
    epoch_seconds: int
    source: str


def _resolve_created_at() -> ExportCreatedAt:
    epoch_raw = os.environ.get("SOURCE_DATE_EPOCH")
    if epoch_raw:
        try:
            epoch = int(epoch_raw)
            dt = datetime.fromtimestamp(epoch, tz=timezone.utc)
            return ExportCreatedAt(
                iso8601=dt.isoformat().replace("+00:00", "Z"),
                epoch_seconds=epoch,
                source="source_date_epoch",
            )
        except Exception:
            pass
    epoch = int(datetime.now(tz=timezone.utc).timestamp())
    dt = datetime.fromtimestamp(epoch, tz=timezone.utc)
    return ExportCreatedAt(
        iso8601=dt.isoformat().replace("+00:00", "Z"),
        epoch_seconds=epoch,
        source="runtime_utc_now",
    )


def _maybe_read_git_revision(root: Path) -> str | None:
    head_path = root / ".git" / "HEAD"
    try:
        head = head_path.read_text().strip()
    except OSError:
        return None
    if head.startswith("ref:"):
        ref = head.split(":", 1)[1].strip()
        if ref:
            ref_path = root / ".git" / ref
            try:
                revision = ref_path.read_text().strip()
            except OSError:
                revision = None
            if revision:
                return revision
        return None
    if head:
        return head
    return None


def build_pack_index_payload(format_version: str) -> dict[str, object]:
    """Build a consumer-facing pack root index.

    This is a pure convenience layer: it points at canonical entry files and
    documents a few navigation conventions without changing any extracted data.
    """

    return {
        "schema": {
            "name": "binary_lens",
            "version": format_version,
        },
        "start_here": {
            "docs_overview_ref": "docs/overview.md",
            "manifest_ref": "manifest.json",
            "contracts_index_ref": "contracts/index.json",
        },
        "entrypoints": {
            "docs_readme_ref": "docs/README.md",
            "docs_overview_ref": "docs/overview.md",
            "docs_navigation_ref": "docs/navigation.md",
            "docs_surfaces_ref": "docs/surfaces.md",
            "docs_field_guide_ref": "docs/field_guide.md",
            "docs_examples_ref": "docs/examples.md",
            "schema_readme_ref": "schema/README.md",
            "binary_ref": "binary.json",
            "manifest_ref": "manifest.json",
            "modes_index_ref": "modes/index.json",
            "modes_dispatch_sites_ref": "modes/dispatch_sites.json",
            "modes_slices_ref": "modes/slices.json",
            "interfaces_index_ref": "interfaces/index.json",
            "interfaces_env_ref": "interfaces/env.json",
            "interfaces_fs_ref": "interfaces/fs.json",
            "interfaces_process_ref": "interfaces/process.json",
            "interfaces_net_ref": "interfaces/net.json",
            "interfaces_output_ref": "interfaces/output.json",
            "cli_options_ref": "cli/options.json",
            "cli_parse_loops_ref": "cli/parse_loops.json",
            "errors_messages_ref": "errors/messages.json",
            "errors_exit_paths_ref": "errors/exit_paths.json",
            "errors_error_sites_ref": "errors/error_sites.json",
            "contracts_index_ref": "contracts/index.json",
            "strings_ref": "strings.json",
            "functions_index_ref": "functions/index.json",
            "imports_ref": "imports.json",
            "callgraph_ref": "callgraph.json",
            "callgraph_nodes_ref": "callgraph/nodes.json",
        },
        "conventions": {
            "refs": "Paths in *_ref / *_refs are relative to the pack root.",
            "sharding": (
                "Large inventories use format=sharded_list/v1; follow shards[*].path to enumerate the full list."
            ),
            "truncation": "truncated=true means that record/list was bounded; missing entries may exist.",
        },
    }


def build_manifest(
    bounds: Bounds,
    hashes,
    binary_lens_version,
    format_version,
    *,
    binary_info: dict[str, object] | None = None,
    coverage_summary: dict[str, object] | None = None,
) -> dict[str, object]:
    repo_root = Path(__file__).resolve().parents[2]
    created_at = _resolve_created_at()
    tool_revision = (
        os.environ.get("BINARY_LENS_REVISION")
        or _maybe_read_git_revision(repo_root)
    )

    manifest = {
        "schema": {
            "name": "binary_lens",
            "version": format_version,
        },
        "binary_lens_version": binary_lens_version,
        "format_version": format_version,
        "ghidra_version": str(Application.getApplicationVersion()),
        "created_at": created_at.iso8601,
        "created_at_epoch_seconds": created_at.epoch_seconds,
        "created_at_source": created_at.source,
        "tool": {
            "name": "binary_lens",
            "version": binary_lens_version,
            "revision": tool_revision,
        },
        "bounds": bounds.as_manifest(),
    }
    if hashes:
        manifest["binary_hashes"] = hashes
    if binary_info:
        name = binary_info.get("name")
        if isinstance(name, str) and name.strip():
            manifest["binary_name"] = name.strip()
        executable_path = binary_info.get("executable_path")
        if isinstance(executable_path, str) and executable_path.strip():
            manifest["binary_path"] = executable_path.strip()
        language = binary_info.get("language")
        if isinstance(language, dict):
            manifest["target_arch"] = language.get("processor")
            manifest["target_endian"] = language.get("endian")
        executable_format = binary_info.get("executable_format")
        if isinstance(executable_format, str) and executable_format.strip():
            manifest["executable_format"] = executable_format.strip()
        compiler_spec = binary_info.get("compiler_spec")
        if isinstance(compiler_spec, str) and compiler_spec.strip():
            manifest["compiler_spec"] = compiler_spec.strip()

    manifest["export_platform"] = {
        "os": platform.system().lower() or None,
        "arch": platform.machine() or None,
    }
    if coverage_summary:
        manifest["coverage_summary"] = coverage_summary
    return manifest


def build_strings_payload(
    strings,
    total_strings,
    strings_truncated,
    bounds: Bounds,
    string_bucket_counts,
    string_bucket_limits,
):
    return {
        "total_strings": total_strings,
        "truncated": strings_truncated,
        "max_strings": bounds.optional("max_strings"),
        "buckets": {
            "env_vars": {
                "limit": string_bucket_limits.get("env_vars"),
                "selected": string_bucket_counts.get("env_vars", 0),
            },
            "usage": {
                "limit": string_bucket_limits.get("usage"),
                "selected": string_bucket_counts.get("usage", 0),
            },
            "format": {
                "limit": string_bucket_limits.get("format"),
                "selected": string_bucket_counts.get("format", 0),
            },
            "path": {
                "limit": string_bucket_limits.get("path"),
                "selected": string_bucket_counts.get("path", 0),
            },
        },
        "strings": strings,
    }


def build_index_payload(functions, full_functions, index_functions, summaries, bounds: Bounds):
    max_functions = bounds.max_functions_index
    truncated = bool(max_functions > 0 and len(functions) > max_functions)
    return {
        "total_functions": len(functions),
        "max_functions": bounds.optional("max_functions_index"),
        "truncated": truncated,
        "full_functions": [addr_str(func.getEntryPoint()) for func in full_functions],
        "omitted_functions": max(0, len(functions) - len(index_functions)),
        "functions": summaries,
    }


def build_pack_readme():
    return (
        "# `binary_lens` context pack\n\n"
        "This pack contains observed facts and mechanically derived structure.\n"
        "JSON files are authoritative; evidence files are bounded excerpts.\n"
        "Large inventories are sharded (see `docs/navigation.md`).\n\n"
        "Start here:\n\n"
        "- docs/overview.md\n"
        "- docs/navigation.md\n"
        "- docs/field_guide.md\n"
        "- docs/examples.md\n"
        "- contracts/index.json\n"
        "- index.json\n"
        "\n"
        "Key sections:\n\n"
        "- contracts/\n"
        "- modes/\n"
        "- interfaces/\n"
        "- cli/\n"
        "- errors/\n"
        "- functions/\n"
        "- evidence/\n\n"
        "Pack format notes:\n\n"
        "- schema/README.md\n"
    )
