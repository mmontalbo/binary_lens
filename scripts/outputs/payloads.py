from __future__ import annotations

import os
import platform
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from export_bounds import Bounds
from export_config import PACK_SCHEMA_VERSION
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
            "readme_ref": "README.md",
            "manifest_ref": "manifest.json",
            "facts_index_ref": "facts/index.json",
            "views_index_ref": "views/index.json",
            "evidence_index_ref": "evidence/index.json",
        },
        "entrypoints": {
            "readme_ref": "README.md",
            "docs_examples_ref": "docs/examples.md",
            "schema_readme_ref": "schema/README.md",
            "manifest_ref": "manifest.json",
            "pack_summary_ref": "pack_summary.json",
            "runs_index_ref": "runs/index.json",
            "facts_index_ref": "facts/index.json",
            "views_index_ref": "views/index.json",
            "views_runner_ref": "views/run.py",
            "execution_roots_ref": "execution/roots.json",
            "execution_sinks_ref": "execution/sinks.json",
            "evidence_index_ref": "evidence/index.json",
        },
        "conventions": {
            "refs": "Paths in *_ref / *_refs are relative to the pack root.",
            "facts": "Canonical facts live under facts/ as Parquet tables; see facts/index.json.",
            "tables": "Join on explicit *_id columns (function_id, callsite_id, string_id).",
            "views": "Rendered view outputs embed _lens metadata; sources live under views/.",
            "sql": "Default lenses are derived via DuckDB SQL (see views/queries/*.sql).",
            "truncation": "truncated=true means that record/list was bounded; missing entries may exist.",
            "evidence": "Evidence excerpts live under evidence/; evidence/index.json is a bounded registry.",
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
    evidence_hints: dict[str, object] | None = None,
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
        "pack_schema_version": PACK_SCHEMA_VERSION,
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
    if evidence_hints:
        manifest["evidence_hints"] = evidence_hints
    return manifest
