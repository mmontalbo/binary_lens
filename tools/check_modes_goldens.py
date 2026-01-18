#!/usr/bin/env python3
"""Check the `modes/` lens invariants for a generated `binary_lens` pack.

This is a lightweight regression guardrail that operates purely on the exported JSON pack
(`out/.../binary.lens`) and does not invoke Ghidra.
"""

from __future__ import annotations

import argparse
import difflib
import json
import sys
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any

MODES_RELATIVE_JSON_FILES = (
    Path("manifest.json"),
    Path("modes/index.json"),
    Path("modes/dispatch_sites.json"),
    Path("modes/slices.json"),
)


@dataclass(frozen=True)
class PackIdentity:
    name: str | None
    sha256: str | None


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "pack",
        type=Path,
        help="Path to a generated pack root (binary.lens) or its parent output directory",
    )
    parser.add_argument(
        "--mode",
        choices=("auto", "git", "coreutils", "generic"),
        default="auto",
        help="Expectation profile to apply (default: %(default)s)",
    )
    parser.add_argument(
        "--min-modes",
        type=int,
        default=None,
        help="Override minimum expected modes (default depends on --mode)",
    )
    parser.add_argument(
        "--min-coverage",
        type=float,
        default=0.98,
        help="Minimum fraction of modes with dispatch_site_count > 0 (default: %(default)s)",
    )
    parser.add_argument(
        "--diff",
        action="store_true",
        help="Diff modes-lens JSON files against committed goldens",
    )
    parser.add_argument(
        "--golden",
        type=Path,
        default=None,
        help="Golden root (e.g. goldens/modes/git). If omitted, inferred for git/coreutils",
    )
    return parser.parse_args(argv)


def resolve_pack_root(path: Path) -> Path:
    if path.is_dir() and (path / "manifest.json").is_file():
        return path
    candidate = path / "binary.lens"
    if candidate.is_dir() and (candidate / "manifest.json").is_file():
        return candidate
    return path


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text())
    except FileNotFoundError:
        raise
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in {path}: {exc}") from exc


def pack_identity(pack_root: Path) -> PackIdentity:
    name = None
    sha256 = None

    try:
        manifest = load_json(pack_root / "manifest.json")
        if isinstance(manifest, dict):
            value = manifest.get("binary_name")
            if isinstance(value, str) and value.strip():
                name = value.strip()
            hashes = manifest.get("binary_hashes")
            if isinstance(hashes, dict):
                value = hashes.get("sha256")
                if isinstance(value, str) and value.strip():
                    sha256 = value.strip()
    except FileNotFoundError:
        pass

    return PackIdentity(name=name, sha256=sha256)


def infer_mode(identity: PackIdentity) -> str:
    if identity.name is None:
        return "generic"
    lowered = identity.name.strip().lower()
    if lowered == "git":
        return "git"
    if lowered == "coreutils":
        return "coreutils"
    return "generic"


def normalize_json(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def unified_json_diff(label: str, golden: Any, candidate: Any) -> str:
    golden_text = normalize_json(golden).splitlines(keepends=True)
    candidate_text = normalize_json(candidate).splitlines(keepends=True)
    diff = difflib.unified_diff(
        golden_text,
        candidate_text,
        fromfile=f"golden/{label}",
        tofile=f"pack/{label}",
    )
    return "".join(diff)


def normalize_for_diff(rel_path: Path, value: Any) -> Any:
    """Normalize JSON objects for golden diffs.

    Some pack fields are intentionally *environment- or build-specific* (for example,
    tool revisions and local filesystem paths). The modes golden diff is intended to
    guard output structure and selection behavior, not these volatile metadata fields.
    """

    if rel_path == Path("manifest.json") and isinstance(value, dict):
        cleaned = deepcopy(value)
        # Coverage totals are derived from analysis state and can drift slightly
        # between runs even when the target binary is unchanged. Keep bounds and
        # binary identity stable, but do not diff coverage summary fields.
        cleaned.pop("coverage_summary", None)
        for key in (
            "binary_path",
            "created_at",
            "created_at_epoch_seconds",
            "created_at_source",
            "export_platform",
        ):
            cleaned.pop(key, None)
        tool = cleaned.get("tool")
        if isinstance(tool, dict):
            normalized_tool = dict(tool)
            normalized_tool.pop("revision", None)
            cleaned["tool"] = normalized_tool
        return cleaned

    return value


def check_required_files(pack_root: Path) -> list[str]:
    missing = []
    for rel_path in MODES_RELATIVE_JSON_FILES:
        path = pack_root / rel_path
        if not path.is_file():
            missing.append(str(rel_path))
    return missing


def check_modes_index(modes_index: Any, *, mode: str, min_modes: int, min_coverage: float) -> list[str]:
    errors: list[str] = []
    if not isinstance(modes_index, dict):
        return ["modes/index.json must be an object"]

    total_modes = modes_index.get("total_modes")
    if not isinstance(total_modes, int) or total_modes <= 0:
        errors.append("modes/index.json total_modes must be > 0")

    modes = modes_index.get("modes")
    if not isinstance(modes, list) or not modes:
        errors.append("modes/index.json modes must be a non-empty list")
        return errors

    if len(modes) < min_modes:
        errors.append(f"modes/index.json contains {len(modes)} modes; expected >= {min_modes}")

    kinds = {entry.get("kind") for entry in modes if isinstance(entry, dict)}
    if mode == "git" and "subcommand" not in kinds:
        errors.append("expected at least one mode with kind=subcommand")
    if mode == "coreutils" and "argv0" not in kinds:
        errors.append("expected at least one mode with kind=argv0")

    uncovered = []
    for entry in modes:
        if not isinstance(entry, dict):
            continue
        count = entry.get("dispatch_site_count")
        if not isinstance(count, int) or count <= 0:
            uncovered.append(entry.get("name") or entry.get("mode_id") or "<unknown>")
    coverage = 1.0 - (len(uncovered) / max(1, len(modes)))
    if coverage < min_coverage:
        errors.append(
            f"dispatch coverage {coverage:.3f} below threshold {min_coverage:.3f} "
            f"({len(uncovered)} uncovered of {len(modes)})"
        )
    return errors


def default_min_modes(mode: str) -> int:
    if mode in ("git", "coreutils"):
        return 50
    return 1


def infer_golden_root(mode: str) -> Path | None:
    if mode == "git":
        return Path("goldens/modes/git")
    if mode == "coreutils":
        return Path("goldens/modes/coreutils")
    return None


def diff_against_golden(pack_root: Path, golden_root: Path) -> tuple[list[str], str]:
    errors: list[str] = []
    chunks: list[str] = []

    for rel_path in MODES_RELATIVE_JSON_FILES:
        pack_path = pack_root / rel_path
        golden_path = golden_root / rel_path
        if not pack_path.is_file():
            errors.append(f"missing pack file: {pack_path}")
            continue
        if not golden_path.is_file():
            errors.append(f"missing golden file: {golden_path}")
            continue

        pack_json = load_json(pack_path)
        golden_json = load_json(golden_path)
        diff = unified_json_diff(
            str(rel_path),
            normalize_for_diff(rel_path, golden_json),
            normalize_for_diff(rel_path, pack_json),
        )
        if diff:
            chunks.append(diff)

    return errors, "\n".join(chunks)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    pack_root = resolve_pack_root(args.pack)
    missing = check_required_files(pack_root)
    if missing:
        for rel_path in missing:
            sys.stderr.write(f"error: missing required file: {pack_root / rel_path}\n")
        return 1

    identity = pack_identity(pack_root)
    selected_mode = args.mode
    if selected_mode == "auto":
        selected_mode = infer_mode(identity)

    min_modes = args.min_modes if args.min_modes is not None else default_min_modes(selected_mode)

    modes_index = load_json(pack_root / "modes/index.json")

    errors = []
    errors.extend(check_modes_index(modes_index, mode=selected_mode, min_modes=min_modes, min_coverage=args.min_coverage))

    diff_output = ""
    if args.diff:
        golden_root = args.golden
        if golden_root is None:
            golden_root = infer_golden_root(selected_mode)
        if golden_root is None:
            errors.append("unable to infer --golden for this pack; provide --golden explicitly")
        else:
            diff_errors, diff_output = diff_against_golden(pack_root, golden_root)
            errors.extend(diff_errors)
            if diff_output:
                errors.append("pack differs from golden (see diff output)")

    if errors:
        if identity.name or identity.sha256:
            sys.stderr.write(
                f"pack: name={identity.name or '<unknown>'} sha256={identity.sha256 or '<unknown>'}\n"
            )
        for message in errors:
            sys.stderr.write(f"error: {message}\n")
        if diff_output:
            sys.stdout.write(diff_output)
        return 1

    if diff_output:
        sys.stdout.write(diff_output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
