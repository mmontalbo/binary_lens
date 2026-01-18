#!/usr/bin/env python3
"""Check pack reference integrity for binary_lens outputs.

Validates JSON *_ref / *_refs fields and contract markdown references without
invoking Ghidra.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterable

MARKDOWN_REF_PATTERNS = (
    re.compile(r"functions/f_[A-Za-z0-9_]+\.json"),
    re.compile(r"evidence/decomp/f_[A-Za-z0-9_]+\.json"),
    re.compile(r"evidence/callsites\.json"),
)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "pack",
        type=Path,
        help="Path to a generated pack root (binary.lens) or its parent output directory",
    )
    parser.add_argument(
        "--include-docs",
        action="store_true",
        help="Also scan docs/ markdown for pack-relative links",
    )
    return parser.parse_args(argv)


def resolve_pack_root(path: Path) -> Path:
    if path.is_dir() and (path / "manifest.json").is_file():
        return path
    candidate = path / "binary.lens"
    if candidate.is_dir() and (candidate / "manifest.json").is_file():
        return candidate
    return path


def iter_ref_values(value: Any) -> Iterable[Any]:
    if isinstance(value, dict):
        for key, entry in value.items():
            if key.endswith("_ref") or key.endswith("_refs"):
                yield entry
            yield from iter_ref_values(entry)
        return
    if isinstance(value, list):
        for item in value:
            yield from iter_ref_values(item)


def iter_ref_paths(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        ref = value.strip()
        if ref:
            yield ref
        return
    if isinstance(value, list):
        for item in value:
            if isinstance(item, str):
                ref = item.strip()
                if ref:
                    yield ref


def normalize_ref_path(ref: str) -> str:
    if ref.startswith("./"):
        return ref[2:]
    return ref


def ref_exists(pack_root: Path, ref: str) -> bool:
    candidate = Path(ref)
    if not candidate.is_absolute():
        candidate = pack_root / candidate
    return candidate.is_file()


def collect_json_ref_errors(pack_root: Path) -> tuple[list[str], set[tuple[str, str]]]:
    parse_errors: list[str] = []
    missing: set[tuple[str, str]] = set()
    for json_path in pack_root.rglob("*.json"):
        if not json_path.is_file():
            continue
        rel_source = str(json_path.relative_to(pack_root))
        try:
            data = json.loads(json_path.read_text())
        except json.JSONDecodeError as exc:
            parse_errors.append(f"{rel_source}: {exc}")
            continue
        for value in iter_ref_values(data):
            for ref in iter_ref_paths(value):
                ref = normalize_ref_path(ref)
                if not ref_exists(pack_root, ref):
                    missing.add((ref, rel_source))
    return parse_errors, missing


def iter_markdown_refs(text: str) -> Iterable[str]:
    for pattern in MARKDOWN_REF_PATTERNS:
        for match in pattern.findall(text):
            yield match


def collect_markdown_ref_errors(pack_root: Path, *, include_docs: bool) -> set[tuple[str, str]]:
    missing: set[tuple[str, str]] = set()
    roots = [pack_root / "contracts"]
    if include_docs:
        roots.append(pack_root / "docs")
    for root in roots:
        if not root.is_dir():
            continue
        for md_path in root.rglob("*.md"):
            if not md_path.is_file():
                continue
            rel_source = str(md_path.relative_to(pack_root))
            for ref in iter_markdown_refs(md_path.read_text()):
                ref = normalize_ref_path(ref)
                if not ref_exists(pack_root, ref):
                    missing.add((ref, rel_source))
    return missing


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    pack_root = resolve_pack_root(args.pack)
    if not pack_root.is_dir():
        print(f"Pack root not found: {pack_root}", file=sys.stderr)
        return 2
    if not (pack_root / "manifest.json").is_file():
        print(f"manifest.json not found under pack root: {pack_root}", file=sys.stderr)
        return 2

    parse_errors, missing = collect_json_ref_errors(pack_root)
    missing |= collect_markdown_ref_errors(pack_root, include_docs=args.include_docs)

    if parse_errors:
        print("Invalid JSON:", file=sys.stderr)
        for entry in sorted(parse_errors):
            print(f"- {entry}", file=sys.stderr)

    if missing:
        print("Missing refs:", file=sys.stderr)
        for ref, source in sorted(missing):
            print(f"- {ref} (referenced by {source})", file=sys.stderr)
        return 1

    if parse_errors:
        return 1

    print(f"Pack refs ok: {pack_root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
