#!/usr/bin/env python3
"""Check pack reference integrity for binary_lens outputs.

Validates JSON *_ref / *_refs fields and pack-embedded markdown references
without invoking Ghidra.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterable

MARKDOWN_REF_PATTERNS = (
    re.compile(r"facts/[A-Za-z0-9_./-]+\.(?:json|parquet)"),
    re.compile(r"views/[A-Za-z0-9_./-]+\.(?:json|sql|md|py)"),
    re.compile(r"execution/[A-Za-z0-9_./-]+\.json"),
    re.compile(r"schema/[A-Za-z0-9_./-]+\.md"),
    re.compile(r"docs/[A-Za-z0-9_./-]+\.md"),
    re.compile(r"evidence/index\.json"),
    re.compile(r"evidence/decomp/f_[A-Za-z0-9_]+\.json"),
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
    if candidate.is_file():
        return True
    if ref.endswith("/") and candidate.is_dir():
        return True
    return False


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


def collect_facts_index_errors(pack_root: Path) -> set[tuple[str, str]]:
    missing: set[tuple[str, str]] = set()
    facts_index = pack_root / "facts" / "index.json"
    if not facts_index.is_file():
        missing.add(("facts/index.json", "pack_root"))
        return missing
    try:
        payload = json.loads(facts_index.read_text())
    except json.JSONDecodeError:
        missing.add(("facts/index.json (invalid JSON)", "pack_root"))
        return missing
    tables = payload.get("tables") if isinstance(payload, dict) else None
    if not isinstance(tables, list):
        missing.add(("facts/index.json (missing tables list)", "pack_root"))
        return missing
    for table in tables:
        if not isinstance(table, dict):
            continue
        paths = table.get("paths")
        if not isinstance(paths, list):
            continue
        for path in paths:
            if not isinstance(path, str):
                continue
            if not ref_exists(pack_root, path):
                missing.add((path, "facts/index.json"))
    return missing


def collect_views_index_errors(pack_root: Path) -> set[tuple[str, str]]:
    missing: set[tuple[str, str]] = set()
    views_index = pack_root / "views" / "index.json"
    if not views_index.is_file():
        missing.add(("views/index.json", "pack_root"))
        return missing
    try:
        payload = json.loads(views_index.read_text())
    except json.JSONDecodeError:
        missing.add(("views/index.json (invalid JSON)", "pack_root"))
        return missing
    views = payload.get("views") if isinstance(payload, dict) else None
    if not isinstance(views, list):
        missing.add(("views/index.json (missing views list)", "pack_root"))
        return missing
    for view in views:
        if not isinstance(view, dict):
            continue
        query_ref = view.get("query_ref")
        if isinstance(query_ref, str) and not ref_exists(pack_root, query_ref):
            missing.add((query_ref, "views/index.json"))
        template_ref = view.get("template_ref")
        if isinstance(template_ref, str) and not ref_exists(pack_root, template_ref):
            missing.add((template_ref, "views/index.json"))
        template_tables = view.get("template_tables")
        if isinstance(template_tables, dict):
            for entry in template_tables.values():
                if isinstance(entry, str) and not ref_exists(pack_root, entry):
                    missing.add((entry, "views/index.json"))
    load_tables_ref = payload.get("load_tables_ref") if isinstance(payload, dict) else None
    if isinstance(load_tables_ref, str) and not ref_exists(pack_root, load_tables_ref):
        missing.add((load_tables_ref, "views/index.json"))
    return missing


def iter_markdown_refs(text: str) -> Iterable[str]:
    for pattern in MARKDOWN_REF_PATTERNS:
        for match in pattern.findall(text):
            yield match


def collect_markdown_ref_errors(pack_root: Path, *, include_docs: bool) -> set[tuple[str, str]]:
    missing: set[tuple[str, str]] = set()

    readme_path = pack_root / "README.md"
    if readme_path.is_file():
        for ref in iter_markdown_refs(readme_path.read_text()):
            ref = normalize_ref_path(ref)
            if not ref_exists(pack_root, ref):
                missing.add((ref, "README.md"))

    roots = [pack_root / "contracts", pack_root / "schema"]
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
    missing |= collect_facts_index_errors(pack_root)
    missing |= collect_views_index_errors(pack_root)
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
