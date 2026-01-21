#!/usr/bin/env python3
"""Check that rendered views reproduce the shipped lens outputs."""

from __future__ import annotations

import argparse
import json
import runpy
import sys
import tempfile
from pathlib import Path
from typing import Any


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "pack",
        type=Path,
        help="Path to a generated pack root (binary.lens) or its parent output directory",
    )
    parser.add_argument(
        "--view",
        action="append",
        default=None,
        help="Optional view id to check (repeatable).",
    )
    return parser.parse_args(argv)


def resolve_pack_root(path: Path) -> Path:
    if path.is_dir() and (path / "manifest.json").is_file():
        return path
    candidate = path / "binary.lens"
    if candidate.is_dir() and (candidate / "manifest.json").is_file():
        return candidate
    return path


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text())


def _load_views_index(pack_root: Path) -> list[dict[str, Any]]:
    index_path = pack_root / "views" / "index.json"
    if not index_path.is_file():
        raise FileNotFoundError(f"views/index.json not found under {pack_root}")
    index_payload = _load_json(index_path)
    views = index_payload.get("views")
    if not isinstance(views, list):
        raise ValueError("views/index.json missing views list")
    return [view for view in views if isinstance(view, dict)]


def _require_sql_views(views: list[dict[str, Any]]) -> list[str]:
    errors: list[str] = []
    for view in views:
        query_ref = view.get("query_ref")
        if not isinstance(query_ref, str):
            errors.append(f"View missing query_ref: {view.get('id') or view.get('output_path')}")
            continue
        if not query_ref.lower().endswith(".sql"):
            errors.append(f"View {view.get('id') or view.get('output_path')} does not use .sql query_ref: {query_ref}")
    return errors


def _render_views(pack_root: Path, output_root: Path, view_ids: set[str] | None) -> None:
    runner_path = pack_root / "views" / "run.py"
    if not runner_path.is_file():
        raise FileNotFoundError(f"views/run.py not found under {pack_root}")
    try:
        namespace = runpy.run_path(str(runner_path))
    except ModuleNotFoundError as exc:
        if exc.name == "duckdb":
            raise RuntimeError(
                "duckdb is required to render SQL lenses; run under nix develop or install duckdb."
            ) from exc
        raise
    render_views = namespace.get("render_views")
    if not callable(render_views):
        raise RuntimeError("views/run.py does not define render_views")
    render_views(pack_root, output_root=output_root, view_ids=view_ids)


def _compare_json(expected_path: Path, actual_path: Path) -> bool:
    try:
        expected = _load_json(expected_path)
    except Exception:
        return False
    try:
        actual = _load_json(actual_path)
    except Exception:
        return False
    return expected == actual


def _compare_text(expected_path: Path, actual_path: Path) -> bool:
    try:
        expected = expected_path.read_text()
        actual = actual_path.read_text()
    except Exception:
        return False
    return expected == actual


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    pack_root = resolve_pack_root(args.pack)
    if not pack_root.is_dir():
        print(f"Pack root not found: {pack_root}", file=sys.stderr)
        return 2
    if not (pack_root / "manifest.json").is_file():
        print(f"manifest.json not found under pack root: {pack_root}", file=sys.stderr)
        return 2

    view_ids = set(args.view) if args.view else None
    views = _load_views_index(pack_root)
    errors: list[str] = []
    errors.extend(_require_sql_views(views))
    if view_ids:
        views = [view for view in views if (view.get("id") or view.get("output_path")) in view_ids]

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_root = Path(tmp_dir)
        _render_views(pack_root, tmp_root, view_ids)
        for view in views:
            view_id = view.get("id") or view.get("output_path")
            output_path = view.get("output_path")
            output_format = view.get("output_format")
            if not isinstance(output_path, str):
                errors.append(f"Missing output_path for view {view_id}")
                continue
            expected_path = pack_root / output_path
            actual_path = tmp_root / output_path
            if not expected_path.is_file():
                errors.append(f"Missing shipped output: {output_path}")
                continue
            if not actual_path.is_file():
                errors.append(f"Missing rendered output: {output_path}")
                continue
            if output_format == "text":
                if not _compare_text(expected_path, actual_path):
                    errors.append(f"Mismatch in {output_path}")
            else:
                if not _compare_json(expected_path, actual_path):
                    errors.append(f"Mismatch in {output_path}")

    if errors:
        print("Lens repro check failed:", file=sys.stderr)
        for entry in errors:
            print(f"- {entry}", file=sys.stderr)
        return 1

    print(f"Lens repro ok: {pack_root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
