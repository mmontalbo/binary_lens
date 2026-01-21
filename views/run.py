#!/usr/bin/env python3
"""Render binary_lens view outputs from shipped DuckDB SQL sources."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import duckdb


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text())


def _ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def _write_json(path: Path, payload: Any) -> None:
    _ensure_parent(path)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n")


def _write_text(path: Path, content: str) -> None:
    _ensure_parent(path)
    path.write_text(content)


def _load_views_index(pack_root: Path) -> dict[str, Any]:
    index_path = pack_root / "views" / "index.json"
    if not index_path.is_file():
        raise FileNotFoundError(f"views/index.json not found under {pack_root}")
    data = _load_json(index_path)
    if not isinstance(data, dict):
        raise ValueError("views/index.json must be a JSON object")
    return data


def _view_hash(
    view: dict[str, Any],
    query_path: Path,
    template_path: Path | None,
    extra_query_paths: list[Path] | None = None,
) -> str:
    spec = {
        "id": view.get("id"),
        "output_path": view.get("output_path"),
        "query_ref": view.get("query_ref"),
        "template_ref": view.get("template_ref"),
        "output_format": view.get("output_format"),
        "output_mode": view.get("output_mode"),
        "output_key": view.get("output_key"),
        "output_meta": view.get("output_meta"),
    }
    template_table_key = view.get("template_table_key")
    if template_table_key is not None:
        spec["template_table_key"] = template_table_key
    template_tables = view.get("template_tables")
    if template_tables is not None:
        spec["template_tables"] = template_tables
    spec_bytes = json.dumps(spec, sort_keys=True).encode("utf-8")
    query_bytes = query_path.read_bytes()
    template_bytes = template_path.read_bytes() if template_path and template_path.is_file() else b""
    payload = query_bytes + b"\n" + template_bytes
    if extra_query_paths:
        for extra_path in extra_query_paths:
            payload += b"\n" + extra_path.read_bytes()
    payload += b"\n" + spec_bytes
    return hashlib.sha256(payload).hexdigest()


def _format_template_value(value: Any) -> str:
    if value is None:
        return "unknown"
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _render_template(template: str, context: dict[str, Any]) -> str:
    rendered = template
    for key, value in context.items():
        rendered = rendered.replace(f"{{{{{key}}}}}", _format_template_value(value))
    return rendered


def _markdown_table(headers: list[str], rows: list[list[str]]) -> str:
    if not headers:
        return ""
    divider = ["---"] * len(headers)
    header_line = "| " + " | ".join(headers) + " |"
    divider_line = "| " + " | ".join(divider) + " |"
    lines = [header_line, divider_line]
    for row in rows:
        lines.append("| " + " | ".join(row) + " |")
    return "\n".join(lines)


def _sql_string(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


@contextmanager
def _chdir(path: Path):
    prev = Path.cwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(prev)


def _connect_duckdb(pack_root: Path) -> duckdb.DuckDBPyConnection:
    con = duckdb.connect(database=":memory:")
    facts_index = pack_root / "facts" / "index.json"
    if facts_index.is_file():
        index_payload = _load_json(facts_index)
        tables = index_payload.get("tables")
        if isinstance(tables, list):
            for entry in tables:
                if not isinstance(entry, dict):
                    continue
                name = entry.get("name")
                paths = entry.get("paths")
                if not isinstance(name, str) or not name.strip():
                    continue
                if not isinstance(paths, list) or not paths:
                    continue
                abs_paths = [
                    str(pack_root / path)
                    for path in paths
                    if isinstance(path, str) and path.strip()
                ]
                if not abs_paths:
                    continue
                if len(abs_paths) == 1:
                    source = f"read_parquet({_sql_string(abs_paths[0])})"
                else:
                    source = "read_parquet([" + ", ".join(_sql_string(p) for p in abs_paths) + "])"
                con.execute(f"CREATE OR REPLACE VIEW {name} AS SELECT * FROM {source}")

    manifest_path = pack_root / "manifest.json"
    if manifest_path.is_file():
        con.execute(
            "CREATE OR REPLACE VIEW manifest AS SELECT * FROM read_json_auto("
            + _sql_string(str(manifest_path))
            + ")"
        )
    con.execute(
        "CREATE OR REPLACE VIEW usage_help_functions AS "
        "SELECT function_id, function_addr_int, name, signature "
        "FROM callgraph_nodes "
        "WHERE name IS NOT NULL "
        "AND ("
        "lower(name) like 'usage%' "
        "OR lower(name) like '%_usage%' "
        "OR lower(name) like '%help%'"
        ")"
    )
    return con


def _run_sql(con: duckdb.DuckDBPyConnection, query_path: Path) -> tuple[list[str], list[tuple[Any, ...]]]:
    sql = query_path.read_text()
    result = con.execute(sql)
    columns = [desc[0] for desc in result.description] if result.description else []
    rows = result.fetchall() if columns else []
    return columns, rows


def _render_json_view(
    view: dict[str, Any],
    columns: list[str],
    rows: list[tuple[Any, ...]],
) -> dict[str, Any]:
    output_mode = view.get("output_mode") or "rows"
    output_key = view.get("output_key")
    output_meta = view.get("output_meta")
    payload: dict[str, Any] = {}

    def _row_to_dict(row: tuple[Any, ...]) -> dict[str, Any]:
        return {col: value for col, value in zip(columns, row)}

    if output_mode == "single":
        payload = _row_to_dict(rows[0]) if rows else {}
    else:
        items = [_row_to_dict(row) for row in rows]
        if output_key:
            payload[output_key] = items
        else:
            payload["rows"] = items

    if isinstance(output_meta, dict):
        payload.update(output_meta)
    return payload


def _render_view(
    pack_root: Path,
    output_root: Path,
    view: dict[str, Any],
    *,
    views_version: str | None,
    load_tables_ref: str | None,
    con: duckdb.DuckDBPyConnection,
) -> None:
    view_id = view.get("id") or view.get("output_path")
    output_path = view.get("output_path")
    view_query_ref = view.get("query_ref")
    template_ref = view.get("template_ref") if isinstance(view.get("template_ref"), str) else None
    output_format = view.get("output_format")
    if not output_path or not isinstance(output_path, str):
        raise ValueError(f"View missing output_path: {view_id}")
    if not view_query_ref or not isinstance(view_query_ref, str):
        raise ValueError(f"View missing query_ref: {view_id}")
    query_path = pack_root / view_query_ref
    if not query_path.is_file():
        raise FileNotFoundError(f"Query source not found: {view_query_ref}")

    template_path = (pack_root / template_ref) if template_ref else None
    if template_path and not template_path.is_file():
        raise FileNotFoundError(f"Template not found: {template_ref}")

    columns, rows = _run_sql(con, query_path)

    extra_query_paths: list[Path] = []
    template_tables = view.get("template_tables")
    if isinstance(template_tables, dict):
        for key in sorted(template_tables):
            table_query_ref = template_tables.get(key)
            if not isinstance(table_query_ref, str) or not table_query_ref.strip():
                continue
            query_path_entry = pack_root / table_query_ref
            if not query_path_entry.is_file():
                raise FileNotFoundError(
                    f"Template table query not found: {table_query_ref}"
                )
            extra_query_paths.append(query_path_entry)

    lens_hash = _view_hash(view, query_path, template_path, extra_query_paths)
    version = views_version or "unknown"
    reproduce_runner = f"python views/run.py --pack . --view {view_id}"
    reproduce_duckdb = None
    if load_tables_ref:
        reproduce_duckdb = (
            f"duckdb -c \".read {load_tables_ref}\" -c \".read {view_query_ref}\""
        )
    lens_meta = {
        "view_id": view_id,
        "view_ref": "views/index.json",
        "query_ref": view_query_ref,
        "template_ref": template_ref,
        "version": version,
        "hash": lens_hash,
        "reproduce": reproduce_runner,
        "reproduce_duckdb": reproduce_duckdb,
    }

    output_target = output_root / output_path
    if output_format == "text":
        template_text = template_path.read_text() if template_path else ""
        context: dict[str, Any] = {}
        table_key = view.get("template_table_key")
        if isinstance(table_key, str) and table_key:
            table_rows = [[str(cell) for cell in row] for row in rows]
            context[table_key] = _markdown_table(columns, table_rows)
        if rows and columns:
            context.update({col: value for col, value in zip(columns, rows[0])})
        template_tables = view.get("template_tables")
        if isinstance(template_tables, dict):
            for key, table_query_ref in template_tables.items():
                if not isinstance(key, str) or not key.strip():
                    continue
                if not isinstance(table_query_ref, str) or not table_query_ref.strip():
                    continue
                query_path = pack_root / table_query_ref
                if not query_path.is_file():
                    raise FileNotFoundError(
                        f"Template table query not found: {table_query_ref}"
                    )
                table_columns, table_rows = _run_sql(con, query_path)
                rendered_rows = [[str(cell) for cell in row] for row in table_rows]
                context[key] = _markdown_table(table_columns, rendered_rows)
        rendered = _render_template(template_text, context)
        if not rendered.endswith("\n"):
            rendered += "\n"
        comment = (
            "<!-- lens: "
            f"view_id={view_id}; "
            f"view_ref=views/index.json; "
            f"query_ref={view_query_ref}; "
            f"template_ref={template_ref or ''}; "
            f"version={version}; "
            f"hash={lens_hash}; "
            f"reproduce={reproduce_runner}; "
            f"reproduce_duckdb={reproduce_duckdb or ''} "
            "-->\n"
        )
        _write_text(output_target, rendered + comment)
        return

    output_payload = _render_json_view(view, columns, rows)
    output_payload["_lens"] = lens_meta
    _write_json(output_target, output_payload)


def render_views(
    pack_root: Path,
    *,
    output_root: Path | None = None,
    view_ids: set[str] | None = None,
) -> None:
    pack_root = pack_root.resolve()
    views_index = _load_views_index(pack_root)
    views = views_index.get("views")
    if not isinstance(views, list):
        raise ValueError("views/index.json missing views list")
    views_version = views_index.get("views_version")
    load_tables_ref = views_index.get("load_tables_ref")
    output_root = (output_root or pack_root).resolve()
    with _chdir(pack_root):
        con = _connect_duckdb(pack_root)
        for view in views:
            if not isinstance(view, dict):
                continue
            view_id = view.get("id") or view.get("output_path")
            if view_ids and view_id not in view_ids:
                continue
            _render_view(
                pack_root,
                output_root,
                view,
                views_version=views_version,
                load_tables_ref=load_tables_ref,
                con=con,
            )


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--pack",
        default=".",
        help="Path to a generated pack root (binary.lens).",
    )
    parser.add_argument(
        "--out",
        default=None,
        help="Optional output root (defaults to pack root).",
    )
    parser.add_argument(
        "--view",
        action="append",
        default=None,
        help="Render only the specified view id (repeatable).",
    )
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    pack_root = Path(args.pack)
    output_root = Path(args.out) if args.out else None
    view_ids = set(args.view) if args.view else None
    render_views(pack_root, output_root=output_root, view_ids=view_ids)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
