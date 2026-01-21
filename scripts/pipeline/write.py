"""Write stage for the context pack export pipeline (pack format v2)."""

from __future__ import annotations

import runpy
import shutil
from pathlib import Path
from typing import Any, Iterable

from export_bounds import Bounds
from export_config import BINARY_LENS_VERSION
from outputs.facts import write_fact_tables
from outputs.io import ensure_dir, write_json
from outputs.writers import write_decomp_excerpts
from pipeline.layout import PackLayout
from pipeline.phases import phase
from pipeline.types import CollectedData, DerivedPayloads


def _ensure_pack_dirs(layout: PackLayout) -> None:
    for path in (
        layout.docs_dir,
        layout.schema_dir,
        layout.views_dir,
        layout.views_dir / "queries",
        layout.views_dir / "templates",
        layout.facts_dir,
        layout.evidence_dir,
        layout.evidence_decomp_dir,
        layout.root / "execution",
    ):
        ensure_dir(path)


def _write_json_payloads(items: Iterable[tuple[Any, Any]]) -> None:
    for path, payload in items:
        write_json(path, payload)


def _copy_view_sources(views_dir: Path, views_index: dict[str, Any]) -> None:
    repo_root = Path(__file__).resolve().parents[2]
    repo_views = repo_root / "views"
    if not repo_views.is_dir():
        return

    run_src = repo_views / "run.py"
    if run_src.is_file():
        shutil.copy2(run_src, views_dir / "run.py")

    refs: set[str] = set()
    views = views_index.get("views") if isinstance(views_index, dict) else None
    if isinstance(views, list):
        for view in views:
            if not isinstance(view, dict):
                continue
            for key in ("query_ref", "template_ref"):
                ref = view.get(key)
                if isinstance(ref, str) and ref.strip():
                    refs.add(ref)
            template_tables = view.get("template_tables")
            if isinstance(template_tables, dict):
                for entry in template_tables.values():
                    if isinstance(entry, str) and entry.strip():
                        refs.add(entry)

    for ref in sorted(refs):
        if ref == "views/queries/load_tables.sql":
            continue
        if not ref.startswith("views/"):
            continue
        src = repo_root / ref
        if not src.is_file():
            continue
        dest = views_dir / Path(ref).relative_to("views")
        ensure_dir(dest.parent)
        shutil.copy2(src, dest)


def _write_load_tables_sql(views_dir: Path, facts_index: dict[str, Any]) -> None:
    tables = facts_index.get("tables") if isinstance(facts_index, dict) else None
    if not isinstance(tables, list):
        return
    lines = [
        "-- Auto-generated DuckDB loader for pack facts.",
        "-- NOTE: Run from the pack root (binary.lens). Prefer views/run.py which sets CWD.",
    ]
    for entry in tables:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        paths = entry.get("paths")
        if not isinstance(name, str) or not name.strip():
            continue
        if not isinstance(paths, list) or not paths:
            continue
        path_literals = ", ".join(f"'{path}'" for path in paths if isinstance(path, str))
        if not path_literals:
            continue
        if len(paths) == 1:
            source = f"read_parquet({path_literals})"
        else:
            source = f"read_parquet([{path_literals}])"
        lines.append(f"CREATE OR REPLACE VIEW {name} AS SELECT * FROM {source};")
    lines.append("")
    lines.append("-- Helper views.")
    lines.append(
        "CREATE OR REPLACE VIEW usage_help_functions AS "
        "SELECT function_id, function_addr_int, name, signature "
        "FROM callgraph_nodes "
        "WHERE name IS NOT NULL "
        "AND ("
        "lower(name) like 'usage%' "
        "OR lower(name) like '%_usage%' "
        "OR lower(name) like '%help%'"
        ");"
    )
    content = "\n".join(lines) + "\n"
    (views_dir / "queries" / "load_tables.sql").write_text(content)


def _render_views(pack_root: Path) -> None:
    repo_root = Path(__file__).resolve().parents[2]
    runner_path = repo_root / "views" / "run.py"
    if not runner_path.is_file():
        raise FileNotFoundError(f"View runner not found: {runner_path}")
    namespace = runpy.run_path(str(runner_path))
    render_views = namespace.get("render_views")
    if not callable(render_views):
        raise RuntimeError("views/run.py does not define render_views")
    render_views(pack_root)


def _build_views_index() -> dict[str, Any]:
    view_entries: list[dict[str, Any]] = []

    def _add_view_entry(
        output_path: str,
        *,
        query_ref: str,
        output_format: str,
        output_mode: str | None = None,
        output_key: str | None = None,
        output_meta: dict[str, Any] | None = None,
        template_ref: str | None = None,
        template_table_key: str | None = None,
        template_tables: dict[str, str] | None = None,
    ) -> None:
        entry: dict[str, Any] = {
            "id": output_path,
            "output_path": output_path,
            "query_ref": query_ref,
            "output_format": output_format,
        }
        if output_mode:
            entry["output_mode"] = output_mode
        if output_key:
            entry["output_key"] = output_key
        if output_meta:
            entry["output_meta"] = output_meta
        if template_ref:
            entry["template_ref"] = template_ref
        if template_table_key:
            entry["template_table_key"] = template_table_key
        if template_tables:
            entry["template_tables"] = template_tables
        view_entries.append(entry)

    _add_view_entry(
        "execution/roots.json",
        query_ref="views/queries/execution_roots.sql",
        output_format="json",
        output_mode="rows",
        output_key="roots",
        output_meta={
            "schema": {"name": "binary_lens_execution_roots", "version": "v1"},
            "facts_ref": "facts/index.json",
        },
    )
    _add_view_entry(
        "execution/sinks.json",
        query_ref="views/queries/execution_sinks.sql",
        output_format="json",
        output_mode="rows",
        output_key="sinks",
        output_meta={
            "schema": {"name": "binary_lens_execution_sinks", "version": "v1"},
            "facts_ref": "facts/index.json",
        },
    )

    def _add_template_view(
        output_path: str,
        template_ref: str,
        query_ref: str,
        *,
        template_table_key: str | None = None,
        template_tables: dict[str, str] | None = None,
    ) -> None:
        _add_view_entry(
            output_path,
            query_ref=query_ref,
            output_format="text",
            template_ref=template_ref,
            template_table_key=template_table_key,
            template_tables=template_tables,
        )

    _add_template_view(
        "README.md",
        "views/templates/README.md",
        "views/queries/docs_overview.sql",
    )
    _add_template_view(
        "docs/examples.md",
        "views/templates/docs/examples.md",
        "views/queries/pack_meta.sql",
        template_tables={
            "example_execution_roots_table": "views/queries/examples_execution_roots.sql",
            "example_reachability_table": "views/queries/examples_reachability.sql",
            "example_env_vars_table": "views/queries/examples_env_vars.sql",
            "example_output_templates_table": "views/queries/examples_output_templates.sql",
            "example_usage_strings_table": "views/queries/examples_usage_strings.sql",
            "example_exit_callsites_table": "views/queries/examples_exit_callsites.sql",
            "example_top_external_calls_table": "views/queries/examples_top_external_calls.sql",
        },
    )
    _add_template_view(
        "schema/README.md",
        "views/templates/schema/README.md",
        "views/queries/schema_table.sql",
        template_table_key="schema_table",
    )

    view_entries.sort(key=lambda entry: entry.get("output_path") or "")
    return {
        "schema": {
            "name": "binary_lens_views",
            "version": "v2",
        },
        "views_version": BINARY_LENS_VERSION,
        "runner_ref": "views/run.py",
        "load_tables_ref": "views/queries/load_tables.sql",
        "views": view_entries,
    }


def write_outputs(
    program: Any,
    collected: CollectedData,
    derived: DerivedPayloads,
    layout: PackLayout,
    bounds: Bounds,
    monitor: Any,
    profiler: Any,
) -> None:
    hinted_function_ids = set()
    evidence_hints = derived.evidence_hints
    if isinstance(evidence_hints, dict):
        applied_ids = evidence_hints.get("applied_function_ids")
        if isinstance(applied_ids, list):
            hinted_function_ids = {
                item for item in applied_ids if isinstance(item, str) and item.strip()
            }
    with phase(profiler, "write_evidence_decomp"):
        evidence_entries = write_decomp_excerpts(
            program,
            derived.full_functions,
            bounds,
            collected.string_refs_by_func,
            collected.string_tags_by_id,
            collected.string_value_by_id,
            layout.evidence_decomp_dir,
            monitor,
            hinted_function_ids,
        )

    with phase(profiler, "write_outputs"):
        _ensure_pack_dirs(layout)

        _write_json_payloads(
            [
                (layout.root / "index.json", derived.pack_index_payload),
                (layout.root / "manifest.json", derived.manifest),
            ]
        )

        facts_index = write_fact_tables(layout.root, derived.facts)
        write_json(layout.facts_dir / "index.json", facts_index)

        evidence_index_payload = {
            "schema": {"name": "binary_lens_evidence_index", "version": "v1"},
            "bounded": True,
            "entries": evidence_entries,
        }
        write_json(layout.evidence_dir / "index.json", evidence_index_payload)

        views_index = _build_views_index()
        write_json(layout.views_dir / "index.json", views_index)
        _copy_view_sources(layout.views_dir, views_index)
        _write_load_tables_sql(layout.views_dir, facts_index)
        _render_views(layout.root)
