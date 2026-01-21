"""Parquet fact table writer for pack format v2."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable

from outputs.io import ensure_dir
from pipeline.types import FactTable


def _arrow_type(type_name: str):
    import pyarrow as pa

    if type_name == "string":
        return pa.string()
    if type_name == "int64":
        return pa.int64()
    if type_name == "bool":
        return pa.bool_()
    if type_name == "list<string>":
        return pa.list_(pa.string())
    raise ValueError(f"Unsupported fact column type: {type_name}")


def write_fact_tables(pack_root: Path, tables: Iterable[FactTable]) -> dict[str, Any]:
    import pyarrow as pa
    import pyarrow.parquet as pq

    facts_dir = pack_root / "facts"
    ensure_dir(facts_dir)

    registry_tables: list[dict[str, Any]] = []
    for table in tables:
        schema_fields = [
            pa.field(name, _arrow_type(type_name), nullable=True)
            for name, type_name in table.schema
        ]
        schema = pa.schema(schema_fields)
        arrow_table = pa.Table.from_pylist(table.rows, schema=schema)
        filename = f"{table.name}.parquet"
        table_path = facts_dir / filename
        pq.write_table(arrow_table, table_path)
        registry_tables.append(
            {
                "name": table.name,
                "version": table.version,
                "primary_key": list(table.primary_key),
                "paths": [f"facts/{filename}"],
                "schema": [
                    {"name": name, "type": type_name}
                    for name, type_name in table.schema
                ],
                "row_count": arrow_table.num_rows,
                "description": table.description,
            }
        )

    registry_tables.sort(key=lambda entry: entry.get("name") or "")
    return {
        "schema": {"name": "binary_lens_facts", "version": "v1"},
        "tables": registry_tables,
        "table_count": len(registry_tables),
    }
