import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

ROOT = Path(__file__).resolve().parents[1]
VIEWS_RUN_PATH = ROOT / "views" / "run.py"
QUERY_TEXT = ROOT / "views" / "queries" / "examples_evidence_usage_text.sql"
QUERY_QUOTES = ROOT / "views" / "queries" / "examples_evidence_usage_quotes.sql"


def _load_views_run():
    spec = importlib.util.spec_from_file_location("views_run", VIEWS_RUN_PATH)
    module = importlib.util.module_from_spec(spec)
    if spec.loader is None:
        raise RuntimeError("Failed to load views/run.py")
    spec.loader.exec_module(module)
    return module


def _write_empty_callgraph_nodes(parquet_path: Path) -> None:
    schema = pa.schema(
        [
            ("function_id", pa.string()),
            ("function_addr_int", pa.int64()),
            ("name", pa.string()),
            ("signature", pa.string()),
        ]
    )
    table = pa.Table.from_arrays(
        [
            pa.array([], type=pa.string()),
            pa.array([], type=pa.int64()),
            pa.array([], type=pa.string()),
            pa.array([], type=pa.string()),
        ],
        schema=schema,
    )
    pq.write_table(table, parquet_path)


class EvidenceViewTest(unittest.TestCase):
    def test_evidence_queries_handle_empty_decomp(self):
        views_run = _load_views_run()
        with tempfile.TemporaryDirectory() as tmpdir:
            pack_root = Path(tmpdir)
            facts_dir = pack_root / "facts"
            evidence_dir = pack_root / "evidence"
            facts_dir.mkdir(parents=True, exist_ok=True)
            evidence_dir.mkdir(parents=True, exist_ok=True)

            parquet_path = facts_dir / "callgraph_nodes.parquet"
            _write_empty_callgraph_nodes(parquet_path)

            facts_index = {
                "tables": [
                    {
                        "name": "callgraph_nodes",
                        "paths": ["facts/callgraph_nodes.parquet"],
                    }
                ]
            }
            (facts_dir / "index.json").write_text(json.dumps(facts_index))

            evidence_index = {
                "schema": {"name": "binary_lens_evidence_index", "version": "v1"},
                "bounded": False,
                "entries": [],
            }
            (evidence_dir / "index.json").write_text(json.dumps(evidence_index))

            con = views_run._connect_duckdb(pack_root)
            try:
                for query_path in (QUERY_TEXT, QUERY_QUOTES):
                    columns, rows = views_run._run_sql(con, query_path)
                    self.assertIsInstance(columns, list)
                    self.assertEqual(rows, [])
            finally:
                con.close()


if __name__ == "__main__":
    unittest.main()
