import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from export_settings import (  # noqa: E402
    CONFIG_SCHEMA,
    REQUESTS_SCHEMA,
    build_export_config_digest,
    build_export_config_record,
    resolve_settings,
)


class ExportSettingsResolutionTest(unittest.TestCase):
    def test_resolution_precedence_and_dependencies(self):
        config = {
            "schema": dict(CONFIG_SCHEMA),
            "artifacts": {"strings": False, "call_args": False},
            "budgets": {"max_full_functions": 10},
            "advanced": {"analysis_profile": "minimal"},
        }
        requests = {
            "schema": dict(REQUESTS_SCHEMA),
            "evidence": {"decomp": {"include_function_ids": ["0x2", "0x1"]}},
            "call_args": {"targets": {"symbol_names": ["getopt"]}, "max_callsites": 5},
        }
        cli_overrides = {
            "budgets": {"max_full_functions": 20},
            "evidence": {"decomp": {"include_function_ids": ["0x3"]}},
            "artifacts": {"callgraph": False},
        }

        settings = resolve_settings(
            config=config,
            requests=requests,
            cli_overrides=cli_overrides,
        )

        self.assertEqual(settings.requested["budgets"]["max_full_functions"], 20)
        self.assertFalse(settings.requested["artifacts"]["strings"])
        self.assertFalse(settings.requested["artifacts"]["callgraph"])
        self.assertEqual(
            settings.requested["evidence"]["decomp"]["include_function_ids"],
            ["0x3"],
        )

        self.assertTrue(settings.resolved["artifacts"]["call_args"])
        self.assertTrue(settings.resolved["artifacts"]["callgraph"])
        self.assertIn("getopt", settings.resolved["call_args"]["targets"]["symbol_names"])
        implied_settings = {entry["setting"] for entry in settings.implied}
        self.assertIn("artifacts.call_args", implied_settings)
        self.assertIn("artifacts.callgraph", implied_settings)


class ExportSettingsDigestTest(unittest.TestCase):
    def test_digest_is_stable_for_ordering(self):
        resolved_a = {
            "artifacts": {"strings": True, "callgraph": True, "call_args": True, "evidence_decomp": True},
            "budgets": {
                "max_full_functions": 50,
                "max_strings": 0,
                "max_call_edges": 0,
                "max_decomp_lines": 200,
            },
            "timeouts": {"decompile_seconds": 30},
            "analysis_profile": "full",
            "profile": False,
            "evidence": {"decomp": {"include_name_regex": "", "include_function_ids": ["0x2", "0x1"]}},
            "call_args": {"targets": {"function_ids": ["0x9", "0x8"], "symbol_names": []}, "max_callsites": None},
        }
        resolved_b = {
            "analysis_profile": "full",
            "profile": False,
            "timeouts": {"decompile_seconds": 30},
            "budgets": {
                "max_call_edges": 0,
                "max_strings": 0,
                "max_full_functions": 50,
                "max_decomp_lines": 200,
            },
            "artifacts": {"call_args": True, "strings": True, "callgraph": True, "evidence_decomp": True},
            "evidence": {"decomp": {"include_function_ids": ["0x1", "0x2"], "include_name_regex": ""}},
            "call_args": {"targets": {"function_ids": ["0x8", "0x9"], "symbol_names": []}, "max_callsites": None},
        }

        digest_a = build_export_config_digest(
            resolved_a,
            binary_hashes={"sha256": "deadbeef"},
            ghidra_version="10.0",
            tool_info={"name": "binary_lens", "version": "0.1.0"},
        )
        digest_b = build_export_config_digest(
            resolved_b,
            binary_hashes={"sha256": "deadbeef"},
            ghidra_version="10.0",
            tool_info={"name": "binary_lens", "version": "0.1.0"},
        )
        self.assertEqual(digest_a, digest_b)


class ExportConfigRecordTest(unittest.TestCase):
    def test_digest_is_top_level(self):
        record = build_export_config_record(
            requested={"artifacts": {"strings": False}},
            resolved={"artifacts": {"strings": False}},
            binary_hashes={"sha256": "deadbeef"},
            ghidra_version="10.0",
            tool_info={"name": "binary_lens", "version": "0.1.0"},
        )
        self.assertIn("export_config", record)
        self.assertIn("export_config_digest", record)
        self.assertNotIn("export_config_digest", record["export_config"])
        self.assertTrue(str(record["export_config_digest"]).startswith("sha256:"))


if __name__ == "__main__":
    unittest.main()
