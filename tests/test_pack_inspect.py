import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from pack_inspect import build_capability_report  # noqa: E402


class PackInspectReportTest(unittest.TestCase):
    def test_report_includes_manifest_fields(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            pack_root = Path(tmpdir)
            manifest = {
                "binary_name": "demo",
                "format_version": "v2",
                "export_config_digest": "sha256:deadbeef",
                "bounds": {},
                "coverage_summary": {},
            }
            (pack_root / "manifest.json").write_text(json.dumps(manifest))

            report = build_capability_report(pack_root)
            self.assertEqual(report.get("binary_name"), "demo")
            self.assertEqual(report.get("format_version"), "v2")
            self.assertEqual(report.get("export_config_digest"), "sha256:deadbeef")
            self.assertEqual(report.get("manifest_ref"), "manifest.json")


if __name__ == "__main__":
    unittest.main()
