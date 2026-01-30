import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import binary_lens_cli  # noqa: E402


class BinaryLensCliParsingTest(unittest.TestCase):
    def test_parse_args_legacy_consumes_flag_values_before_binary(self):
        binary_path, _out_dir, _out_dir_set, script_args, _scenario_argv = (
            binary_lens_cli._parse_args_legacy(
                ["--from-pack", "/tmp/pack", "--requests", "more.json", "--explain"],
                allow_missing_binary=True,
            )
        )
        self.assertIsNone(binary_path)
        self.assertEqual(
            script_args,
            ["--from-pack", "/tmp/pack", "--requests", "more.json", "--explain"],
        )

    def test_explain_from_pack_does_not_require_binary(self):
        with tempfile.TemporaryDirectory() as tmp:
            pack_root = Path(tmp) / "binary.lens"
            pack_root.mkdir(parents=True)
            (pack_root / "manifest.json").write_text(json.dumps({"schema": {"name": "binary_lens", "version": "v2"}}))

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                binary_lens_cli.main(
                    [
                        "--from-pack",
                        str(pack_root),
                        "--explain",
                    ]
                )
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload.get("schema", {}).get("name"), "binary_lens_export_explain")


if __name__ == "__main__":
    unittest.main()

