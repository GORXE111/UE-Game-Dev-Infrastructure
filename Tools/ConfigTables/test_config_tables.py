import hashlib
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

from config_tables import export_tables


class ConfigTablesTests(unittest.TestCase):
    def setUp(self):
        scratch = TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.root = Path(scratch.name)
        self.source = self.root / "source"
        self.source.mkdir()
        self.schema = {
            "version": 2,
            "tables": [
                {"name": "Items", "fields": [
                    {"name": "Price", "type": "int"},
                    {"name": "Title", "type": "string"},
                    {"name": "Enabled", "type": "bool"},
                    {"name": "Weight", "type": "float"},
                ]},
                {"name": "Effects", "fields": [{"name": "Value", "type": "int"}]},
            ],
        }
        self.write_schema()
        self.write_csv("Effects", "Name,Value\nStun,10\n")
        self.write_csv("Items", "Name,Price,Title,Enabled,Weight\nZed,3,,FALSE,.5\nApple,2,苹果,true,1e-3\n")

    def write_schema(self):
        (self.source / "schema.json").write_text(json.dumps(self.schema), encoding="utf-8")

    def write_csv(self, name, content):
        (self.source / f"{name}.csv").write_text(content, encoding="utf-8-sig", newline="")

    def test_deterministic_export_and_manifest(self):
        first = self.root / "first"
        second = self.root / "second"
        manifest = export_tables(self.source, first)
        self.schema["tables"].reverse()
        self.write_schema()
        self.write_csv("Items", "Name,Price,Title,Enabled,Weight\nApple,2,苹果,true,1e-3\nZed,3,,FALSE,.5\n")
        self.assertEqual(manifest, export_tables(self.source, second))
        self.assertEqual(list(manifest["files"]), ["Effects.json", "Items.json"])
        for name, entry in manifest["files"].items():
            data = (first / name).read_bytes()
            self.assertEqual(data, (second / name).read_bytes())
            self.assertEqual(entry["sha256"], hashlib.sha256(data).hexdigest())
            self.assertEqual(entry["size"], len(data))
        self.assertEqual((first / "manifest.json").read_bytes(), (second / "manifest.json").read_bytes())
        self.assertEqual(json.loads((first / "Items.json").read_bytes()), [
            {"Name": "Apple", "Price": 2, "Title": "苹果", "Enabled": True, "Weight": 0.001},
            {"Name": "Zed", "Price": 3, "Title": "", "Enabled": False, "Weight": 0.5},
        ])

    def test_invalid_rows_leave_no_output(self):
        output = self.root / "output"
        cases = [
            ("Wrong,Price,Title,Enabled,Weight\n", "header"),
            ("Name,Price,Title,Enabled,Weight\n", "at least one data row"),
            ("Name,Price,Title,Enabled,Weight\nApple,2,,true\n", "expected 5 columns"),
            ("Name,Price,Title,Enabled,Weight\nApple,,,true,1\n", "Price"),
            ("Name,Price,Title,Enabled,Weight\nApple,2147483648,,true,1\n", "int32"),
            ("Name,Price,Title,Enabled,Weight\nApple,2,,true,1e999\n", "finite float"),
            ("Name,Price,Title,Enabled,Weight\nApple,2,,true,1e39\n", "float32"),
            ("Name,Price,Title,Enabled,Weight\nApple,2,,yes,1\n", "expected bool"),
            ("Name,Price,Title,Enabled,Weight\nNone,2,,true,1\n", "invalid row Name"),
            ("Name,Price,Title,Enabled,Weight\nApple,2,,true,1\napple,3,,false,1\n", "duplicate row"),
        ]
        for csv, message in cases:
            with self.subTest(message=message):
                self.write_csv("Items", csv)
                with self.assertRaisesRegex(ValueError, message):
                    export_tables(self.source, output)
                self.assertFalse(output.exists())
                self.assertFalse(list(self.root.glob(".config-tables-*")))

    def test_reject_unsafe_paths_and_case_collisions(self):
        existing = self.root / "existing"
        existing.mkdir()
        sentinel = existing / "untouched.txt"
        sentinel.write_text("keep", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "new output"):
            export_tables(self.source, existing)
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "keep")
        with self.assertRaisesRegex(ValueError, "outside the source"):
            export_tables(self.source, self.source / "output")

        self.schema["tables"][1]["name"] = "items"
        self.write_schema()
        with self.assertRaisesRegex(ValueError, "duplicate or reserved table"):
            export_tables(self.source)

    def test_cli_check_does_not_write_files(self):
        script = Path(__file__).with_name("config_tables.py")
        result = subprocess.run([sys.executable, "-X", "utf8", "-B", str(script), "--source", str(self.source), "--check"],
                                cwd=self.root, capture_output=True, text=True, encoding="utf-8", check=True)
        report = json.loads(result.stdout)
        self.assertEqual(report["status"], "config-validated")
        self.assertEqual(report["schemaVersion"], 2)
        self.assertEqual(list(self.root.iterdir()), [self.source])


if __name__ == "__main__":
    unittest.main()
