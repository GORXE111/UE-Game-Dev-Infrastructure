import hashlib
from importlib.util import find_spec
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

    def write_workbook(self, sheets):
        from openpyxl import Workbook

        workbook = Workbook()
        workbook.remove(workbook.active)
        try:
            for title, rows in sheets.items():
                sheet = workbook.create_sheet(title)
                for row in rows:
                    sheet.append(row)
                sheet["H2"].number_format = "0.00"
            workbook.save(self.source / "Items.xlsx")
        finally:
            workbook.close()

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

    @unittest.skipUnless(find_spec("openpyxl") and find_spec("defusedxml"), "optional XLSX dependencies unavailable")
    def test_xlsx_and_csv_produce_identical_output(self):
        csv_output = self.root / "csv"
        export_tables(self.source, csv_output)
        (self.source / "Items.csv").unlink()
        rows = [
            ["Name", "Price", "Title", "Enabled", "Weight"],
            ["Zed", 3, None, False, 0.5],
            ["Apple", 2.0, "苹果", True, 0.001],
        ]
        for index, sheets in enumerate(({"Sheet1": rows}, {"Notes": [["Not a config table"]], "Items": rows})):
            with self.subTest(sheets=list(sheets)):
                self.write_workbook(sheets)
                workbook = self.source / "Items.xlsx"
                original = workbook.read_bytes()
                output = self.root / f"xlsx-{index}"
                manifest = export_tables(self.source, output)
                for filename in (*manifest["files"], "manifest.json"):
                    self.assertEqual((csv_output / filename).read_bytes(), (output / filename).read_bytes())
                self.assertEqual(workbook.read_bytes(), original)

    @unittest.skipUnless(find_spec("openpyxl") and find_spec("defusedxml"), "optional XLSX dependencies unavailable")
    def test_xlsx_rejects_bad_inputs_before_output(self):
        (self.source / "Items.csv").unlink()
        header = ["Name", "Price", "Title", "Enabled", "Weight"]
        valid_row = ["Apple", 2, "苹果", True, 0.001]
        output = self.root / "output"
        cases = [
            ({"Notes": [header, valid_row], "Other": [header, valid_row]}, "worksheet named 'Items'"),
            ({"Items": [header, ["Apple", "=1+1", "苹果", True, 0.001]]}, "Items:B2: replace formulas"),
            ({"Items": [header, ["Apple", "#DIV/0!", "苹果", True, 0.001]]}, "resolve spreadsheet error"),
            ({"Items": [header, ["Apple", 2.5, "苹果", True, 0.001]]}, "Price.*expected int"),
            ({"Items": [header, ["Apple", True, "苹果", True, 0.001]]}, "Price.*expected int"),
            ({"Items": [header, ["Apple", 2, "苹果", 1, 0.001]]}, "Enabled.*expected bool"),
            ({"Items": [header, ["Apple", 2, 1, True, 0.001]]}, "Title.*expected string"),
            ({"Items": [header, [*valid_row, "unexpected"]]}, "expected 5 columns"),
            ({"Items": [header, valid_row, ["apple", 4, "重复", True, 0.1]]}, "duplicate row Name"),
        ]
        for sheets, message in cases:
            with self.subTest(message=message):
                self.write_workbook(sheets)
                with self.assertRaisesRegex(ValueError, message):
                    export_tables(self.source, output)
                self.assertFalse(output.exists())
        (self.source / "Items.xlsx").write_bytes(b"not an XLSX file")
        with self.assertRaisesRegex(ValueError, "could not read XLSX workbook"):
            export_tables(self.source, output)
        self.assertFalse(output.exists())

    def test_rejects_ambiguous_source_without_opening_workbook(self):
        (self.source / "Items.xlsx").write_bytes(b"not an XLSX file")
        with self.assertRaisesRegex(ValueError, "provide exactly one of Items.csv or Items.xlsx"):
            export_tables(self.source)


if __name__ == "__main__":
    unittest.main()
