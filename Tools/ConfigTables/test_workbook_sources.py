from importlib.util import find_spec
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from config_tables import export_tables


class WorkbookSourcesTests(unittest.TestCase):
    def setUp(self):
        scratch = TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.root = Path(scratch.name)
        self.source = self.root / "tables"
        self.source.mkdir()
        self.output = self.root / "generated"

    def write_schema(self, sources):
        tables = [
            {"name": name, "fields": [{"name": "Value", "type": "int"}], "source": options}
            for name, options in sources.items()
        ]
        (self.source / "schema.json").write_text(json.dumps({"version": 2, "tables": tables}), encoding="utf-8")

    def write_workbook(self, sheets):
        from openpyxl import Workbook

        workbook = Workbook()
        workbook.remove(workbook.active)
        path = self.source / "input" / "平衡.xlsx"
        path.parent.mkdir(exist_ok=True)
        try:
            for title, rows in sheets.items():
                sheet = workbook.create_sheet(title)
                for row in rows:
                    sheet.append(row)
            workbook.save(path)
        finally:
            workbook.close()

    def test_explicit_csv_path_and_physical_header_row(self):
        self.write_schema({"Items": {"file": "表格/手动导出.CSV", "headerRow": 3}})
        path = self.source / "表格" / "手动导出.CSV"
        path.parent.mkdir()
        path.write_text('说明行\n"这里无需是有效的 CSV\nName,Value\nOne,wrong\n', encoding="utf-8-sig")
        with self.assertRaisesRegex(ValueError, r"表格/手动导出\.CSV:4 \(Value\): expected int"):
            export_tables(self.source, self.output)
        self.assertFalse(self.output.exists())
        path.write_text("说明行\n\nName,Value\nOne,42\n", encoding="utf-8-sig")
        export_tables(self.source, self.output)
        self.assertEqual(json.loads((self.output / "Items.json").read_bytes()), [{"Name": "One", "Value": 42}])

    def test_rejects_invalid_source_options_and_paths(self):
        cases = [
            ({}, "needs file"),
            ({"file": "../Items.csv"}, "relative CSV or XLSX path"),
            ({"file": "C:\\Items.csv"}, "relative CSV or XLSX path"),
            ({"file": "\\\\host\\share\\Items.csv"}, "relative CSV or XLSX path"),
            ({"file": "Items.csv:alternate"}, "relative CSV or XLSX path"),
            ({"file": "NUL.csv"}, "relative CSV or XLSX path"),
            ({"file": "input./Items.csv"}, "relative CSV or XLSX path"),
            ({"file": "Items.xls"}, "must name a CSV or XLSX file"),
            ({"file": "Items.csv", "sheet": "Items"}, "nonempty XLSX worksheet"),
            ({"file": "Items.xlsx", "sheet": None}, "nonempty XLSX worksheet"),
            ({"file": "Items.xlsx", "headerRow": True}, "headerRow must be an integer"),
            ({"file": "Items.xlsx", "headerRow": 0}, "headerRow must be an integer"),
        ]
        for options, message in cases:
            with self.subTest(options=options):
                self.write_schema({"Items": options})
                with self.assertRaisesRegex(ValueError, message):
                    export_tables(self.source, self.output)
                self.assertFalse(self.output.exists())

    def test_linked_parent_cannot_escape_source_directory(self):
        outside = self.root / "outside"
        outside.mkdir()
        (outside / "Items.csv").write_text("Name,Value\nOne,1\n", encoding="utf-8")
        try:
            (self.source / "linked").symlink_to(outside, target_is_directory=True)
        except OSError as error:
            self.skipTest(f"directory link creation unavailable: {error}")
        self.write_schema({"Items": {"file": "linked/Items.csv"}})
        with self.assertRaisesRegex(ValueError, "without links"):
            export_tables(self.source, self.output)
        self.assertFalse(self.output.exists())

    @unittest.skipUnless(find_spec("openpyxl") and find_spec("defusedxml"), "optional XLSX dependencies unavailable")
    def test_one_workbook_routes_distinct_sheets_with_notes(self):
        self.write_schema({
            "Enemies": {"file": "input/平衡.xlsx", "sheet": "敌人参数", "headerRow": 3},
            "Waves": {"file": "input\\平衡.xlsx", "sheet": "Wave Data"},
        })
        self.write_workbook({
            "敌人参数": [["值由设计师维护", "=1+2"], ["第二条说明"], ["Name", "Value"], ["Goblin", 9]],
            "Wave Data": [["Name", "Value"], ["Wave2", 5], ["Wave1", 3]],
        })
        export_tables(self.source, self.output)
        self.assertEqual(json.loads((self.output / "Enemies.json").read_bytes()), [{"Name": "Goblin", "Value": 9}])
        self.assertEqual(json.loads((self.output / "Waves.json").read_bytes()), [
            {"Name": "Wave1", "Value": 3}, {"Name": "Wave2", "Value": 5},
        ])

    @unittest.skipUnless(find_spec("openpyxl") and find_spec("defusedxml"), "optional XLSX dependencies unavailable")
    def test_exact_sheet_conflicts_and_workbook_error_location(self):
        self.write_workbook({"Shared": [["Name", "Value"], ["One", 1]]})
        self.write_schema({"Items": {"file": "input/平衡.xlsx", "sheet": "shared"}})
        with self.assertRaisesRegex(ValueError, "worksheet 'shared' does not exist"):
            export_tables(self.source, self.output)

        self.write_schema({
            "Items": {"file": "input/平衡.xlsx", "sheet": "Shared"},
            "Waves": {"file": "input\\平衡.xlsx"},
        })
        with self.assertRaisesRegex(ValueError, "same source is already assigned"):
            export_tables(self.source, self.output)

        self.write_schema({"Items": {"file": "input/平衡.xlsx", "sheet": "Shared", "headerRow": 3}})
        self.write_workbook({"Shared": [["notes"], [], ["Name", "Value"], ["One", "=1+2"]]})
        with self.assertRaisesRegex(ValueError, r"input/平衡\.xlsx!Shared:B4: replace formulas"):
            export_tables(self.source, self.output)
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
