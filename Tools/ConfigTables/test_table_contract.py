import copy
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from config_tables import export_tables
from table_contract import FieldPolicy, build_contract, parse_field_policy


class TableContractTests(unittest.TestCase):
    def setUp(self):
        self.fields = {"Enemies": {"Health": "int", "SpawnWeight": "int"},
                       "Waves": {"Enemy": "string", "Count": "int"}}
        self.policies = {"Enemies": {"SpawnWeight": FieldPolicy("server")},
                         "Waves": {"Enemy": FieldPolicy(ref="Enemies")}}
        self.rows = {"Enemies": [{"Name": "Tank", "Health": 20, "SpawnWeight": 1},
                                 {"Name": "Scout", "Health": 10, "SpawnWeight": 5}],
                     "Waves": [{"Name": "Intro", "Enemy": "Scout", "Count": 2}]}
        self.locations = {"Waves": {"Intro": "Campaign.xlsx!Waves:6"}}

    def contract(self, rows=None, version=1):
        return build_contract(version, self.fields, self.policies, rows or self.rows, self.locations)

    def test_policy_requires_valid_audience_and_string_reference(self):
        self.assertIsNone(parse_field_policy({"name": "Count", "type": "int"}, "schema.json: Waves.Count"))
        self.assertEqual(parse_field_policy({"name": "Enemy", "type": "string", "ref": "Enemies"}, "schema.json"),
                         FieldPolicy(ref="Enemies"))
        for declaration in ({"type": "int", "ref": "Enemies"}, {"type": "string", "ref": None},
                            {"type": "string", "ref": "../Enemies"}, {"type": "int", "audience": "both"}):
            with self.subTest(declaration=declaration), self.assertRaisesRegex(ValueError, r"schema\.json"):
                parse_field_policy(declaration, "schema.json")

    def test_server_values_are_private_and_have_separate_source_identity(self):
        original = self.contract()
        self.assertNotIn("SpawnWeight", original.client["Enemies"][0])
        self.assertEqual(original.server["Enemies"][0]["SpawnWeight"], 5)
        changed = copy.deepcopy(self.rows)
        changed["Enemies"][0]["SpawnWeight"] = 2
        private = self.contract(changed, version=2)
        self.assertEqual(original.compatibility_sha256, private.compatibility_sha256)
        self.assertNotEqual(original.source_sha256, private.source_sha256)
        changed["Enemies"][0]["Health"] = 30
        public = self.contract(changed)
        self.assertNotEqual(private.compatibility_sha256, public.compatibility_sha256)

    def test_rows_are_sorted_deterministically_without_mutating_input(self):
        original = self.contract()
        changed = copy.deepcopy(self.rows)
        changed["Enemies"].reverse()
        self.assertEqual(original, self.contract(changed))
        self.assertEqual(self.rows["Enemies"][0]["Name"], "Tank")

    def test_missing_reference_reports_the_source_row_and_field(self):
        self.rows["Waves"][0]["Enemy"] = "scout"
        with self.assertRaisesRegex(ValueError, r"Campaign\.xlsx!Waves:6 \(Enemy\): .*Enemies\.Name"):
            self.contract()
        self.policies["Waves"]["Enemy"] = FieldPolicy(ref="Unknown")
        with self.assertRaisesRegex(ValueError, r"Waves\.Enemy references unknown table 'Unknown'"):
            self.contract()

    def test_shared_floats_match_unreal_precision_and_reject_underflow(self):
        self.fields["Waves"]["Delay"] = "float"
        row = self.rows["Waves"][0]
        row["Delay"] = 0.1
        contract = self.contract()
        self.assertEqual(contract.client["Waves"][0]["Delay"], 0.10000000149011612)
        self.assertEqual(contract.client["Waves"], contract.server["Waves"])
        self.assertEqual(row["Delay"], 0.1)
        row["Delay"] = 1e-50
        with self.assertRaisesRegex(ValueError, r"Campaign\.xlsx!Waves:6 \(Delay\).*underflows"):
            self.contract()

    def test_export_publishes_split_bundles_and_blocks_bad_foreign_key(self):
        with TemporaryDirectory() as scratch:
            root = Path(scratch)
            source = root / 'source'
            source.mkdir()
            schema = {"version": 1, "tables": [
                {"name": "Enemies", "fields": [{"name": "Health", "type": "int"},
                                                 {"name": "Budget", "type": "int", "audience": "server"}]},
                {"name": "Waves", "fields": [{"name": "EnemyId", "type": "string", "ref": "Enemies"}]},
            ]}
            (source / 'schema.json').write_text(json.dumps(schema), encoding='utf-8')
            (source / 'Enemies.csv').write_text('Name,Health,Budget\nScout,35,4\n', encoding='utf-8')
            waves = source / 'Waves.csv'
            waves.write_text('Name,EnemyId\nOpening,Scout\n', encoding='utf-8')
            output = root / 'export'
            report = export_tables(source, output)
            client = json.loads((output / 'client/Enemies.json').read_bytes())[0]
            server = json.loads((output / 'server/Enemies.json').read_bytes())[0]
            client_manifest = json.loads((output / 'client/manifest.json').read_bytes())
            server_manifest = json.loads((output / 'server/manifest.json').read_bytes())
            self.assertEqual(client, {"Name": "Scout", "Health": 35})
            self.assertEqual(server["Budget"], 4)
            self.assertNotIn('sourceSha256', client_manifest)
            self.assertEqual(report['compatibilitySha256'], client_manifest['compatibilitySha256'])
            self.assertEqual(client_manifest['compatibilitySha256'], server_manifest['compatibilitySha256'])
            self.assertEqual(len(server_manifest['sourceSha256']), 64)

            waves.write_text('Name,EnemyId\nOpening,Missing\n', encoding='utf-8')
            blocked = root / 'blocked'
            with self.assertRaisesRegex(ValueError, r'Waves\.csv:2 \(EnemyId\)'):
                export_tables(source, blocked)
            self.assertFalse(blocked.exists())


if __name__ == "__main__":
    unittest.main()
