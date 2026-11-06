import copy
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

from project_profile import read_profile


class ProjectProfileTests(unittest.TestCase):
    def setUp(self):
        scratch = TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.root = Path(scratch.name).resolve() / "adoption 示例"
        self.root.mkdir()
        self.file = self.root / "profile.json"
        self.project = self.root / "Sample Game" / "SampleGame.uproject"
        self.project.parent.mkdir()
        self.project.write_text("{}", encoding="utf-8")
        self.config = self.root / "表配置"
        self.config.mkdir()
        self.asset_plan = self.root / "assets.json"
        self.asset = "/Game/Config/DT_GameplayTags.DT_GameplayTags"
        self.assets = {"version": 1, "assets": [{"path": self.asset, "class": "/Script/Engine.DataTable"},
                                               {"path": "/Engine/Maps/Entry.Entry", "class": "/Script/Engine.World"}]}
        self.asset_plan.write_text(json.dumps(self.assets), encoding="utf-8")
        self.profile = {
            "version": 1,
            "project": "Sample Game\\SampleGame.uproject",
            "configSource": "表配置",
            "assetPlan": "assets.json",
            "dataTables": [{"table": "GameplayTags", "asset": self.asset,
                            "rowStruct": "/Script/GameplayTags.GameplayTagTableRow"}],
            "build": {"target": "SampleGame", "platform": "Win64", "configuration": "Development",
                      "maps": ["/Game/Maps/Entry", "/Engine/Maps/Entry"]},
            "startup": {"map": "/Game/Maps/Entry", "readyMarker": "Ready for test"},
            "serverTarget": "SampleGameServer",
        }

    def write_profile(self, profile):
        self.file.write_text(json.dumps(profile, ensure_ascii=False), encoding="utf-8-sig")

    def test_normalizes_paths_and_preserves_declared_build(self):
        self.write_profile(self.profile)
        result = read_profile(self.file)
        self.assertEqual(result, {**self.profile, "project": str(self.project),
                                  "configSource": str(self.config), "assetPlan": str(self.asset_plan),
                                  "build": {**self.profile["build"], "editorTarget": "SampleGameEditor"}})
        self.profile.pop("serverTarget")
        self.profile["configSource"] = "."
        self.profile["build"]["editorTarget"] = "AdoptionEditor"
        self.write_profile(self.profile)
        result = read_profile(self.file)
        self.assertNotIn("serverTarget", result)
        self.assertEqual(result["configSource"], str(self.root))
        self.assertEqual(result["build"]["editorTarget"], "AdoptionEditor")

    def test_rejects_unsafe_and_missing_inputs(self):
        cases = [
            ("project", "../Escape.uproject", "relative"),
            ("project", "C:Escape.uproject", "relative"),
            ("project", r"\\host\Share\Escape.uproject", "relative"),
            ("project", "Sample Game/SampleGame.uproject:stream", "relative"),
            ("project", "assets.json", "uproject file"),
            ("assetPlan", str(self.asset_plan), "relative"),
            ("assetPlan", "missing.json", "existing path"),
            ("configSource", "assets.json", "directory"),
        ]
        for key, value, error in cases:
            with self.subTest(key=key, value=value):
                self.write_profile({**self.profile, key: value})
                with self.assertRaisesRegex(ValueError, error):
                    read_profile(self.file)

    def test_rejects_inconsistent_build_and_startup(self):
        cases = [
            ("build", "target", "SampleGame -cook", "target name"),
            ("build", "editorTarget", "SampleGame -Editor", "editorTarget name"),
            ("build", "platform", "Android", "Win64 Development"),
            ("build", "configuration", "Shipping", "Win64 Development"),
            ("build", "maps", ["/Game/Maps/Entry+Other"], "long package paths"),
            ("build", "maps", ["/Game/Maps/Entry", "/game/maps/entry"], "repeated map"),
            ("startup", "map", "/Game/Maps/Missing", "build.maps entry"),
            ("startup", "readyMarker", "READY\nOTHER", "single visible ASCII"),
        ]
        for group, field, value, error in cases:
            with self.subTest(field=field, value=value):
                profile = copy.deepcopy(self.profile)
                profile[group][field] = value
                self.write_profile(profile)
                with self.assertRaisesRegex(ValueError, error):
                    read_profile(self.file)

    def test_rejects_unknown_duplicate_and_invalid_version_fields(self):
        self.write_profile({**self.profile, "password": "unused"})
        with self.assertRaisesRegex(ValueError, "Profile needs"):
            read_profile(self.file)
        self.write_profile({**self.profile, "version": True})
        with self.assertRaisesRegex(ValueError, "version 1"):
            read_profile(self.file)
        self.file.write_text('{"version":1,"version":2}', encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "Repeated JSON key"):
            read_profile(self.file)

    def test_data_tables_must_match_declared_assets(self):
        profile = copy.deepcopy(self.profile)
        profile["dataTables"].append({**profile["dataTables"][0], "table": "gameplaytags"})
        self.write_profile(profile)
        with self.assertRaisesRegex(ValueError, "repeated table or asset"):
            read_profile(self.file)

        for field, value, error in [
            ("table", "Bad table", "table name"),
            ("asset", "/Engine/Config/DT.DT", "/Game object path"),
            ("asset", "/Game/Config/DT.Other", "package leaf"),
            ("rowStruct", "/Game/BP_Row.BP_Row", "/Script/Module.Struct"),
        ]:
            with self.subTest(field=field):
                profile = copy.deepcopy(self.profile)
                profile["dataTables"][0][field] = value
                self.write_profile(profile)
                with self.assertRaisesRegex(ValueError, error):
                    read_profile(self.file)

        self.write_profile(self.profile)
        self.assets["assets"][0]["class"] = "/Script/Engine.World"
        self.asset_plan.write_text(json.dumps(self.assets), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "Declare .* as /Script/Engine.DataTable"):
            read_profile(self.file)
        self.assets["assets"][1]["path"] = "/Plugin/Maps/Entry.Entry"
        self.asset_plan.write_text(json.dumps(self.assets), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "paths in /Game or /Engine"):
            read_profile(self.file)

    def test_cli_reports_success_and_failure_in_stdout(self):
        script = Path(__file__).with_name("project_profile.py")
        command = [sys.executable, "-X", "utf8", "-B", str(script), "--profile", str(self.file)]
        self.write_profile(self.profile)
        result = subprocess.run(command, cwd=self.root, capture_output=True, text=True, encoding="utf-8")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(result.stderr, "")
        self.assertEqual(json.loads(result.stdout)["status"], "validated")
        self.file.write_text("{}", encoding="utf-8")
        result = subprocess.run(command, cwd=self.root, capture_output=True, text=True, encoding="utf-8")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, "")
        self.assertEqual(json.loads(result.stdout)["status"], "blocked")


if __name__ == "__main__":
    unittest.main()
