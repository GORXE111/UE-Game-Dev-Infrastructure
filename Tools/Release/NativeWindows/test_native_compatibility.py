"""Real input inventories: permit implementation edits, reject ABI/data/identity drift."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).parent))
import native_compatibility as compat


class CompatibilityGuardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.project = self.root / "project"
        files = {"SampleGame.uproject": "{}", "Source/Game/Core.h": "struct FCore {};", "Source/Game/Core.cpp": "int Update(){return 1;}",
                 "Source/Game/Game.Build.cs": "public class Game {}", "Config/DefaultEngine.ini": "[/Script/Engine.RendererSettings]\nr.MobileHDR=False",
                 "Content/Lua/game/rules.lua": "return {}", "Content/Maps/Main.umap": "asset-fixture",
                 "Plugins/Plugin/Plugin.uplugin": "{}", "Plugins/Plugin/Source/Game/Loader.java": "class Loader {}",
                 "Plugins/Plugin/Source/Game/Loader_UPL.xml": "<root/>", "Plugins/Plugin/Content/Icon.uasset": "plugin-content"}
        for name, data in files.items():
            target = self.project / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(data)
        self.engine = self.root / "engine"
        modules = self.engine / "Engine/Binaries/Win64/UnrealEditor.modules"
        modules.parent.mkdir(parents=True)
        modules.write_text('{"BuildId":"fixture-engine"}')
        self.record = self.root / "frozen-compat.json"
        frozen = compat.freeze(self.project, self.engine, 123, "test-native", self.record)
        self.install = self.root / "install"
        self.install.mkdir()
        public = "a" * 64
        fields = dict(projectId="SampleGame", channel="test-native", platform="Windows", baseReleaseId=123, engineBuildId="fixture-engine")
        config = dict(fields, format=1, compatibilityId=frozen["compatibilityId"], publicKeyHex=public,
                      nativeFiles=[dict(path="SampleGame/Binaries/Win64/SampleGame.exe", size=1, sha256="b"*64)],
                      manifestUrl="https://example.test/samplegame/test-native/native/manifest.json", contentLauncher="SampleContent.exe", contentConfig="sample-player.json", allowOffline=True)
        self.config = self.install / "native-player.json"
        self.config.write_text(json.dumps(config))
        (self.install / "sample-player.json").write_text(json.dumps(dict(fields, nativeApiVersion=2)))

    def validate(self):
        return compat.validate(self.record, self.project, self.engine, self.config)

    def test_cpp_function_body_changes_are_permitted_but_header_changes_require_new_base(self):
        before = self.validate()
        (self.project / "Source/Game/Core.cpp").write_text("int Update(){return 2;} // native revision")
        self.assertEqual(before["compatibilityId"], self.validate()["compatibilityId"])
        (self.project / "Source/Game/Core.h").write_text("struct FCore { int ChangedLayout; };")
        with self.assertRaisesRegex(ValueError, "Headers"):
            self.validate()

    def test_build_java_upl_config_content_and_plugin_assets_are_guarded(self):
        for name in ("Source/Game/Game.Build.cs", "Plugins/Plugin/Source/Game/Loader.java", "Plugins/Plugin/Source/Game/Loader_UPL.xml",
                     "Config/DefaultEngine.ini", "Content/Lua/game/rules.lua", "Plugins/Plugin/Content/Icon.uasset"):
            with self.subTest(name=name):
                target = self.project / name
                before = target.read_bytes()
                target.write_bytes(before + b"changed")
                with self.assertRaisesRegex(ValueError, "Headers"):
                    self.validate()
                target.write_bytes(before)

    def test_generated_bootstraps_and_build_caches_are_not_self_references(self):
        before = self.validate()
        for name in ("Content/Release/native-bootstrap.json", "Content/Release/update-bootstrap.json", "Intermediate/generated.h", "Source/Game/Binaries/generated.h"):
            target = self.project / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("generated")
        self.assertEqual(before["compatibilityId"], self.validate()["compatibilityId"])

    def test_engine_identity_or_player_api_drift_and_record_overwrite_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "new"):
            compat.freeze(self.project, self.engine, 123, "test-native", self.record)
        modules = self.engine / "Engine/Binaries/Win64/UnrealEditor.modules"
        modules.write_text('{"BuildId":"different-engine"}')
        with self.assertRaisesRegex(ValueError, "identity"):
            self.validate()
        modules.write_text('{"BuildId":"fixture-engine"}')
        content = self.install / "sample-player.json"
        changed = json.loads(content.read_text())
        changed["nativeApiVersion"] = 3
        content.write_text(json.dumps(changed))
        with self.assertRaisesRegex(ValueError, "API"):
            self.validate()

    def test_production_publisher_cli_cannot_omit_guard(self):
        process = subprocess.run([sys.executable, str(Path(__file__).with_name("publish_native_windows.py")),
                                  "--config", str(self.config), "--source-root", str(self.root), "--private-key", str(self.root/"unused.pem"),
                                  "--version", "1", "--output", str(self.root/"never-created")], capture_output=True, text=True, check=False)
        self.assertEqual(process.returncode, 2)
        self.assertIn("--compatibility-record", process.stderr)
        self.assertFalse((self.root/"never-created").exists())


if __name__ == "__main__":
    unittest.main()
