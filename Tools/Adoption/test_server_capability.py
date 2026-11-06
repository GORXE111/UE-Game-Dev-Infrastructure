import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest


SCRIPT = Path(__file__).with_name("server_capability.py")
ENTRY = ('(PlatformName="Win64", Configuration="Development", PlatformType="Server", Architecture="x64", '
         'RequiredFile="Engine\\Binaries\\Win64\\UnrealServer.target", ProjectType="Any", bCanBeDisplayed=False)')


class ServerCapabilityTests(unittest.TestCase):
    def setUp(self):
        scratch = TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.root = Path(scratch.name) / "UE build 示例"
        self.write("Engine/Build/BatchFiles/Build.bat")
        self.write("Engine/Binaries/DotNET/UnrealBuildTool/UnrealBuildTool.dll")

    def write(self, path, content="fixture"):
        file = self.root / path
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(content, encoding="utf-8")

    def write_platform(self, lines):
        self.write("Engine/Build/InstalledBuild.txt", "")
        self.write("Engine/Config/BaseEngine.ini", "\n".join(lines))

    def write_receipt(self, **overrides):
        data = {"TargetName": "UnrealServer", "TargetType": "Server", "Platform": "Win64",
                "Configuration": "Development", "Architecture": "x64",
                "Launch": "$(EngineDir)/Binaries/Win64/UnrealServer.exe"}
        data.update(overrides)
        self.write("Engine/Binaries/Win64/UnrealServer.target", json.dumps(data))

    def invoke(self, expected_exit):
        result = subprocess.run([sys.executable, "-X", "utf8", "-B", str(SCRIPT), "--engine", str(self.root)],
                                capture_output=True, text=True, encoding="utf-8", check=False)
        self.assertEqual(result.returncode, expected_exit, result.stderr + result.stdout)
        return json.loads(result.stdout)

    def test_source_is_ready_to_plan_without_claiming_build(self):
        self.write("Engine/Source/UnrealServer.Target.cs")
        result = self.invoke(0)
        self.assertEqual(result["status"], "source-ready-to-plan")
        self.assertFalse(result["precompiledServer"])
        self.assertIsNone(result["serverReceipt"])
        self.write_receipt()
        self.write("Engine/Binaries/Win64/UnrealServer.exe")
        result = self.invoke(0)
        self.assertEqual(result["status"], "source-ready-to-plan")
        self.assertTrue(result["precompiledServer"])

    def test_installed_server_requires_entry_receipt_and_launch_executable(self):
        self.write_platform(["[InstalledPlatforms]", "+InstalledPlatformConfigurations=" + ENTRY])
        self.assertTrue(self.invoke(1)["installedPlatformEntry"])
        self.write_receipt()
        self.assertIn("launch executable is missing", self.invoke(1)["error"])
        self.write("Engine/Binaries/Win64/UnrealServer.exe")
        result = self.invoke(0)
        self.assertEqual(result["status"], "installed-ready")
        self.assertTrue(result["precompiledServer"])
        self.assertEqual(result["serverReceipt"], "Engine/Binaries/Win64/UnrealServer.target")

    def test_ignores_inactive_entries_and_honors_ini_array_changes(self):
        add = "+InstalledPlatformConfigurations=" + ENTRY
        game = "InstalledPlatformConfigurations=" + ENTRY.replace('PlatformType="Server"', 'PlatformType="Game"')
        for lines in (["[Other]", add], ["[InstalledPlatforms]", ";" + add],
                      ["[InstalledPlatforms]", add, "!InstalledPlatformConfigurations"],
                      ["[InstalledPlatforms]", add, "-InstalledPlatformConfigurations=" + ENTRY.lower()],
                      ["[InstalledPlatforms]", add, game],
                      ["[InstalledPlatforms]", add.replace('Architecture="x64"', 'Architecture="arm64"')]):
            with self.subTest(lines=lines):
                self.write_platform(lines)
                self.assertFalse(self.invoke(1)["installedPlatformEntry"])

    def test_blocks_receipt_for_wrong_target_or_with_external_paths(self):
        self.write_platform(["[InstalledPlatforms]", "+InstalledPlatformConfigurations=" + ENTRY])
        self.write_receipt(TargetType="Game")
        self.assertIn("does not identify UnrealServer", self.invoke(1)["error"])
        self.write_receipt(Launch="$(EngineDir)/../UnrealServer.exe")
        self.assertIn("Unexpected dedicated-server path", self.invoke(1)["error"])
        self.write_platform(["[InstalledPlatforms]", "+InstalledPlatformConfigurations=" +
                             ENTRY.replace('Engine\\Binaries\\Win64\\UnrealServer.target', '../UnrealServer.target')])
        self.assertIn("Unexpected dedicated-server path", self.invoke(1)["error"])

    def test_blocks_a_source_tree_without_server_rules(self):
        result = self.invoke(1)
        self.assertEqual(result["engineKind"], "source")
        self.assertIn("server target rules are missing", result["error"])


if __name__ == "__main__":
    unittest.main()
