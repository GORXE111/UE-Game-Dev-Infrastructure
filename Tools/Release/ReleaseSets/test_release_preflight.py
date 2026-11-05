"""Conservative planning gates, not synthetic claims of UE or phone qualification."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import compatibility
import content_plan
import release_preflight
import release_set as sets
from map_inventory_fixtures import source_maps


class PreflightTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.project = Path(temporary.name)
        source_maps(self.project)
        self.write("SampleGame.uproject", "baseline")
        self.write("Source/Game/Enemy.h", "baseline header")
        self.write("Content/Enemy.uasset", "baseline asset")
        self.base = compatibility.freeze(self.project, "engine")
        value = dict(format=1, requiredMaps=list(content_plan.LEGACY_MAPS))
        self.plan = dict(plan=value, sha256=hashlib.sha256(sets.canonical(value)).hexdigest())

    def write(self, name, text):
        path = self.project / name; path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def assess(self, engine="engine", save=None):
        return release_preflight.assess(self.base, self.project, engine,
                                        save or compatibility.CURRENT_SAVE_POLICY, self.plan)

    def test_unchanged_source_still_does_not_approve_a_release(self):
        value = self.assess()
        self.assertEqual(value["decision"], "no-project-input-changes")
        self.assertFalse(value["releaseReady"])
        self.assertFalse(value["productionQualified"])
        self.assertFalse(value["deviceRuntimeValidated"])
        self.assertFalse(value["publicChannelsChanged"])

    def test_new_enemy_class_and_asset_are_allowed_only_for_review(self):
        self.write("Source/Game/NewEnemy.cpp", "new gameplay implementation")
        self.write("Source/Game/NewEnemy.h", "new reflection layout")
        self.write("Content/NewEnemy.uasset", "new enemy blueprint")
        value = self.assess()
        self.assertFalse(value["requiresNewBase"])
        self.assertEqual(value["decision"], "review-and-runtime-evidence-required")
        self.assertIn("reflection-blueprint-and-serialized-layout-review", value["requiredReviews"])
        self.assertIn("native-performance-impact-review", value["requiredReviews"])

    def test_same_namespace_cannot_exempt_new_module_manifest_config_or_engine(self):
        for name in ("Source/Game/Game.Build.cs", "Config/DefaultInput.ini", "Build/Android/AndroidManifest.xml"):
            with self.subTest(name=name):
                self.write(name, "same namespace but different frozen shell")
                self.assertTrue(self.assess()["requiresNewBase"])
                (self.project / name).unlink()
        self.assertEqual(self.assess("other-engine")["decision"], "new-baseline-required")

    def test_asset_deletion_requires_redirect_and_save_reference_review(self):
        (self.project / "Content/Enemy.uasset").unlink()
        self.assertIn("asset-redirects-and-persistent-reference-review", self.assess()["requiredReviews"])

    def test_new_unplanned_map_is_visible_without_claiming_it_will_ship(self):
        self.write("Content/Expansion/NewMap.umap", "synthetic map")
        value = self.assess()
        self.assertEqual(value["unplannedChangedMaps"], ["Content/Expansion/NewMap.umap"])
        self.assertIn("changed-map-shipping-intent-review", value["requiredReviews"])

    def test_planned_new_map_requires_explicit_runtime_load_check(self):
        self.write("Content/Expansion/NewMap.umap", "synthetic map")
        self.plan["plan"]["requiredMaps"].append("/Game/Expansion/NewMap")
        self.plan["sha256"] = hashlib.sha256(sets.canonical(self.plan["plan"])).hexdigest()
        value = self.assess()
        self.assertFalse(value["missingSourceMaps"])
        self.assertFalse(value["unplannedChangedMaps"])
        self.assertIn("map-load:/Game/Expansion/NewMap", value["requiredRuntimeChecks"])
        (self.project / "Content/Expansion/NewMap.umap").unlink()
        self.assertEqual(self.assess()["decision"], "blocked-missing-cook-roots")

    def test_unreadable_schema_is_not_approved_by_source_classification(self):
        value = self.assess(save=dict(schema=9, readable=[9], migrations=[]))
        self.assertTrue(value["requiresNewBase"])

    def test_unsupported_lua_identity_blocks_before_build_without_claiming_a_new_base_is_needed(self):
        self.write("Content/Lua/game/release_status.lua", 'local version = "1.0.7-dev.1"\n')
        value = self.assess()
        self.assertEqual(value["decision"], "blocked-invalid-lua-identity")
        self.assertTrue(value["identityErrors"])
        self.assertFalse(value["requiresNewBase"])

    def test_real_cli_records_dirty_planning_and_refuses_blocked_and_existing_outputs(self):
        repo = self.project / "cli-repo"
        project = repo / "Project/SampleGame"
        source_maps(project, content_plan.snapshot()["plan"]["requiredMaps"])
        (project / "SampleGame.uproject").write_text("synthetic fixture")
        subprocess.run(["git", "init", "-q", str(repo)], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(repo), "add", "."], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(repo), "-c", "user.name=Release fixture", "-c", "user.email=fixture@localhost",
                        "commit", "-qm", "fixture"], check=True, capture_output=True)
        engine = self.project / "cli-engine"
        modules = engine / "Engine/Binaries/Win64/UnrealEditor.modules"
        modules.parent.mkdir(parents=True); modules.write_text(json.dumps(dict(BuildId="engine")))
        base = compatibility.freeze(project, "engine")
        frozen = self.project / "cli-freeze.json"; frozen.write_bytes(sets.canonical(base))
        manifest = self.project / "cli-manifest.json"
        manifest.write_bytes(sets.canonical(dict(kind="samplegame-release-set", projectId="SampleGame", platform="Windows",
                                                baseReleaseId=420, releaseId=420, buildId="a" * 64,
                                                engineBuildId="engine", shellCompatibilityId=base["shellCompatibilityId"],
                                                save=compatibility.CURRENT_SAVE_POLICY)))
        command = [sys.executable, "-B", str(Path(release_preflight.__file__)), "--project", str(project),
                   "--engine", str(engine), "--shell-freeze", str(frozen), "--base-manifest", str(manifest)]
        config = project / "Config/DefaultInput.ini"; config.parent.mkdir(); config.write_text("new install configuration")
        output = self.project / "cli-evidence"
        result = subprocess.run(command + ["--output", str(output)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2, result.stderr)
        value = sets.parse((output / "report.json").read_bytes())
        self.assertFalse(value["workingTreeClean"])
        self.assertFalse(value["releaseReady"])
        self.assertEqual(value["decision"], "new-baseline-required")
        before = (output / "report.json").read_bytes()
        retry = subprocess.run(command + ["--output", str(output)], capture_output=True, text=True)
        self.assertNotEqual(retry.returncode, 0)
        self.assertEqual(before, (output / "report.json").read_bytes())
        config.unlink()
        success = subprocess.run(command + ["--output", str(self.project / "cli-clean-evidence")], capture_output=True, text=True)
        self.assertEqual(success.returncode, 0, success.stderr)


if __name__ == "__main__":
    unittest.main()
