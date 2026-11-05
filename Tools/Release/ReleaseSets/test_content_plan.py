"""Cook-plan rejection tests use synthetic assets/listings, never claim device execution."""
import copy
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import android_pipeline
import content_plan
import release_set as sets
import windows_pipeline
from map_inventory_fixtures import listing, source_maps, unrealpak_tool


class ContentPlanTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.plan_path = self.root / "release-content.json"
        self.addCleanup(patch.stopall)
        patch.object(content_plan, "PLAN_PATH", self.plan_path).start()
        self.value = dict(format=1, requiredMaps=list(content_plan.LEGACY_MAPS))
        self.write()

    def write(self, value=None):
        self.plan_path.write_text(json.dumps(self.value if value is None else value), encoding="utf-8")

    def test_default_tracked_plan_preserves_the_baseline_roots(self):
        self.assertEqual(content_plan.snapshot()["plan"], self.value)
        self.assertIs(android_pipeline.COOK_MAPS, content_plan.LEGACY_MAPS)

    def test_new_map_is_digest_bound_and_legacy_evidence_keeps_its_original_roots(self):
        original = content_plan.snapshot()
        self.value["requiredMaps"].append("/Game/SampleGame/Maps/Expansion/Arena02")
        self.write()
        expanded = content_plan.snapshot()
        self.assertNotEqual(original["sha256"], expanded["sha256"])
        self.assertEqual(content_plan.proof_maps({"contentPlan": expanded}), tuple(self.value["requiredMaps"]))
        self.assertEqual(content_plan.proof_maps({}), content_plan.LEGACY_MAPS)
        with self.assertRaisesRegex(ValueError, "changed since"):
            content_plan.proof_maps({"contentPlan": original})

    def test_recorded_plan_hash_and_unknown_fields_cannot_be_relabeled(self):
        record = content_plan.snapshot()
        record["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "digest"):
            content_plan.proof_maps({"contentPlan": record})
        record["approved"] = True
        with self.assertRaises(ValueError):
            content_plan.proof_maps({"contentPlan": record})

    def test_invalid_paths_duplicates_core_removal_and_types_are_rejected(self):
        for name in ("/Game/../External", "/Game/A.umap", "/Game/A+B", "/Game/A:B", "/Plugin/Map", "/Game//Map", "/Game/A Map", "C:/Map"):
            value = copy.deepcopy(self.value); value["requiredMaps"].append(name)
            with self.subTest(name=name), self.assertRaises(ValueError):
                content_plan.validate(value)
        for value in (dict(format=True, requiredMaps=self.value["requiredMaps"]),
                      dict(format=1, requiredMaps=self.value["requiredMaps"][:2]),
                      dict(self.value, allowNewEngine=True),
                      dict(format=1, requiredMaps=self.value["requiredMaps"] + [self.value["requiredMaps"][0].lower()]),
                      dict(format=1, requiredMaps=self.value["requiredMaps"] + ["/Game/Map%d" % i for i in range(254)])):
            with self.subTest(value=str(value)[:140]), self.assertRaises(ValueError):
                content_plan.validate(value)

    def test_duplicate_json_keys_and_oversized_input_are_rejected(self):
        self.plan_path.write_text('{"format":1,"format":1,"requiredMaps":[]}', encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            content_plan.snapshot()
        self.plan_path.write_bytes(b" " * (128 * 1024 + 1))
        with self.assertRaises(ValueError):
            content_plan.snapshot()

    def test_extra_map_missing_from_source_rejects_both_producers_before_build(self):
        project = self.root / "repo/Project/SampleGame"
        source_maps(project)
        engine = self.root / "engine"
        for name in ("Engine/Build/Android/Java/src/com/epicgames/unreal/GameActivity.java.template",
                     "Engine/Build/BatchFiles/Build.bat", "Engine/Build/BatchFiles/RunUAT.bat"):
            path = engine / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(b"synthetic")
        self.value["requiredMaps"].append("/Game/SampleGame/Maps/Expansion/Arena02"); self.write()
        for producer in (windows_pipeline, android_pipeline):
            args = SimpleNamespace(project=project, engine=engine, output=self.root / "never-output")
            with self.subTest(producer=producer.__name__), patch.object(producer, "identity") as identify, patch.object(producer, "execute") as execute:
                with self.assertRaisesRegex(ValueError, "Required Cook map is missing.*Arena02"):
                    producer.build(args)
                identify.assert_not_called(); execute.assert_not_called()
                self.assertFalse(args.output.exists())

    def test_extra_cook_argument_without_an_actual_pak_entry_is_rejected(self):
        engine = self.root / "engine"; unrealpak_tool(engine)
        pak = self.root / "synthetic.pak"; pak.write_bytes(b"not a real PAK")
        maps = content_plan.LEGACY_MAPS + ("/Game/Expansion/Arena02",)
        with self.assertRaisesRegex(ValueError, "Required maps missing.*Arena02"):
            windows_pipeline.map_inventory(engine, [pak], self.root, listing, maps=maps)

    def test_expanded_maps_are_verified_across_all_paks_and_cannot_shrink_the_inventory(self):
        engine = self.root / "engine"; unrealpak_tool(engine)
        pak = self.root / "synthetic.pak"; pak.write_bytes(b"not a real PAK")
        maps = content_plan.LEGACY_MAPS + ("/Game/Expansion/Arena02",)
        def run(arguments, log):
            return listing(arguments, log, maps)
        value = windows_pipeline.map_inventory(engine, [pak], self.root, run, maps=maps)
        self.assertEqual(value["requiredMaps"], list(maps))
        self.assertEqual(len(value["paks"][0]["maps"]), 4)
        with self.assertRaises(ValueError):
            windows_pipeline.validate_map_inventory(value, engine, [pak])
        value["requiredMaps"] = list(content_plan.LEGACY_MAPS)
        with self.assertRaises(ValueError):
            windows_pipeline.validate_map_inventory(value, engine, [pak], maps)


if __name__ == "__main__":
    unittest.main()
