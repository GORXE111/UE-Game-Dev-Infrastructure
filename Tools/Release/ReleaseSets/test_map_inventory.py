"""Required-map release gates with tiny synthetic PAKs and fake execute logs; no Unreal/UE run."""
import copy
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import android_pipeline
import release_set as sets
import windows_pipeline as pipeline
from map_inventory_fixtures import isolate_content_plan, listing, map_proof, source_maps, unrealpak_tool


class RequiredMapInventoryTests(unittest.TestCase):
    def setUp(self):
        isolate_content_plan(self)
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.project = self.root / "repo/Project/SampleGame"
        source_maps(self.project)
        self.engine = self.root / "engine"
        unrealpak_tool(self.engine)
        for relative in ("Engine/Build/Android/Java/src/com/epicgames/unreal/GameActivity.java.template",
                         "Engine/Build/BatchFiles/Build.bat", "Engine/Build/BatchFiles/RunUAT.bat"):
            path = self.engine / relative; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(b"synthetic engine input")
        self.pak = self.root / "first.pak"; self.pak.write_bytes(b"tiny synthetic PAK placeholder")
        self.output = self.root / "evidence"; self.output.mkdir()

    def test_one_shared_tuple_resolves_the_three_actual_source_maps(self):
        self.assertIs(android_pipeline.COOK_MAPS, pipeline.COOK_MAPS)
        self.assertEqual(pipeline.COOK_MAPS, ("/Game/SampleGame/Maps/UI/SettingsPreview", "/Game/LD/level/PrototypeArena", "/Game/Maps/CombatArena"))
        pipeline.check_cook_maps(self.project)

    def test_missing_source_map_rejects_both_platforms_before_hash_editor_native_cook_or_output(self):
        (self.project / "Content/Maps/CombatArena.umap").unlink()
        for producer, candidate in ((pipeline, False), (android_pipeline, False), (android_pipeline, True)):
            args = SimpleNamespace(project=self.project, engine=self.engine, output=self.root / "never-output",
                                   candidate_base=self.root / "never-read.apk" if candidate else None)
            with self.subTest(platform=producer.__name__, candidate=candidate), \
                 patch.object(producer, "identity") as identify, patch.object(producer, "execute") as execute, \
                 patch.object(producer, "fresh_output") as fresh:
                with self.assertRaisesRegex(ValueError, "Required Cook map is missing"):
                    producer.build(args)
                identify.assert_not_called(); execute.assert_not_called(); fresh.assert_not_called()
                self.assertFalse(args.output.exists())

    def test_directory_instead_of_umap_is_rejected_before_any_operation(self):
        target = self.project / "Content/Maps/CombatArena.umap"; target.unlink(); target.mkdir()
        with self.assertRaisesRegex(ValueError, "Required Cook map is missing"):
            pipeline.check_cook_maps(self.project)

    def test_no_pak_or_missing_pak_cannot_produce_an_inventory(self):
        for paks in ([], [self.root / "missing.pak"]):
            with self.subTest(paks=paks), patch.object(pipeline, "execute") as execute:
                with self.assertRaises((ValueError, FileNotFoundError)):
                    pipeline.map_inventory(self.engine, paks, self.output)
                execute.assert_not_called()

    def test_each_real_pak_is_listed_and_required_maps_may_span_the_complete_set(self):
        second = self.root / "second.pak"; second.write_bytes(b"second tiny synthetic PAK")
        calls = []
        def execute(arguments, log):
            calls.append(arguments)
            return listing(arguments, log, pipeline.COOK_MAPS[:2] if Path(arguments[1]) == self.pak else pipeline.COOK_MAPS[2:])
        value = pipeline.map_inventory(self.engine, [second, self.pak], self.output, execute)
        self.assertEqual(len(calls), 2)
        self.assertEqual({item["map"] for pak in value["paks"] for item in pak["maps"]}, set(pipeline.COOK_MAPS))
        for item in value["paks"]:
            self.assertEqual(item["listing"]["exitCode"], 0)
            self.assertEqual(item["listing"]["sha256"], sets.digest(item["listing"]["path"]))
            self.assertEqual(item["sha256"], sets.digest(item["path"]))

    def test_missing_umap_entry_is_rejected_despite_successful_cook_arguments_and_similar_names(self):
        def execute(arguments, log):
            result = listing(arguments, log, pipeline.COOK_MAPS[:2])
            with Path(log).open("a", encoding="utf-8") as stream:
                stream.write('-MapList=' + "+".join(pipeline.COOK_MAPS) + '\nBUILD SUCCESSFUL\n')
                stream.write('LogPakFile: Display: "Other/Content/Maps/CombatArena.umap" offset: 0, size: 8 bytes, sha1: ' + "b" * 40 + ', compression: None.\n')
                stream.write('LogPakFile: Display: "SampleGame/Content/Maps/CombatArena.umap.backup" offset: 0, size: 8 bytes, sha1: ' + "c" * 40 + ', compression: None.\n')
            result["sha256"] = sets.digest(log)
            return result
        with self.assertRaisesRegex(ValueError, "Required maps missing.*CombatArena"):
            pipeline.map_inventory(self.engine, [self.pak], self.output, execute)

    def test_nonzero_unrealpak_exit_is_rejected_even_with_all_three_entries(self):
        with self.assertRaisesRegex(ValueError, "UnrealPak listing failed"):
            pipeline.map_inventory(self.engine, [self.pak], self.output, lambda args, log: listing(args, log, exit_code=9))

    def test_log_without_actual_mount_and_entry_records_is_rejected(self):
        def execute(arguments, log):
            Path(log).write_text("BUILD SUCCESSFUL " + " ".join(pipeline.COOK_MAPS))
            return dict(path=str(log), sha256=sets.digest(log), exitCode=0)
        with self.assertRaisesRegex(ValueError, "actual mount point"):
            pipeline.map_inventory(self.engine, [self.pak], self.output, execute)

    def test_old_proof_missing_inventory_and_changed_log_or_return_code_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "actual PAK map inventory"):
            pipeline.validate_map_inventory(None, self.engine, [self.pak])
        value = map_proof(self.engine, [self.pak], self.output)
        bad = copy.deepcopy(value); bad["paks"][0]["listing"]["exitCode"] = 4
        with self.assertRaisesRegex(ValueError, "listing failed or changed"):
            pipeline.validate_map_inventory(bad, self.engine, [self.pak])
        log = Path(value["paks"][0]["listing"]["path"]); log.write_text("replaced evidence")
        with self.assertRaisesRegex(ValueError, "listing failed or changed"):
            pipeline.validate_map_inventory(value, self.engine, [self.pak])

    def test_new_missing_or_replaced_pak_cannot_reuse_the_successful_listing(self):
        value = map_proof(self.engine, [self.pak], self.output)
        other = self.root / "unlisted.pak"; other.write_bytes(b"unlisted")
        with self.assertRaisesRegex(ValueError, "complete payload"):
            pipeline.validate_map_inventory(value, self.engine, [self.pak, other])
        self.pak.write_bytes(b"changed PAK bytes")
        with self.assertRaisesRegex(ValueError, "Listed PAK changed"):
            pipeline.validate_map_inventory(value, self.engine, [self.pak])
        self.pak.unlink()
        with self.assertRaises(FileNotFoundError):
            pipeline.validate_map_inventory(value, self.engine, [self.pak])

    def test_relabelled_matching_evidence_still_must_have_the_required_real_map_records(self):
        value = map_proof(self.engine, [self.pak], self.output)
        record = value["paks"][0]
        listing([self.engine / "Engine/Binaries/Win64/UnrealPak.exe", self.pak, "-List"], record["listing"]["path"], pipeline.COOK_MAPS[:2])
        record["listing"]["sha256"] = sets.digest(record["listing"]["path"])
        record["maps"] = pipeline.listed_maps(record["listing"]["path"])[1]
        with self.assertRaisesRegex(ValueError, "Required maps missing.*CombatArena"):
            pipeline.validate_map_inventory(value, self.engine, [self.pak])

    @unittest.skipUnless(os.name == "nt" and shutil.which("cmd"), "Actual Windows engine-junction path identity")
    def test_actual_ascii_engine_junction_revalidates_at_real_path_without_changing_recorded_argv(self):
        alias = self.root / "ascii-engine-alias"
        result = subprocess.run(["cmd", "/c", "mklink", "/J", str(alias), str(self.engine)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.addCleanup(lambda: alias.rmdir() if alias.exists() else None)
        value = map_proof(alias, [self.pak], self.output)
        original_path = str(alias / "Engine/Binaries/Win64/UnrealPak.exe")
        original_arguments = list(value["paks"][0]["listing"]["arguments"])
        self.assertEqual(value["unrealPak"]["path"], original_path)
        self.assertEqual(Path(original_path).resolve(), (self.engine / "Engine/Binaries/Win64/UnrealPak.exe").resolve())
        self.assertEqual(pipeline.validate_map_inventory(value, self.engine, [self.pak]), value)
        self.assertEqual(value["unrealPak"]["path"], original_path)
        self.assertEqual(value["paks"][0]["listing"]["arguments"], original_arguments)
        (self.engine / "Engine/Binaries/Win64/UnrealPak.exe").write_bytes(b"replaced synthetic tool")
        with self.assertRaisesRegex(ValueError, "UnrealPak inventory tool changed"):
            pipeline.validate_map_inventory(value, self.engine, [self.pak])


if __name__ == "__main__":
    unittest.main()
