"""Producer evidence and inventory rejection; synthetic PE files never imply UE execution."""
import copy
import hashlib
import shutil
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import release_set as sets
import content_plan
import windows_pipeline as pipeline
from map_inventory_fixtures import isolate_content_plan, listing, map_proof, source_maps, unrealpak_tool


class WindowsProducerTests(unittest.TestCase):
    def setUp(self):
        isolate_content_plan(self)
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.native = self.root / "Archive/SampleGame/Binaries/Win64/SampleGame.exe"
        self.native.parent.mkdir(parents=True)
        pe = bytearray(128); pe[:2] = b"MZ"; struct.pack_into("<I", pe, 60, 64)
        pe[64:68] = b"PE\0\0"; struct.pack_into("<H", pe, 68, 0x8664); struct.pack_into("<H", pe, 88, 0x20B)
        self.native.write_bytes(pe)
        self.pak = self.root / "Archive/SampleGame/Content/Paks/SampleGame.pak"
        self.pak.parent.mkdir(parents=True); self.pak.write_bytes(b"synthetic-pak")
        self.identity = dict(sourceCommit="a" * 40, nativeSourceHash="b" * 64, engineBuildId="engine", shellCompatibilityId="c" * 64, sourceInventorySha256="d" * 64)
        self.proof = dict(format=1, kind="samplegame-complete-windows-build", **self.identity, configuration="Development", fullCook=True,
                          archiveRoot=str(self.root / "Archive"), gameExe=dict(size=128, sha256=sets.digest(self.native)),
                          files=pipeline.payload_records(self.root / "Archive"), mapInventory=map_proof(self.root, [self.pak], self.root / "maps"))
        for key, marker in (("editorBuild", "Result: Succeeded"), ("nativeBuild", "Result: Succeeded"), ("cook", "BUILD SUCCESSFUL")):
            log = self.root / (key + ".log"); log.write_text(marker)
            self.proof[key] = dict(path=str(log), sha256=sets.digest(log), exitCode=0)

    def validate(self, proof=None):
        with patch.object(pipeline, "identity", return_value=(self.identity, {})):
            return pipeline.validate_build(proof or self.proof, self.root, self.root)

    def test_matching_evidence_and_complete_file_inventory(self):
        self.assertEqual(self.validate()[0], self.root / "Archive")

    def test_archive_layout_accepts_flat_or_platform_folder_and_rejects_ambiguity(self):
        archive = self.root / "Archive"
        self.assertEqual(pipeline.archive_root(archive), archive)
        nested = self.root / "nested"
        shutil.copytree(archive, nested / "Windows")
        self.assertEqual(pipeline.archive_root(nested), nested / "Windows")
        shutil.copytree(archive / "SampleGame", nested / "SampleGame")
        with self.assertRaisesRegex(ValueError, "exactly one"):
            pipeline.archive_root(nested)
        empty = self.root / "empty"; empty.mkdir()
        with self.assertRaisesRegex(ValueError, "exactly one"):
            pipeline.archive_root(empty)

    def test_producer_build_records_both_supported_archive_layouts(self):
        from types import SimpleNamespace
        project = self.root / "repo/Project/SampleGame"
        original = project / "Binaries/Win64/SampleGame.exe"
        original.parent.mkdir(parents=True); shutil.copy2(self.native, original)
        source_maps(project)
        unrealpak_tool(self.root / "engine")
        for layout in ("flat", "nested", "missing-map"):
            with self.subTest(layout=layout):
                output = self.root / (layout + "-build")
                args = SimpleNamespace(project=project, engine=self.root / "engine", llvm_root=self.root / "llvm",
                                       output=output, base_release_id=400)
                commands = []
                def operation(arguments, log):
                    command = [str(item) for item in arguments]; commands.append(command)
                    if "-List" in command:
                        return listing(command, log, pipeline.COOK_MAPS[:2] if layout == "missing-map" else pipeline.COOK_MAPS)
                    if "-ArchiveDirectory" in command:
                        archive = Path(command[command.index("-ArchiveDirectory") + 1])
                        shutil.copytree(self.root / "Archive", archive if layout == "flat" else archive / "Windows")
                    Path(log).write_text("Result: Succeeded\nBUILD SUCCESSFUL")
                    return dict(path=str(log), sha256=sets.digest(log), exitCode=0)
                with patch.object(pipeline, "identity", return_value=(self.identity, {})), \
                     patch.object(pipeline, "execute", side_effect=operation):
                    if layout == "missing-map":
                        with self.assertRaisesRegex(ValueError, "Required maps missing.*CombatArena"):
                            pipeline.build(args)
                        self.assertFalse((output / "build-proof.json").exists())
                        continue
                    proof = pipeline.build(args)
                selected = output / "Archive" if layout == "flat" else output / "Archive/Windows"
                self.assertEqual(Path(proof["archiveRoot"]), selected)
                self.assertEqual(proof["gameExe"]["sha256"], sets.digest(original))
                self.assertEqual(proof["files"], pipeline.payload_records(selected))
                self.assertEqual(len(commands), 4)
                self.assertEqual(commands[2][commands[2].index("-MapList") + 1], "+".join(pipeline.COOK_MAPS))
                self.assertEqual(proof["mapInventory"]["requiredMaps"], list(pipeline.COOK_MAPS))
                self.assertFalse(proof["runtimeValidated"])

    def test_changed_cooked_pak_is_rejected(self):
        self.pak.write_bytes(b"changed-after-cook")
        with self.assertRaises(ValueError):
            self.validate()

    def test_expanded_plan_reaches_the_cook_command_proof_and_pak_gate(self):
        from types import SimpleNamespace
        project = self.root / "repo/Project/SampleGame"
        original = project / "Binaries/Win64/SampleGame.exe"
        original.parent.mkdir(parents=True); shutil.copy2(self.native, original)
        source_maps(project)
        extra = project / "Content/Expansion/NewMap.umap"
        extra.parent.mkdir(); extra.write_bytes(b"synthetic map")
        engine = self.root / "engine"; unrealpak_tool(engine)
        value = dict(format=1, requiredMaps=list(pipeline.COOK_MAPS) + ["/Game/Expansion/NewMap"])
        plan = dict(plan=value, sha256=hashlib.sha256(sets.canonical(value)).hexdigest())
        for mutate in (False, True):
            with self.subTest(mutate=mutate):
                args = SimpleNamespace(project=project, engine=engine, llvm_root=self.root / "llvm",
                                       output=self.root / ("expanded-mutated" if mutate else "expanded"), base_release_id=400)
                commands = []
                def operation(arguments, log):
                    command = [str(item) for item in arguments]; commands.append(command)
                    if "-List" in command:
                        return listing(command, log, value["requiredMaps"])
                    if "-ArchiveDirectory" in command:
                        target = Path(command[command.index("-ArchiveDirectory") + 1])
                        shutil.copytree(self.root / "Archive", target)
                    Path(log).write_text("Result: Succeeded\nBUILD SUCCESSFUL")
                    return dict(path=str(log), sha256=sets.digest(log), exitCode=0)
                with patch.object(pipeline, "identity", return_value=(self.identity, {})), \
                     patch.object(pipeline, "execute", side_effect=operation), \
                     patch.object(content_plan, "snapshot", side_effect=[plan, dict(plan, sha256="f" * 64)] if mutate else None,
                                  return_value=plan):
                    if mutate:
                        with self.assertRaisesRegex(ValueError, "content plan changed during"):
                            pipeline.build(args)
                        self.assertFalse((args.output / "build-proof.json").exists())
                    else:
                        proof = pipeline.build(args)
                        self.assertEqual(proof["contentPlan"], plan)
                        self.assertEqual(proof["mapInventory"]["requiredMaps"], value["requiredMaps"])
                        self.assertEqual(commands[2][commands[2].index("-MapList") + 1], "+".join(value["requiredMaps"]))

    def test_expanded_proof_cannot_omit_its_plan_to_masquerade_as_legacy(self):
        value = dict(format=1, requiredMaps=list(pipeline.COOK_MAPS) + ["/Game/Expansion/NewMap"])
        plan = dict(plan=value, sha256=hashlib.sha256(sets.canonical(value)).hexdigest())
        proof = copy.deepcopy(self.proof)
        proof["contentPlan"] = plan
        def run(arguments, log):
            return listing(arguments, log, value["requiredMaps"])
        proof["mapInventory"] = pipeline.map_inventory(self.root, [self.pak], self.root, run, maps=value["requiredMaps"])
        with patch.object(content_plan, "snapshot", return_value=plan):
            self.validate(proof)
        del proof["contentPlan"]
        with self.assertRaisesRegex(ValueError, "map inventory"):
            self.validate(proof)

    def test_replaced_native_executable_is_rejected(self):
        with self.native.open("ab") as output:
            output.write(b"replacement")
        with self.assertRaises(ValueError):
            self.validate()

    def test_changed_source_and_failed_build_evidence_are_rejected(self):
        bad = copy.deepcopy(self.proof); bad["sourceCommit"] = "e" * 40
        with self.assertRaises(ValueError):
            self.validate(bad)
        bad = copy.deepcopy(self.proof); bad["nativeBuild"]["exitCode"] = 7
        with self.assertRaises(ValueError):
            self.validate(bad)
        bad = copy.deepcopy(self.proof); bad["fullCook"] = False
        with self.assertRaises(ValueError):
            self.validate(bad)

    def test_changed_log_cannot_be_relabelled_successful(self):
        Path(self.proof["cook"]["path"]).write_text("BUILD FAILED")
        with self.assertRaises(ValueError):
            self.validate()

    def test_tools_only_repackage_preserves_actual_build_commit_and_rejects_project_changes(self):
        repo = self.root / "provenance-fixture"
        project = repo / "Project/SampleGame"; project.mkdir(parents=True)
        def git(*arguments):
            return subprocess.run(["git", "-C", str(repo), "-c", "user.name=Release fixture", "-c", "user.email=fixture@localhost", *arguments], capture_output=True, text=True, check=True).stdout.strip()
        git("init")
        (project / "project-input.txt").write_text("native/cook source")
        git("add", "."); git("commit", "-m", "fixture baseline")
        built = git("rev-parse", "HEAD")
        (repo / "tool.txt").write_text("updated installer")
        git("add", "."); git("commit", "-m", "fixture tool update")
        current = dict(self.identity, sourceCommit=git("rev-parse", "HEAD"))
        proof = copy.deepcopy(self.proof); proof["sourceCommit"] = built
        with patch.object(pipeline, "identity", return_value=(current, {})):
            selected = pipeline.validate_build(proof, project, self.root)
            self.assertEqual(selected[1]["sourceCommit"], built)
            altered_inventory = dict(current, sourceInventorySha256="f" * 64)
            with patch.object(pipeline, "identity", return_value=(altered_inventory, {})):
                with self.assertRaises(ValueError):
                    pipeline.validate_build(proof, project, self.root)
        (project / "project-input.txt").write_text("different game code")
        git("add", "."); git("commit", "-m", "fixture game update")
        current["sourceCommit"] = git("rev-parse", "HEAD")
        with patch.object(pipeline, "identity", return_value=(current, {})):
            with self.assertRaises(ValueError):
                pipeline.validate_build(proof, project, self.root)

    def test_additional_support_file_or_mutable_directory_is_rejected(self):
        (self.pak.parent / "unexpected.pak").write_bytes(b"other")
        with self.assertRaises(ValueError):
            self.validate()
        (self.native.parents[2] / "Saved").mkdir()
        with self.assertRaises(ValueError):
            pipeline.payload_records(self.root / "Archive")


if __name__ == "__main__":
    unittest.main()
