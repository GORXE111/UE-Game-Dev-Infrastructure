"""APK producer invariants; all tiny archives/native/logs here are synthetic fixtures."""
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import subprocess
import unittest
from unittest.mock import patch
from map_inventory_fixtures import isolate_content_plan, listing, map_proof, source_maps, unrealpak_tool
import zipfile

import android_pipeline as pipeline
import content_plan
import release_set as sets


class AndroidProducerTests(unittest.TestCase):
    def setUp(self):
        isolate_content_plan(self)
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.apk = self.root / "fixture.apk"
        self.obb = io.BytesIO()
        with zipfile.ZipFile(self.obb, "w") as inner:
            inner.writestr("SampleGame/Content/Paks/SampleGame-Android_ASTC.pak", b"synthetic full cook")
            inner.writestr("SampleGame/Content/Movies/loading.mp4", b"shell video")
        with zipfile.ZipFile(self.apk, "x") as outer:
            outer.writestr(pipeline.NATIVE_ENTRY, b"synthetic native bytes", compress_type=zipfile.ZIP_DEFLATED)
            outer.writestr(pipeline.OBB_ENTRY, self.obb.getvalue(), compress_type=zipfile.ZIP_STORED)
            outer.writestr("AndroidManifest.xml", b"synthetic binary XML")
            outer.writestr("META-INF/MANIFEST.MF", b"obsolete jar signature")
            outer.writestr("META-INF/CERT.RSA", b"obsolete signer")
            outer.writestr(pipeline.LEGACY_NATIVE_ENTRY, b"obsolete independent native configuration")
        self.identity = dict(sourceCommit="a" * 40, nativeSourceHash="b" * 64, engineBuildId="test-engine",
                             shellCompatibilityId="c" * 64, sourceInventorySha256="d" * 64)
        self.trust = dict(projectId="SampleGame", platform="Android_ARM64", channel="test-android", baseReleaseId=400,
                          engineBuildId="test-engine", shellCompatibilityId="c" * 64, loaderVersion=1)

    def prepared(self):
        import base64
        files, entries = pipeline.payload_records(self.apk, 400)
        value, raw = pipeline.make_manifest(self.identity, files, self.trust, 400)
        trust = dict(self.trust, baseManifestSha256=__import__("hashlib").sha256(raw).hexdigest())
        config = dict(format=1, trust=trust, packageName=pipeline.PACKAGE,
                      manifestUrl="https://example.test/v106/updates/manifest.json", allowOffline=True,
                      signatureAlgorithm="SHA256withRSA", certificateBase64=base64.b64encode(b"fixture certificate").decode(),
                      certificateSha256=pipeline.CERTIFICATE_SHA256, baseArchiveEntries=entries)
        output = self.root / "prepared.apk"
        removed = pipeline.rewrite_apk(self.apk, output, config, raw)
        return output, config, value, raw, removed

    def staged(self, root):
        root.mkdir(parents=True)
        with pipeline.apk_payload(self.apk) as (_, inner, _):
            for item in inner.infolist():
                target = root / item.filename
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(inner.read(item))
        for name in ("Manifest_UFSFiles_Android.txt", "Manifest_NonUFSFiles_Android.txt"):
            (root / name).write_text("synthetic UAT stage manifest\n")
        return root

    def test_exact_obb_entry_mapping_and_release_specific_pak_names(self):
        files, entries = pipeline.payload_records(self.apk, 400)
        self.assertEqual([record["path"] for record in files], ["Content/Paks/r400_SampleGame-Android_ASTC.pak", "libUnreal.so"])
        self.assertEqual(entries[0], dict(path=files[0]["path"], apkPath=pipeline.OBB_ENTRY,
                                         obbPath="SampleGame/Content/Paks/SampleGame-Android_ASTC.pak"))
        self.assertEqual(entries[1], dict(path="libUnreal.so", apkPath=pipeline.NATIVE_ENTRY, obbPath=""))
        candidate, _ = pipeline.payload_records(self.apk, 401)
        self.assertEqual(candidate[0]["path"], "Content/Paks/r401_SampleGame-Android_ASTC.pak")
        self.assertEqual(candidate[0]["sha256"], files[0]["sha256"])

    def test_extraction_copies_the_complete_payload_and_checksums(self):
        root = self.root / "payload"; root.mkdir()
        files, _ = pipeline.payload_records(self.apk, 401, root)
        sets.verify_tree(root, files)
        self.assertEqual((root / "libUnreal.so").read_bytes(), b"synthetic native bytes")
        with self.assertRaises(FileExistsError):
            pipeline.payload_records(self.apk, 401, root)

    def test_preparation_preserves_native_obb_methods_and_removes_old_independent_loader(self):
        output, config, value, _, removed = self.prepared()
        self.assertEqual({item["path"] for item in removed}, {pipeline.LEGACY_NATIVE_ENTRY, "META-INF/MANIFEST.MF", "META-INF/CERT.RSA"})
        with patch.object(pipeline, "certificate", return_value=b"fixture certificate"):
            self.assertEqual(pipeline.read_player(output)[:2], (config, value))
        with zipfile.ZipFile(output) as rebuilt, zipfile.ZipFile(self.apk) as original:
            for name in (pipeline.NATIVE_ENTRY, pipeline.OBB_ENTRY, "AndroidManifest.xml"):
                self.assertEqual(rebuilt.read(name), original.read(name))
                self.assertEqual(rebuilt.getinfo(name).compress_type, original.getinfo(name).compress_type)
        with self.assertRaises(ValueError):
            pipeline.rewrite_apk(output, self.root / "wrapped-again.apk", config, sets.canonical(value))

    def test_traversal_case_alias_and_special_archives_are_rejected(self):
        for invalid in ("../bad", "a/../b", "a\\bad", "/bad", "x:bad", "a//b"):
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, "w") as archive:
                # ZipInfo's Windows constructor normalizes backslashes, so set
                # the raw central-directory name after construction.
                info = zipfile.ZipInfo("fixture")
                info.filename = invalid
                archive.writestr(info, b"bad")
            with zipfile.ZipFile(io.BytesIO(buffer.getvalue())) as archive, self.assertRaises(ValueError):
                pipeline.zip_entries(archive)
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("File", b"one"); archive.writestr("file", b"two")
        with zipfile.ZipFile(io.BytesIO(buffer.getvalue())) as archive, self.assertRaises(ValueError):
            pipeline.zip_entries(archive)
        buffer = io.BytesIO()
        info = zipfile.ZipInfo("link"); info.external_attr = 0o120777 << 16
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr(info, b"somewhere")
        with zipfile.ZipFile(io.BytesIO(buffer.getvalue())) as archive, self.assertRaises(ValueError):
            pipeline.zip_entries(archive)

    def test_iostore_or_pak_outside_the_project_is_not_silently_omitted(self):
        for invalid in ("Other/Content/Paks/other.pak", "SampleGame/Content/Paks/game.utoc"):
            data = io.BytesIO()
            with zipfile.ZipFile(data, "w") as inner:
                inner.writestr("SampleGame/Content/Paks/SampleGame.pak", b"pak")
                inner.writestr(invalid, b"other")
            apk = self.root / ("bad-" + str(len(invalid)) + ".apk")
            with zipfile.ZipFile(apk, "x") as outer:
                outer.writestr(pipeline.NATIVE_ENTRY, b"native")
                outer.writestr(pipeline.OBB_ENTRY, data.getvalue())
            with self.assertRaises(ValueError):
                pipeline.payload_records(apk, 400)

    def replace_metadata(self, output, config, raw):
        replaced = self.root / "replaced.apk"
        with zipfile.ZipFile(output) as source, zipfile.ZipFile(replaced, "x") as target:
            for item in source.infolist():
                if item.filename not in (pipeline.CONFIG_ENTRY, pipeline.MANIFEST_ENTRY):
                    target.writestr(item, source.read(item))
            target.writestr(pipeline.CONFIG_ENTRY, sets.canonical(config))
            target.writestr(pipeline.MANIFEST_ENTRY, raw)
        return replaced

    def test_false_archive_mapping_and_unpinned_manifest_are_rejected(self):
        output, config, _, raw, _ = self.prepared()
        config["baseArchiveEntries"][0]["obbPath"] = "SampleGame/Content/Paks/wrong.pak"
        replaced = self.replace_metadata(output, config, raw)
        with patch.object(pipeline, "certificate", return_value=b"fixture certificate"), self.assertRaises(ValueError):
            pipeline.read_player(replaced)
        replaced.unlink()
        config["trust"]["baseManifestSha256"] = "0" * 64
        replaced = self.replace_metadata(output, config, raw)
        with patch.object(pipeline, "certificate", return_value=b"fixture certificate"), self.assertRaises(ValueError):
            pipeline.read_player(replaced)

    def test_configuration_rejects_unknown_fields_and_non_https_transport(self):
        output, config, _, raw, _ = self.prepared()
        config["unknown"] = True
        replaced = self.replace_metadata(output, config, raw)
        with patch.object(pipeline, "certificate", return_value=b"fixture certificate"), self.assertRaises(ValueError):
            pipeline.read_player(replaced)
        for invalid in ("http://example.test/manifest.json", "https://x:444/manifest.json", "https://x/a/../manifest.json",
                        "https://x/%2e%2e/manifest.json", "https://u:p@x/manifest.json", "https://x/manifest.json?q=x",
                        "https://x/a//manifest.json", "https://x/a+plus/manifest.json"):
            with self.assertRaises(ValueError):
                pipeline.https(invalid)

    def fixture_proof(self):
        project = self.root / "Project/SampleGame"
        binary = project / "Binaries/Android/SampleGame-arm64.so"
        binary.parent.mkdir(parents=True); binary.write_bytes(b"synthetic source ELF")
        receipt = binary.parent / "SampleGame.target"; receipt.write_text("synthetic receipt")
        tool = self.root / "llvm-strip.exe"; tool.write_bytes(b"synthetic tool")
        meta = self.root / "source.properties"; meta.write_bytes(b"synthetic metadata")
        files, mapping = pipeline.payload_records(self.apk)
        native = next(item for item in files if item["role"] == "native")
        proof = dict(format=1, kind="samplegame-complete-android-build", **self.identity, configuration="Development",
                     architecture="arm64", textureFormat="ASTC", fullCook=True, rawApk=str(self.apk),
                     rawApkSha256=sets.digest(self.apk), rawApkSize=self.apk.stat().st_size, files=files, archiveEntries=mapping,
                     apkShellFiles=pipeline.apk_shell_inventory(self.apk),
                     nativeDerivation=dict(sourceBinary=str(binary), sourceSha256=sets.digest(binary), sourceElf={"fixture": True},
                                           targetReceipt=str(receipt), targetReceiptSha256=sets.digest(receipt),
                                           stripTool=str(tool), stripToolSha256=sets.digest(tool),
                                           ndkMetadata=str(meta), ndkMetadataSha256=sets.digest(meta),
                                           deliverySize=native["size"], deliverySha256=native["sha256"]))
        for key, marker in (("editorBuild", "Result: Succeeded"), ("nativeBuild", "Result: Succeeded"), ("cook", "BUILD SUCCESSFUL")):
            log = self.root / (key + ".log"); log.write_text(marker)
            proof[key] = dict(path=str(log), sha256=sets.digest(log), exitCode=0)
        log = self.root / "strip.log"; log.write_text("synthetic strip return")
        proof["nativeDerivation"]["operation"] = dict(path=str(log), sha256=sets.digest(log), exitCode=0)
        delivery = self.root / "fixture-delivery.so"; delivery.write_bytes(b"synthetic native bytes")
        stage = self.staged(self.root / "baseline-stage/Android_ASTC")
        proof["nativeDerivation"]["deliveryBinary"] = str(delivery)
        proof.update(stageRoot=str(stage), stageFiles=pipeline.stage_inventory(stage),
                     looseObbFiles=pipeline.stage_obb_inventory(stage),
                     mapInventory=map_proof(self.root, sorted(stage.rglob("*.pak")), self.root / "maps"))
        return proof, project

    def validate(self, proof, project):
        with patch.object(pipeline, "identity", return_value=(self.identity, {})), patch.object(pipeline, "loader_elf", return_value={"fixture": True}):
            return pipeline.validate_build(proof, project, self.root)

    def test_actual_proof_checks_reject_changed_source_logs_apk_and_native(self):
        proof, project = self.fixture_proof()
        self.assertEqual(self.validate(proof, project)[0], self.apk)
        for field, value in (("configuration", "Shipping"), ("textureFormat", "ETC2"), ("nativeSourceHash", "e" * 64),
                             ("fullCook", False), ("rawApkSha256", "0" * 64)):
            bad = copy.deepcopy(proof); bad[field] = value
            with self.assertRaises(ValueError):
                self.validate(bad, project)
        Path(proof["nativeDerivation"]["sourceBinary"]).write_bytes(b"replaced source")
        with self.assertRaises(ValueError):
            self.validate(proof, project)

    def test_failed_or_replaced_cook_evidence_cannot_be_relabelled_as_complete(self):
        proof, project = self.fixture_proof()
        bad = copy.deepcopy(proof); bad["cook"]["exitCode"] = 1
        with self.assertRaises(ValueError):
            self.validate(bad, project)
        Path(proof["cook"]["path"]).write_text("BUILD FAILED")
        with self.assertRaises(ValueError):
            self.validate(proof, project)

    def test_tools_only_repackage_preserves_build_commit_but_project_edits_are_refused(self):
        proof, _ = self.fixture_proof()
        repo = self.root / "provenance-fixture"
        project = repo / "Project/SampleGame"; project.mkdir(parents=True)
        def git(*arguments):
            return subprocess.run(["git", "-C", str(repo), "-c", "user.name=Release fixture", "-c", "user.email=fixture@localhost",
                                   *arguments], capture_output=True, text=True, check=True).stdout.strip()
        git("init")
        (project / "project-input.txt").write_text("same genuine source")
        git("add", "."); git("commit", "-m", "fixture baseline")
        proof["sourceCommit"] = git("rev-parse", "HEAD")
        native = project / "Binaries/Android/SampleGame-arm64.so"; native.parent.mkdir(parents=True)
        native.write_bytes(b"synthetic source ELF")
        receipt = native.parent / "SampleGame.target"; receipt.write_text("synthetic receipt")
        proof["nativeDerivation"].update(sourceBinary=str(native), targetReceipt=str(receipt))
        (repo / "tool.txt").write_text("new tool outside the built project")
        git("add", "tool.txt"); git("commit", "-m", "fixture tool update")
        current = dict(self.identity, sourceCommit=git("rev-parse", "HEAD"))
        with patch.object(pipeline, "identity", return_value=(current, {})), patch.object(pipeline, "loader_elf", return_value={"fixture": True}):
            selected = pipeline.validate_build(proof, project, self.root)
            self.assertEqual(selected[1]["sourceCommit"], proof["sourceCommit"])
        (project / "project-input.txt").write_text("changed gameplay source")
        git("add", "Project/SampleGame/project-input.txt"); git("commit", "-m", "fixture game edit")
        current["sourceCommit"] = git("rev-parse", "HEAD")
        with patch.object(pipeline, "identity", return_value=(current, {})), self.assertRaises(ValueError):
            pipeline.validate_build(proof, project, self.root)

    def test_changed_apk_shell_is_detected_independently_of_native_and_pak(self):
        original = pipeline.apk_shell_inventory(self.apk)
        output, _, _, _, _ = self.prepared()
        self.assertEqual(pipeline.apk_shell_inventory(output), original)
        replaced = self.root / "changed-shell.apk"
        with zipfile.ZipFile(self.apk) as archive, zipfile.ZipFile(replaced, "x") as target:
            for item in archive.infolist():
                target.writestr(item, b"changed Java/permissions" if item.filename == "AndroidManifest.xml" else archive.read(item))
        self.assertNotEqual(pipeline.apk_shell_inventory(replaced), original)
        self.assertEqual(pipeline.payload_records(replaced), pipeline.payload_records(self.apk))

    def changed_obb(self, mode):
        obb = io.BytesIO()
        movie = "SampleGame/Content/Movies/loading.mp4"
        with zipfile.ZipFile(self.obb) as source, zipfile.ZipFile(obb, "w") as target:
            for item in source.infolist():
                if mode == "delete" and item.filename == movie:
                    continue
                if mode == "directory" and item.filename == movie:
                    target.writestr(movie + "/", b"")
                    continue
                data = b"changed loose movie" if mode == "change" and item.filename == movie else source.read(item)
                target.writestr(item, data)
            if mode == "add":
                target.writestr("Engine/Content/Renderer/new-loose-table.bin", b"new loose engine input")
            if mode == "add-directory":
                target.writestr("Engine/Content/NewDirectory/", b"")
        apk = self.root / ("loose-" + mode + ".apk")
        with zipfile.ZipFile(self.apk) as source, zipfile.ZipFile(apk, "x") as target:
            for item in source.infolist():
                target.writestr(item, obb.getvalue() if item.filename == pipeline.OBB_ENTRY else source.read(item))
        return apk

    def test_loose_obb_bytes_entries_and_directory_types_are_part_of_the_frozen_shell(self):
        original = pipeline.apk_shell_inventory(self.apk)
        record = next(item for item in original if item["path"].endswith("!SampleGame/Content/Movies/loading.mp4"))
        self.assertEqual(record["type"], "file")
        self.assertEqual(record["sha256"], __import__("hashlib").sha256(b"shell video").hexdigest())
        for mode in ("change", "add", "delete", "directory", "add-directory"):
            with self.subTest(mode=mode):
                apk = self.changed_obb(mode)
                self.assertNotEqual(pipeline.apk_shell_inventory(apk), original)
                # These bytes are absent from the switched native/PAK payload;
                # equality here proves the separate frozen-shell gate matters.
                self.assertEqual(pipeline.payload_records(apk), pipeline.payload_records(self.apk))
                if mode == "add-directory":
                    directory = next(item for item in pipeline.apk_shell_inventory(apk) if item["path"].endswith("!Engine/Content/NewDirectory/"))
                    self.assertEqual(directory["type"], "directory")
                    self.assertEqual(directory["size"], 0)

    def test_candidates_refuse_changed_added_or_deleted_loose_obb_before_reserving_or_signing(self):
        from types import SimpleNamespace
        output, config, value, _, _ = self.prepared()
        freeze = self.root / "freeze.json"; freeze.write_bytes(sets.canonical({"shellCompatibilityId": self.identity["shellCompatibilityId"]}))
        for mode in ("change", "add", "delete", "directory", "add-directory"):
            with self.subTest(mode=mode):
                apk = self.changed_obb(mode)
                proof_path = self.root / (mode + "-proof.json")
                proof_path.write_bytes(sets.canonical({"fixture": True, "apkShellFiles": pipeline.apk_shell_inventory(apk)}))
                args = SimpleNamespace(player_apk=output, build_proof=proof_path, project=self.root, engine=self.root,
                                       shell_freeze=freeze, release_id=401, registry_root=self.root / "registry", output=self.root / "candidate")
                with patch.object(pipeline, "read_player", return_value=(config, value, b"fixture")), \
                     patch.object(pipeline, "validate_build", return_value=(apk, self.identity, {})), \
                     patch.object(pipeline.compatibility, "compare", return_value={"requiresNewBase": False}), \
                     patch.object(pipeline, "sign_manifest") as sign:
                    with self.assertRaisesRegex(ValueError, "changed APK Java/resources/dependencies"):
                        pipeline.candidate(args)
                    sign.assert_not_called()
                self.assertFalse(args.registry_root.exists())
                self.assertFalse(args.output.exists())

    def test_signed_candidate_reserves_id_before_any_signing_failure(self):
        from types import SimpleNamespace
        output, config, value, _, _ = self.prepared()
        proof_path = self.root / "proof.json"
        proof_path.write_bytes(sets.canonical({"fixture": True, "apkShellFiles": pipeline.apk_shell_inventory(self.apk)}))
        freeze = self.root / "freeze.json"; freeze.write_bytes(sets.canonical({"shellCompatibilityId": self.identity["shellCompatibilityId"]}))
        args = SimpleNamespace(player_apk=output, build_proof=proof_path, project=self.root, engine=self.root,
                               shell_freeze=freeze, release_id=401, registry_root=self.root / "registry", output=self.root / "candidate")
        with patch.object(pipeline, "read_player", return_value=(config, value, b"fixture")), \
             patch.object(pipeline, "validate_build", return_value=(self.apk, self.identity, {})), \
             patch.object(pipeline.compatibility, "compare", return_value={"requiresNewBase": False}), \
             patch.object(pipeline, "fresh_output", side_effect=lambda output, *_: (output.mkdir(), output)[1]), \
             patch.object(pipeline, "verify_signed_apk", return_value={"fixture": True}), \
             patch.object(pipeline, "sign_manifest", side_effect=ValueError("fixture signing rejected")):
            with self.assertRaisesRegex(ValueError, "fixture signing rejected"):
                pipeline.candidate(args)
            state = sets.parse((args.registry_root / "test-android-400/state.json").read_bytes())
            self.assertEqual(state["highestReleaseId"], 401)
            args.output = self.root / "candidate-retry"
            with self.assertRaisesRegex(ValueError, "already reserved"):
                pipeline.candidate(args)

    def test_dual_engine_build_uses_editor_runtime_only_for_editor_compile(self):
        from types import SimpleNamespace
        import shutil
        engine = self.root / "complete-android-engine"
        editor = self.root / "trimmed-windows-editor"
        for relative in ("Engine/Build/Android/Java/src/com/epicgames/unreal/GameActivity.java.template",
                         "Engine/Build/BatchFiles/Build.bat", "Engine/Build/BatchFiles/RunUAT.bat"):
            path = engine / relative; path.parent.mkdir(parents=True, exist_ok=True); path.write_text("synthetic engine input")
        modules = editor / "Engine/Binaries/Win64/UnrealEditor.modules"; modules.parent.mkdir(parents=True)
        modules.write_text(json.dumps({"BuildId": self.identity["engineBuildId"]}))
        args = SimpleNamespace(project=self.root / "repo/Project/SampleGame", engine=engine, editor_engine=editor,
                               output=self.root / "build-output", llvm_root=self.root / "llvm", sdk_root=self.root / "sdk",
                               ndk_root=self.root / "ndk", java_home=self.root / "jdk", base_release_id=400)
        args.project.mkdir(parents=True)
        source_maps(args.project)
        unrealpak_tool(engine)
        default_stage = args.project / "Saved/StagedBuilds/Android_ASTC"
        self.staged(default_stage)
        old_obb = default_stage.with_suffix(".obb"); old_obb.write_bytes(b"obsolete OBB")
        commands = []
        delivery = self.root / "derived-native.so"; delivery.write_bytes(b"synthetic native bytes")
        def operation(arguments, log, env=None):
            command = [str(item) for item in arguments]; commands.append(command)
            if "-List" in command:
                return listing(command, log)
            if "-ArchiveDirectory" in command:
                self.assertNotIn("-StagingDirectory", command)
                self.assertFalse(default_stage.exists())
                self.assertFalse(old_obb.exists())
                archive = Path(command[command.index("-ArchiveDirectory") + 1]); archive.mkdir()
                shutil.copy2(self.apk, archive / "synthetic.apk")
                self.staged(default_stage)
            return dict(path=str(log), sha256="e" * 64, exitCode=0, arguments=command)
        with patch.object(pipeline, "identity", return_value=(self.identity, {})), \
             patch.object(pipeline, "fresh_output", side_effect=lambda output, *_: (output.mkdir(), output)[1]), \
             patch.object(pipeline, "execute", side_effect=operation), \
             patch.object(pipeline, "native_derivation", return_value={"fixture": True, "deliveryBinary": str(delivery)}):
            proof = pipeline.build(args)
        self.assertEqual(len(commands), 4)
        self.assertEqual(commands[0][commands[0].index("-EngineRoot") + 1], str(editor.resolve()))
        self.assertEqual(commands[1][0], str(engine.resolve() / "Engine/Build/BatchFiles/Build.bat"))
        self.assertIn("-rootdirectory=" + str(engine.resolve()), commands[1])
        self.assertEqual(commands[2][commands[2].index("-EngineRoot") + 1], str(engine.resolve()))
        self.assertNotIn(str(editor.resolve()), commands[2])
        self.assertIn("-SkipEditorBuild", commands[2])
        self.assertEqual(commands[2][commands[2].index("-MapList") + 1], "+".join(pipeline.COOK_MAPS))
        self.assertEqual(proof["mapInventory"]["requiredMaps"], list(pipeline.COOK_MAPS))
        self.assertFalse(proof["runtimeValidated"])
        self.assertEqual(Path(proof["stageRoot"]), default_stage)
        self.assertEqual((args.output / "quarantine/Android_ASTC.obb").read_bytes(), b"obsolete OBB")
        self.assertEqual(proof["stageQuarantine"]["sha256"], sets.digest(args.output / "stage-quarantine.json"))

    def test_default_stage_quarantine_preserves_old_stage_main_patch_and_all_overflows(self):
        project = self.root / "project"; project.mkdir()
        saved = project / "Saved/StagedBuilds"; saved.mkdir(parents=True)
        old_stage = saved / "Android_ASTC/SampleGame/Content/Paks"; old_stage.mkdir(parents=True)
        (old_stage / "old_0_P.pak").write_bytes(b"obsolete patch pak")
        expected = {}
        for name in ("Android_ASTC.obb", "Android_ASTC.patch.obb", "Android_ASTC.overflow1.obb", "Android_ASTC.overflow3.obb"):
            (saved / name).write_bytes(name.encode("ascii"))
            expected[name] = sets.digest(saved / name)
        other = saved / "Android_ETC2.obb"; other.write_bytes(b"other platform")
        output = self.root / "new-build"; output.mkdir()
        evidence = pipeline.quarantine_default_stage(project, output)
        receipt = sets.parse((output / "stage-quarantine.json").read_bytes())
        self.assertEqual(evidence["sha256"], sets.digest(evidence["path"]))
        self.assertEqual(receipt["status"], "quarantined")
        self.assertEqual(len(receipt["entries"]), 5)
        for item in receipt["entries"]:
            self.assertFalse(Path(item["originalPath"]).exists())
            self.assertEqual(pipeline.cache_inventory(item["quarantinePath"]), item["inventory"])
            self.assertTrue(item["moved"] and item["verified"])
        for name, digest in expected.items():
            self.assertEqual(sets.digest(output / "quarantine" / name), digest)
        self.assertEqual((output / "quarantine/Android_ASTC/SampleGame/Content/Paks/old_0_P.pak").read_bytes(), b"obsolete patch pak")
        self.assertEqual(other.read_bytes(), b"other platform")

    def test_default_stage_unknown_or_case_alias_is_rejected_before_any_move(self):
        for name in ("Android_ASTC.unknown.obb", "Android_ASTC.overflow0.obb", "android_astc.obb"):
            with self.subTest(name=name):
                project = self.root / name / "project"; saved = project / "Saved/StagedBuilds"; saved.mkdir(parents=True)
                stage = saved / "Android_ASTC"; stage.mkdir(); (stage / "old.pak").write_bytes(b"preserved")
                (saved / name).write_bytes(b"unknown old cache")
                output = self.root / name / "output"; output.mkdir()
                with self.assertRaisesRegex(ValueError, "Unknown or case-aliased"):
                    pipeline.quarantine_default_stage(project, output)
                self.assertEqual((stage / "old.pak").read_bytes(), b"preserved")
                self.assertTrue((saved / name).is_file())
                self.assertFalse((output / "quarantine").exists())

    def test_default_stage_quarantine_rejects_hardlinks_and_inside_project_output(self):
        project = self.root / "project"; stage = project / "Saved/StagedBuilds/Android_ASTC"; stage.mkdir(parents=True)
        external = self.root / "external.pak"; external.write_bytes(b"linked")
        os.link(external, stage / "aliased.pak")
        output = self.root / "output"; output.mkdir()
        with self.assertRaisesRegex(ValueError, "Hard-linked"):
            pipeline.quarantine_default_stage(project, output)
        self.assertTrue((stage / "aliased.pak").is_file())
        inside = project / "output"; inside.mkdir()
        with self.assertRaisesRegex(ValueError, "outside the project"):
            pipeline.quarantine_default_stage(project, inside)
        self.assertFalse((inside / "quarantine").exists())

    def test_quarantine_move_failure_keeps_old_bytes_and_an_incomplete_receipt(self):
        project = self.root / "project"; saved = project / "Saved/StagedBuilds"; saved.mkdir(parents=True)
        old = saved / "Android_ASTC.obb"; old.write_bytes(b"preserve on failure")
        output = self.root / "output"; output.mkdir()
        with patch.object(Path, "rename", side_effect=OSError("synthetic locked cache")), self.assertRaises(OSError):
            pipeline.quarantine_default_stage(project, output)
        receipt = sets.parse((output / "stage-quarantine.json").read_bytes())
        self.assertEqual(receipt["status"], "incomplete-preserved")
        self.assertFalse(receipt["entries"][0]["moved"])
        self.assertEqual(old.read_bytes(), b"preserve on failure")

    def test_stage_payload_contains_all_paks_and_actual_stripped_native(self):
        stage = self.staged(self.root / "Stage/Android_ASTC")
        native = self.root / "derived.so"; native.write_bytes(b"synthetic native bytes")
        self.assertEqual(pipeline.stage_payload_records(stage, native), pipeline.payload_records(self.apk)[0])
        pipeline.verify_stage_shell(stage, self.apk)
        output = self.root / "payload"; output.mkdir()
        files = pipeline.stage_payload_records(stage, native, 401, output)
        sets.verify_tree(output, files)
        self.assertEqual(files[0]["path"], "Content/Paks/r401_SampleGame-Android_ASTC.pak")

    def test_candidate_build_selects_stage_only_and_records_distinct_non_apk_proof(self):
        from types import SimpleNamespace
        apk, _, _, _, _ = self.prepared()
        engine = self.root / "source-engine"
        for relative in ("Engine/Build/Android/Java/src/com/epicgames/unreal/GameActivity.java.template",
                         "Engine/Build/BatchFiles/Build.bat", "Engine/Build/BatchFiles/RunUAT.bat"):
            path = engine / relative; path.parent.mkdir(parents=True, exist_ok=True); path.write_text("synthetic input")
        modules = engine / "Engine/Binaries/Win64/UnrealEditor.modules"; modules.parent.mkdir(parents=True)
        modules.write_text(json.dumps({"BuildId": self.identity["engineBuildId"]}))
        freeze = self.root / "frozen.json"; freeze.write_bytes(sets.canonical({"shellCompatibilityId": self.identity["shellCompatibilityId"]}))
        args = SimpleNamespace(project=self.root / "repo/Project/SampleGame", engine=engine, editor_engine=None,
                               output=self.root / "staged-build", llvm_root=self.root / "llvm", sdk_root=self.root / "sdk",
                               ndk_root=self.root / "ndk", java_home=self.root / "jdk", base_release_id=400,
                               candidate_base=apk, candidate_shell_freeze=freeze)
        saved = args.project / "Saved/StagedBuilds"; saved.mkdir(parents=True)
        source_maps(args.project)
        extra = args.project / "Content/Expansion/NewMap.umap"
        extra.parent.mkdir(); extra.write_bytes(b"synthetic expansion map")
        plan_value = dict(format=1, requiredMaps=list(pipeline.COOK_MAPS) + ["/Game/Expansion/NewMap"])
        plan = dict(plan=plan_value, sha256=hashlib.sha256(sets.canonical(plan_value)).hexdigest())
        unrealpak_tool(engine)
        # Even a default cache this producer would reject for a baseline must
        # remain untouched by a candidate, which never invokes MakeApk.
        old = saved / "Android_ASTC.unknown.obb"; old.write_bytes(b"old default cache")
        native = self.root / "candidate-derived.so"; native.write_bytes(b"synthetic native bytes")
        commands = []
        listing_maps = tuple(plan_value["requiredMaps"])
        def operation(arguments, log, env=None):
            command = [str(item) for item in arguments]; commands.append(command)
            if "-List" in command:
                return listing(command, log, listing_maps)
            if "-StagingDirectory" in command:
                self.assertIn("-StageOnly", command)
                self.staged(Path(command[command.index("-StagingDirectory") + 1]) / "Android_ASTC")
                Path(log).write_text("COOK COMMAND COMPLETED\nSTAGE COMMAND COMPLETED\nBUILD SUCCESSFUL")
            else:
                Path(log).write_text("Result: Succeeded")
            return dict(path=str(log), sha256=sets.digest(log), exitCode=0, arguments=command)
        with patch.object(pipeline, "identity", return_value=(self.identity, {})), \
             patch.object(pipeline, "fresh_output", side_effect=lambda output, *_: (output.mkdir(), output)[1]), \
             patch.object(pipeline, "certificate", return_value=b"fixture certificate"), \
             patch.object(pipeline.compatibility, "compare", return_value={"requiresNewBase": False}), \
             patch.object(pipeline, "verify_signed_apk", return_value={"fixture": True}), \
             patch.object(content_plan, "snapshot", return_value=plan), \
             patch.object(pipeline, "execute", side_effect=operation), \
             patch.object(pipeline, "native_derivation", return_value={"deliveryBinary": str(native)}):
            proof = pipeline.build(args)
        self.assertEqual(proof["kind"], "samplegame-staged-android-candidate-build")
        self.assertIs(proof["packageBuilt"], False)
        self.assertNotIn("rawApk", proof)
        self.assertEqual(proof["candidateBase"]["sha256"], sets.digest(apk))
        self.assertEqual(len(commands), 4)
        self.assertEqual(commands[2][commands[2].index("-MapList") + 1], "+".join(plan_value["requiredMaps"]))
        self.assertEqual(proof["mapInventory"]["requiredMaps"], plan_value["requiredMaps"])
        self.assertEqual(proof["contentPlan"], plan)
        self.assertFalse((args.output / "Archive").exists())
        self.assertFalse((args.output / "quarantine").exists())
        self.assertEqual(old.read_bytes(), b"old default cache")
        self.assertEqual(Path(proof["stageRoot"]), args.output / "Stage/Android_ASTC")
        args.output = self.root / "staged-missing-map"
        listing_maps = pipeline.COOK_MAPS
        with patch.object(pipeline, "identity", return_value=(self.identity, {})), \
             patch.object(pipeline, "certificate", return_value=b"fixture certificate"), \
             patch.object(pipeline.compatibility, "compare", return_value={"requiresNewBase": False}), \
             patch.object(pipeline, "verify_signed_apk", return_value={"fixture": True}), \
             patch.object(content_plan, "snapshot", return_value=plan), \
             patch.object(pipeline, "execute", side_effect=operation):
            with self.assertRaisesRegex(ValueError, "Required maps missing.*NewMap"):
                pipeline.build(args)
        self.assertFalse((args.output / "build-proof.json").exists())
        self.assertEqual(old.read_bytes(), b"old default cache")

    def test_stage_gate_rejects_changed_missing_new_loose_and_new_native_dependency(self):
        for mode in ("changed", "deleted", "new-loose", "new-library", "empty-directory", "unknown-root"):
            with self.subTest(mode=mode):
                stage = self.staged(self.root / mode / "Android_ASTC")
                movie = stage / "SampleGame/Content/Movies/loading.mp4"
                if mode == "changed":
                    movie.write_bytes(b"changed loose movie")
                elif mode == "deleted":
                    movie.unlink(); movie.parent.rmdir()
                elif mode == "new-loose":
                    path = stage / "Engine/Content/Debug/new-loose.dat"; path.parent.mkdir(parents=True); path.write_bytes(b"not in installed APK")
                elif mode == "new-library":
                    (movie.parent / "new-dependency.so").write_bytes(b"not in installed APK")
                elif mode == "empty-directory":
                    (stage / "SampleGame/new-empty-directory").mkdir()
                else:
                    (stage / "unknown.txt").write_bytes(b"unknown routing")
                with self.assertRaises(ValueError):
                    pipeline.verify_stage_shell(stage, self.apk)

    def staged_proof(self):
        proof, project = self.fixture_proof()
        apk, config, base, _, _ = self.prepared()
        stage = self.staged(self.root / "candidate-stage/Android_ASTC")
        delivery = self.root / "stripped-candidate.so"; delivery.write_bytes(b"synthetic native bytes")
        derived = proof["nativeDerivation"]
        derived.update(deliveryBinary=str(delivery), deliverySize=delivery.stat().st_size,
                       deliverySha256=sets.digest(delivery), deliveryElf={"fixture": True})
        derived["operation"]["arguments"] = [derived["stripTool"], "--strip-unneeded", "-o", str(delivery), derived["sourceBinary"]]
        cook = Path(proof["cook"]["path"])
        cook.write_text("synthetic COOK COMMAND COMPLETED\nSTAGE COMMAND COMPLETED\nBUILD SUCCESSFUL")
        proof["cook"]["sha256"] = sets.digest(cook)
        for name in ("rawApk", "rawApkSha256", "rawApkSize", "archiveEntries", "apkShellFiles"):
            proof.pop(name)
        verification = {}
        for name in ("signature", "alignment"):
            log = self.root / ("base-" + name + ".log"); log.write_text("synthetic public APK verification")
            verification[name] = dict(path=str(log), sha256=sets.digest(log), exitCode=0)
        proof.update(kind="samplegame-staged-android-candidate-build", packageBuilt=False, stageRoot=str(stage),
                     stageFiles=pipeline.stage_inventory(stage), looseObbFiles=pipeline.stage_obb_inventory(stage),
                     files=pipeline.stage_payload_records(stage, delivery), candidateBase=dict(path=str(apk), size=apk.stat().st_size,
                     sha256=sets.digest(apk), trust=config["trust"], buildId=base["buildId"], verification=verification))
        proof["mapInventory"] = map_proof(self.root, sorted(stage.rglob("*.pak")), self.root / "staged-maps")
        return proof, project, apk

    def validate_staged(self, proof, project, apk):
        with patch.object(pipeline, "identity", return_value=(self.identity, {})), \
             patch.object(pipeline, "loader_elf", return_value={"fixture": True}), \
             patch.object(pipeline, "certificate", return_value=b"fixture certificate"):
            return pipeline.validate_staged_build(proof, project, self.root, apk)

    def test_real_staged_evidence_has_no_apk_claim_and_rejects_packaging_or_missing_stage_markers(self):
        proof, project, apk = self.staged_proof()
        self.assertEqual(self.validate_staged(proof, project, apk)[0], Path(proof["stageRoot"]))
        for changed in (dict(packageBuilt=True), dict(rawApk="invented.apk")):
            bad = dict(proof, **changed)
            with self.assertRaises(ValueError):
                self.validate_staged(bad, project, apk)
        log = Path(proof["cook"]["path"])
        for message in ("COOK COMMAND COMPLETED\nBUILD SUCCESSFUL", "COOK COMMAND COMPLETED\nSTAGE COMMAND COMPLETED\nPACKAGE COMMAND STARTED\nBUILD SUCCESSFUL"):
            log.write_text(message); proof["cook"]["sha256"] = sets.digest(log)
            with self.assertRaises(ValueError):
                self.validate_staged(proof, project, apk)

    def test_staged_evidence_rejects_replaced_native_or_new_loose_even_with_matching_new_inventory(self):
        proof, project, apk = self.staged_proof()
        stage = Path(proof["stageRoot"])
        path = stage / "SampleGame/Content/Movies/loading.mp4"; path.write_bytes(b"changed loose")
        proof["stageFiles"] = pipeline.stage_inventory(stage)
        proof["looseObbFiles"] = pipeline.stage_obb_inventory(stage)
        with self.assertRaisesRegex(ValueError, "loose OBB"):
            self.validate_staged(proof, project, apk)
        path.write_bytes(b"shell video")
        proof["stageFiles"] = pipeline.stage_inventory(stage)
        proof["looseObbFiles"] = pipeline.stage_obb_inventory(stage)
        Path(proof["nativeDerivation"]["deliveryBinary"]).write_bytes(b"replaced native")
        with self.assertRaisesRegex(ValueError, "native derivation"):
            self.validate_staged(proof, project, apk)

    def test_staged_candidate_signs_only_paired_stage_bytes_against_the_original_installed_apk(self):
        from types import SimpleNamespace
        proof, project, apk = self.staged_proof()
        proof_path = self.root / "candidate-proof.json"; proof_path.write_bytes(sets.canonical(proof))
        freeze = self.root / "freeze.json"; freeze.write_bytes(sets.canonical({"shellCompatibilityId": self.identity["shellCompatibilityId"]}))
        args = SimpleNamespace(player_apk=apk, build_proof=proof_path, project=project, engine=self.root, shell_freeze=freeze,
                               release_id=401, registry_root=self.root / "registry", output=self.root / "signed-stage")
        with patch.object(pipeline, "identity", return_value=(self.identity, {})), \
             patch.object(pipeline, "loader_elf", return_value={"fixture": True}), \
             patch.object(pipeline, "certificate", return_value=b"fixture certificate"), \
             patch.object(pipeline.compatibility, "compare", return_value={"requiresNewBase": False}), \
             patch.object(pipeline, "verify_signed_apk", return_value={"fixture": True}), \
             patch.object(pipeline, "fresh_output", side_effect=lambda output, *_: (output.mkdir(), output)[1]), \
             patch.object(pipeline, "sign_manifest", return_value=b"synthetic fixture signature"):
            receipt = pipeline.candidate(args)
        self.assertEqual(receipt["buildProofKind"], "samplegame-staged-android-candidate-build")
        value = sets.parse((args.output / "manifest.json").read_bytes())
        sets.verify_tree(args.output / "versions/401/payload", value["files"])
        self.assertFalse(any(args.output.rglob("*.apk")))
        self.assertFalse(receipt["runtimeValidated"])

    def test_cropped_engine_is_rejected_before_source_hashing_or_any_compile(self):
        from types import SimpleNamespace
        args = SimpleNamespace(project=self.root / "repo/Project/SampleGame", engine=self.root / "trimmed-editor")
        with patch.object(pipeline, "identity") as fingerprint, patch.object(pipeline, "execute") as operation:
            with self.assertRaisesRegex(ValueError, "complete engine"):
                pipeline.build(args)
            fingerprint.assert_not_called()
            operation.assert_not_called()


PACKAGE_ADAPTER = Path(__file__).resolve().parents[2] / "Package-Project.ps1"
requires_package_adapter = unittest.skipUnless(PACKAGE_ADAPTER.is_file(), "Requires the project-specific Package-Project.ps1 adapter")


@unittest.skipUnless(__import__("os").name == "nt" and __import__("shutil").which("pwsh"), "PowerShell/Windows batch argument integration")
class PackageProjectStageTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.engine = self.root / "synthetic-engine"
        batch = self.engine / "Engine/Build/BatchFiles/RunUAT.bat"; batch.parent.mkdir(parents=True)
        batch.write_text("@echo off\r\necho SYNTHETIC_UAT_ARGS %*\r\nexit /b 0\r\n")

    def run_package(self, *arguments):
        return subprocess.run(["pwsh", "-NoProfile", "-File", str(PACKAGE_ADAPTER), "-EngineRoot", str(self.engine),
                               "-Compiler", "Clang", "-Platform", "Android", "-SkipEditorBuild", "-SkipGameBuild",
                               *[str(item) for item in arguments]], capture_output=True, text=True, encoding="utf-8", errors="replace")

    @requires_package_adapter
    def test_stage_only_passes_real_cook_stage_pak_but_no_package_archive_or_deploy(self):
        result = self.run_package("-StageOnly", "-StagingDirectory", self.root / "fresh-stage")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("SYNTHETIC_UAT_ARGS", result.stdout)
        for argument in ("-cook", "-stage", "-pak", "-skippackage", "-neverpackage", "-skipbuild"):
            self.assertRegex(result.stdout, r"(?:^|\s)" + argument + r"(?:\s|$)")
        self.assertIn("-stagingdirectory=", result.stdout)
        for argument in ("-package", "-archive", "-deploy", "-skipcook", "-iterativecooking"):
            self.assertNotRegex(result.stdout, r"(?:^|\s)" + argument + r"(?:\s|$)")

    @requires_package_adapter
    def test_baseline_default_still_packages_and_archives(self):
        result = self.run_package("-ArchiveDirectory", self.root / "archive")
        self.assertEqual(result.returncode, 0, result.stderr)
        for argument in ("-package", "-archive", "-stage", "-pak"):
            self.assertRegex(result.stdout, r"(?:^|\s)" + argument + r"(?:\s|$)")
        self.assertNotIn("-skippackage", result.stdout)
        self.assertNotIn("-stagingdirectory=", result.stdout)

    def test_quarantine_refuses_real_junctions_in_stage_or_its_parent(self):
        for mode in ("saved-parent", "stage", "nested-stage"):
            with self.subTest(mode=mode):
                root = self.root / mode; project = root / "project"; project.mkdir(parents=True)
                output = root / "output"; output.mkdir()
                target = root / "unrelated-data"; target.mkdir(); (target / "keep.bin").write_bytes(b"do not move")
                if mode == "saved-parent":
                    link = project / "Saved"
                elif mode == "stage":
                    link = project / "Saved/StagedBuilds/Android_ASTC"
                else:
                    link = project / "Saved/StagedBuilds/Android_ASTC/linked-content"
                link.parent.mkdir(parents=True, exist_ok=True)
                create = root / "junction.ps1"
                create.write_text("param([string]$Link,[string]$Target)\n$ErrorActionPreference='Stop'\nNew-Item -ItemType Junction -Path $Link -Target $Target | Out-Null\n", encoding="utf-8")
                created = subprocess.run(["pwsh", "-NoProfile", "-File", str(create), "-Link", str(link), "-Target", str(target)],
                                         capture_output=True, text=True, encoding="utf-8", errors="replace")
                self.assertEqual(created.returncode, 0, created.stderr)
                try:
                    with self.assertRaisesRegex(ValueError, "reparse"):
                        pipeline.quarantine_default_stage(project, output)
                    self.assertEqual((target / "keep.bin").read_bytes(), b"do not move")
                    self.assertTrue(link.is_dir())
                    self.assertFalse((output / "quarantine").exists())
                finally:
                    link.rmdir()  # Remove only the temporary junction, never its target.

    @requires_package_adapter
    def test_stage_only_rejects_missing_reused_or_incremental_output_before_uat(self):
        reused = self.root / "reused"; reused.mkdir()
        for arguments in (("-StageOnly",), ("-StageOnly", "-StagingDirectory", reused),
                          ("-StageOnly", "-StagingDirectory", self.root / "fresh", "-SkipCook"),
                          ("-StageOnly", "-StagingDirectory", self.root / "fresh", "-IterativeCook")):
            with self.subTest(arguments=arguments):
                result = self.run_package(*arguments)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("SYNTHETIC_UAT_ARGS", result.stdout)

    def test_ascii_junction_is_retained_for_ndk_processes_while_safety_resolves_target(self):
        target = self.root / "实体引擎"; target.mkdir()
        alias = self.root / "ascii-engine"
        create = self.root / "create-junction.ps1"
        create.write_text("param([string]$Link,[string]$Target)\n$ErrorActionPreference='Stop'\nNew-Item -ItemType Junction -Path $Link -Target $Target | Out-Null\n", encoding="utf-8")
        result = subprocess.run(["pwsh", "-NoProfile", "-File", str(create), "-Link", str(alias), "-Target", str(target)],
                                capture_output=True, text=True, encoding="utf-8", errors="replace")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(alias.resolve(), target.resolve())
        self.assertEqual(pipeline.process_path(alias), alias.absolute())
        self.assertNotEqual(pipeline.process_path(alias), target.resolve())
        with self.assertRaisesRegex(ValueError, "outside source and engine"):
            pipeline.fresh_output(target / "inside-engine", self.root / "repo/Project/SampleGame", alias)


if __name__ == "__main__":
    unittest.main()
