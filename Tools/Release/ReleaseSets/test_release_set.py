"""Real file/signature/lease transactions; tiny payloads do not execute UE."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import compatibility
import release_set as sets


def policy(schema):
    return dict(schema=schema, readable=list(range(schema + 1)),
                migrations=[dict(**{"from": item}, to=item + 1, id=f"colalab-v{item}-to-v{item+1}") for item in range(schema)])


class ReleaseSetTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="gj-release-set-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.key = Ed25519PrivateKey.generate()
        self.public = self.key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
        self.trust = dict(projectId="SampleGame", platform="Windows", channel="v106-host", baseReleaseId=100,
                          engineBuildId="engine-build", shellCompatibilityId="a" * 64, loaderVersion=1)
        self.old, self.base = self.product(100, b"old", schema=0)
        self.trust["baseManifestSha256"] = hashlib.sha256(self.base).hexdigest()
        self.store = self.new_store()
        self.lease = self.store.lease()
        self.lease.__enter__()
        self.addCleanup(lambda: self.lease.__exit__(None, None, None))
        legacy = self.root / "legacy"
        legacy.mkdir()
        (legacy / "SampleQuickSave.sav").write_bytes(b"original-v0-save")
        self.store.initialize(self.old, self.base, legacy)
        self.base_selection = self.store.boot()
        self.confirm(self.base_selection)
        self.reopen()

    def reopen(self):
        self.lease.__exit__(None, None, None)
        self.store = self.new_store()
        self.lease = self.store.lease()
        self.lease.__enter__()

    def boot(self):
        # Each boot in the model represents a new process, never a live UE swap.
        self.reopen()
        return self.store.boot()

    def new_store(self):
        return sets.ReleaseSetStore(self.root / "store", self.trust, sets.ed25519_verifier(self.public))

    def product(self, release, payload, schema=1, platform=None):
        platform = platform or self.trust["platform"]
        source = self.root / ("product-" + str(release))
        source.mkdir()
        if platform == "Windows":
            names = [("SampleGame/Binaries/Win64/SampleGame.exe", "native"),
                     ("SampleGame/Content/Paks/SampleGame-Windows.pak", "content")]
        else:
            names = [("libUnreal.so", "native"), ("Content/Paks/SampleGame-Android.pak", "content")]
        records = []
        for name, role in names:
            path = source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(role.encode() + b":" + payload)
            records.append(dict(path=name, role=role, size=path.stat().st_size, sha256=sets.digest(path)))
        value = {key: self.trust[key] for key in sets.BINDINGS}
        value.update(platform=platform, format=1, kind="samplegame-release-set", releaseId=release, minLoaderVersion=1,
                     sourceCommit="b" * 40, nativeSourceHash=hashlib.sha256(payload).hexdigest(),
                     files=sorted(records, key=lambda item: item["path"]), save=policy(schema))
        value["buildId"] = sets.build_id(value)
        return source, sets.canonical(value)

    def stage(self, release=101, schema=1):
        source, raw = self.product(release, f"new-{release}".encode(), schema=schema)
        return self.store.stage(source, raw, self.key.sign(raw))

    def confirm(self, selected):
        ref = selected["reference"]
        return self.store.confirm(selected["attemptId"], ref["releaseId"], ref["manifestSha256"], selected["manifest"]["save"]["schema"])

    def assert_pair(self, selected, expected):
        root = Path(selected["payloadRoot"])
        for item in selected["manifest"]["files"]:
            self.assertTrue((root / item["path"]).read_bytes().endswith(expected))

    def test_complete_pair_switches_once_and_staging_is_invisible(self):
        self.stage()
        self.assert_pair(self.store._selection(self.store._state()["active"]), b"old")
        candidate = self.store.activate(101)
        self.assert_pair(candidate, b"new-101")
        selected = self.boot()
        self.confirm(selected)
        self.assertEqual(self.store._state()["active"]["releaseId"], 101)

    def test_unconfirmed_process_recovers_old_pair_and_old_saves(self):
        self.stage()
        candidate = self.store.activate(101)
        (Path(candidate["savesRoot"]) / "SampleQuickSave.sav").write_bytes(b"migrated-in-failed-process")
        self.boot()  # Simulate a process that dies before its acknowledgement.
        recovered = self.boot()
        self.assert_pair(recovered, b"old")
        self.assertEqual((Path(recovered["savesRoot"]) / "SampleQuickSave.sav").read_bytes(), b"original-v0-save")
        self.assertEqual((Path(candidate["savesRoot"]) / "SampleQuickSave.sav").read_bytes(), b"migrated-in-failed-process")
        self.assertEqual(self.store._state()["blocked"], [101])
        self.assertEqual(self.store._state()["highestReleaseId"], 101)

    def test_new_process_reopens_state_instead_of_using_in_memory_selection(self):
        self.stage()
        self.store.activate(101)
        self.boot()
        self.lease.__exit__(None, None, None)
        self.store = self.new_store()
        self.lease = self.store.lease()
        self.lease.__enter__()
        self.assert_pair(self.boot(), b"old")

    def test_failure_after_state_commit_keeps_a_complete_new_pair(self):
        self.stage()
        real_atomic = sets.atomic
        def interrupted(path, value):
            real_atomic(path, value)
            raise OSError("process ended after commit")
        with patch.object(sets, "atomic", side_effect=interrupted):
            with self.assertRaises(OSError):
                self.store.activate(101)
        self.assert_pair(self.boot(), b"new-101")

    def test_failure_before_state_commit_keeps_complete_old_pair(self):
        self.stage()
        with patch.object(sets.os, "replace", side_effect=OSError("interrupted rename")):
            with self.assertRaises(OSError):
                self.store.activate(101)
        self.assert_pair(self.boot(), b"old")
        self.assertEqual(self.store._state()["highestReleaseId"], 100)

    def test_failed_staging_does_not_touch_active(self):
        source, raw = self.product(101, b"incomplete")
        with patch.object(sets, "copy_verified_payload", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                self.store.stage(source, raw, self.key.sign(raw))
        self.assert_pair(self.boot(), b"old")
        self.assertFalse(self.store._path(101).exists())
        self.assertFalse(list((self.store.root / "versions").glob("stage-*")))

    def test_low_disk_space_rejects_payload_without_changing_selection(self):
        source, raw = self.product(101, b"low-space")
        with patch.object(sets.shutil, "disk_usage") as space:
            space.return_value.free = 0
            with self.assertRaises(ValueError):
                self.store.stage(source, raw, self.key.sign(raw))
        self.assert_pair(self.boot(), b"old")

    def test_low_space_for_save_fork_does_not_commit_candidate(self):
        self.stage()
        with patch.object(sets.shutil, "disk_usage") as space:
            space.return_value.free = 0
            with self.assertRaises(ValueError):
                self.store.activate(101)
        self.assertEqual(self.store._state()["active"]["releaseId"], 100)
        self.assertEqual(self.store._state()["highestReleaseId"], 100)

    def test_explicit_startup_failure_rolls_back_both(self):
        self.stage()
        self.store.activate(101)
        selected = self.boot()
        self.assert_pair(self.store.reject(selected["attemptId"]), b"old")

    def test_corrupt_content_rejects_native_too(self):
        self.stage()
        self.store.activate(101)
        pak = self.store._path(101) / "SampleGame/Content/Paks/SampleGame-Windows.pak"
        pak.write_bytes(b"corrupted")
        self.assert_pair(self.boot(), b"old")

    def test_corrupt_native_rejects_content_too(self):
        self.stage()
        self.store.activate(101)
        binary = self.store._path(101) / "SampleGame/Binaries/Win64/SampleGame.exe"
        binary.write_bytes(b"corrupted")
        self.assert_pair(self.boot(), b"old")

    def test_corrupt_selected_and_previous_falls_back_to_verified_base(self):
        self.stage()
        self.store.activate(101)
        self.confirm(self.boot())
        self.reopen()
        self.stage(102)
        self.store.activate(102)
        self.boot()
        (self.store._path(101) / "SampleGame/Content/Paks/SampleGame-Windows.pak").write_bytes(b"bad")
        self.assert_pair(self.boot(), b"old")

    def test_corrupt_base_cannot_be_silently_called_healthy(self):
        (self.store._path(100) / "SampleGame/Content/Paks/SampleGame-Windows.pak").write_bytes(b"bad")
        with self.assertRaises(ValueError):
            self.boot()

    def test_stale_health_acknowledgement_cannot_confirm_another_attempt(self):
        first = self.boot()
        self.confirm(first)
        second = self.boot()
        with self.assertRaises(ValueError):
            self.confirm(first)
        self.confirm(second)

    def test_wrong_set_or_save_schema_cannot_confirm(self):
        self.stage()
        self.store.activate(101)
        selected = self.boot()
        with self.assertRaises(ValueError):
            self.store.confirm(selected["attemptId"], 101, selected["reference"]["manifestSha256"], 0)
        with self.assertRaises(ValueError):
            self.store.confirm(selected["attemptId"], 100, selected["reference"]["manifestSha256"], 1)
        with self.assertRaises(ValueError):
            self.store.confirm(selected["attemptId"], 101, "0" * 64, 1)
        self.confirm(selected)

    def test_rollback_never_reaccepts_failed_version(self):
        release = self.stage()
        self.store.activate(release)
        selected = self.boot()
        self.store.reject(selected["attemptId"])
        self.reopen()
        with self.assertRaises(ValueError):
            self.store.activate(release)
        raw = (self.store._path(release) / "manifest.json").read_bytes()
        with self.assertRaises(ValueError):
            self.store.stage(self.root / "product-101", raw, self.key.sign(raw))
        self.stage(102)
        self.assertEqual(self.store.activate(102)["reference"]["releaseId"], 102)

    def test_stage_signature_is_verified_before_copy(self):
        source, raw = self.product(101, b"signed")
        with self.assertRaises(Exception):
            self.store.stage(source, raw, Ed25519PrivateKey.generate().sign(raw))
        self.assertFalse(self.store._path(101).exists())

    def test_cached_manifest_signature_is_rechecked_at_boot(self):
        self.stage()
        self.store.activate(101)
        (self.store._path(101) / "manifest.sig").write_bytes(b"x" * 64)
        self.assert_pair(self.boot(), b"old")
        self.assertEqual(self.store._state()["blocked"], [101])

    def test_save_forks_are_independent_and_preserve_legacy_bytes(self):
        self.stage()
        selected = self.store.activate(101)
        old = Path(self.base_selection["savesRoot"]) / "SampleQuickSave.sav"
        new = Path(selected["savesRoot"]) / "SampleQuickSave.sav"
        self.assertNotEqual(old.parent, new.parent)
        self.assertEqual(old.read_bytes(), new.read_bytes())
        new.write_bytes(b"new-schema")
        self.assertEqual(old.read_bytes(), b"original-v0-save")

    def test_missing_save_migration_rejects_activation(self):
        source, raw = self.product(101, b"incompatible")
        value = sets.parse(raw)
        value["save"] = dict(schema=1, readable=[1], migrations=[])
        value["buildId"] = sets.build_id(value)
        raw = sets.canonical(value)
        self.store.stage(source, raw, self.key.sign(raw))
        with self.assertRaises(ValueError):
            self.store.activate(101)

    def test_migration_path_must_be_explicit_contiguous_and_unique(self):
        for value in (dict(schema=2, readable=[0, 2], migrations=[]),
                      dict(schema=1, readable=[0, 1], migrations=[{"from": 0, "to": 2, "id": "skip"}])):
            with self.subTest(value=value), self.assertRaises(ValueError):
                sets.save_policy(value)

    def test_unknown_extra_missing_and_case_colliding_payloads_rejected(self):
        source, raw = self.product(101, b"inventory")
        (source / "unlisted.dll").write_bytes(b"unlisted")
        with self.assertRaises(ValueError):
            self.store.stage(source, raw, self.key.sign(raw))
        (source / "unlisted.dll").unlink()
        value = sets.parse(raw)
        value["files"].append(copy.deepcopy(value["files"][0]))
        value["buildId"] = sets.build_id(value)
        with self.assertRaises(ValueError):
            sets.manifest(sets.canonical(value), self.trust)

    def test_cross_shell_build_and_platform_rejected(self):
        _, raw = self.product(101, b"cross")
        for field, value in (("platform", "Android_ARM64"), ("shellCompatibilityId", "c" * 64),
                             ("baseReleaseId", 99), ("engineBuildId", "other"), ("minLoaderVersion", 2)):
            changed = sets.parse(raw)
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                sets.manifest(sets.canonical(changed), self.trust)

    def test_native_content_binding_cannot_be_relabelled(self):
        _, raw = self.product(101, b"mixed")
        value = sets.parse(raw)
        value["nativeSourceHash"] = "e" * 64
        with self.assertRaises(ValueError):
            sets.manifest(sets.canonical(value), self.trust)

    def test_android_manifest_uses_same_transaction_contract(self):
        _, raw = self.product(101, b"android", platform="Android_ARM64")
        trust = dict(self.trust, platform="Android_ARM64")
        value = sets.manifest(raw, trust)
        self.assertEqual({item["role"] for item in value["files"]}, {"native", "content"})

    def test_unsafe_paths_noncanonical_json_and_boolean_ids_rejected(self):
        for value in ("../escape", "x/../escape", "C:/absolute", "x\\y", "CON.txt", "/root", "x/./a", "x//a"):
            with self.subTest(path=value), self.assertRaises(ValueError):
                sets.relative(value)
        for raw in (b'{"a":1,"a":2}', b'{ "a":1}', b'{"a":NaN}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                sets.parse(raw)
        with self.assertRaises(ValueError):
            sets.number(True)

    def test_mutations_require_exclusive_os_lease(self):
        another = self.new_store()
        with self.assertRaises(ValueError):
            another.boot()
        with self.assertRaises(OSError):
            with another.lease():
                self.fail("A second process lease was granted")

    def test_confirmed_running_process_cannot_activate_another_pair(self):
        selected = self.boot()
        self.confirm(selected)
        self.stage()
        with self.assertRaises(ValueError):
            self.store.activate(101)
        with self.assertRaises(ValueError):
            self.store.boot()
        self.reopen()
        self.store.activate(101)
        self.assert_pair(self.store.boot(), b"new-101")

    def test_explicit_failure_requires_new_process_before_loading_fallback(self):
        self.stage()
        self.store.activate(101)
        selected = self.boot()
        self.store.reject(selected["attemptId"])
        with self.assertRaises(ValueError):
            self.store.boot()
        self.assert_pair(self.boot(), b"old")


    def test_save_handover_verifies_manifest_but_does_not_need_old_executable(self):
        self.stage()
        selected = self.store.activate(101)
        self.confirm(self.store.boot())
        before = (self.store.root / "state.json").read_bytes()
        executable = Path(selected["payloadRoot"]) / "SampleGame/Binaries/Win64/SampleGame.exe"
        executable.write_bytes(b"damaged-old-code")
        imported = self.store.confirmed_save_source([1])
        self.assertEqual(imported["reference"]["releaseId"], 101)
        self.assertEqual((self.store.root / "state.json").read_bytes(), before)
        with self.assertRaisesRegex(ValueError, "cannot read"):
            self.store.confirmed_save_source([0])
        (Path(selected["payloadRoot"]) / "manifest.sig").write_bytes(b"x" * 64)
        with self.assertRaisesRegex(ValueError, "signature rejected"):
            self.store.confirmed_save_source([1])

    def test_interrupted_first_import_retries_without_overwriting_source_saves(self):
        target = sets.ReleaseSetStore(self.root / "new-baseline", self.trust, sets.ed25519_verifier(self.public))
        source = self.store.confirmed_save_source([0])["savesRoot"]
        before = (Path(source) / "SampleQuickSave.sav").read_bytes()
        with target.lease():
            with patch.object(sets, "atomic", side_effect=OSError("interrupted initial commit")):
                with self.assertRaises(OSError):
                    target.initialize(self.old, self.base, source)
            self.assertFalse((target.root / "state.json").exists())
            selected = target.initialize(self.old, self.base, source)
            self.assertEqual((Path(selected["savesRoot"]) / "SampleQuickSave.sav").read_bytes(), before)
        self.assertEqual((Path(source) / "SampleQuickSave.sav").read_bytes(), before)


class CompatibilityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="gj-shell-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        for name in ("SampleGame.uproject", "Source/Game/Player.h", "Source/Game/Game.Build.cs",
                     "Content/Example.uasset", "Config/DefaultEngine.ini", "Build/Android/AndroidManifest.xml",
                     "Plugins/Update/Source/Android/Java/Loader.java"):
            self.write(name, "baseline")
        self.base = compatibility.freeze(self.root, "engine")

    def write(self, name, text):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def compare(self, engine="engine", new=None):
        return compatibility.compare(self.base, self.root, engine, policy(0), new or policy(1))

    def test_gameplay_header_and_content_changes_require_full_pair_evidence(self):
        self.write("Source/Game/Player.h", "new class layout")
        self.write("Content/Example.uasset", "matching blueprint")
        result = self.compare()
        self.assertFalse(result["requiresNewBase"])
        self.assertFalse(result["productionQualified"])
        self.assertIn("same-commit-full-cook", result["requiredEvidence"])
        self.assertEqual({item["kind"] for item in result["changes"]}, {"gameplay-native", "cooked-content"})

    def test_java_manifest_build_config_and_engine_remain_frozen(self):
        for name in ("Config/DefaultEngine.ini", "Source/Game/Game.Build.cs", "Build/Android/AndroidManifest.xml",
                     "Plugins/Update/Source/Android/Java/Loader.java"):
            self.write(name, "changed")
        self.assertTrue(self.compare()["requiresNewBase"])
        self.assertTrue(self.compare("new-engine")["requiresNewBase"])

    def test_unknown_native_input_is_conservatively_shell(self):
        self.write("Source/Game/External.assembly", "unknown")
        self.assertTrue(self.compare()["requiresNewBase"])

    def test_generated_cook_logs_do_not_change_the_frozen_installation_shell(self):
        for name in compatibility.GENERATED_COOK_LOGS:
            self.write(name, "Cook regenerated this output")
        result = self.compare()
        self.assertFalse(result["requiresNewBase"])
        self.assertEqual(result["changes"], [])
        # Authored ordering and PSO inputs must remain frozen; do not ignore an entire Build subtree.
        self.write("Build/Windows/FileOpenOrder/GameOpenOrder.log", "authored recorded order")
        self.assertTrue(self.compare()["requiresNewBase"])

    def test_only_the_proven_fixed_android_java_and_astc_outputs_bypass_freeze(self):
        expected_java = {"Build/Android/src/com/epicgames/unreal/DownloadShim.java",
                         "Build/Android/src/com/team/samplegame/AlarmReceiver.java",
                         "Build/Android/src/com/team/samplegame/DownloaderActivity.java",
                         "Build/Android/src/com/team/samplegame/OBBData.java",
                         "Build/Android/src/com/team/samplegame/OBBDownloaderService.java"}
        self.assertEqual(compatibility.GENERATED_ANDROID_JAVA, expected_java)
        self.assertEqual(compatibility.GENERATED_COOK_LOGS, {
            "Build/Windows/FileOpenOrder/CookerOpenOrder.log", "Build/Windows/FileOpenOrder/EditorOpenOrder.log",
            "Build/Android_ASTC/FileOpenOrder/CookerOpenOrder.log", "Build/Android_ASTC/FileOpenOrder/EditorOpenOrder.log"})
        for name in sorted(expected_java | compatibility.GENERATED_COOK_LOGS):
            self.write(name, "synthetic generated output")
        before = compatibility.freeze(self.root, "engine")
        for name in sorted(expected_java | compatibility.GENERATED_COOK_LOGS):
            self.write(name, "regenerated bytes with different length")
        self.assertEqual(compatibility.freeze(self.root, "engine"), before)
        self.assertEqual(before, self.base)
        self.assertEqual(self.compare()["changes"], [])
        self.assertFalse(self.compare()["requiresNewBase"])

    def test_custom_java_templates_other_platforms_game_order_and_pso_stay_frozen(self):
        cases = ("Build/Android/src/com/team/samplegame/CustomLoader.java",
                 "Build/Android/src/com/epicgames/unreal/GameActivity.java",
                 "Build/Android/src/com/other/game/OBBData.java",
                 "Build/Android/src/com/epicgames/custom/DownloadShim.java",
                 "Build/Android/src/com/team/samplegame/obbdata.java",
                 "Build/Android/JavaTemplates/DownloaderActivity.java.template",
                 "Build/Android_ASTC/FileOpenOrder/GameOpenOrder.log",
                 "Build/Android_ASTC/FileOpenOrder/GameOpenOrder-Recorded.log",
                 "Build/Android_ASTC/FileOpenOrder/CookerOpenOrder-Custom.log",
                 "Build/Android/FileOpenOrder/CookerOpenOrder.log",
                 "Build/Android_ETC2/FileOpenOrder/EditorOpenOrder.log",
                 "Build/Android_ASTC/PipelineCaches/SampleGame.stable.upipelinecache",
                 "Build/Android_ASTC/PipelineCaches/SampleGame.spc")
        for name in cases:
            with self.subTest(path=name):
                self.assertEqual(compatibility.classify(name), "shell")
                self.write(name, "authored shell input")
                result = self.compare()
                self.assertTrue(result["requiresNewBase"])
                self.assertEqual([(item["path"], item["kind"]) for item in result["changes"]], [(name, "shell")])
                (self.root / name).unlink()

    def test_old_freeze_containing_generated_java_cannot_be_relabelled_as_new(self):
        # Synthetic old-policy snapshot: actual producer proofs are never edited.
        import copy
        import hashlib
        old = copy.deepcopy(self.base)
        name = "Build/Android/src/com/team/samplegame/OBBData.java"
        self.write(name, "old generated length")
        old["files"].append(dict(path=name, kind="shell", size=(self.root / name).stat().st_size,
                                  sha256=sets.digest(self.root / name)))
        old["files"].sort(key=lambda item: item["path"])
        old["shellCompatibilityId"] = hashlib.sha256(sets.canonical(dict(policy=old["policy"],
            engineBuildId=old["engineBuildId"], files=[item for item in old["files"] if item["kind"] == "shell"]))).hexdigest()
        result = compatibility.compare(old, self.root, "engine", policy(0), policy(1))
        self.assertTrue(result["requiresNewBase"])
        self.assertIn("frozen-shell-or-engine-changed", result["reasons"])

    def test_save_schema_without_path_requires_new_base_or_explicit_migration(self):
        self.assertTrue(self.compare(new=dict(schema=1, readable=[1], migrations=[]))["requiresNewBase"])


if __name__ == "__main__":
    unittest.main()
