"""Real signed ZIP, filesystem transaction and child-exit tests; no UE claim."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import zipfile

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption

SPEC = importlib.util.spec_from_file_location("native_launcher", Path(__file__).with_name("native_launcher.py"))
native = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(native)
GAME = "SampleGame/Binaries/Win64/SampleGame.exe"
DLL = "SampleGame/Binaries/Win64/Companion.dll"


class NativeUpdateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.key = Ed25519PrivateKey.generate()
        self.base = {GAME: b"base-executable", DLL: b"base-companion"}
        for name, data in self.base.items():
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        self.config = dict(format=1, projectId="SampleGame", channel="test-native", platform="Windows", baseReleaseId=123,
                           engineBuildId="test-engine-id", compatibilityId="test-compatibility-id", manifestUrl="https://updates.example.com/game/native/manifest.json",
                           publicKeyHex=self.key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex(),
                           nativeFiles=self.records(self.base), contentLauncher="SampleContent.exe", contentConfig="sample-player.json", allowOffline=True)
        self.config_path = self.root / "native-player.json"
        self.config_path.write_text(json.dumps(self.config), encoding="utf-8")
        (self.root / "SampleContent.exe").write_bytes(b"frozen-delegate-placeholder")
        (self.root / "sample-player.json").write_text('{"fixedContentTrust":"unchanged"}', encoding="utf-8")
        self.install = native.NativeInstallation(self.root, self.config)
        self.install.recover()

    @staticmethod
    def records(files):
        return [{"path": name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()} for name, data in files.items()]

    def candidate(self, number=1, files=None, zip_entries=None, mutation=None):
        files = files or {GAME: b"updated-executable", DLL: b"updated-companion"}
        archive = self.root / f"payload-{number}-{len(list(self.root.glob('payload*')))}.zip"
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zipped:
            for name, data in (zip_entries or files).items():
                zipped.writestr(name, data)
        manifest = {key: self.config[key] for key in native.IDENTITY}
        manifest.update(format=1, kind="samplegame-native-windows", nativeVersion=number,
                        archive={"path": f"versions/{number}/native-windows.zip", "size": archive.stat().st_size, "sha256": native.digest(archive)},
                        files=self.records(files))
        if mutation:
            mutation(manifest)
        raw = json.dumps(manifest, separators=(",", ":")).encode()
        return raw, self.key.sign(raw), archive

    def stage(self, number=1):
        raw, signature, archive = self.candidate(number)
        return self.install.stage(raw, signature, archive)

    def test_signed_native_update_clean_child_exit_commits_at_original_game_path(self):
        candidate = self.stage()
        self.install.activate(candidate)
        self.assertEqual((self.root / GAME).read_bytes(), b"updated-executable")
        self.assertEqual(self.install.state()["pendingVersion"], candidate)
        self.install.finish(True)
        self.assertEqual(self.install.state()["activeVersion"], 1)
        self.assertFalse(self.install.journal_path.exists())
        self.assertEqual((self.root / "sample-player.json").read_text(), '{"fixedContentTrust":"unchanged"}')

    def test_bad_exit_and_interrupted_pending_restore_every_original_file_and_block_candidate(self):
        for interrupted in (False, True):
            with self.subTest(interrupted=interrupted):
                number = 1 if not interrupted else 2
                self.install.activate(self.stage(number))
                if interrupted:
                    native.NativeInstallation(self.root, self.config).recover()
                else:
                    self.install.finish(False)
                for name, data in self.base.items():
                    self.assertEqual((self.root / name).read_bytes(), data)
                self.assertIn(number, self.install.state()["blockedVersions"])
                self.assertEqual(self.install.state()["activeVersion"], 0)

    def test_partial_multifile_apply_recovers_from_preexisting_journal(self):
        number = self.stage()
        real_apply = self.install.apply
        def partial_then_fail(version):
            (self.root / GAME).write_bytes(b"updated-executable")
            raise OSError("injected second-file replace failure")
        with patch.object(self.install, "apply", partial_then_fail), self.assertRaises(OSError):
            self.install.activate(number)
        self.install.apply = real_apply
        self.install.recover()
        for name, data in self.base.items():
            self.assertEqual((self.root / name).read_bytes(), data)
        self.assertEqual(self.install.state()["blockedVersions"], [number])

    def test_commit_then_journal_cleanup_interruption_keeps_committed_version(self):
        number = self.stage()
        self.install.activate(number)
        state = self.install.state()
        state.update(activeVersion=number, pendingVersion=0)
        native.atomic_json(self.install.state_path, state)
        self.install.recover()
        self.assertEqual(self.install.state()["activeVersion"], number)
        self.assertEqual((self.root / GAME).read_bytes(), b"updated-executable")

    def test_downgrade_blocked_and_immutable_native_version_rejected(self):
        self.install.activate(self.stage(2))
        self.install.finish(True)
        with self.assertRaisesRegex(ValueError, "downgrade"):
            self.install.stage(*self.candidate(1))
        third = self.stage(3)
        changed = self.candidate(3, {GAME: b"different-executable", DLL: b"different-companion"})
        with self.assertRaisesRegex(ValueError, "immutable"):
            self.install.stage(*changed)
        self.assertEqual(third, 3)

    def test_signature_identity_size_and_hash_corruption_are_rejected(self):
        raw, signature, archive = self.candidate()
        with self.assertRaisesRegex(ValueError, "signature"):
            native.signed_manifest(raw + b" ", signature, self.config)
        changed = self.candidate(2, mutation=lambda value: value.update(baseReleaseId=999))
        with self.assertRaisesRegex(ValueError, "identity"):
            self.install.stage(*changed)
        archive.write_bytes(archive.read_bytes() + b"corrupt")
        with self.assertRaisesRegex(ValueError, "archive"):
            self.install.stage(raw, signature, archive)

    def test_signed_zip_traversal_extra_entries_and_symlinks_are_rejected(self):
        for unsafe in ("../outside.exe", "/absolute.exe", "C:/outside.exe", GAME.upper()):
            with self.subTest(unsafe=unsafe):
                entries = {GAME: b"updated-executable", DLL: b"updated-companion", unsafe: b"unexpected"}
                with self.assertRaises(ValueError):
                    self.install.stage(*self.candidate(zip_entries=entries))
        files = {GAME: b"link-target", DLL: b"updated-companion"}
        raw, _, archive = self.candidate(files=files)
        with zipfile.ZipFile(archive, "w") as zipped:
            info = zipfile.ZipInfo(GAME)
            info.create_system = 3
            info.external_attr = (0o120777 << 16)
            zipped.writestr(info, files[GAME])
            zipped.writestr(DLL, files[DLL])
        manifest = json.loads(raw)
        manifest["archive"].update(size=archive.stat().st_size, sha256=native.digest(archive))
        raw = json.dumps(manifest).encode()
        with self.assertRaisesRegex(ValueError, "links"):
            self.install.stage(raw, self.key.sign(raw), archive)

    def test_missing_allowlist_dll_cannot_create_mixed_native_version(self):
        with self.assertRaisesRegex(ValueError, "complete"):
            self.install.stage(*self.candidate(files={GAME: b"only-one-file"}))

    def test_installed_tamper_repairs_only_from_verified_cache(self):
        self.install.activate(self.stage())
        self.install.finish(True)
        (self.root / GAME).write_bytes(b"tampered")
        self.install.recover()
        self.assertEqual((self.root / GAME).read_bytes(), b"updated-executable")
        (self.install.version(1) / GAME).write_bytes(b"cache-corrupt")
        with self.assertRaises(ValueError):
            self.install.recover()

    def test_json_duplicates_url_schemes_and_windows_paths_are_not_accepted(self):
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            native.parse_json(b'{"format":1,"format":1}')
        for url in ("http://updates.example.com/manifest.json", "https://u:p@example/manifest.json", "https://example/manifest.json?q=1"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                native.https_origin(url)
        for name in ("../x.exe", "CON.exe", "safe/NUL.dll", "x\\y.exe", "file.exe:stream", "safe/../file.exe", "safe//file.exe"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                native.relative_path(name)

    def test_all_compatibility_fields_are_enforced_even_with_a_valid_signature(self):
        for field in native.IDENTITY:
            def mutation(value):
                value[field] = 999 if field == "baseReleaseId" else "other-identity"
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.install.stage(*self.candidate(mutation=mutation))

    def test_redirects_and_download_overflow_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "redirect"):
            native.NoRedirect().redirect_request(None, None, 302, "redirect", {}, "https://other.example/file")
        class Response:
            headers = {"Content-Length": "11"}
            def __enter__(self): return self
            def __exit__(self, *arguments): pass
            def geturl(self): return "https://example.test/file"
        class Opener:
            def open(self, *arguments, **keywords): return Response()
        with patch.object(native, "build_opener", return_value=Opener()), self.assertRaisesRegex(ValueError, "limit"):
            native.fetch("https://example.test/file", 10)

    def test_wrapper_configuration_preserves_actual_game_and_frozen_content_trust(self):
        spec = importlib.util.spec_from_file_location("native_distribution", Path(__file__).with_name("native_distribution.py"))
        distribution = importlib.util.module_from_spec(spec)
        with patch.dict(sys.modules, native_launcher=native):
            spec.loader.exec_module(distribution)
        install = self.root / "fresh-install"
        game = install / GAME
        game.parent.mkdir(parents=True)
        game.write_bytes(b"real-verified-base-game")
        (install / "SampleGame.exe").write_bytes(b"frozen-samplecontent-content-entry")
        content = {key: self.config[key] for key in native.IDENTITY[:-1]}
        content.update(publicKeyHex=self.config["publicKeyHex"], gameExe=GAME)
        raw_content = json.dumps(content).encode()
        (install / "sample-player.json").write_bytes(raw_content)
        build = self.root / "launcher-build"
        (build / "_native_internal").mkdir(parents=True)
        (build / "SampleGameNativeLauncher.exe").write_bytes(b"new-native-wrapper")
        (build / "_native_internal" / "fixture.dll").write_bytes(b"runtime")
        distribution.configure(install, build, self.config["manifestUrl"], "fixture-compat")
        self.assertEqual(game.read_bytes(), b"real-verified-base-game")
        self.assertEqual((install / "sample-player.json").read_bytes(), raw_content)
        self.assertEqual((install / "SampleContent.exe").read_bytes(), b"frozen-samplecontent-content-entry")
        self.assertEqual((install / "SampleGame.exe").read_bytes(), b"new-native-wrapper")
        self.assertEqual(native.read_config(install / "native-player.json")["nativeFiles"][0]["path"], GAME)

    def test_producer_emits_client_verified_immutable_signed_release(self):
        spec = importlib.util.spec_from_file_location("publish_native_windows", Path(__file__).with_name("publish_native_windows.py"))
        producer = importlib.util.module_from_spec(spec)
        with patch.dict(sys.modules, native_launcher=native):
            spec.loader.exec_module(producer)
        source = self.root / "native-source"
        for name in (GAME, DLL):
            data = bytearray(256)
            data[:2] = b"MZ"
            struct.pack_into("<I", data, 60, 128)
            data[128:132] = b"PE\0\0"
            struct.pack_into("<H", data, 132, 0x8664)
            struct.pack_into("<H", data, 150, 2 | (0x2000 if name.endswith(".dll") else 0))
            struct.pack_into("<H", data, 152, 0x20B)
            target = source / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        key = self.root / "fixture-signing-key.pem"
        key.write_bytes(self.key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
        output = self.root / "native-release-1"
        receipt = producer.publish(self.config_path, source, key, 1, output)
        self.assertTrue(receipt["clientSignatureVerified"])
        self.assertTrue(receipt["clientExtractVerified"])
        self.assertFalse(receipt["realUERuntimeValidated"])
        self.install.stage((output / "manifest.json").read_bytes(), (output / "manifest.json.sig").read_bytes(), output / "versions/1/native-windows.zip")
        with self.assertRaisesRegex(ValueError, "fresh"):
            producer.publish(self.config_path, source, key, 1, output)
        with self.assertRaisesRegex(ValueError, "reserved/published"):
            producer.publish(self.config_path, source, key, 1, self.root / "different-output-same-version")
        (source / GAME).write_bytes(b"not-a-pe")
        with self.assertRaisesRegex(ValueError, "PE image"):
            producer.publish(self.config_path, source, key, 2, self.root / "native-release-2")

    def test_real_child_exit_is_preserved_and_content_trust_configuration_is_unchanged(self):
        real_subprocess = subprocess.run
        before = (self.root / "sample-player.json").read_bytes()
        for number, code in ((1, 0), (2, 7)):
            candidate = self.stage(number)
            def child(command, **kwargs):
                self.assertEqual(Path(command[0]), self.root / "SampleContent.exe")
                self.assertEqual(Path(command[1]), self.root / "sample-player.json")
                self.assertNotIn("--headless", command)
                self.assertEqual(kwargs["cwd"], self.root)
                return real_subprocess([sys.executable, "-c", f"import sys;sys.exit({code})"], **kwargs)
            with patch.object(native, "check_update", return_value=candidate), patch.object(native.subprocess, "run", side_effect=child):
                self.assertEqual(native.run(self.config_path), code)
            self.assertEqual(self.install.state()["activeVersion"], 1)
        self.assertEqual((self.root / "sample-player.json").read_bytes(), before)

    def test_live_game_prevents_mutation_and_transaction_can_recover(self):
        candidate = self.stage()
        with patch.object(native, "running_managed_game", return_value=True), patch.object(native, "NATIVE_REPLACE_WAIT_SECONDS", 0), self.assertRaisesRegex(ValueError, "running"):
            self.install.activate(candidate)
        for name, data in self.base.items():
            self.assertEqual((self.root / name).read_bytes(), data)
        self.install.recover()
        self.assertEqual(self.install.state()["activeVersion"], 0)

    def test_matching_process_exiting_after_snapshot_is_rescanned_not_assumed_absent(self):
        with patch.object(native, "_running_managed_game_once", side_effect=[native.ProcessInspectionError("pid disappeared"), False]) as scan, patch.object(native.time, "sleep") as sleep:
            self.assertFalse(native.running_managed_game(self.root, self.install.base_records))
        self.assertEqual(scan.call_count, 2)
        sleep.assert_called_once_with(0.05)

    def test_persistent_unknown_process_permissions_preserve_pending_recovery_journal(self):
        self.install.activate(self.stage())
        with patch.object(native, "_running_managed_game_once", side_effect=native.ProcessInspectionError("pid=42 winerror=5")) as scan, patch.object(native.time, "sleep"), self.assertRaisesRegex(native.ProcessInspectionError, "winerror=5"):
            self.install.finish(False)
        self.assertEqual(scan.call_count, native.PROCESS_SCAN_ATTEMPTS)
        self.assertTrue(self.install.journal_path.exists())
        self.assertEqual(self.install.state()["pendingVersion"], 1)
        self.assertEqual((self.root / GAME).read_bytes(), b"updated-executable")
        self.install.recover()
        self.assertEqual(self.install.state()["blockedVersions"], [1])

    def test_terminated_handle_and_exit_during_image_query_are_not_live_games(self):
        dead = SimpleNamespace(WaitForSingleObject=Mock(return_value=0), QueryFullProcessImageNameW=Mock())
        self.assertIsNone(native._process_image_if_alive(dead, 123, 42))
        dead.QueryFullProcessImageNameW.assert_not_called()
        exiting = SimpleNamespace(WaitForSingleObject=Mock(side_effect=[258, 0]), QueryFullProcessImageNameW=Mock(return_value=0))
        self.assertIsNone(native._process_image_if_alive(exiting, 123, 42))
        unknown = SimpleNamespace(WaitForSingleObject=Mock(return_value=258), QueryFullProcessImageNameW=Mock(return_value=0))
        with self.assertRaisesRegex(native.ProcessInspectionError, "image path pid=42"):
            native._process_image_if_alive(unknown, 123, 42)

    def test_process_exit_wait_and_transient_image_lock_allow_complete_verified_rollback(self):
        self.install.activate(self.stage())
        clock = SimpleNamespace(now=0.0)
        def sleep(seconds):
            clock.now += seconds
        real_replace = os.replace
        attempts = []
        def replace(source, target):
            if Path(target) == self.root / GAME and ".native-" in Path(source).name:
                attempts.append(str(source))
                if len(attempts) <= 2:
                    error = PermissionError("injected exiting image sharing violation")
                    error.winerror = 32
                    raise error
            return real_replace(source, target)
        presence = iter([True, False])
        with patch.object(native, "running_managed_game", side_effect=lambda *args: next(presence, False)), patch.object(native.time, "monotonic", side_effect=lambda: clock.now), patch.object(native.time, "sleep", side_effect=sleep), patch.object(native.os, "replace", side_effect=replace):
            self.install.finish(False)
        self.assertEqual(len(attempts), 3)
        self.assertGreaterEqual(clock.now, 0.3 - 1.e-9)
        self.assertEqual(self.install.state()["activeVersion"], 0)
        self.assertEqual(self.install.state()["blockedVersions"], [1])
        self.assertFalse(self.install.journal_path.exists())
        for name, data in self.base.items():
            self.assertEqual((self.root / name).read_bytes(), data)

    def test_persistent_image_lock_times_out_without_false_commit_and_remains_recoverable(self):
        self.install.activate(self.stage())
        clock = SimpleNamespace(now=0.0)
        def sleep(seconds):
            clock.now += seconds
        real_replace = os.replace
        def replace(source, target):
            if Path(target) == self.root / GAME and ".native-" in Path(source).name:
                error = PermissionError("persistent native image lock")
                error.winerror = 32
                raise error
            return real_replace(source, target)
        with patch.object(native, "running_managed_game", return_value=False), patch.object(native.time, "monotonic", side_effect=lambda: clock.now), patch.object(native.time, "sleep", side_effect=sleep), patch.object(native.os, "replace", side_effect=replace), self.assertRaisesRegex(PermissionError, "persistent native image lock"):
            self.install.finish(False)
        self.assertAlmostEqual(clock.now, native.NATIVE_REPLACE_WAIT_SECONDS)
        self.assertEqual(self.install.state()["pendingVersion"], 1)
        self.assertTrue(self.install.journal_path.exists())
        self.assertEqual((self.root / GAME).read_bytes(), b"updated-executable")
        self.install.recover()
        self.assertEqual(self.install.state()["activeVersion"], 0)
        self.assertEqual(self.install.state()["blockedVersions"], [1])

    def test_headless_unexpected_recovery_exception_is_written_to_actual_log(self):
        with patch.object(native, "run", side_effect=PermissionError("injected rollback permission failure")):
            self.assertEqual(native.main([str(self.config_path), "--headless"]), 1)
        log = (self.root / "native-update.log").read_text(encoding="utf-8")
        self.assertIn("NATIVE_CHECK_START", log)
        self.assertIn("Traceback (most recent call last)", log)
        self.assertIn("PermissionError: injected rollback permission failure", log)

    def public_fetch(self, raw, signature, archive=None):
        requests = []
        def fetch(url, maximum, destination=None, progress=None):
            requests.append(url)
            if url == self.config["manifestUrl"]:
                return raw
            if url == self.config["manifestUrl"] + ".sig":
                return signature
            self.assertIsNotNone(archive, "An already staged native version must make zero archive requests")
            self.assertTrue(url.endswith("/versions/1/native-windows.zip"))
            data = archive.read_bytes()
            self.assertLessEqual(len(data), maximum)
            Path(destination).write_bytes(data)
            return len(data)
        return requests, fetch

    def test_fresh_candidate_miss_downloads_and_stages_without_fabricating_activation_state(self):
        raw, signature, archive = self.candidate()
        requests, fetch = self.public_fetch(raw, signature, archive)
        before = self.install.state()
        def download(installation, url, manifest, signed_raw, signed_signature, progress):
            self.assertEqual((signed_raw, signed_signature), (raw, signature))
            target, sidecar = native.archive_partial_paths(installation, manifest['nativeVersion'])
            fetch(url, manifest['archive']['size'], target, progress)
            return target
        with patch.object(native, "fetch", side_effect=fetch), patch.object(native, "download_archive", side_effect=download):
            self.assertEqual(native.check_update(self.install), 1)
        self.assertEqual(len(requests), 3)
        self.assertTrue(requests[-1].endswith("/versions/1/native-windows.zip"))
        self.install.verify_version(1)
        self.assertEqual(self.install.state(), before)
        self.assertFalse(self.install.journal_path.exists())

    def test_exact_verified_staged_candidate_reuses_cache_and_normal_activation_transaction(self):
        self.stage()
        directory = self.install.version(1)
        raw = (directory / "manifest.json").read_bytes()
        signature = (directory / "manifest.json.sig").read_bytes()
        before = self.install.state()
        requests, fetch = self.public_fetch(raw, signature)
        with patch.object(native, "fetch", side_effect=fetch):
            candidate = native.check_update(self.install)
        self.assertEqual(candidate, 1)
        self.assertEqual(len(requests), 2)
        self.assertEqual(self.install.state(), before)
        self.assertFalse(self.install.journal_path.exists())
        self.install.activate(candidate)
        self.assertEqual(self.install.state()["pendingVersion"], 1)
        self.assertTrue(self.install.journal_path.exists())
        self.install.finish(True)
        self.assertEqual(self.install.state()["activeVersion"], 1)

    def test_corrupt_or_changed_cached_candidate_is_rejected_without_download_or_overwrite(self):
        self.stage()
        directory = self.install.version(1)
        originals = {name: (directory / name).read_bytes() for name in ("manifest.json", "manifest.json.sig", GAME)}
        for changed in originals:
            with self.subTest(changed=changed):
                path = directory / changed
                path.write_bytes(originals[changed] + b"tampered")
                requests, fetch = self.public_fetch(originals["manifest.json"], originals["manifest.json.sig"])
                before = self.install.state()
                with patch.object(native, "fetch", side_effect=fetch), self.assertRaises(ValueError):
                    native.check_update(self.install)
                self.assertEqual(len(requests), 2)
                self.assertEqual(path.read_bytes(), originals[changed] + b"tampered")
                self.assertEqual(self.install.state(), before)
                self.assertFalse(self.install.journal_path.exists())
                path.write_bytes(originals[changed])

    def test_staged_cache_does_not_bypass_public_signature_or_payload_origin_checks(self):
        self.stage()
        directory = self.install.version(1)
        raw = (directory / "manifest.json").read_bytes()
        signature = (directory / "manifest.json.sig").read_bytes()
        requests, fetch = self.public_fetch(raw, signature[:-1] + bytes([signature[-1] ^ 1]))
        with patch.object(native, "fetch", side_effect=fetch), self.assertRaisesRegex(ValueError, "signature"):
            native.check_update(self.install)
        self.assertEqual(len(requests), 2)
        changed_raw = raw + b" "  # Valid JSON and a valid new signature, but an immutable ID was republished.
        requests, fetch = self.public_fetch(changed_raw, self.key.sign(changed_raw))
        with patch.object(native, "fetch", side_effect=fetch), self.assertRaisesRegex(ValueError, "Cached staged"):
            native.check_update(self.install)
        self.assertEqual(len(requests), 2)
        self.assertEqual((directory / "manifest.json").read_bytes(), raw)
        requests, fetch = self.public_fetch(raw, signature)
        # A valid cache must not move the hit ahead of the existing URL gate.
        with patch.object(native, "fetch", side_effect=fetch), patch.object(native, "urljoin", return_value="https://untrusted.example/native-windows.zip"), self.assertRaisesRegex(ValueError, "origin"):
            native.check_update(self.install)
        self.assertEqual(len(requests), 2)

    def test_staged_cache_keeps_blocked_high_water_and_committed_version_rules(self):
        self.stage()
        directory = self.install.version(1)
        raw = (directory / "manifest.json").read_bytes()
        signature = (directory / "manifest.json.sig").read_bytes()
        self.install.activate(1)
        self.install.finish(False)
        before = self.install.state()
        requests, fetch = self.public_fetch(raw, signature)
        with patch.object(native, "fetch", side_effect=fetch):
            self.assertIsNone(native.check_update(self.install))
        self.assertEqual(len(requests), 2)
        self.assertEqual(self.install.state(), before)
        self.assertEqual(before["blockedVersions"], [1])
        self.assertEqual(before["highestVersion"], 1)
        self.install.activate(self.stage(2))
        self.install.finish(True)
        before = self.install.state()
        # A lower published version cannot reactivate a previously blocked ID.
        requests, fetch = self.public_fetch(raw, signature)
        with patch.object(native, "fetch", side_effect=fetch):
            self.assertIsNone(native.check_update(self.install))
        self.assertEqual(len(requests), 2)
        self.assertEqual(self.install.state(), before)
        second = self.install.version(2)
        raw2, signature2 = (second / "manifest.json").read_bytes(), (second / "manifest.json.sig").read_bytes()
        requests, fetch = self.public_fetch(raw2, signature2)
        with patch.object(native, "fetch", side_effect=fetch):
            self.assertIsNone(native.check_update(self.install))
        self.assertEqual(len(requests), 2)
        changed_raw2 = raw2 + b" "
        requests, fetch = self.public_fetch(changed_raw2, self.key.sign(changed_raw2))
        with patch.object(native, "fetch", side_effect=fetch), self.assertRaisesRegex(ValueError, "republished"):
            native.check_update(self.install)
        self.assertEqual(self.install.state(), before)


if __name__ == "__main__":
    unittest.main()
