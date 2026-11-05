import copy
import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import configure_nginx
import deploy_players
import players
import remote_players as remote


class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="samplegame-player-hosting-")
        self.directory = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)
        self.receipts = []
        for platform, base, channel, extension in (("Windows", 320, "v104r2-pc", ".zip"),
                                                   ("Android_ASTC_arm64", 330, "v104r2-android", ".apk")):
            archive = self.directory / f"SampleGame-Test-Base{base}{extension}"
            with zipfile.ZipFile(archive, "w") as zipped:
                if platform == "Windows":
                    for name, kind in (("native-player.json", "native"), ("sample-player.json", "updates")):
                        zipped.writestr("Windows/" + name, json.dumps(dict(baseReleaseId=base, channel=channel,
                            manifestUrl=f"{players.ORIGIN}/samplegame/{channel}/{kind}/manifest.json")))
                    zipped.writestr("Windows/SampleGame.exe", b"fixture-frozen-wrapper")
                else:
                    zipped.writestr("AndroidManifest.xml", b"fixture-manifest")
                    zipped.writestr("lib/arm64-v8a/libUnreal.so", b"fixture-so")
            certificate = hashlib.sha256(b"fixture-public-certificate").hexdigest()
            package = dict(platform=platform, baseReleaseId=base, channel=channel, signingCertificateSha256=certificate)
            download = dict(path=str(archive), size=archive.stat().st_size, sha256=players.digest(archive),
                            baseReleaseId=base, signingCertificateSha256=certificate)
            package_path, download_path = self.directory / (channel + "-package.json"), self.directory / (channel + "-download.json")
            package_path.write_text(json.dumps(package)); download_path.write_text(json.dumps(download))
            self.receipts.extend((package_path, download_path))
        self.prepared = self.directory / "prepared"
        self.plan = players.prepare(self.prepared, "v104r2-test", "1.0.4", "性能与下载可靠性优化",
                                    *self.receipts, "v104r2-native-android")
        self.server = self.directory / "server"
        self.server.mkdir()
        self.site, self.nginx = self.server / "index.html", self.server / "nginx.conf"
        self.site.write_bytes(b"original-website")
        self.nginx.write_bytes(b"# SampleGame player downloads\noriginal-game-routes")
        self.root = self.server / "players"
        for name, value in dict(ROOT=self.root, SITE=self.site, NGINX=self.nginx,
                                CONTENT=self.server / "channels", NATIVE=self.server / "native").items():
            context = patch.object(remote, name, value); context.start(); self.addCleanup(context.stop)
        try:
            probe = self.server / "directory-link-probe"
            probe.symlink_to(self.server, target_is_directory=True)
            probe.unlink()
            self.has_symlinks = True
        except OSError:
            self.has_symlinks = False

    def staged(self):
        stage = remote.execute("stage", {"plan": self.plan})
        for name in self.plan["files"]:
            shutil.copyfile(self.prepared / "payload" / name, self.root / stage["stageName"] / name)
        return stage

    def commit(self, stage):
        return remote.execute("commit", dict(plan=self.plan, **stage))

    def test_prepare_preserves_original_bytes_and_generates_metadata(self):
        self.assertEqual(players.load_plan(self.prepared), self.plan)
        self.assertEqual(self.plan["catalog"]["nativeBaselineRevision"], 3)
        self.assertEqual(self.plan["catalog"]["nativeTargetRevision"], 4)
        for package in self.plan["catalog"]["packages"]:
            self.assertEqual(players.digest(self.prepared / "payload" / package["filename"]), package["sha256"])
            self.assertEqual((self.prepared / "payload" / (package["filename"] + ".sha256")).read_text(),
                             package["sha256"] + "  " + package["filename"] + "\n")

    def test_duplicate_prepare_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "already exists"):
            players.prepare(self.prepared, "v104r2-test", "1.0.4", "fixture", *self.receipts, "v104r2-native-android")

    def test_nginx_transport_failure_preserves_unknown_outcome_receipt(self):
        host = deploy_players.Host("fixture@example.test", self.directory / "fixture-identity", 22)
        report = self.directory / "nginx-unknown.json"
        with patch.object(configure_nginx.subprocess, "run", side_effect=subprocess.TimeoutExpired("ssh", 240)):
            result = configure_nginx.apply_config(b"old", b"proposed", host,
                                                   "/etc/nginx/sites-available/fixture", report)
        self.assertFalse(result["installed"])
        self.assertTrue(result["remoteOutcomeUnknown"])
        self.assertEqual(json.loads(report.read_bytes()), result)
        with patch.object(configure_nginx.subprocess, "run") as execute:
            with self.assertRaisesRegex(ValueError, "fresh report"):
                configure_nginx.apply_config(b"old", b"new", host,
                                             "/etc/nginx/sites-available/fixture", report)
            execute.assert_not_called()

    def test_nginx_receipt_parent_must_exist_before_ssh(self):
        host = deploy_players.Host("fixture@example.test", self.directory / "fixture-identity", 22)
        with patch.object(configure_nginx.subprocess, "run") as execute:
            with self.assertRaisesRegex(ValueError, "existing external directory"):
                configure_nginx.apply_config(b"old", b"new", host,
                                             "/etc/nginx/sites-available/fixture", self.directory / "absent" / "report.json")
            execute.assert_not_called()

    def test_changed_archive_or_prepared_inventory_rejected(self):
        package = self.plan["catalog"]["packages"][0]
        (self.prepared / "payload" / package["filename"]).write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "bytes changed"):
            players.load_plan(self.prepared)

    def test_unsafe_catalog_paths_and_decreasing_revision_are_rejected(self):
        for replacement in ("../escape", "bad/dir", "a..b"):
            altered = copy.deepcopy(self.plan); altered["distributionId"] = replacement
            with self.assertRaises(ValueError): remote.validate(altered)
        altered = copy.deepcopy(self.plan); altered["catalog"]["nativeTargetRevision"] = 2
        with self.assertRaisesRegex(ValueError, "identity"): remote.validate(altered)

    def test_complete_base_with_no_pending_native_patch_can_be_published(self):
        prepared = self.directory / "complete-current-base"
        plan = players.prepare(prepared, "v105-complete", "1.0.5", "完整原生基包",
                               *self.receipts, "v104r2-native-android", 4, 4)
        self.assertEqual(players.load_plan(prepared), plan)
        self.assertEqual(remote.validate(plan), plan)
        self.assertEqual(plan["catalog"]["nativeBaselineRevision"], 4)
        self.assertEqual(plan["catalog"]["nativeTargetRevision"], 4)

    def test_private_keys_in_archive_rejected(self):
        download = players.read_json(self.receipts[1]); archive = Path(download["path"])
        with zipfile.ZipFile(archive, "a") as zipped: zipped.writestr("Windows/release.key", b"fixture-not-a-real-key")
        download.update(size=archive.stat().st_size, sha256=players.digest(archive))
        self.receipts[1].write_text(json.dumps(download))
        with self.assertRaisesRegex(ValueError, "Private credentials"):
            players.package_record(self.receipts[0], self.receipts[1], "Windows", "another")

    def test_archive_traversal_rejected(self):
        download = players.read_json(self.receipts[1]); archive = Path(download["path"])
        with zipfile.ZipFile(archive, "a") as zipped: zipped.writestr("Windows/../escape", b"fixture")
        download.update(size=archive.stat().st_size, sha256=players.digest(archive)); self.receipts[1].write_text(json.dumps(download))
        with self.assertRaisesRegex(ValueError, "Unsafe archive"):
            players.package_record(self.receipts[0], self.receipts[1], "Windows", "another")

    def test_missing_route_and_low_space_stop_before_upload(self):
        self.nginx.write_bytes(b"original-without-player-route")
        with self.assertRaisesRegex(ValueError, "route"): remote.execute("stage", {"plan": self.plan})
        self.nginx.write_bytes(b"# SampleGame player downloads")
        with patch.object(remote.shutil, "disk_usage", return_value=type("Usage", (), {"free": 0})()):
            with self.assertRaisesRegex(ValueError, "space"): remote.execute("stage", {"plan": self.plan})
        self.assertFalse(list(self.root.glob(".upload-*")))

    def test_corrupt_or_extra_stage_file_cannot_commit(self):
        stage = self.staged(); directory = self.root / stage["stageName"]
        (directory / "secret.key").write_bytes(b"fixture")
        with self.assertRaisesRegex(ValueError, "allowlist"): self.commit(stage)
        self.assertTrue(directory.exists()); self.assertFalse((self.root / "releases/v104r2-test").exists())

    def test_protected_website_race_cannot_commit(self):
        stage = self.staged(); self.site.write_bytes(b"concurrent-site-change")
        with self.assertRaisesRegex(ValueError, "changed"): self.commit(stage)
        self.assertTrue((self.root / stage["stageName"]).exists())

    def test_immutable_release_is_not_overwritten(self):
        stage = self.staged(); self.commit(stage)
        with self.assertRaisesRegex(ValueError, "already exists"):
            remote.execute("stage", {"plan": self.plan})
        self.assertIsNone(remote.current_target())

    def test_recovery_verifies_existing_immutable_release_without_reupload(self):
        stage = self.staged(); self.commit(stage)
        result = remote.execute("recover-commit", {"plan": self.plan, **stage})
        self.assertTrue(result["recoveredExistingImmutableRelease"])
        self.assertIsNone(remote.current_target())

    def test_actual_atomic_activation_and_pointer_only_rollback(self):
        if not self.has_symlinks: self.skipTest("Host lacks directory symlink privilege; real nginx/SSH remains unexecuted")
        stage = self.staged(); self.commit(stage)
        result = remote.execute("activate", {"plan": self.plan, "before": stage["before"]})
        self.assertEqual(result["current"], "releases/v104r2-test")
        remote.execute("rollback", {"plan": self.plan, "before": stage["before"]})
        self.assertIsNone(remote.current_target())
        self.assertTrue((self.root / "releases/v104r2-test").is_dir())
        self.assertTrue(list(self.root.glob(".failed-current-*")))
        self.assertEqual(self.site.read_bytes(), b"original-website")

    def test_nginx_insertion_preserves_all_original_bytes(self):
        before = b"server {\n    server_name updates.example.com;\n    # Signed manifest and signature:\n    location / { return 404; }\n}\n"
        proposed = configure_nginx.proposed_config(before)
        fragment = Path(configure_nginx.__file__).with_name("nginx-player.locations.conf").read_bytes()
        self.assertEqual(proposed.replace(fragment + b"\n", b"", 1), before)
        with self.assertRaisesRegex(ValueError, "already exists"): configure_nginx.proposed_config(proposed)

    def test_ssh_keeps_alive_without_archive_recompression(self):
        host = deploy_players.Host("root@example.invalid", "fixture-path-not-a-key")
        with patch.object(deploy_players.subprocess, "run", return_value=type("Done", (), {"returncode": 0, "stderr": b""})()) as run:
            host.copy(Path("SampleGame-Test-Base320.zip"), ".upload-v104r2-test-" + "a"*32, 60)
        command = run.call_args.args[0]
        self.assertIn("ServerAliveInterval=15", command); self.assertIn("ServerAliveCountMax=6", command)
        self.assertNotIn("-C", command)
        with self.assertRaises(ValueError): host.copy(Path("fixture.zip"), "../../escape", 60)

    def test_redirects_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "redirects"):
            deploy_players.NoRedirect().redirect_request(None, None, 302, "moved", {}, "https://elsewhere.invalid")

    def response_fixture(self, data, status, headers):
        result = io.BytesIO(data)
        result.status, result.headers = status, headers
        return result

    def test_full_public_get_size_sha_and_range_are_required(self):
        package = self.plan["catalog"]["packages"][0]
        data = (self.prepared / "payload" / package["filename"]).read_bytes()
        size = len(data)
        replies = [self.response_fixture(b"", 200, {"Content-Length": str(size), "Cache-Control": "immutable"}),
                   self.response_fixture(data, 206, {"Content-Range": f"bytes 0-{size-1}/{size}"}),
                   self.response_fixture(data, 200, {"Content-Length": str(size)})]
        sidecar = (package["sha256"] + "  " + package["filename"] + "\n").encode()
        destination = self.directory / "verified.zip"
        with patch.object(deploy_players, "response", side_effect=replies), patch.object(deploy_players, "bounded", return_value=sidecar):
            result = deploy_players.verify_package(package, self.prepared / "payload", destination, 60)
        self.assertTrue(result["fullPublicGetVerified"])
        self.assertEqual(destination.read_bytes(), data)

    def test_bad_full_public_sha_retains_partial_and_rejects(self):
        package = self.plan["catalog"]["packages"][0]
        data = (self.prepared / "payload" / package["filename"]).read_bytes(); size = len(data)
        changed = data[:-1] + bytes([data[-1] ^ 1])
        replies = [self.response_fixture(b"", 200, {"Content-Length": str(size), "Cache-Control": "immutable"}),
                   self.response_fixture(data, 206, {"Content-Range": f"bytes 0-{size-1}/{size}"}),
                   self.response_fixture(changed, 200, {"Content-Length": str(size)})]
        sidecar = (package["sha256"] + "  " + package["filename"] + "\n").encode()
        destination = self.directory / "bad-public.zip"
        with patch.object(deploy_players, "response", side_effect=replies), patch.object(deploy_players, "bounded", return_value=sidecar):
            with self.assertRaisesRegex(ValueError, "Complete public"):
                deploy_players.verify_package(package, self.prepared / "payload", destination, 60)
        self.assertFalse(destination.exists()); self.assertTrue(destination.with_name(destination.name + ".partial").exists())

    def fake_host(self, events):
        protected = {"website": "unchanged", "old-six-channels": "unchanged"}
        class FakeHost:
            active = False
            def run(inner, action, plan, **kwargs):
                events.append(action)
                if action == "stage": return {"stageName": ".upload-v104r2-test-" + "a"*32, "before": {"current": None, "protected": protected}}
                if action == "activate": inner.active = True; return {"activated": True}
                if action == "inspect": return {"protected": protected, "current": "releases/v104r2-test" if inner.active else None}
                return {"committed": True}
            def copy(inner, *args): events.append("copy")
        return FakeHost()

    def test_current_promotion_follows_both_complete_public_verifications(self):
        events = []; host = self.fake_host(events)
        def verified(*args): events.append("full-public-verify"); return {"fullPublicGetVerified": True}
        with patch.object(deploy_players, "verify_package", side_effect=verified), patch.object(deploy_players, "bounded", return_value=players.canonical(self.plan["catalog"])):
            result = deploy_players.publish(self.prepared, self.directory / "publish-evidence", host, 60)
        self.assertEqual(result["status"], "passed")
        self.assertEqual(events.count("full-public-verify"), 2)
        self.assertGreater(events.index("activate"), max(i for i,x in enumerate(events) if x == "full-public-verify"))

    def test_failed_full_public_verification_never_promotes_current(self):
        events = []; host = self.fake_host(events)
        with patch.object(deploy_players, "verify_package", side_effect=ValueError("incomplete public download")):
            result = deploy_players.publish(self.prepared, self.directory / "failed-publish-evidence", host, 60)
        self.assertEqual(result["status"], "failed")
        self.assertNotIn("activate", events)
        self.assertFalse(result["currentPromotionAttempted"])
        self.assertTrue(result["failedStageAndReleasesRetained"])

    def test_resume_reuses_complete_remote_release_without_scp(self):
        events = []; host = self.fake_host(events)
        first_dir = self.directory / "first-failed-public-verification"
        with patch.object(deploy_players, "verify_package", side_effect=ValueError("incomplete public download")):
            failed = deploy_players.publish(self.prepared, first_dir, host, 60)
        self.assertEqual(failed["status"], "failed")
        events.clear()
        with patch.object(deploy_players, "verify_package", return_value={"fullPublicGetVerified": True}), patch.object(deploy_players, "bounded", return_value=players.canonical(self.plan["catalog"])):
            result = deploy_players.publish(self.prepared, self.directory / "fresh-resume-evidence", host, 60, first_dir / "report.json")
        self.assertEqual(result["status"], "passed")
        self.assertIn("recover-commit", events); self.assertNotIn("copy", events); self.assertNotIn("stage", events)


if __name__ == "__main__": unittest.main()
