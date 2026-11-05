"""Small actual-crypto fixtures; these are not UE builds or device evidence."""
import base64
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa
from cryptography.x509.oid import NameOID

import deploy_release_sets as publisher
import players
import release_set_archives
import remote_release_sets as remote

sets = publisher.sets


def fixture(root, platform="Windows", release=401, signing_key=None, content_overrides=None):
    base = 400 if platform == "Windows" else 410
    channel = "v106-release-pc" if platform == "Windows" else "v106-release-android"
    root.mkdir()
    payload = root / f"versions/{release}/payload"
    payload.mkdir(parents=True)
    files = ({"SampleGame/Binaries/Win64/SampleGame.exe": ("native", b"synthetic-native"),
              "SampleGame/Content/Paks/game.pak": ("content", b"synthetic-content")}
             if platform == "Windows" else {"libUnreal.so": ("native", b"synthetic-elf"),
                                            f"Content/Paks/r{base}_game.pak": ("content", b"synthetic-pak")})
    records = []
    for name, (role, data) in sorted(files.items()):
        data = (content_overrides or {}).get(role, data)
        path = payload / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(data)
        records.append(dict(path=name, role=role, size=len(data), sha256=hashlib.sha256(data).hexdigest()))
    trust = dict(projectId="SampleGame", platform=platform, channel=channel, baseReleaseId=base,
                 engineBuildId="fixture-engine", shellCompatibilityId="ab"*32, loaderVersion=1)
    value = {key: trust[key] for key in sets.BINDINGS}
    value.update(format=1, kind="samplegame-release-set", releaseId=release, minLoaderVersion=1, sourceCommit="ab"*20,
                 nativeSourceHash="cd"*32, files=records, save=dict(schema=1, readable=[1], migrations=[]))
    value["buildId"] = sets.build_id(value)
    raw = sets.canonical(value); trust["baseManifestSha256"] = hashlib.sha256(raw).hexdigest()
    config = dict(format=1, trust=trust, manifestUrl=f"{players.ORIGIN}/samplegame/{channel}/updates/manifest.json", allowOffline=True)
    if platform == "Windows":
        key = signing_key or ed25519.Ed25519PrivateKey.generate()
        config["publicKeyHex"] = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
        signature = key.sign(raw)
    else:
        key = signing_key or rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic unit fixture only")])
        certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                       .serial_number(1).not_valid_before(datetime.now(timezone.utc)-timedelta(days=1))
                       .not_valid_after(datetime.now(timezone.utc)+timedelta(days=1)).sign(key, hashes.SHA256()))
        der = certificate.public_bytes(serialization.Encoding.DER)
        config.update(signatureAlgorithm="SHA256withRSA", certificateBase64=base64.b64encode(der).decode(),
                      certificateSha256=hashlib.sha256(der).hexdigest(), packageName="com.example.samplegame")
        signature = key.sign(raw, padding.PKCS1v15(), hashes.SHA256())
        config["baseArchiveEntries"] = [dict(path=item["path"], apkPath="lib/arm64-v8a/libUnreal.so" if item["role"] == "native" else "assets/main.obb.png",
                                            obbPath="" if item["role"] == "native" else "SampleGame/Content/Paks/game.pak") for item in records]
    (root / "manifest.json").write_bytes(raw); (root / "manifest.json.sig").write_bytes(signature)
    (root / "config.json").write_bytes(sets.canonical(config))
    display = dict(schemaVersion=1, kind="samplegame-release-set-display", **{name: value[name] for name in
                   ("projectId", "platform", "channel", "releaseId", "baseReleaseId", "buildId")},
                   manifestSha256=hashlib.sha256(raw).hexdigest(), version="1.0.6", headline="Synthetic unit fixture only",
                   changes=[dict(title="Synthetic", text="Not a built game or runtime acceptance.")])
    (root / "display.json").write_bytes(sets.canonical(display))
    return value, config, payload


class ReleaseSetPublicationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="samplegame-set-publisher-fixture-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "candidate"
        self.key = ed25519.Ed25519PrivateKey.generate()
        self.value, self.config, self.payload = fixture(self.source, signing_key=self.key)
        self.prepared = self.root / "prepared"
        self.plan = publisher.prepare(self.source, self.source / "config.json", self.source / "display.json", self.prepared)
        server = self.root / "server"; server.mkdir()
        for name, path in dict(ROOT=server / "channels", SITE=server / "site.html", PLAYERS=server / "players/current",
                               NGINX=server / "nginx.conf", NATIVE=server / "native").items():
            context = patch.object(remote, name, path); context.start(); self.addCleanup(context.stop)
        remote.ROOT.mkdir(); remote.SITE.write_bytes(b"original-site")
        remote.NGINX.write_bytes(b"# /updates/versions/ route fixture")

    def stage(self, plan=None, prepared=None):
        plan, prepared = plan or self.plan, prepared or self.prepared
        stage = remote.execute("stage", dict(plan=plan))
        target = remote.ROOT / plan["channel"] / "releases" / stage["stageName"]
        for name in plan["files"]:
            shutil.copyfile(prepared / "payload" / name, target / name)
        return stage, target

    def test_actual_ed25519_and_rsa_signatures_are_checked(self):
        self.assertEqual(publisher.load(self.prepared), self.plan)
        source = self.root / "android"
        fixture(source, "Android_ARM64", 411)
        android = publisher.prepare(source, source / "config.json", source / "display.json", self.root / "android-prepared")
        self.assertEqual(android["verification"]["algorithm"], "SHA256withRSA")
        signature = source / "manifest.json.sig"; raw = bytearray(signature.read_bytes()); raw[0] ^= 1; signature.write_bytes(raw)
        with self.assertRaises(Exception):
            publisher.prepare(source, source / "config.json", source / "display.json", self.root / "bad-android")

    def test_other_channels_and_mismatched_display_cannot_prepare(self):
        altered = copy.deepcopy(self.plan); altered["channel"] = "v105-pc"
        with self.assertRaisesRegex(ValueError, "channels are writable"):
            remote.validate(altered)
        display = json.loads((self.source / "display.json").read_bytes()); display["manifestSha256"] = "ef"*32
        (self.source / "display.json").write_bytes(sets.canonical(display))
        with self.assertRaisesRegex(ValueError, "Display identity"):
            publisher.prepare(self.source, self.source / "config.json", self.source / "display.json", self.root / "mismatch")

    def test_real_stage_signature_inventory_and_immutable_commit(self):
        stage, target = self.stage()
        result = remote.execute("commit", dict(plan=self.plan, **stage))
        self.assertTrue(result["immutablePresent"])
        self.assertFalse(target.exists())
        self.assertIsNone(remote.pointer(remote.ROOT / self.plan["channel"] / "current"))
        resumed = remote.execute("resume", dict(plan=self.plan, **stage))
        self.assertTrue(resumed["immutablePresent"])
        self.assertFalse(resumed["uploadedAgain"])

    def test_corruption_extra_files_low_space_and_protected_races_stop_before_promotion(self):
        with patch.object(remote.shutil, "disk_usage", return_value=type("Usage", (), {"free": 0})()):
            with self.assertRaisesRegex(ValueError, "space"):
                remote.execute("stage", dict(plan=self.plan))
        stage, target = self.stage()
        first = next(name for name in self.plan["files"] if "/payload/" in name)
        (target / first).write_bytes(b"corrupt")
        with self.assertRaisesRegex(ValueError, "bytes differ"):
            remote.execute("commit", dict(plan=self.plan, **stage))
        shutil.copyfile(self.prepared / "payload" / first, target / first)
        (target / "unexpected.txt").write_bytes(b"extra")
        with self.assertRaisesRegex(ValueError, "inventory"):
            remote.execute("commit", dict(plan=self.plan, **stage))
        (target / "unexpected.txt").unlink(); remote.SITE.write_bytes(b"concurrent-change")
        with self.assertRaisesRegex(ValueError, "Protected"):
            remote.execute("commit", dict(plan=self.plan, **stage))

    def test_lease_owner_and_installed_route_limit_cannot_be_bypassed(self):
        stage, _ = self.stage()
        with self.assertRaisesRegex(ValueError, "another operation"):
            remote.execute("commit", dict(plan=self.plan, token="ab"*16, before=stage["before"]))
        altered = copy.deepcopy(self.plan)
        path = f"versions/{self.value['releaseId']}/payload/" + "a"*99 + "/" + "b"*99
        altered["files"][path] = dict(size=1, sha256="ab"*32); altered["payloadBytes"] += 1
        with self.assertRaisesRegex(ValueError, "route limit"):
            remote.validate(altered)

    def test_unknown_ssh_outcome_records_failure_without_overwriting_producer(self):
        host = unittest.mock.Mock()
        host.run.side_effect = [dict(token="ab"*16, stageName="fixture", before={"current": None, "protected": {}}),
                               TimeoutError("synthetic lost commit acknowledgment")]
        original = (self.source / "config.json").read_bytes()
        report = publisher.publish(self.prepared, self.root / "failure-report", host)
        self.assertEqual(report["status"], "failed")
        self.assertFalse(report["currentPromotionAttempted"])
        self.assertTrue(report["failedFilesAndLeaseRetained"])
        self.assertEqual((self.source / "config.json").read_bytes(), original)

    def test_signature_and_manifest_are_promoted_and_cas_rollback_together(self):
        stage, _ = self.stage(); remote.execute("commit", dict(plan=self.plan, **stage))
        try:
            result = remote.execute("activate", dict(plan=self.plan, **stage))
        except OSError as error:
            if getattr(error, "winerror", None) == 1314:
                self.skipTest("Host lacks directory symlink privilege; Linux transaction still needs actual verification")
            raise
        self.assertEqual(result["current"], "releases/401")
        resumed = remote.execute("resume", dict(plan=self.plan, **stage))
        self.assertTrue(resumed["alreadyActivated"])
        remote.execute("rollback", dict(plan=self.plan, **stage))
        self.assertIsNone(remote.pointer(remote.ROOT / self.plan["channel"] / "current"))

    def current_release(self):
        stage, _ = self.stage()
        remote.execute("commit", dict(plan=self.plan, **stage))
        try:
            remote.execute("activate", dict(plan=self.plan, **stage))
        except OSError as error:
            if getattr(error, "winerror", None) == 1314:
                self.skipTest("Actual hardlink/current fixture requires Linux directory symlink support")
            raise
        remote.execute("release-lock", dict(plan=self.plan, **stage))
        return remote.ROOT / self.plan["channel"] / "releases" / str(self.value["releaseId"])

    def next_candidate(self, overrides=None):
        source = self.root / "next-candidate"
        fixture(source, release=402, signing_key=self.key, content_overrides=overrides)
        # Every update uses the installed baseline pin, not a new fixture pin.
        (source / "config.json").write_bytes(sets.canonical(self.config))
        prepared = self.root / "next-prepared"
        plan = publisher.prepare(source, source / "config.json", source / "display.json", prepared)
        return plan, prepared

    def test_identical_payloads_share_readonly_inodes_but_metadata_stays_independent(self):
        old = self.current_release()
        old_payload = old / "versions/401/payload"
        original = {item["path"]: ((old_payload / item["path"]).stat(), (old_payload / item["path"]).read_bytes()) for item in self.value["files"]}
        plan, prepared = self.next_candidate(); stage, _ = self.stage(plan, prepared)
        result = remote.execute("commit", dict(plan=plan, **stage))
        final = remote.ROOT / plan["channel"] / "releases/402"
        for name, (before, data) in original.items():
            source, target = old_payload / name, final / "versions/402/payload" / name
            self.assertEqual(source.stat().st_ino, before.st_ino)
            self.assertEqual(target.stat().st_ino, source.stat().st_ino)
            self.assertGreaterEqual(source.stat().st_nlink, 2)
            self.assertEqual(source.stat().st_mtime_ns, before.st_mtime_ns)
            self.assertEqual(source.stat().st_mode, before.st_mode)
            self.assertFalse(source.stat().st_mode & 0o222)
            self.assertEqual(source.read_bytes(), data)
        self.assertEqual(result["storageReuse"]["reusedFiles"], 2)
        self.assertEqual(result["storageReuse"]["reusedBytes"], sum(item["size"] for item in self.value["files"]))
        metadata = [old / name for name in ("manifest.json", "manifest.json.sig", "versions/401/manifest.json", "versions/401/manifest.json.sig", "versions/401/release-display.json")]
        metadata += [final / name for name in ("manifest.json", "manifest.json.sig", "versions/402/manifest.json", "versions/402/manifest.json.sig", "versions/402/release-display.json")]
        self.assertEqual(len({path.stat().st_ino for path in metadata}), len(metadata))
        self.assertTrue(all(path.stat().st_nlink == 1 for path in metadata))
        self.assertEqual(remote.pointer(remote.ROOT / plan["channel"] / "current"), "releases/401")

    def test_changed_payload_bytes_are_not_linked(self):
        old = self.current_release()
        plan, prepared = self.next_candidate({"content": b"different cooked payload"})
        stage, _ = self.stage(plan, prepared)
        result = remote.execute("commit", dict(plan=plan, **stage))
        new = remote.ROOT / plan["channel"] / "releases/402/versions/402/payload"
        for item in self.value["files"]:
            source, target = old / "versions/401/payload" / item["path"], new / item["path"]
            self.assertEqual(source.stat().st_ino == target.stat().st_ino, item["role"] == "native")
            self.assertEqual(source.read_bytes(), (self.payload / item["path"]).read_bytes())
        self.assertEqual(result["storageReuse"]["reusedFiles"], 1)

    def test_writable_old_payload_refuses_reuse_without_chmod_or_pointer_change(self):
        old = self.current_release()
        item = self.value["files"][0]; source = old / "versions/401/payload" / item["path"]
        source.chmod(0o644); before = source.stat(); data = source.read_bytes()
        plan, prepared = self.next_candidate(); stage, _ = self.stage(plan, prepared)
        with self.assertRaisesRegex(ValueError, "read-only"):
            remote.execute("commit", dict(plan=plan, **stage))
        self.assertEqual(source.read_bytes(), data); self.assertEqual(source.stat().st_mode, before.st_mode)
        self.assertEqual(source.stat().st_ino, before.st_ino)
        self.assertEqual(remote.pointer(remote.ROOT / plan["channel"] / "current"), "releases/401")
        remote.verify(remote.ROOT / plan["channel"] / "releases/402", plan)

    def test_corrupt_old_payload_refuses_reuse_without_rewriting_it(self):
        old = self.current_release()
        item = self.value["files"][0]; source = old / "versions/401/payload" / item["path"]
        source.chmod(0o644); source.write_bytes(b"x" * item["size"]); source.chmod(0o444)
        before = source.stat(); data = source.read_bytes()
        plan, prepared = self.next_candidate(); stage, _ = self.stage(plan, prepared)
        with self.assertRaisesRegex(ValueError, "Reuse source SHA"):
            remote.execute("commit", dict(plan=plan, **stage))
        self.assertEqual(source.read_bytes(), data); self.assertEqual(source.stat().st_ino, before.st_ino)
        self.assertEqual(remote.pointer(remote.ROOT / plan["channel"] / "current"), "releases/401")
        remote.verify(remote.ROOT / plan["channel"] / "releases/402", plan)

    def test_midway_link_failure_and_abrupt_orphan_resume_never_reupload_final(self):
        old = self.current_release()
        original = {item["path"]: ((old / "versions/401/payload" / item["path"]).stat().st_ino,
                                  (old / "versions/401/payload" / item["path"]).read_bytes()) for item in self.value["files"]}
        plan, prepared = self.next_candidate(); stage, _ = self.stage(plan, prepared)
        actual_link, calls = remote.os.link, []
        def interrupted_link(*args, **kwargs):
            calls.append(args)
            if len(calls) == 2:
                raise OSError("synthetic worker interruption after first replacement")
            return actual_link(*args, **kwargs)
        with patch.object(remote.os, "link", side_effect=interrupted_link):
            with self.assertRaisesRegex(OSError, "worker interruption"):
                remote.execute("commit", dict(plan=plan, **stage))
        final = remote.ROOT / plan["channel"] / "releases/402"
        remote.verify(final, plan)
        self.assertEqual(remote.pointer(remote.ROOT / plan["channel"] / "current"), "releases/401")
        # Model SIGKILL between link(temp) and replace: the private sibling link
        # does not enter final's signed inventory and cannot trigger reupload.
        orphan = final.parent / (".reuse-link-402-" + "ab"*16)
        actual_link(old / "versions/401/payload" / self.value["files"][0]["path"], orphan)
        previous = self.root / "interrupted-report.json"
        previous.write_bytes(sets.canonical(dict(channel=plan["channel"], releaseId=plan["releaseId"], stage=stage,
            preparedPlanSha256=sets.digest(prepared / "prepared.json"))))
        class LocalHost:
            def run(self, action, plan, **parameters):
                return remote.execute(action, dict(plan=plan, **parameters))
            def copy(self, *args):
                raise AssertionError("Resume must never upload or truncate an immutable final file")
        with patch.object(publisher, "public_verify", return_value=[]), patch.object(publisher.deploy_players, "bounded",
                side_effect=lambda path, maximum: (prepared / "payload" / ("manifest.json.sig" if path.endswith(".sig") else "manifest.json")).read_bytes()):
            report = publisher.publish(prepared, self.root / "resume-report", LocalHost(), previous_report=previous)
        self.assertEqual(report["status"], "passed")
        self.assertTrue(report["immutableCommit"]["immutablePresent"])
        for name, (inode, data) in original.items():
            source = old / "versions/401/payload" / name
            self.assertEqual(source.stat().st_ino, inode); self.assertEqual(source.read_bytes(), data)

    def test_matching_bytes_in_another_channel_are_never_reused(self):
        old = self.current_release()
        source = self.root / "android-next"
        fixture(source, "Android_ARM64", 411, content_overrides={"native": b"synthetic-native", "content": b"synthetic-content"})
        prepared = self.root / "android-next-prepared"
        plan = publisher.prepare(source, source / "config.json", source / "display.json", prepared)
        stage, _ = self.stage(plan, prepared)
        result = remote.execute("commit", dict(plan=plan, **stage))
        final = remote.ROOT / plan["channel"] / "releases/411/versions/411/payload"
        native = next(item for item in self.value["files"] if item["role"] == "native")
        old_native = old / "versions/401/payload" / native["path"]
        self.assertEqual((final / "libUnreal.so").read_bytes(), old_native.read_bytes())
        self.assertNotEqual((final / "libUnreal.so").stat().st_ino, old_native.stat().st_ino)
        self.assertEqual(result["storageReuse"]["reusedFiles"], 0)


class ReleaseSetArchiveTests(unittest.TestCase):
    def test_new_pc_and_android_archives_use_actual_new_receipts(self):
        with tempfile.TemporaryDirectory(prefix="samplegame-archive-fixture-") as temporary:
            root = Path(temporary); receipts = []
            for platform, base in (("Windows", 400), ("Android_ARM64", 410)):
                source = root / platform
                value, config, payload = fixture(source, platform, base)
                producer = {name: value[name] for name in ("baseReleaseId", "engineBuildId", "shellCompatibilityId", "sourceCommit", "nativeSourceHash", "buildId")}
                producer.update(kind="samplegame-windows-release-set-player" if platform == "Windows" else "samplegame-android-release-set-player",
                                manifestSha256=config["trust"]["baseManifestSha256"], runtimeValidated=False, published=False)
                archive = root / f"SampleGame-Fixture-Base{base}{'.zip' if platform == 'Windows' else '.apk'}"
                with zipfile.ZipFile(archive, "w") as output:
                    output.writestr("release-player.json" if platform == "Windows" else "assets/release-player.json", sets.canonical(config))
                    output.writestr("base/manifest.json" if platform == "Windows" else "assets/release-base-manifest.json", sets.canonical(value))
                    if platform == "Windows":
                        wrapper = b"synthetic-wrapper"; producer["frozenPlayerSha256"] = hashlib.sha256(wrapper).hexdigest()
                        output.writestr("SampleGame.exe", wrapper); output.writestr("_release_internal/fixture.txt", b"synthetic-runtime")
                        for item in value["files"]:
                            output.write(payload / item["path"], "base/payload/" + item["path"])
                    else:
                        producer["signingCertificateSha256"] = config["certificateSha256"]
                        output.writestr("AndroidManifest.xml", b"synthetic-manifest")
                        output.write(payload / "libUnreal.so", "lib/arm64-v8a/libUnreal.so")
                        obb = io.BytesIO()
                        with zipfile.ZipFile(obb, "w") as nested:
                            nested.writestr("SampleGame/Content/Paks/game.pak", b"synthetic-pak")
                        output.writestr("assets/main.obb.png", obb.getvalue())
                download = dict(path=str(archive), size=archive.stat().st_size, sha256=players.digest(archive), version="1.0.6",
                                platform=platform, baseReleaseId=base, runtimeValidated=False, published=False)
                if platform != "Windows":
                    download["signingCertificateSha256"] = producer["signingCertificateSha256"]
                producer_path, download_path = root / f"{platform}-producer.json", root / f"{platform}-download.json"
                producer_path.write_bytes(sets.canonical(producer)); download_path.write_bytes(sets.canonical(download))
                receipts.extend((producer_path, download_path))
            plan = players.prepare_release_sets(root / "prepared", "v106-fixture", "1.0.6", "Synthetic only", *receipts, 6, 6)
            self.assertEqual({item["platform"] for item in plan["catalog"]["packages"]}, {"Windows", "Android_ARM64"})
            self.assertTrue(all(item["updateProtocol"] == "release-set-v1" for item in plan["catalog"]["packages"]))
            self.assertTrue(all(players.read_json(path).get("runtimeValidated") is False for path in receipts))
            original = players.read_json(receipts[2]); original["nativeSourceHash"] = "ef"*32
            receipts[2].write_bytes(sets.canonical(original))
            with self.assertRaisesRegex(ValueError, "Producer/archive identity"):
                players.prepare_release_sets(root / "wrong-source", "v106-wrong", "1.0.6", "Synthetic", *receipts, 6, 6)


if __name__ == "__main__":
    unittest.main()
