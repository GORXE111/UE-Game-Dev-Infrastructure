import base64
import hashlib
import importlib.util
import json
import re
from pathlib import Path
import shutil
import subprocess
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
import deploy_native as deploy
import configure_nginx as nginx


class NativeHostingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "release"
        self.source.mkdir()
        self.key = Ed25519PrivateKey.generate()
        self.public = self.key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
        self.origin = "https://updates.example"
        self.name = "test-native"
        game = "SampleGame/Binaries/Win64/SampleGame.exe"
        data = b"fixture-payload"
        self.native_files = [{"path": game, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}]
        self.config = dict(format=1, projectId="SampleGame", channel=self.name, platform="Windows", baseReleaseId=100,
                           engineBuildId="engine", compatibilityId="compat", publicKeyHex=self.public, nativeFiles=self.native_files,
                           manifestUrl=self.origin + f"/samplegame/{self.name}/native/manifest.json", contentLauncher="SampleContent.exe", contentConfig="sample-player.json", allowOffline=True)
        self.config_path = self.root / "native-player.json"
        self.config_path.write_text(json.dumps(self.config), encoding="utf-8")
        archive = self.source / "versions/123/native-windows.zip"
        archive.parent.mkdir(parents=True)
        with zipfile.ZipFile(archive, "w") as zipped:
            zipped.writestr(game, data)
        manifest = {key: self.config[key] for key in deploy.client.IDENTITY}
        manifest.update(format=1, kind="samplegame-native-windows", nativeVersion=123,
                        archive={"path": "versions/123/native-windows.zip", "size": archive.stat().st_size, "sha256": deploy.client.digest(archive)}, files=self.native_files)
        raw = json.dumps(manifest).encode()
        (self.source / "manifest.json").write_bytes(raw)
        (self.source / "manifest.json.sig").write_bytes(self.key.sign(raw))
        (self.source / "producer-receipt.json").write_text("private local paths must never upload")
        (self.source / "private.key").write_text("not a real secret; forbidden upload fixture")

    def verified(self):
        version, files = deploy.verify_windows(self.source, self.config_path, self.public, self.name, self.origin)
        return {"version": version, "files": files, "channel": self.name, "origin": self.origin}

    def test_windows_real_signature_and_archive_verification_only_select_public_files(self):
        plan = self.verified()
        self.assertEqual(plan["version"], 123)
        self.assertEqual({item["path"] for item in plan["files"]}, {"manifest.json", "manifest.json.sig", "versions/123/native-windows.zip"})
        self.assertNotIn("producer-receipt.json", json.dumps(plan))
        with self.assertRaises(ValueError):
            deploy.verify_windows(self.source, self.config_path, "a" * 64, self.name, self.origin)
        with self.assertRaises(ValueError):
            deploy.verify_windows(self.source, self.config_path, self.public, self.name, "https://other.example")

    def test_signed_archive_corruption_and_destination_channel_are_rejected(self):
        archive = self.source / "versions/123/native-windows.zip"
        archive.write_bytes(archive.read_bytes() + b"changed")
        with self.assertRaises(ValueError):
            self.verified()
        with self.assertRaises(ValueError):
            deploy.verify_windows(self.source, self.config_path, self.public, "different", self.origin)

    def test_android_real_rsa_envelope_elf_and_certificate_pin(self):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding, rsa
        from cryptography.x509.oid import NameOID
        from datetime import datetime, timedelta, timezone
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fixture")])
        now = datetime.now(timezone.utc)
        certificate = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key()).serial_number(1)
                       .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=1)).sign(key, hashes.SHA256())).public_bytes(Encoding.DER)
        der = self.root / "public-fixture.der"
        der.write_bytes(certificate)
        pin = hashlib.sha256(certificate).hexdigest()
        source = self.root / "android"
        source.mkdir()
        data = bytearray(16384)
        data[:7] = b"\x7fELF\x02\x01\x01"
        struct.pack_into("<HHI", data, 16, 3, 183, 1)
        struct.pack_into("<Q", data, 32, 64)
        struct.pack_into("<HHH", data, 52, 64, 56, 1)
        struct.pack_into("<IIQQQQQQ", data, 64, 1, 5, 0, 0, 0, len(data), len(data), 16384)
        (source / "libUnreal.so").write_bytes(data)
        bootstrap = dict(format=1, platform="Android_ARM64", packageName="test.fixture", channel=self.name, abi="arm64-v8a", baseReleaseId=100,
                         baseNativeSourceHash="a"*64, nativeApiVersion=2, engineBuildId="engine", contentCompatibilityId="b"*64,
                         manifestUrl=deploy.public_url(self.origin, self.name)+"manifest.json")
        base = self.root / "native-base.json"
        base.write_text(json.dumps({"bootstrap": bootstrap, "signingCertificateSha256": pin}))
        payload = {field: bootstrap[field] for field in deploy.ANDROID_BINDINGS}
        payload.update(releaseId=123, nativeSourceHash="c"*64, soSha256=hashlib.sha256(data).hexdigest(), soSize=len(data),
                       soUrl=deploy.public_url(self.origin,self.name)+"versions/123/libUnreal.so", versionLabel="fixture")
        raw = json.dumps(payload).encode()
        envelope = dict(format=1, payloadBase64=base64.b64encode(raw).decode(), signatureBase64=base64.b64encode(key.sign(raw,padding.PKCS1v15(),hashes.SHA256())).decode(), signatureAlgorithm="SHA256withRSA")
        (source/"manifest.json").write_text(json.dumps(envelope))
        version, files = deploy.verify_android(source,base,der,self.name,self.origin,certificate_pin=pin)
        self.assertEqual(version,123)
        self.assertEqual(len(files),2)
        with self.assertRaisesRegex(ValueError,"pinned"):
            deploy.verify_android(source,base,der,self.name,self.origin)
        envelope["signatureBase64"] = base64.b64encode(b"corrupt").decode()
        (source/"manifest.json").write_text(json.dumps(envelope))
        with self.assertRaises(Exception):
            deploy.verify_android(source,base,der,self.name,self.origin,certificate_pin=pin)

    def test_channel_release_and_origin_do_not_allow_command_or_path_injection(self):
        for name in ("../prod", "prod;id", "a/b", "Prod", "x" * 33, "-option"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                deploy.channel(name)
        for version in (0, -1, 1000000000, True):
            with self.subTest(version=version), self.assertRaises(ValueError):
                deploy.release_id(version)
        with self.assertRaises(ValueError):
            deploy.public_url("https://updates.example.com/extra", self.name)

    def test_actual_remote_prepare_and_existing_release_hash_checks_run_locally(self):
        plan = self.verified()
        remote_root = self.root / "remote-native"
        script = deploy.REMOTE_RELEASE.replace("pathlib.Path('/srv/ue-game-updates/native')", "pathlib.Path(" + repr(str(remote_root)) + ")")
        payload = {"channel": self.name, "version": 123, "phase": "prepare", "token": "a" * 32,
                   "files": [{key: item[key] for key in ("path", "size", "sha256")} for item in plan["files"]]}
        def run():
            return subprocess.run([sys.executable, "-", base64.b64encode(json.dumps(payload).encode()).decode()], input=script, text=True, capture_output=True, check=False)
        first = run()
        self.assertEqual(first.returncode, 0, first.stderr)
        prepared = json.loads(first.stdout)
        staging = Path(prepared["staging"])
        for item in plan["files"]:
            shutil.copyfile(item["source"], staging / item["path"])
        final = remote_root / self.name / "releases/123"
        staging.rename(final)
        existing = run()
        self.assertEqual(existing.returncode, 0, existing.stderr)
        self.assertTrue(json.loads(existing.stdout)["present"])
        (final / "manifest.json").write_bytes(b"corrupt")
        self.assertNotEqual(run().returncode, 0)

    def test_https_failure_restores_previous_current_and_uploads_only_allowlist(self):
        calls, uploaded = [], []
        class FakeHost:
            def run(self, script, payload):
                calls.append(payload)
                if payload["phase"] == "prepare": return {"present": False, "staging": "/fixture-staging"}
                if payload["phase"] == "commit": return {"previous": "releases/122"}
                return {"restored": "releases/122"}
            def upload(self, source, target): uploaded.append(Path(source).name)
        with patch.object(deploy, "verify_https", side_effect=ValueError("incorrect HTTPS body")), self.assertRaises(ValueError):
            deploy.deploy(self.verified(), FakeHost())
        self.assertEqual([entry["phase"] for entry in calls], ["prepare", "commit", "restore"])
        self.assertEqual(set(uploaded), {"manifest.json", "manifest.json.sig", "native-windows.zip"})

    def test_scp_uses_transport_compression_and_preserves_verified_source_arguments(self):
        identity = self.root / "fixture ssh identity"
        identity.write_bytes(b"not a credential; subprocess is mocked")
        source = self.root / "verified native fixture.so"
        source.write_bytes(b"original signed native bytes")
        original = source.read_bytes()
        host = deploy.Host("fixture@updates.example", identity, port=2222)
        destination = "/srv/ue-game-updates/native/test-native/releases/.upload-123-" + "a" * 32 + "/versions/123/libUnreal.so"
        with patch.object(deploy.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)) as invoked:
            host.upload(source, destination)
        command = invoked.call_args.args[0]
        self.assertEqual(command[:2], ["scp", "-C"])
        self.assertEqual(command.count("-C"), 1)
        self.assertEqual(command[-2:], [str(source), "fixture@updates.example:" + destination])
        self.assertEqual(command[command.index("-i") + 1], str(identity.resolve()))
        self.assertEqual(command[command.index("-P") + 1], "2222")
        self.assertIn("StrictHostKeyChecking=yes", command)
        self.assertIn("BatchMode=yes", command)
        self.assertIn("ServerAliveInterval=15", command)
        self.assertIn("ServerAliveCountMax=6", command)
        self.assertEqual(invoked.call_args.kwargs, {"timeout": 1800, "check": False})
        self.assertEqual(source.read_bytes(), original)
        with patch.object(deploy.subprocess, "run", return_value=subprocess.CompletedProcess([], 1)), self.assertRaisesRegex(ValueError, "upload failed"):
            host.upload(source, destination)

    def test_nginx_insertion_retains_existing_routes_and_refuses_repeat(self):
        before = b'server {\n    server_name updates.example.com;\n    # Signed manifest and signature: old\n    location / { return 404; }\n}\n'
        result = nginx.proposed_config(before)
        self.assertIn(before.decode(), result.decode().replace(Path(HERE / "nginx-native.locations.conf").read_text() + "\n", "", 1))
        self.assertIn(b"/srv/ue-game-updates/native/", result)
        with self.assertRaises(ValueError):
            nginx.proposed_config(result)
        self.assertNotIn("rm -", deploy.REMOTE_RELEASE)
        self.assertNotIn("rm -", nginx.REMOTE_NGINX)

    def test_actual_multidot_nginx_site_filename_is_safe_but_traversal_is_not(self):
        pattern = re.search(r"assert re.fullmatch\(r'([^']+)',name\)", nginx.REMOTE_NGINX).group(1)
        self.assertIsNotNone(re.fullmatch(pattern, "/etc/nginx/sites-available/updates.example.com"))
        self.assertIsNotNone(re.fullmatch(pattern, "/etc/nginx/conf.d/updates.example.com.conf"))
        for name in ("/etc/nginx/sites-available/../secret", "/etc/nginx/sites-available/.hidden", "/etc/nginx/sites-available/sub/file", "/etc/nginx/confXd/site"):
            with self.subTest(name=name):
                self.assertIsNone(re.fullmatch(pattern, name))


if __name__ == "__main__":
    unittest.main()
