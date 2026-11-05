"""Synthetic producer evidence and real signatures; no UE or device execution."""
import hashlib
from pathlib import Path
import shutil
from types import SimpleNamespace
import unittest

from cryptography.hazmat.primitives import serialization

import baseline_feed
import release_notes
import release_set as sets
import test_release_set as fixtures
import windows_player


class BaselineFeedTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.ReleaseSetTests(methodName="runTest")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root = self.fixture.root
        self.player = self.root / "prepared/Windows"
        (self.player / "base").mkdir(parents=True)
        shutil.copytree(self.fixture.old, self.player / "base/payload")
        (self.player / "base/manifest.json").write_bytes(self.fixture.base)
        (self.player / "SampleGame.exe").write_bytes(b"synthetic-frozen-wrapper")
        config = dict(format=2, trust=self.fixture.trust, publicKeyHex=self.fixture.public,
                      manifestUrl="https://updates.example.test/v107/manifest.json", allowOffline=True)
        (self.player / "release-player.json").write_bytes(sets.canonical(config))
        value = sets.parse(self.fixture.base)
        self.notes = self.root / "notes.json"
        self.notes.write_bytes(sets.canonical(dict(schemaVersion=1, version="1.0.7", headline="Fixture only",
                                                  changes=[dict(title="Fixture", text="No game runtime claim")])))
        _, binding = release_notes.load(self.notes, "1.0.7")
        proof = {key: value[key] for key in ("sourceCommit", "nativeSourceHash", "engineBuildId", "shellCompatibilityId")}
        proof.update(kind="samplegame-complete-windows-build", fullCook=True, files=value["files"],
                     luaIdentity=dict(version="1.0.7", sha256="e" * 64, releaseNotes=binding))
        path = self.root / "build-proof.json"; path.write_bytes(sets.canonical(proof))
        producer = {key: value[key] for key in ("baseReleaseId", "sourceCommit", "nativeSourceHash", "buildId", "engineBuildId", "shellCompatibilityId")}
        producer.update(kind="samplegame-windows-release-set-player", manifestSha256=hashlib.sha256(self.fixture.base).hexdigest(),
                        playerRoot=str(self.player), frozenPlayerSha256=sets.digest(self.player / "SampleGame.exe"),
                        luaIdentity=proof["luaIdentity"], buildProofPath=str(path), buildProofSha256=sets.digest(path))
        self.producer = self.root / "prepared/producer-receipt.json"; self.producer.write_bytes(sets.canonical(producer))
        self.key = self.root / "private.pem"
        self.key.write_bytes(self.fixture.key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        self.args = SimpleNamespace(producer=self.producer, notes=self.notes, output=self.root / "feed", private_key=self.key,
                                    sdk_root=None, java_home=None, keystore=None)

    def test_exact_installed_baseline_is_signed_without_creating_a_redundant_candidate(self):
        receipt = baseline_feed.prepare(self.args)
        raw = (self.args.output / "manifest.json").read_bytes()
        self.assertEqual(raw, self.fixture.base)
        sets.ed25519_verifier(self.fixture.public)(raw, (self.args.output / "manifest.json.sig").read_bytes())
        self.assertEqual(receipt["releaseId"], receipt["baseReleaseId"])
        self.assertEqual(receipt["version"], "1.0.7")
        self.assertFalse(receipt["runtimeValidated"] or receipt["published"])
        self.assertFalse((self.player / ".release-sets").exists())
        sets.verify_tree(self.args.output / "versions/100/payload", sets.parse(raw)["files"])
        config = windows_player.read_config(self.player)
        requests = []
        def metadata_only(url, maximum):
            requests.append(url)
            if url == config["manifestUrl"]:
                return raw
            self.assertEqual(url, config["manifestUrl"] + ".sig", "A fresh installer must not download unchanged payload files")
            return (self.args.output / "manifest.json.sig").read_bytes()
        before = (self.fixture.store.root / "state.json").read_bytes()
        self.assertFalse(windows_player.candidate(self.fixture.store, config, metadata_only))
        self.assertEqual(len(requests), 2)
        self.assertEqual((self.fixture.store.root / "state.json").read_bytes(), before)
        with self.assertRaisesRegex(ValueError, "fresh external"):
            baseline_feed.prepare(self.args)

    def test_changed_payload_cannot_be_signed_as_the_original_baseline(self):
        path = self.player / "base/payload/SampleGame/Binaries/Win64/SampleGame.exe"
        path.write_bytes(b"replaced-code")
        with self.assertRaises(ValueError):
            baseline_feed.prepare(self.args)
        self.assertFalse(self.args.output.exists())

    def test_current_announcement_cannot_replace_the_frozen_cook_notes(self):
        self.notes.write_bytes(self.notes.read_bytes() + b"\n")
        with self.assertRaisesRegex(ValueError, "frozen Cook"):
            baseline_feed.prepare(self.args)
        self.assertFalse(self.args.output.exists())


if __name__ == "__main__":
    unittest.main()
