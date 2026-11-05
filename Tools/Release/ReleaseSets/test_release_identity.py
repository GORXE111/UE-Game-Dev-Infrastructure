"""Frozen-client version grammar and literal-source binding; no Lua or device execution."""
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import release_identity
import windows_pipeline
import android_pipeline
import release_set as sets
from map_inventory_fixtures import source_maps


class ReleaseIdentityTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.project = self.root / "repo/Project/SampleGame"
        source_maps(self.project)
        self.source = self.project / release_identity.SOURCE

    def test_frozen_android_grammar_accepts_numeric_version_and_metadata(self):
        for value in ("0.0.0", "1.0.7", "1.0.7+dev.1", "1.0.6+hotfix.1", "999.999.999+test-2"):
            self.assertEqual(release_identity.validate_version(value), value)

    def test_prerelease_leading_zero_unicode_and_unbounded_version_are_rejected(self):
        for value in ("1.0.7-dev.1", "01.0.7", "1.00.7", "1000.0.0", "1.0.7+", "1.0.7+x..y", "1.0.7+测试", "1.0.7+x\n", "1.0.7+" + "x" * 96, None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                release_identity.validate_version(value)

    def test_actual_literal_and_raw_source_bytes_are_bound_to_proof(self):
        original = release_identity.snapshot(self.project)
        self.assertEqual(original["version"], "1.0.6")
        self.assertEqual(release_identity.proof_identity(dict(luaIdentity=original), self.project), original)
        self.source.write_text('local version = "1.0.7+dev.1"\n', encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "changed since"):
            release_identity.proof_identity(dict(luaIdentity=original), self.project)
        self.assertEqual(release_identity.proof_identity({}, self.project)["version"], "1.0.7+dev.1")

    def test_ambiguous_dynamic_and_unsupported_old_sources_cannot_be_signed(self):
        for source in ('local version = get_version()\n', 'local version = "1.0.7"\nlocal version = "1.0.8"\n',
                       'local version = "1.0.7-dev.1"\n', 'return {version="1.0.7"}\n'):
            self.source.write_text(source, encoding="utf-8")
            with self.subTest(source=source), self.assertRaises(ValueError):
                release_identity.proof_identity({}, self.project)

    def test_both_builders_reject_bad_identity_before_hash_compile_or_output(self):
        self.source.write_text('local version = "1.0.7-dev.1"\n', encoding="utf-8")
        engine = self.root / "engine"
        for name in ("Engine/Build/Android/Java/src/com/epicgames/unreal/GameActivity.java.template",
                     "Engine/Build/BatchFiles/Build.bat", "Engine/Build/BatchFiles/RunUAT.bat"):
            file = engine / name; file.parent.mkdir(parents=True, exist_ok=True); file.write_bytes(b"synthetic")
        for producer in (windows_pipeline, android_pipeline):
            args = SimpleNamespace(project=self.project, engine=engine, output=self.root / "never")
            with patch.object(producer, "check_cook_maps"), patch.object(producer, "identity") as identity, patch.object(producer, "execute") as execute:
                with self.assertRaisesRegex(ValueError, "installed Android health protocol"):
                    producer.build(args)
                identity.assert_not_called(); execute.assert_not_called()
                self.assertFalse(args.output.exists())

    def test_installer_version_comes_from_immutable_cook_proof(self):
        value = dict(baseReleaseId=200, sourceCommit="a" * 40, nativeSourceHash="b" * 64,
                     buildId="c" * 64, engineBuildId="engine", shellCompatibilityId="d" * 64)
        identity = dict(version="1.0.7", sha256="e" * 64)
        proof = {key: value[key] for key in ("sourceCommit", "nativeSourceHash", "engineBuildId", "shellCompatibilityId")}
        proof["luaIdentity"] = identity
        path = self.root / "proof.json"; path.write_bytes(sets.canonical(proof))
        receipt = dict(**value, luaIdentity=identity, buildProofPath=str(path), buildProofSha256=sets.digest(path),
                       manifestSha256=release_identity.hashlib.sha256(sets.canonical(value)).hexdigest())
        producer = self.root / "producer.json"; producer.write_bytes(sets.canonical(receipt))
        self.assertEqual(release_identity.archive_version(producer, value), "1.0.7")
        path.write_bytes(sets.canonical(dict(proof, luaIdentity=dict(identity, version="1.0.8"))))
        with self.assertRaisesRegex(ValueError, "proof changed"):
            release_identity.archive_version(producer, value)
        del receipt["luaIdentity"]; producer.write_bytes(sets.canonical(receipt))
        with self.assertRaisesRegex(ValueError, "requires frozen"):
            release_identity.archive_version(producer, value)


if __name__ == "__main__":
    unittest.main()
