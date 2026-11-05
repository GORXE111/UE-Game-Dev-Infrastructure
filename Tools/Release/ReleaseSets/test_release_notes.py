"""Editorial source validation and build/source identity; no engine or public deployment."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import release_identity
import release_notes
import release_set as sets
import compatibility


class ReleaseNotesTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.project = Path(temporary.name)
        self.source = self.project / release_notes.SOURCE
        self.source.parent.mkdir(parents=True)
        self.lua = self.project / release_identity.SOURCE
        self.lua.parent.mkdir(parents=True)
        self.lua.write_text('local version = "1.0.7+dev.1"\n', encoding="utf-8")
        self.value = dict(schemaVersion=1, version="1.0.7+dev.1", headline="本次更新", changes=[dict(title="公告", text="离线可读")])
        self.write(self.value)

    def write(self, value):
        self.source.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")

    def test_exact_source_is_bound_and_editorial_change_invalidates_actual_proof(self):
        identity = release_identity.snapshot(self.project)
        self.assertEqual(release_notes.load(self.source, identity["version"])[0], self.value)
        self.assertIn("releaseNotes", identity)
        self.assertEqual(release_identity.proof_identity(dict(luaIdentity=identity), self.project), identity)
        self.value["changes"][0]["text"] += "，内容已调整"
        self.write(self.value)
        with self.assertRaisesRegex(ValueError, "changed since"):
            release_identity.proof_identity(dict(luaIdentity=identity), self.project)

    def test_wrong_version_unknown_fields_empty_and_unbounded_sections_rejected(self):
        cases = []
        for field, value in (("schemaVersion", True), ("version", "1.0.6"), ("extra", 1), ("changes", []),
                             ("changes", self.value["changes"] * 13), ("headline", "bad\ntext")):
            case = copy.deepcopy(self.value); case[field] = value; cases.append(case)
        case = copy.deepcopy(self.value); case["changes"][0]["text"] = "字" * 401; cases.append(case)
        for case in cases:
            self.write(case)
            with self.subTest(case=case), self.assertRaises(ValueError):
                release_identity.snapshot(self.project)

    def test_duplicate_keys_and_oversized_bytes_rejected(self):
        self.source.write_text('{"version":"1","version":"2"}', encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            release_notes.load(self.source)
        self.source.write_bytes(b" " * (16 * 1024 + 1))
        with self.assertRaises(ValueError):
            release_notes.load(self.source)

    def test_historical_projects_without_announcement_still_supported(self):
        self.source.unlink()
        self.assertNotIn("releaseNotes", release_identity.snapshot(self.project))

    def test_text_limits_match_client_utf16_units(self):
        self.value["changes"][0]["title"] = "😀" * 41
        self.write(self.value)
        with self.assertRaisesRegex(ValueError, "sections"):
            release_identity.snapshot(self.project)

    def test_site_cli_rejects_notes_not_matching_real_build_source(self):
        root = Path(__file__).resolve().parents[1]
        proof = self.project / "proof.json"
        proof.write_text(json.dumps(dict(luaIdentity=release_identity.snapshot(self.project), sourceCommit="a" * 40, nativeSourceHash="b" * 64)), encoding="utf-8")
        manifest = self.project / "manifest.json"
        manifest.write_bytes(sets.canonical(dict(nativeSourceHash="b" * 64, sourceCommit="a" * 40)))
        self.value["headline"] += " changed"; self.write(self.value)
        output = self.project / "must-not-exist.json"
        result = subprocess.run([sys.executable, "-B", str(root / "Site/prepare_release_display.py"), "--manifest", str(manifest),
                                 "--output", str(output), "--notes", str(self.source), "--build-proof", str(proof)], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Announcement does not match", result.stderr)
        self.assertFalse(output.exists())

    def test_site_cli_uses_the_same_cooked_notes_and_manifest_binding(self):
        root = Path(__file__).resolve().parents[1]
        proof = self.project / "proof.json"
        proof.write_text(json.dumps(dict(luaIdentity=release_identity.snapshot(self.project), sourceCommit="a" * 40, nativeSourceHash="b" * 64)), encoding="utf-8")
        value = dict(format=1, kind="samplegame-release-set", projectId="SampleGame", platform="Windows", channel="test-pc",
                     baseReleaseId=100, releaseId=101, engineBuildId="engine-build", shellCompatibilityId="c" * 64,
                     minLoaderVersion=1, sourceCommit="a" * 40, nativeSourceHash="b" * 64, save=copy.deepcopy(compatibility.CURRENT_SAVE_POLICY),
                     files=[dict(path="SampleGame/Binaries/Win64/SampleGame.exe", role="native", size=1, sha256="d" * 64),
                            dict(path="SampleGame/Content/Paks/SampleGame-Windows.pak", role="content", size=1, sha256="e" * 64)])
        value["buildId"] = sets.build_id(value)
        manifest = self.project / "manifest.json"; manifest.write_bytes(sets.canonical(value))
        output = self.project / "display.json"
        result = subprocess.run([sys.executable, "-B", str(root / "Site/prepare_release_display.py"), "--manifest", str(manifest),
                                 "--output", str(output), "--notes", str(self.source), "--build-proof", str(proof)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        display = json.loads(output.read_bytes())
        self.assertEqual(display["changes"], self.value["changes"])
        self.assertEqual(display["version"], self.value["version"])
        self.assertEqual(display["buildId"], value["buildId"])


if __name__ == "__main__":
    unittest.main()
