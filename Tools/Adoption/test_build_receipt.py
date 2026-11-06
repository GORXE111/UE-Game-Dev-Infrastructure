import hashlib
import json
from pathlib import Path
import shutil
from tempfile import TemporaryDirectory
import unittest

from build_receipt import create_receipt, verify_receipt


class BuildReceiptTests(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.archive = self.root / "Windows"
        self.receipt = self.root / "receipt.json"
        self.metadata_path = self.root / "metadata.json"
        self.metadata = {
            "project": "Demo",
            "target": "DemoClient",
            "platform": "Win64",
            "configuration": "Development",
            "commit": "a" * 40,
            "engine": {"version": "5.8.3", "buildId": "dev-build"},
            "sdk": {"windows": "10.0.22621.0", "compiler": "Clang", "compilerVersion": "20.1.8"},
            "configManifestSha256": "b" * 64,
            "tests": {"editor-assets": "passed", "cooked-assets": "passed", "packaged-startup": "passed"},
        }
        self.metadata_path.write_text(json.dumps(self.metadata), encoding="utf-8-sig")
        self.exe = self.write("Demo/Binaries/Win64/DemoClient.exe", b"example executable")
        self.pak = self.write("Demo/Content/Paks/Demo-Windows.pak", b"example archive")
        self.notices = self.write("NOTICES.txt", b"")

    def write(self, relative, content):
        path = self.archive / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return path

    def test_round_trip_portable_and_deterministic(self):
        created = create_receipt(self.archive, self.metadata_path, self.receipt)
        second = self.root / "second.json"
        create_receipt(self.archive, self.metadata_path, second)
        raw = self.receipt.read_bytes()
        self.assertEqual(raw, second.read_bytes())
        self.assertEqual(created["receiptSha256"], hashlib.sha256(raw).hexdigest())
        value = json.loads(raw)
        self.assertEqual(value["metadata"], self.metadata)
        self.assertEqual([record["path"] for record in value["files"]],
                         ["Demo/Binaries/Win64/DemoClient.exe", "Demo/Content/Paks/Demo-Windows.pak", "NOTICES.txt"])
        moved = self.root / "Restored"
        shutil.copytree(self.archive, moved)
        verified = verify_receipt(moved, self.receipt, created["receiptSha256"])
        self.assertEqual(verified, {**created, "status": "verified"})

    def test_changed_added_and_removed_files_block_verification(self):
        create_receipt(self.archive, self.metadata_path, self.receipt)
        original = self.pak.read_bytes()
        self.pak.write_bytes(b"X" + original[1:])
        with self.assertRaisesRegex(ValueError, "Archive file changed: .*pak"):
            verify_receipt(self.archive, self.receipt)
        self.pak.write_bytes(original)
        added = self.write("EXTRA.txt", b"extra")
        with self.assertRaisesRegex(ValueError, "Unexpected archive file: EXTRA.txt"):
            verify_receipt(self.archive, self.receipt)
        added.unlink()
        self.notices.unlink()
        with self.assertRaisesRegex(ValueError, "Archive file missing: NOTICES.txt"):
            verify_receipt(self.archive, self.receipt)

    def test_pinned_receipt_rejects_metadata_replacement(self):
        original = create_receipt(self.archive, self.metadata_path, self.receipt)
        self.metadata["commit"] = "c" * 40
        self.metadata_path.write_text(json.dumps(self.metadata), encoding="utf-8")
        replacement = self.root / "replacement.json"
        create_receipt(self.archive, self.metadata_path, replacement)
        with self.assertRaisesRegex(ValueError, "digest differs"):
            verify_receipt(self.archive, replacement, original["receiptSha256"])

    def test_rejects_failed_tests_missing_exe_and_unsafe_output(self):
        self.metadata["tests"]["packaged-startup"] = "failed"
        self.metadata_path.write_text(json.dumps(self.metadata), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "Expected successful"):
            create_receipt(self.archive, self.metadata_path, self.receipt)
        self.assertFalse(self.receipt.exists())
        self.metadata["tests"]["packaged-startup"] = "passed"
        self.metadata_path.write_text(json.dumps(self.metadata), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "outside its archive"):
            create_receipt(self.archive, self.metadata_path, self.archive / "receipt.json")
        self.exe.unlink()
        with self.assertRaisesRegex(ValueError, "executable missing"):
            create_receipt(self.archive, self.metadata_path, self.receipt)

    def test_links_are_rejected(self):
        outside = self.root / "outside.txt"
        outside.write_bytes(b"not part of the archive")
        try:
            (self.archive / "alias.txt").symlink_to(outside)
        except (OSError, NotImplementedError):
            self.skipTest("Filesystem does not permit test symlinks")
        with self.assertRaisesRegex(ValueError, "Links and reparse points"):
            create_receipt(self.archive, self.metadata_path, self.receipt)


if __name__ == "__main__":
    unittest.main()
