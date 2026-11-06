from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from verify_cooked_assets import verify


class CookedAssetsTests(unittest.TestCase):
    def setUp(self):
        scratch = TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.root = Path(scratch.name)
        self.report = dict(inventories=[], checks=[])

    def write_listing(self, name, mount, paths, footer=None):
        inventory = self.root / (name + ".log")
        lines = [f'LogPakFile: Display: Listing {name}.pak with mount point "{mount}"']
        for path in paths:
            lines.append(f'LogPakFile: Display: "{path}" offset: 7, size: 15 bytes, '
                         f'sha1: {"0" * 40}, compression: None.')
        if footer is None:
            footer = f"{len(paths)} files ({15 * len(paths)} bytes), (0 filtered bytes)."
        lines.append(f"LogPakFile: Display: {footer}")
        inventory.write_text("\n".join(lines) + "\n", encoding="utf-8-sig")
        return inventory

    def test_checks_engine_map_and_game_asset_across_paks(self):
        engine = self.write_listing("pakchunk0", "../../../", ["../../../Engine/Content/Maps/Entry.umap"])
        game = self.write_listing("pakchunk1", "../../../Demo/Content/", ["../../../Demo/Content/Data/Tuning.uasset"])
        verify("Demo", [engine, game], ["/Engine/Maps/Entry"], ["/Game/Data/Tuning.Tuning"], self.report)
        self.assertEqual([item["status"] for item in self.report["checks"]], ["passed", "passed"])
        self.assertEqual(self.report["checks"][1]["foundIn"], [
            dict(pak="pakchunk1.pak", path="Demo/Content/Data/Tuning.uasset", size=15),
        ])

    def test_rejects_similar_paths_and_sidecars(self):
        inventory = self.write_listing("pakchunk0", "../../../", [
            "../../../OtherGame/Content/Data/Tuning.uasset",
            "../../../Demo/Content/Data/Tuning.uexp",
            "../../../Demo/Content/Maps/Entry.uasset",
        ])
        with self.assertRaisesRegex(ValueError, "missing from the staged PAKs"):
            verify("Demo", [inventory], ["/Game/Maps/Entry"], ["/Game/Data/Tuning.Tuning"], self.report)
        self.assertEqual([item["status"] for item in self.report["checks"]], ["failed", "failed"])

    def test_rejects_incomplete_or_unmounted_listings(self):
        map_path = "../../../Engine/Content/Maps/Entry.umap"
        for paths, footer, error in (
            ([map_path], "", "complete unfiltered"),
            ([map_path], "1 files (15 bytes), (6 filtered bytes).", "complete unfiltered"),
            ([map_path], "2 files (30 bytes), (0 filtered bytes).", "complete unfiltered"),
            (["Engine/Content/Maps/Entry.umap"], None, "ExtractToMountPoint"),
        ):
            with self.subTest(paths=paths, footer=footer):
                inventory = self.write_listing("pakchunk0", "../../../", paths, footer)
                with self.assertRaisesRegex(ValueError, error):
                    verify("Demo", [inventory], ["/Engine/Maps/Entry"], [], dict(inventories=[], checks=[]))


if __name__ == "__main__":
    unittest.main()
