"""Signed downloads and actual child-process health/recovery; fixtures are not UE."""
import copy
import json
import shutil
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

import release_set as sets
import windows_player as player
import test_release_set as fixtures


class WindowsPlayerTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.ReleaseSetTests(methodName="runTest")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.store = self.fixture.store
        self.config = dict(format=1, trust=self.fixture.trust, publicKeyHex=self.fixture.public,
                           manifestUrl="https://updates.example.test/v106/manifest.json", allowOffline=True)

    def product(self):
        source, raw = self.fixture.product(101, b"new-pair")
        files = {"https://updates.example.test/v106/manifest.json": raw,
                 "https://updates.example.test/v106/manifest.json.sig": self.fixture.key.sign(raw)}
        for record in sets.parse(raw)["files"]:
            files["https://updates.example.test/v106/versions/101/payload/" + record["path"]] = (source / record["path"]).read_bytes()
        return files

    @staticmethod
    def fetcher(files):
        def fetch(url, maximum, destination=None, progress=None):
            data = files[url]
            if destination:
                Path(destination).write_bytes(data)
                return len(data)
            return data
        return fetch

    def stage(self):
        player.candidate(self.store, self.config, self.fetcher(self.product()))
        return self.store.boot()

    @staticmethod
    def subprocess_fixture(selected, *, status=0, health=True, wrong_pid=False, delay=0, hold=0):
        # An actual Python child models exit/ACK boundaries without pretending to execute the dummy EXE.
        def popen(arguments, **kwargs):
            path = Path(selected["payloadRoot"]).parents[1] / "boots" / selected["attemptId"] / "ticket.json"
            code = """import json,os,pathlib,sys,time
t=json.loads(pathlib.Path(sys.argv[1]).read_text())
time.sleep(float(sys.argv[2]))
if sys.argv[3]=='yes':
 a={k:t[k] for k in ('attemptId','releaseId','manifestSha256','buildId','saveSchema','userRoot')}
 a.update(format=1,pid=os.getpid()+int(sys.argv[4]),luaVersion='1.0.6')
 pathlib.Path(t['ackPath']).write_text(json.dumps(a))
time.sleep(float(sys.argv[6]))
sys.exit(int(sys.argv[5]))
"""
            # On Windows the venv redirector and its interpreter have different process IDs.
            interpreter = Path(sys.base_prefix) / "python.exe" if sys.platform == "win32" else sys.executable
            return subprocess.Popen([interpreter, "-c", code, str(path), str(delay), "yes" if health else "no",
                                     "1" if wrong_pid else "0", str(status), str(hold)], **kwargs)
        return popen

    def test_signed_pair_downloads_and_activates_together(self):
        self.assertTrue(player.candidate(self.store, self.config, self.fetcher(self.product())))
        self.assertEqual(self.store._state()["active"]["releaseId"], 101)
        selected = self.store._selection(self.store._state()["active"])
        self.fixture.assert_pair(selected, b"new-pair")
        self.assertEqual((Path(selected["savesRoot"]) / "SampleQuickSave.sav").read_bytes(), b"original-v0-save")

    def test_corrupt_file_never_activates(self):
        files = self.product()
        key = next(key for key in files if key.endswith(".pak"))
        files[key] = b"corrupt"
        with self.assertRaises(ValueError):
            player.candidate(self.store, self.config, self.fetcher(files))
        self.assertEqual(self.store._state()["active"]["releaseId"], 100)

    def test_signature_rejection_precedes_any_artifact_download(self):
        files = self.product()
        files[self.config["manifestUrl"] + ".sig"] = b"x" * 64
        visited = []
        fetch = self.fetcher(files)
        def traced(url, *args):
            visited.append(url)
            return fetch(url, *args)
        with self.assertRaises(ValueError):
            player.candidate(self.store, self.config, traced)
        self.assertEqual(len(visited), 2)

    def test_real_child_ack_and_normal_exit_confirm(self):
        selected = self.stage()
        self.assertEqual(player.launch(self.store, selected, popen=self.subprocess_fixture(selected)), 0)
        self.assertIsNone(self.store._state()["boot"])
        self.assertEqual(self.store._state()["active"]["releaseId"], 101)

    def test_normal_exit_without_health_rolls_back_complete_pair(self):
        selected = self.stage()
        with self.assertRaises(OSError):
            player.launch(self.store, selected, popen=self.subprocess_fixture(selected, health=False))
        self.assertEqual(self.store._state()["active"]["releaseId"], 100)
        self.assertEqual(self.store._state()["blocked"], [101])

    def test_nonzero_exit_with_health_is_rejected(self):
        selected = self.stage()
        with self.assertRaises(ValueError):
            player.launch(self.store, selected, popen=self.subprocess_fixture(selected, status=7))
        self.assertEqual(self.store._state()["active"]["releaseId"], 100)

    def test_ack_from_another_pid_is_rejected(self):
        selected = self.stage()
        with self.assertRaises(ValueError):
            player.launch(self.store, selected, popen=self.subprocess_fixture(selected, wrong_pid=True))
        self.assertEqual(self.store._state()["active"]["releaseId"], 100)

    def test_invalid_ack_file_does_not_disable_startup_timeout(self):
        selected = self.stage()
        start = self.subprocess_fixture(selected, wrong_pid=True, hold=5)
        with self.assertRaisesRegex(ValueError, "valid startup health"):
            player.launch(self.store, selected, popen=start, startup_timeout=1.5)
        boot = self.store.root / "boots" / selected["attemptId"]
        self.assertTrue((boot / "health.json").is_file())
        self.assertEqual(self.store._state()["active"]["releaseId"], 100)

    def test_startup_timeout_stops_only_our_child_before_releasing_lease(self):
        selected = self.stage()
        children = []
        start = self.subprocess_fixture(selected, delay=30)
        def tracked(*args, **kwargs):
            process = start(*args, **kwargs)
            children.append(process)
            return process
        with self.assertRaises(ValueError):
            player.launch(self.store, selected, popen=tracked, startup_timeout=.1)
        self.assertIsNotNone(children[0].poll())
        self.assertEqual(self.store._state()["active"]["releaseId"], 100)

    def test_health_cannot_change_build_save_identity_or_schema(self):
        selected = self.stage()
        _, expected = player.ticket(self.store, selected)
        good = {key: expected[key] for key in ("attemptId", "releaseId", "manifestSha256", "buildId", "saveSchema", "userRoot")}
        good.update(format=1, pid=123, luaVersion="1.0.6")
        player.acknowledgement(good, expected, 123)
        for field, value in (("attemptId", "c" * 32), ("buildId", "c" * 64), ("saveSchema", 2), ("releaseId", 999), ("userRoot", str(self.fixture.root))):
            bad = copy.deepcopy(good); bad[field] = value
            with self.assertRaises(ValueError):
                player.acknowledgement(bad, expected, 123)

    def test_arguments_cannot_bypass_release_or_saved_root(self):
        selected = self.stage()
        for argument in ("-UserDir=C:/other", "-SampleContentLuaRoot=C:/old", "-ini:Engine:test=x", "-ExecCmds=quit", "-remoteini=C:/old", "/Game/other"):
            with self.assertRaises(ValueError):
                player.game_arguments(selected, Path("ticket.json"), [argument])
        self.assertIn("-NullRHI", player.game_arguments(selected, Path("ticket.json"), ["-NullRHI"]))

    def test_windows_command_quotes_ue_values_and_unicode_paths(self):
        result = player.windows_command(["E:/测试 包/game.exe", "-UserDir=E:/测试 存档", "-NullRHI"])
        self.assertIn('-UserDir="E:/测试 存档"', result)

    def test_only_https_fixed_origin_urls_are_accepted(self):
        for url in ("http://updates.example.test/manifest.json", "https://user:pass@updates.example.test/manifest.json", "https://updates.example.test/a/../manifest.json", "https://updates.example.test/%2e/manifest.json", "https://updates.example.test/manifest.json?q=x"):
            with self.assertRaises(ValueError):
                player.endpoint(url)

    def test_cross_base_import_uses_confirmed_progress_and_preserves_old_state(self):
        confirmed = self.store.confirmed_save_source([0, 1])
        saved = Path(confirmed["savesRoot"]) / "Saved"
        (saved / "SaveGames").mkdir(parents=True)
        (saved / "Config").mkdir()
        (saved / "SaveGames/progress.sav").write_bytes(b"confirmed-progress")
        (saved / "Config/GameUserSettings.ini").write_bytes(b"settings")
        (saved / "private.log").write_bytes(b"not-user-data")
        selected = self.stage()  # Unconfirmed candidate must not be imported.
        candidate = Path(selected["savesRoot"]) / "Saved/SaveGames/progress.sav"
        candidate.write_bytes(b"unconfirmed-progress")
        old = self.fixture.root / "old-install"
        shutil.copytree(self.store.root, old / ".release-sets", ignore=shutil.ignore_patterns("lease.lock"))
        state = old / ".release-sets/state.json"
        before = state.read_bytes()
        target = self.fixture.root / "new-install"; target.mkdir()
        base = dict(baseReleaseId=200, save=dict(readable=[0, 1]))
        with patch.dict(player.PREVIOUS_BASES, {100: self.fixture.trust["baseManifestSha256"]}, clear=True):
            snapshot, receipt = player.release_snapshot(target, old, self.config, base)
        self.assertTrue(receipt["pendingBootSkipped"])
        self.assertEqual(receipt["reference"]["releaseId"], 100)
        self.assertEqual((snapshot / "Saved/SaveGames/progress.sav").read_bytes(), b"confirmed-progress")
        self.assertEqual((snapshot / "Saved/Config/GameUserSettings.ini").read_bytes(), b"settings")
        self.assertFalse((snapshot / "Saved/private.log").exists())
        self.assertEqual(state.read_bytes(), before)

    def test_new_pc_baselines_have_separate_stores_and_keep_legacy_layout(self):
        root = self.fixture.root
        self.assertEqual(player.store_root(root, self.config), root / ".release-sets")
        config = copy.deepcopy(self.config); config["format"] = 2
        first = player.store_root(root, config)
        config["trust"]["baseReleaseId"] += 1
        self.assertNotEqual(first, player.store_root(root, config))

    def test_cross_base_import_rejects_unknown_official_pin(self):
        old = self.fixture.root / "old-install"
        shutil.copytree(self.store.root, old / ".release-sets", ignore=shutil.ignore_patterns("lease.lock"))
        target = self.fixture.root / "new-install"; target.mkdir()
        with self.assertRaisesRegex(ValueError, "Unsupported prior"):
            player.release_snapshot(target, old, self.config, dict(baseReleaseId=200, save=dict(readable=[0, 1])))


if __name__ == "__main__":
    unittest.main()
