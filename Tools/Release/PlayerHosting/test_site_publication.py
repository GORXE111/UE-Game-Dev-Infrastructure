"""Website-only publisher fixtures; no production network or game acceptance."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SITE_SOURCE = Path(__file__).resolve().parents[1] / "Site"
SITE_ADAPTER_AVAILABLE = all((SITE_SOURCE / name).is_file() for name in ("deploy_site.py", "remote_site.py"))


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, SITE_SOURCE / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


if SITE_ADAPTER_AVAILABLE:
    publisher = module("site_publisher_fixture", "deploy_site.py")
    remote = module("site_remote_fixture", "remote_site.py")


@unittest.skipUnless(SITE_ADAPTER_AVAILABLE, "Requires the project-specific website publisher and remote worker")
class SitePublicationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="samplegame-site-publication-fixture-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        public = self.root / "public"; (public / "assets").mkdir(parents=True)
        art = b"synthetic-art-fixture"; name = hashlib.sha256(art).hexdigest() + ".png"
        (public / "assets" / name).write_bytes(art)
        (public / "index.html").write_text('<!doctype html><section data-channel="v106-release-pc"></section>'
            '<section data-channel="v106-release-android"></section><img src="/site-assets/' + name + '">', encoding="utf-8")
        self.prepared = self.root / "prepared"
        self.plan = publisher.prepare(public, self.prepared)
        self.server = self.root / "server"; self.server.mkdir()
        site, backups, content, native, players = [self.server / name for name in ("site", "backups", "channels", "native", "players")]
        for directory in (site, backups, content, native, players):
            directory.mkdir()
        (site / "assets").mkdir(); (site / "index.html").write_bytes(b"old-homepage")
        nginx = self.server / "nginx.conf"; nginx.write_bytes(b"original-nginx")
        for name, value in dict(SITE=site, BACKUPS=backups, CONTENT=content, NATIVE=native, PLAYERS=players, NGINX=nginx,
                                CHANNELS=((content, "v106-release-pc"), (content, "v106-release-android"))).items():
            context = patch.object(remote, name, value); context.start(); self.addCleanup(context.stop)

    def test_site_only_deployment_and_exact_html_rollback_preserve_game_catalog(self):
        before = remote.snapshot()
        result = remote.deploy(self.prepared / "site.tar.gz", self.plan, before)
        self.assertEqual(remote.protected_state(), before["protected"])
        self.assertEqual(remote.file_state(remote.SITE / "index.html")["sha256"], self.plan["files"]["index.html"]["sha256"])
        remote.rollback(result["backup"], result["indexSha256"])
        self.assertEqual((remote.SITE / "index.html").read_bytes(), b"old-homepage")
        self.assertEqual(remote.protected_state(), before["protected"])

    def test_protected_state_race_and_changed_tar_cannot_replace_html(self):
        before = remote.snapshot(); remote.NGINX.write_bytes(b"concurrent-nginx")
        with self.assertRaisesRegex(AssertionError, "changed"):
            remote.deploy(self.prepared / "site.tar.gz", self.plan, before)
        self.assertEqual((remote.SITE / "index.html").read_bytes(), b"old-homepage")
        (self.prepared / "site.tar.gz").write_bytes(b"bad-archive")
        with self.assertRaisesRegex(ValueError, "changed"):
            publisher.load(self.prepared)

    def test_unknown_deployment_acknowledgment_is_preserved_as_failed(self):
        host = unittest.mock.Mock()
        inspection = self.root / "inspection.json"
        inspection.write_text(json.dumps(dict(action="inspect", status="passed", remote=remote.snapshot(),
            preparedPlanSha256=publisher.players.digest(self.prepared / "prepared.json"))))
        host.run.side_effect = [dict(stage="/srv/ue-game-updates/.site-upload-" + "ab"*16), TimeoutError("synthetic lost acknowledgment")]
        report = publisher.network("publish", self.prepared, self.root / "report", host, inspection)
        self.assertEqual(report["status"], "failed")
        self.assertIn("lost acknowledgment", report["error"])
        self.assertNotIn("htmlOnlyRollback", report)

    def test_real_linux_publication_lock_rejects_concurrent_owner(self):
        try:
            import fcntl
        except ImportError:
            self.skipTest("Actual site lease requires the Linux host")
        with remote.publication_lease():
            with self.assertRaises(BlockingIOError):
                with remote.publication_lease():
                    pass


if __name__ == "__main__":
    unittest.main()
