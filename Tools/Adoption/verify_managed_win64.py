"""Exercise accepted ProfileSample builds through the managed player on loopback HTTPS."""

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from ipaddress import ip_address
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import sys
from threading import Thread
from urllib.request import HTTPSHandler, ProxyHandler, build_opener

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

import build_receipt

RELEASE_TOOLS = Path(__file__).resolve().parents[1] / "Release" / "ReleaseSets"
sys.path.insert(0, str(RELEASE_TOOLS))
import release_set as sets
import windows_player

PROJECT = "ProfileSample"
ENTRY = sets.windows_entry(PROJECT)
ROLES = ("baseline", "candidate", "fault")
PREFIX = "/profile-sample/adoption-qa/updates/"
ORIGIN = "https://127.0.0.1"
SAVE = "Saved/SaveGames/AdoptionRelease.sav"


def checked_archive(report_path, role):
    report_path = report_path.resolve(strict=True)
    report, _ = build_receipt.read_json(report_path, build_receipt.MAX_METADATA)
    sets.require(report["status"] == "project-profile-passed" and report["gameExitCode"] == 0,
                 f"{role} requires a passed project profile")
    archive = Path(report["archive"]).resolve(strict=True)
    receipt_path = Path(report["buildReceipt"]).resolve(strict=True)
    receipt_hash = sets.sha(report["buildReceiptSha256"])
    build_receipt.verify_receipt(archive, receipt_path, receipt_hash)
    receipt, raw = build_receipt.read_json(receipt_path, build_receipt.MAX_RECEIPT)
    sets.require(hashlib.sha256(raw).hexdigest() == receipt_hash, "Receipt changed during verification")
    metadata = receipt["metadata"]
    sets.require(metadata["project"] == metadata["target"] == PROJECT and
                 metadata["configManifestSha256"] == report["configManifestSha256"], "Unexpected sample build identity")
    output = Path(report["outputDirectory"])
    expected = f"UE_ADOPTION_RELEASE_PAIR_READY native={role} content={role}"
    sets.require(expected in (output / "packaged-game.log").read_text(encoding="utf-8", errors="replace"),
                 f"{role} did not prove its packaged native/content pair")
    normalized = json.loads((output / "normalized-profile.json").read_text(encoding="utf-8-sig"))
    source = Path(normalized["project"]).parent
    native_tree = subprocess.check_output(
        ["git", "-C", str(source), "ls-tree", "-r", metadata["commit"], "--", "Source"], timeout=30)
    sets.require(native_tree, "The committed sample has no native source inventory")
    records = []
    for item in receipt["files"]:
        name = item["path"]
        if not name.startswith((PROJECT + "/", "Engine/")):
            sets.require(name in {"ProfileSample.exe", "NOTICES.txt", "Manifest_DebugFiles_Win64.txt",
                                  "Manifest_NonUFSFiles_Win64.txt", "Manifest_UFSFiles_Win64.txt"},
                         f"Unexpected top-level archive file {name}")
            continue
        role_name = ("content" if name.startswith(PROJECT + "/Content/Paks/") and name.endswith(".pak")
                     else "native" if name.lower().endswith((".exe", ".dll")) else "support")
        records.append(dict(item, role=role_name))
    return dict(archive=archive, metadata=metadata, files=records, receiptSha256=receipt_hash,
                nativeSourceHash=hashlib.sha256(native_tree).hexdigest())


def immutable_files(build):
    return [record for record in build["files"] if record["path"] != ENTRY and record["role"] != "content"]


def write_version(root, number, trust, build, key):
    directory = root / str(number)
    payload = directory / "payload"
    payload.mkdir(parents=True)
    for item in build["files"]:
        source = sets.child(build["archive"], item["path"])
        destination = sets.child(payload, item["path"])
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
    sets.verify_inventory(payload, build["files"])
    manifest = dict(format=1, kind="samplegame-release-set", **{field: trust[field] for field in sets.BINDINGS},
                    releaseId=number, minLoaderVersion=1, sourceCommit=build["metadata"]["commit"],
                    nativeSourceHash=build["nativeSourceHash"], files=build["files"],
                    save=dict(schema=1, readable=[1], migrations=[]))
    manifest["buildId"] = sets.build_id(manifest)
    raw = sets.canonical(manifest)
    sets.manifest(raw, trust)
    sets.write_new(directory / "manifest.json", raw)
    sets.write_new(directory / "manifest.json.sig", key.sign(raw))
    return hashlib.sha256(raw).hexdigest()


def create_tls(root):
    now = datetime.now(timezone.utc)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ProfileSample temporary test CA")])
    host_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    host_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def certificate(subject, key, ca):
        return (x509.CertificateBuilder().subject_name(subject).issuer_name(ca_name).public_key(key.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
                .not_valid_after(now + timedelta(hours=4))
                .add_extension(x509.BasicConstraints(ca=ca, path_length=0 if ca else None), critical=True)
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False))

    ca = (certificate(ca_name, ca_key, True)
          .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, None, None), critical=True)
          .sign(ca_key, hashes.SHA256()))
    host = (certificate(host_name, host_key, False)
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ip_address("127.0.0.1"))]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))
    ca_file, cert_file, key_file = (root / name for name in ("qa-ca.pem", "qa-host.pem", "qa-host-key.pem"))
    sets.write_new(ca_file, ca.public_bytes(serialization.Encoding.PEM))
    sets.write_new(cert_file, host.public_bytes(serialization.Encoding.PEM))
    sets.write_new(key_file, host_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                   serialization.NoEncryption()))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        context.load_cert_chain(cert_file, key_file)
    finally:
        key_file.unlink()
    return context, ca_file


class TestOrigin:
    def __init__(self, versions, context):
        self.release = 100
        self.switch_after_manifest = None
        self.requests = []
        self.files = {f"versions/{item.relative_to(versions).as_posix()}": item
                      for item in versions.rglob("*") if item.is_file()}
        origin = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_GET(self):
                name = self.path.removeprefix(PREFIX)
                current = self.path.startswith(PREFIX) and name in ("manifest.json", "manifest.json.sig")
                versioned = f"versions/{origin.release}/{name}" if current else name
                source = origin.files.get(versioned) if self.path.startswith(PREFIX) else None
                if source is None:
                    self.send_error(404)
                    return
                origin.requests.append(versioned)
                if current and name == "manifest.json" and origin.switch_after_manifest is not None:
                    origin.release, origin.switch_after_manifest = origin.switch_after_manifest, None
                self.send_response(200)
                self.send_header("Content-Length", str(source.stat().st_size))
                self.send_header("Cache-Control", "no-store" if current else "public, max-age=31536000, immutable")
                self.end_headers()
                with source.open("rb") as stream:
                    shutil.copyfileobj(stream, self.wfile, 256 * 1024)

        self.server = ThreadingHTTPServer(("127.0.0.1", 443), Handler)
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.thread = Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_):
        self.server.shutdown()
        self.thread.join()
        self.server.server_close()


def verify_downloads(origin, ca_file, destination):
    opener = build_opener(ProxyHandler({}), HTTPSHandler(context=ssl.create_default_context(cafile=ca_file)))
    verified = []
    for name, path in sorted(origin.files.items()):
        url = ORIGIN + PREFIX + name
        with opener.open(url, timeout=30) as response:
            sets.require(response.status == 200 and response.geturl() == url
                         and response.headers["Cache-Control"].endswith("immutable")
                         and int(response.headers["Content-Length"]) == path.stat().st_size, "Unexpected HTTPS metadata")
            result = hashlib.sha256()
            size = 0
            for block in iter(lambda: response.read(1024 * 1024), b""):
                size += len(block)
                result.update(block)
            sets.require(size == path.stat().st_size and result.hexdigest() == sets.digest(path),
                         f"Full HTTPS download differs: {name}")
            verified.append(dict(path=name, size=size, sha256=result.hexdigest()))
    sets.write_new(destination, sets.canonical(verified))
    return len(verified)


def launch(output, install, config, ca_file, name, expected_exit, game_role=None, release=None):
    state = windows_player.store_root(install, config)
    existing = set((state / "boots").glob("*"))
    env = dict(os.environ, SSL_CERT_FILE=str(ca_file), NO_PROXY="127.0.0.1")
    command = [sys.executable, "-X", "utf8", "-B", str(RELEASE_TOOLS / "windows_player.py"),
               "--root", str(install), "--headless", "--", "-NullRHI", "-NoSound", "-Unattended", "-NoSplash"]
    with (output / (name + ".log")).open("xb") as log:
        result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, env=env, timeout=600)
    sets.require(result.returncode == expected_exit, f"Unexpected launcher exit for {name}")
    attempts = set((state / "boots").glob("*")) - existing
    if game_role is None:
        sets.require(not attempts, "Untrusted metadata reached game startup")
        return
    sets.require(len(attempts) == 1, f"Expected one actual game launch for {name}")
    boot = attempts.pop()
    ticket = sets.parse((boot / "ticket.json").read_bytes(), 8192)
    result = sets.parse((boot / "result.json").read_bytes(), 8192)
    game = (boot / "game.log").read_text(encoding="utf-8", errors="replace")
    progress = 997 if game_role == "fault" else 731
    sets.require(ticket["releaseId"] == release
                 and f"UE_ADOPTION_RELEASE_PAIR_READY native={game_role} content={game_role}" in game
                 and f"UE_ADOPTION_RELEASE_SAVE_READY native={game_role} progress={progress}" in game,
                 f"Actual game did not prove the expected pair and save for {name}")
    if game_role == "fault":
        sets.require(result["status"] == "rolled-back" and "status 23" in result["reason"]
                     and "UE_ADOPTION_RELEASE_FAULT_BEFORE_HEALTH" in game and not (boot / "health.json").exists(),
                     "Fault candidate did not exit before acknowledgement")
    else:
        sets.require(result["status"] == "confirmed"
                     and f"UE_ADOPTION_RELEASE_HEALTH release={release} native={game_role}" in game,
                     f"Managed player did not confirm {name}")
    return dict(attempt=str(boot), save=sets.digest(Path(ticket["userRoot"]) / SAVE), saveRoot=ticket["userRoot"])


def run(args, output, report):
    builds = [checked_archive(getattr(args, role), role) for role in ROLES]
    baseline = builds[0]
    for build in builds[1:]:
        sets.require(all(build["metadata"][key] == baseline["metadata"][key]
                         for key in ("engine", "sdk", "configManifestSha256")) and
                     immutable_files(build) == immutable_files(baseline), "Engine, config or installed support bytes differ")
    sets.require(len({build["metadata"]["commit"] for build in builds}) == len(ROLES)
                 and len({build["nativeSourceHash"] for build in builds}) == len(ROLES)
                 and len({next(item["sha256"] for item in build["files"] if item["path"] == ENTRY) for build in builds}) == len(ROLES)
                 and len({sets.canonical([item for item in build["files"] if item["role"] == "content"])
                          for build in builds}) == len(ROLES), "Each variant must contain a different committed source, EXE and PAK")
    report["receiptSha256"] = {role: build["receiptSha256"] for role, build in zip(ROLES, builds)}
    trust = dict(projectId=PROJECT, platform="Windows", channel="adoption-qa", baseReleaseId=100,
                 engineBuildId=baseline["metadata"]["engine"]["buildId"], loaderVersion=1,
                 shellCompatibilityId=hashlib.sha256(sets.canonical(immutable_files(baseline))).hexdigest())
    key = ed25519.Ed25519PrivateKey.generate()
    versions = output / "Versions"
    report["phase"] = "sign-receipt-payloads"
    manifests = [write_version(versions, number, trust, build, key)
                 for number, build in enumerate(builds, 100)]
    trust["baseManifestSha256"] = manifests[0]
    report["manifestSha256"] = manifests
    install = output / "Installed"
    shutil.copytree(versions / "100" / "payload", install / "base" / "payload")
    shutil.copyfile(versions / "100" / "manifest.json", install / "base" / "manifest.json")
    config = dict(format=2, trust=trust, publicKeyHex=key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex(),
                  manifestUrl=ORIGIN + PREFIX + "manifest.json", allowOffline=False)
    sets.write_new(install / "release-player.json", sets.canonical(config))
    report["phase"] = "full-https-download"
    context, ca_file = create_tls(output)
    with TestOrigin(versions, context) as origin:
        report["verifiedDownloads"] = verify_downloads(origin, ca_file, output / "https-full-downloads.json")
        report["phase"] = "fresh-install"
        report["baseline"] = launch(output, install, config, ca_file, "baseline", 0, "baseline", 100)
        report["phase"] = "promotion-race"
        origin.requests.clear()
        origin.switch_after_manifest = 101
        launch(output, install, config, ca_file, "mixed-generation", 1)
        sets.require(origin.requests == ["versions/100/manifest.json", "versions/101/manifest.json.sig"]
                     and "signature rejected" in (output / "mixed-generation.log").read_text(encoding="utf-8").lower(),
                     "Mixed metadata did not fail closed before fetching payload")
        report["mixedGenerationRejected"] = True
        report["phase"] = "valid-update"
        report["candidate"] = launch(output, install, config, ca_file, "candidate", 0, "candidate", 101)
        report["phase"] = "fault-and-rollback"
        origin.release = 102
        report["fault"] = launch(output, install, config, ca_file, "fault", 1, "fault", 102)
        report["recovered"] = launch(output, install, config, ca_file, "recovered", 0, "candidate", 101)
    old, candidate, fault, recovered = (report[key] for key in ("baseline", "candidate", "fault", "recovered"))
    state = sets.parse((windows_player.store_root(install, config) / "state.json").read_bytes(), 65536)
    sets.require(old["save"] == candidate["save"] == recovered["save"] != fault["save"]
                 and candidate["saveRoot"] == recovered["saveRoot"]
                 and len({old["saveRoot"], candidate["saveRoot"], fault["saveRoot"]}) == 3
                 and state["active"]["releaseId"] == 101 and 102 in state["blocked"] and state["boot"] is None,
                 "Rollback did not preserve the original save and known-good version")
    report["phase"] = "complete"
    report["status"] = "managed-win64-passed"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for role in ROLES:
        parser.add_argument("--" + role, type=Path, required=True, help="Trusted project-profile report and receipt digest")
    parser.add_argument("--output", type=Path, required=True, help="Fresh short output outside the repository")
    args = parser.parse_args()
    output = args.output.resolve()
    sets.require(os.name == "nt" and not output.is_relative_to(Path(__file__).resolve().parents[2]),
                 "Use a Windows host and output outside the repository")
    output.mkdir()
    report = dict(status="blocked", phase="verify-build-receipts", origin=ORIGIN, scope="isolated-win64")
    try:
        run(args, output, report)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        report["error"] = str(error)
    sets.write_new(output / "report.json", sets.canonical(report))
    print(json.dumps(report, indent=2))
    return 0 if report["status"] == "managed-win64-passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
