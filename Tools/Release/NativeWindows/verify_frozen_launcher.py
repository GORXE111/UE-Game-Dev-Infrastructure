"""Exercise the real frozen entry over local trusted HTTPS using a fixture child, never UE."""
import argparse
from datetime import datetime, timedelta, timezone
import http.server
import ipaddress
import json
from pathlib import Path
import re
import shutil
import ssl
import struct
import subprocess
import sys
import threading
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
from cryptography.x509.oid import NameOID

import native_distribution
import native_launcher as native
import publish_native_windows as producer


def pe_fixture(tag):
    data = bytearray(256)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 60, 128)
    data[128:132] = b"PE\0\0"
    struct.pack_into("<H", data, 132, 0x8664)
    struct.pack_into("<H", data, 150, 2)
    struct.pack_into("<H", data, 152, 0x20B)
    data[160:160 + len(tag)] = tag
    return data


def verify(launcher_build, output):
    import os
    launcher_build = Path(launcher_build).resolve(strict=True)
    output = Path(output).absolute()
    native.require(not output.exists(), "Frozen verification output must be new")
    output.mkdir()
    fixture_script = output / "fixture_content.py"
    fixture_script.write_text('import json,sys\nfrom pathlib import Path\np=Path(sys.argv[1]);c=json.loads(p.read_text());(p.parent/"fixture-child.json").write_text(json.dumps({"arguments":sys.argv[1:]}));sys.exit(int(c.get("fixtureExit",0)))\n', encoding="utf-8")
    build_log = output / "fixture-build.log"
    with build_log.open("w", encoding="utf-8") as log:
        built = subprocess.run([sys.executable, "-m", "PyInstaller", "--onefile", "--windowed", "--name", "SampleContentFixture",
                                "--distpath", str(output / "fixture-dist"), "--workpath", str(output / "fixture-work"),
                                "--specpath", str(output), str(fixture_script)], stdout=log, stderr=subprocess.STDOUT, check=False)
    native.require(built.returncode == 0, "Fixture process freeze failed; see fixture-build.log")
    keys = output / "private-test-keys"
    keys.mkdir()
    signing_key = ed25519.Ed25519PrivateKey.generate()
    signing_file = keys / "signing.pem"
    signing_file.write_bytes(signing_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
    tls_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SampleGame local native fixture")])
    certificate = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(tls_key.public_key())
                   .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=2))
                   .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), False)
                   .add_extension(x509.BasicConstraints(ca=True, path_length=None), True).sign(tls_key, hashes.SHA256()))
    ca_file = keys / "fixture-ca.pem"
    ca_file.write_bytes(certificate.public_bytes(Encoding.PEM))
    tls_file = keys / "tls-key.pem"
    tls_file.write_bytes(tls_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
    routes = {"active": None, "versions": {}, "throttle": False, "archiveRequests": []}
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            selected = None
            for name in ("manifest.json", "manifest.json.sig"):
                if self.path == "/native/" + name and routes["active"]:
                    selected = routes["active"] / name
            if self.path in routes["versions"]:
                selected = routes["versions"][self.path]
            if selected is None or not selected.is_file():
                self.send_error(404)
                return
            raw = selected.read_bytes()
            archive = self.path.endswith('/native-windows.zip')
            range_value = self.headers.get('Range')
            match = re.fullmatch(r'bytes=([0-9]+)-', range_value or '')
            offset = int(match[1]) if match else 0
            if range_value and (not archive or not match or not 0 < offset < len(raw)):
                self.send_error(416)
                return
            status = 206 if offset else 200
            self.send_response(status)
            self.send_header('ETag', '"' + native.digest(selected) + '"')
            if offset:
                self.send_header('Content-Range', f'bytes {offset}-{len(raw)-1}/{len(raw)}')
            self.send_header("Content-Length", str(len(raw)-offset))
            self.end_headers()
            if archive:
                routes['archiveRequests'].append(dict(path=self.path, range=range_value,
                      ifRange=self.headers.get('If-Range'), responseCode=status, offset=offset))
            try:
                for start in range(offset, len(raw), 65536):
                    self.wfile.write(raw[start:start+65536]); self.wfile.flush()
                    if archive and routes['throttle']:
                        time.sleep(.05)
            except (OSError, ssl.SSLError):
                pass  # The first process is intentionally interrupted while receiving real HTTPS bytes.
        def log_message(self, *arguments):
            pass
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_tls.load_cert_chain(ca_file, tls_file)
    server.socket = server_tls.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    game = "SampleGame/Binaries/Win64/SampleGame.exe"
    install = output / "install"
    actual = install / game
    actual.parent.mkdir(parents=True)
    actual.write_bytes(pe_fixture(b"base"))
    shutil.copyfile(output / "fixture-dist/SampleContentFixture.exe", install / "SampleGame.exe")
    public = signing_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    settings = dict(projectId="SampleGame", channel="frozen-fixture", platform="Windows", baseReleaseId=123,
                    engineBuildId="fixture-build", publicKeyHex=public, gameExe=game, fixtureExit=0)
    native.atomic_json(install / "sample-player.json", settings)
    native_distribution.configure(install, launcher_build, f"https://127.0.0.1:{server.server_port}/native/manifest.json", "fixture-compatibility")
    environment = dict(os.environ)
    environment["SSL_CERT_FILE"] = str(ca_file)
    checks = []
    expected_images = {}
    resume_evidence = None
    try:
        for version, child_exit in ((1, 0), (2, 7)):
            source = output / f"source-{version}"
            image = source / game
            image.parent.mkdir(parents=True)
            image.write_bytes(pe_fixture(f"native-{version}".encode()) + (os.urandom(2*1024*1024) if version == 1 else b''))
            expected_images[version] = image.read_bytes()
            release = output / f"release-{version}"
            receipt = producer.publish(install / "native-player.json", source, signing_file, version, release)
            routes["active"] = release
            routes["versions"][f"/native/versions/{version}/native-windows.zip"] = release / f"versions/{version}/native-windows.zip"
            settings["fixtureExit"] = child_exit
            native.atomic_json(install / "sample-player.json", settings)
            if version == 1:
                routes['throttle'] = True
                partial = install/'.native-update/download-1.zip.part'
                sidecar = install/'.native-update/download-1.zip.part.json'
                native.require(not partial.exists() and not sidecar.exists(), 'Frozen resume must begin with no seeded partial')
                interrupted = subprocess.Popen([str(install/'SampleGame.exe'), '--headless'], cwd=install, env=environment)
                deadline = time.monotonic()+60
                try:
                    while True:
                        native.require(interrupted.poll() is None, 'Frozen wrapper exited before the controlled network interruption')
                        length = partial.stat().st_size if partial.exists() else 0
                        if 65536 <= length < receipt['archive']['size'] and sidecar.exists():
                            break
                        native.require(time.monotonic() < deadline, 'Frozen wrapper did not create a genuine partial in time')
                        time.sleep(.02)
                    interrupted.kill()  # Exact owned Popen handle; no other process or user application.
                    stopped_code = interrupted.wait(timeout=15)
                finally:
                    if interrupted.poll() is None:
                        interrupted.kill(); interrupted.wait(timeout=15)
                offset = partial.stat().st_size
                native.require(0 < offset < receipt['archive']['size'], 'Controlled interruption did not leave a partial archive')
                native.require(partial.read_bytes() == routes['versions'][f'/native/versions/{version}/native-windows.zip'].read_bytes()[:offset],
                               'Frozen wrapper partial differs from actual source prefix')
                native.require(not (install/'fixture-child.json').exists(), 'Fixture child unexpectedly started before complete verification')
                resume_evidence = dict(noSeed=True, ownedInterruptedPid=interrupted.pid, actualExitCode=stopped_code,
                                       partialBytesAfterStop=offset, partialSha256=native.digest(partial),
                                       sidecar=native.parse_json(sidecar.read_bytes()), real206Observed=False)
                native.atomic_json(output/'actual-network-interruption.json', resume_evidence)
                routes['throttle'] = False
            process = subprocess.run([str(install / "SampleGame.exe"), "--headless"], cwd=install, env=environment, timeout=90, check=False)
            state = native.parse_json((install / ".native-update/state.json").read_bytes())
            native.require(process.returncode == child_exit, "Frozen entry did not preserve fixture child exit code")
            native.require(state["activeVersion"] == 1 and state["pendingVersion"] == 0, "Frozen entry commit/rollback state is incorrect")
            native.require(actual.read_bytes() == expected_images[1], "Frozen entry did not retain/recover the expected native image")
            if version == 1:
                selected = [item for item in routes['archiveRequests'] if item['responseCode'] == 206]
                native.require(len(selected) == 1 and selected[0]['offset'] == resume_evidence['partialBytesAfterStop'],
                               'Frozen wrapper did not resume its actual stopped prefix with exact HTTPS206')
                log = (install/'native-update.log').read_text(encoding='utf-8')
                native.require('NATIVE_DOWNLOAD_VERIFIED version=1' in log, 'Frozen wrapper did not record whole archive verification')
                native.require(not partial.exists() and not sidecar.exists(), 'Successful frozen stage retained partial authority')
                resume_evidence.update(real206Observed=True, request=selected[0], actualSelectedNativeSha256=native.digest(actual),
                                       signedArchiveSha256=receipt['archive']['sha256'], signatureVerifiedAndWholeArchiveStaged=True)
            if child_exit:
                native.require(version in state["blockedVersions"], "Failed frozen native version was not blocked")
            checks.append({"nativeVersion": version, "childExit": child_exit, "activeVersion": state["activeVersion"],
                           "blockedVersions": state["blockedVersions"], "producerManifestSha256": receipt["manifestSha256"]})
        settings["fixtureExit"] = 0
        native.atomic_json(install / "sample-player.json", settings)
        repeated = subprocess.run([str(install / "SampleGame.exe"), "--headless"], cwd=install, env=environment, timeout=90, check=False)
        state = native.parse_json((install / ".native-update/state.json").read_bytes())
        native.require(repeated.returncode == 0 and state["activeVersion"] == 1 and state["blockedVersions"] == [2], "Blocked native candidate was retried or fallback failed")
        report = {"ok": True, "realFrozenLauncher": True, "realTrustedLocalHttps": True, "realChildProcess": True,
                  "realUERuntimeValidated": False, "scope": "Fixture child and PE-header fixture payload; no UE process or gameplay acceptance.",
                  "launcherSha256": native.digest(launcher_build / "SampleGameNativeLauncher.exe"), "checks": checks,
                  "blockedCandidateRepeatPrevented": True, "actualNetworkResume": resume_evidence,
                  "archiveRequests": routes['archiveRequests']}
        native.atomic_json(output / "report.json", report)
        return report
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--launcher-build", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.launcher_build, args.output), indent=2))


if __name__ == "__main__":
    main()
