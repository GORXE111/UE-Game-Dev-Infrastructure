"""Run the isolated ProfileSample Android install, update and rollback on an owned AVD."""

from __future__ import annotations

import argparse
import base64
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import socket
import ssl
import subprocess
import sys
from threading import Thread
import time
import uuid
from zipfile import ZipFile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "Release" / "ReleaseSets"))
import release_set as sets

PACKAGE = "com.example.profilesample.adoption"
ACTIVITY = PACKAGE + "/com.example.samplegame.update.ReleaseBootstrapActivity"
GAME_ACTIVITY = PACKAGE + "/com.epicgames.unreal.GameActivity"
PREFIX = "/profile-sample/adoption-qa/updates/"
ORIGIN = "https://10.0.2.2"
SAVE = "Saved/SaveGames/AdoptionRelease.sav"
RELEASES = {100: "baseline", 101: "candidate", 102: "fault"}
HEX = re.compile(r"[0-9a-f]{64}\Z")
LOG_LINE = re.compile(r"^\d\d-\d\d\s+\S+\s+(\d+)\s+\d+\s+[VDIWEF]\s+.*?\s*:\s*(.*)$")
TIMEOUT = 300


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def save_json(path, value):
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def absolute_input(value, directory=False):
    path = Path(value)
    require(path.is_absolute(), "Prepared artifact paths must be absolute")
    sets.plain(path, directory)
    return path.resolve(strict=True)


def read_inputs(prepared, tls):
    import ipaddress

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa

    prepared, tls = prepared.resolve(strict=True), tls.resolve(strict=True)
    receipt = json.loads(sets.read_bounded(prepared / "report.json", 1024 * 1024))
    apk, versions = absolute_input(receipt["apk"]), absolute_input(receipt["versions"], True)
    apk_sha256 = sets.digest(apk)
    require(receipt.get("apkSha256", apk_sha256) == apk_sha256, "Prepared APK digest no longer matches its producer report")
    with ZipFile(apk) as archive:
        for name in ("assets/release-player.json", "assets/release-base-manifest.json"):
            matches = [entry for entry in archive.infolist() if entry.filename == name]
            require(len(matches) == 1 and 0 < matches[0].file_size <= sets.MAX_MANIFEST,
                    "APK must contain exactly one bounded copy of each managed bootstrap asset")
        config = sets.parse(archive.read("assets/release-player.json"))
        base_raw = archive.read("assets/release-base-manifest.json")
        require("lib/arm64-v8a/libUnreal.so" in archive.namelist()
                and not any(name.startswith("lib/x86") for name in archive.namelist()),
                "Expected ARM64-only managed APK")
    trust = config["trust"]
    require(config["packageName"] == PACKAGE and config["manifestUrl"] == ORIGIN + PREFIX + "manifest.json"
            and trust["projectId"] == "ProfileSample" and trust["platform"] == "Android_ARM64"
            and trust["baseReleaseId"] == 100 and sha(base_raw) == trust["baseManifestSha256"],
            "APK does not belong to this isolated Android sample cohort")
    signer = base64.b64decode(config["certificateBase64"], validate=True)
    key = x509.load_der_x509_certificate(signer).public_key()
    require(config["signatureAlgorithm"] == "SHA256withRSA" and sha(signer) == config["certificateSha256"]
            and isinstance(key, rsa.RSAPublicKey) and key.key_size >= 2048, "APK sample signing trust is invalid")
    ca_path, cert_path, key_path = (tls / name for name in ("qa-ca.der", "qa-host.pem", "qa-host-key.pem"))
    ca_raw = sets.read_bounded(ca_path, 16384)
    ca = x509.load_der_x509_certificate(ca_raw)
    cert = x509.load_pem_x509_certificate(sets.read_bounded(cert_path, 16384))
    require(ipaddress.ip_address("10.0.2.2") in cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.IPAddress),
            "TLS server certificate must identify the emulator host IP")
    require(ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca and ca_raw != signer,
            "Expected a separate TLS test CA and APK update signer")
    cert.verify_directly_issued_by(ca)
    with ZipFile(apk) as archive:
        anchors = [entry for entry in archive.infolist() if re.fullmatch(r"res/raw/profilesample_qa_ca\.[A-Za-z0-9]+", entry.filename)]
        require(len(anchors) == 1 and anchors[0].file_size == len(ca_raw) and archive.read(anchors[0]) == ca_raw,
                "APK does not embed the exact supplied isolated TLS CA")
    sets.plain(key_path)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert_path, key_path)

    releases = {}
    for number in RELEASES:
        directory = versions / str(number)
        sets.plain(directory, True)
        manifest_path, signature_path = directory / "manifest.json", directory / "manifest.json.sig"
        raw = sets.read_bounded(manifest_path, sets.MAX_MANIFEST)
        signature = sets.read_bounded(signature_path, 4096)
        key.verify(signature, raw, padding.PKCS1v15(), hashes.SHA256())
        manifest = sets.manifest(raw, trust)
        require(manifest["releaseId"] == number and manifest["save"]["schema"] == 1,
                "Prepared Android sample release identity differs")
        require(number != 100 or raw == base_raw, "Baseline feed differs from the exact APK baseline")
        files = manifest["files"]
        require(any(item["role"] == "content" for item in files)
                and all(item["path"].startswith(f"Content/Paks/r{number}_") for item in files if item["role"] == "content"),
                "Manifest PAK paths must carry their release identity")
        sets.verify_tree(directory / "payload", files)
        allowed = {"manifest.json": manifest_path, "manifest.json.sig": signature_path}
        allowed.update({f"versions/{number}/payload/{item['path']}": directory / "payload" / item["path"] for item in files})
        releases[number] = dict(manifest=manifest, manifestSha256=sha(raw), signatureSha256=sha(signature), allowed=allowed)
    for role in ("native", "content"):
        identities = {tuple(sorted(item["sha256"] for item in release["manifest"]["files"] if item["role"] == role))
                      for release in releases.values()}
        require(len(identities) == len(releases), "Expected distinct genuine native and PAK bytes for all three roles")
    return apk, apk_sha256, trust, releases, context, cert.fingerprint(hashes.SHA256()).hex()


class TestOrigin:
    def __init__(self, context, releases):
        self.releases, self.current, self.requests = releases, 100, []
        origin = self

        class Server(ThreadingHTTPServer):
            allow_reuse_address = False

            def server_bind(self):
                if os.name == "nt":
                    self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                super().server_bind()

            def get_request(self):
                connection, address = super().get_request()
                connection.settimeout(25)
                try:
                    return context.wrap_socket(connection, server_side=True, do_handshake_on_connect=False), address
                except BaseException:
                    connection.close()
                    raise

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_HEAD(self):
                self.serve(False)

            def do_GET(self):
                self.serve(True)

            def serve(self, body):
                number = origin.current
                name = self.path.removeprefix(PREFIX) if self.path.startswith(PREFIX) else ""
                path = origin.releases[number]["allowed"].get(name)
                if self.headers.get("Host") not in ("10.0.2.2", "10.0.2.2:443") or path is None:
                    self.send_error(404)
                    return
                self.connection.settimeout(25)
                with path.open("rb") as stream:
                    size = os.fstat(stream.fileno()).st_size
                    start, status = 0, 200
                    requested = self.headers.get("Range")
                    if requested:
                        match = re.fullmatch(r"bytes=([0-9]{1,12})-", requested)
                        if not match or int(match[1]) >= size:
                            self.send_error(416)
                            return
                        start, status = int(match[1]), 206
                    self.send_response(status)
                    self.send_header("Content-Type", "application/octet-stream")
                    self.send_header("Content-Length", str(size - start))
                    self.send_header("Cache-Control", "no-store" if name.startswith("manifest.") else "public, max-age=31536000, immutable")
                    self.send_header("Connection", "close")
                    if status == 206:
                        self.send_header("Content-Range", f"bytes {start}-{size - 1}/{size}")
                    self.end_headers()
                    sent = 0
                    if body:
                        stream.seek(start)
                        while sent < size - start:
                            block = stream.read(min(256 * 1024, size - start - sent))
                            require(block, "Prepared payload was truncated while serving")
                            self.wfile.write(block)
                            sent += len(block)
                    origin.requests.append(dict(release=number, method=self.command, file=name, status=status, offset=start, bytes=sent))

        self.server = Server(("127.0.0.1", 443), Handler)
        self.thread = Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *args):
        self.server.shutdown()
        self.thread.join(timeout=10)
        self.server.server_close()


class Device:
    def __init__(self, args, output, trust):
        self.adb_path = args.adb.resolve(strict=True)
        self.command = [str(self.adb_path), "-s", args.serial]
        self.avd = args.avd
        self.output = output
        self.store = f"app_samplegame-release-sets/b100-{trust['baseManifestSha256'][:16]}"
        self.log_path = output / "actual-logcat.txt"

    def adb(self, *args, timeout=40, check=True):
        result = subprocess.run([*self.command, *map(str, args)], capture_output=True, timeout=timeout)
        if check:
            require(result.returncode == 0, f"ADB {args[0]} failed ({result.returncode}): {result.stderr.decode('utf-8', 'replace')[-1500:]}")
        return result

    def shell(self, *args, timeout=40, check=True):
        return self.adb("shell", shlex.join(map(str, args)), timeout=timeout, check=check).stdout.decode("utf-8", "replace").strip()

    def app(self, *args, timeout=40):
        return self.shell("run-as", PACKAGE, *args, timeout=timeout)

    def read_app(self, path, maximum=65536, missing=False):
        if missing and not self.app_test("-e", path):
            return None
        result = self.adb("exec-out", "run-as", PACKAGE, "cat", path, check=False)
        require(result.returncode == 0 and 0 < len(result.stdout) <= maximum, "Cannot read bounded sample-private evidence: " + path)
        return result.stdout

    def app_test(self, flag, path):
        result = self.adb("shell", shlex.join(("run-as", PACKAGE, "test", flag, path)), check=False)
        require(result.returncode in (0, 1) and not result.stdout and not result.stderr,
                "Could not read exact sample-private path or process status: " + path)
        return result.returncode == 0

    def app_json(self, path, missing=False):
        raw = self.read_app(path, missing=missing)
        return json.loads(raw) if raw is not None else None

    def assert_owner(self):
        name = [line.strip() for line in self.adb("emu", "avd", "name").stdout.decode().splitlines() if line.strip()]
        require(name == [self.avd, "OK"], "ADB serial is not the exact disposable sample AVD")

    def assert_fresh(self):
        packages = self.shell("pm", "list", "packages", "-u", "--user", "0").splitlines()
        require(packages and all(line.startswith("package:") for line in packages)
                and "package:" + PACKAGE not in packages, "An existing or retained sample installation prevents the fresh test")

    def preflight(self, args):
        require(re.fullmatch(r"emulator-[0-9]{4,5}", args.serial) and re.fullmatch(r"ProfileSampleAdoptionQA(?:[-_][A-Za-z0-9]{1,24})?", args.avd),
                "Select the explicitly owned ProfileSample emulator and AVD")
        self.assert_owner()
        require(self.adb("get-state").stdout.strip() == b"device" and self.shell("getprop", "sys.boot_completed") == "1"
                and self.shell("getprop", "ro.kernel.qemu") == "1" and self.shell("id", "-u") == "2000", "Expected a booted ordinary Android emulator shell")
        require(re.findall(r"UserInfo\{(\d+):", self.shell("pm", "list", "users")) == ["0"], "Sample AVD must have only primary user 0")
        self.assert_fresh()
        abi = self.shell("getprop", "ro.product.cpu.abilist").split(",")
        bridge = self.shell("getprop", "ro.dalvik.vm.native.bridge")
        require(self.shell("getprop", "ro.build.version.sdk") == "36" and "arm64-v8a" in abi
                and (abi[0] == "arm64-v8a" or bridge not in ("", "0")), "API36 guest cannot execute the prepared ARM64 package")
        return dict(serial=args.serial, avd=args.avd, api=36, abiList=abi, nativeBridge=bridge,
                    pageSize=int(self.shell("getconf", "PAGE_SIZE")), freshPackageAbsent=True)

    def install(self, apk, digest):
        aapt_name = "aapt2.exe" if os.name == "nt" else "aapt2"
        aapt_tools = sorted(self.adb_path.parent.parent.glob(f"build-tools/*/{aapt_name}"),
                            key=lambda path: tuple(map(int, re.findall(r"\d+", path.parent.name))))
        require(aapt_tools, "Android SDK aapt2 is required to identify the APK before installing")
        badging = subprocess.run([str(aapt_tools[-1]), "dump", "badging", str(apk)], capture_output=True, timeout=40, check=True).stdout.decode("utf-8", "replace")
        require(re.findall(r"^package: name='([^']+)'", badging, re.M) == [PACKAGE]
                and re.findall(r"^launchable-activity: name='([^']+)'", badging, re.M) == [ACTIVITY.split("/", 1)[1]],
                "Actual APK package or launcher differs from the isolated sample")
        (self.output / "actual-apk-badging.txt").write_text(badging, encoding="utf-8")
        self.assert_owner()
        self.assert_fresh()
        result = self.adb("install", apk, timeout=300)
        (self.output / "actual-install.txt").write_bytes(result.stdout + result.stderr)
        require(result.stdout.strip().endswith(b"Success"), "Fresh sample APK install did not report success")
        source = self.shell("pm", "path", "--user", "0", PACKAGE).splitlines()
        require(len(source) == 1 and source[0].startswith("package:/data/app/") and source[0].endswith("/base.apk"),
                "Expected one actually installed sample base APK")
        require(self.shell("sha256sum", source[0].removeprefix("package:")).split()[0] == digest,
                "Installed APK bytes differ from the prepared independent sample")
        uid = int(self.app("id", "-u"))
        require(10000 <= uid < 100000, "Sample is not an ordinary application UID")
        self.uid = uid
        return uid

    def start_log(self):
        log = self.log_path.open("xb")
        try:
            return subprocess.Popen([*self.command, "logcat", "-T", "1", "-v", "threadtime", "SampleGameReleasePlayer:V",
                                     "UE:V", "AndroidRuntime:E", "ActivityManager:I", "ProfileSampleHarness:I", "*:S"],
                                    stdout=log, stderr=subprocess.STDOUT)
        finally:
            log.close()

    def await_log(self, observer):
        marker = "profile-sample-harness-" + uuid.uuid4().hex
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            require(observer.poll() is None, "Owned logcat observer exited before installation test")
            self.shell("log", "-t", "ProfileSampleHarness", marker)
            time.sleep(.3)
            if any(marker in line for _, line in self.logs(0)):
                return
        raise RuntimeError("Owned logcat observer did not receive the test readiness marker")

    def logs(self, start, pid=None):
        with self.log_path.open("rb") as stream:
            stream.seek(start)
            data = stream.read(24 * 1024 * 1024 + 1)
        require(len(data) <= 24 * 1024 * 1024, "Sample log exceeded the observation bound")
        entries = [match.groups() for line in data.decode("utf-8", "replace").splitlines() if (match := LOG_LINE.match(line))]
        return [(int(p), line) for p, line in entries if pid is None or int(p) == pid]

    def launch(self, name):
        self.assert_owner()
        start = self.log_path.stat().st_size
        log = self.shell("am", "start", "-W", "--user", "0", "-n", ACTIVITY, timeout=90)
        (self.output / (name + "-am-start.txt")).write_text(log + "\n", encoding="utf-8")
        require("Status: ok" in log and "Error:" not in log, "Actual Android bootstrap did not launch")
        return start

    def is_alive(self, pid):
        return self.app_test("-d", f"/proc/{pid}")

    def stop(self, evidence):
        self.assert_owner()
        pid = evidence["process"]["pid"]
        require(self.is_alive(pid), "Expected the verified sample main process before its controlled cold restart")
        self.shell("am", "force-stop", "--user", "0", PACKAGE)
        end = time.monotonic() + 20
        while self.is_alive(pid):
            require(time.monotonic() < end, "Sample main process did not exit before cold restart")
            time.sleep(.5)

    def state(self, missing=False):
        return self.app_json(self.store + "/state.json", missing=missing)

    def ticket(self, number, state, boot):
        attempt = boot["attemptId"]
        require(re.fullmatch(r"[a-f0-9]{32}", attempt), "Invalid actual Android attempt identity")
        root = self.store + "/boots/" + attempt
        ticket = self.app_json(root + "/ticket.json")
        ref = state["active"]
        require(ref["releaseId"] == number and ticket["releaseId"] == number and ticket["attemptId"] == attempt
                and ticket["manifestSha256"] == ref["manifestSha256"] and ticket["saveSchema"] == 1
                and re.fullmatch(r"g-[a-f0-9]{32}", ref["saveGeneration"]), "Actual selected release and save reference differ")
        for key, suffix in dict(payloadRoot=f"versions/{number}", userRoot="saves/" + ref["saveGeneration"], ackPath="boots/" + attempt + "/health.json").items():
            require(ticket[key] in [f"{prefix}/{PACKAGE}/{self.store}/{suffix}" for prefix in ("/data/data", "/data/user/0")],
                    "Actual Java ticket path escaped the exact sample store: " + key)
        return ticket, root

    def check_process(self, pid, ticket, name):
        top = self.shell("dumpsys", "activity", "top")
        require(re.search(rf"^\s*ACTIVITY {re.escape(GAME_ACTIVITY)}\s+.*?\bpid={pid}\b", top, re.M),
                "Native log PID is not the actual UE GameActivity main process")
        status = self.app("cat", f"/proc/{pid}/status")
        require(re.search(r"^Uid:\s+" + r"\s+".join([str(self.uid)] * 4) + r"\s*$", status, re.M), "UE process UID does not match installed app")
        proc = self.app("cat", f"/proc/{pid}/stat")
        start_ticks = int(proc[proc.rindex(")") + 2:].split()[19])
        require(start_ticks > 0, "Invalid actual UE process start time")
        maps = self.app("cat", f"/proc/{pid}/maps")
        native = {line.split()[-1] for line in maps.splitlines() if line.endswith("/libUnreal.so")}
        require(len(native) == 1, "Expected only one loaded Unreal library path in the actual game process")
        mapped = next(iter(native))
        expected = ticket["payloadRoot"] + "/libUnreal.so"
        if mapped != expected:
            aliases = {expected, expected.replace("/data/data/", "/data/user/0/", 1), expected.replace("/data/user/0/", "/data/data/", 1)}
            require(mapped in aliases and self.app("stat", "-c", "%d:%i:%u", mapped) == self.app("stat", "-c", "%d:%i:%u", expected),
                    "Loaded library does not match the Java-selected Android object")
        (self.output / (name + "-proc-maps.txt")).write_text(maps + "\n", encoding="utf-8")
        return dict(pid=pid, uid=self.uid, startTicks=start_ticks, actualNativePath=mapped)

    def file_hashes(self, number, release):
        version = f"{self.store}/versions/{number}"
        require(sha(self.read_app(version + "/manifest.json", sets.MAX_MANIFEST)) == release["manifestSha256"],
                "Guest manifest differs from the exact signed selection")
        if number != 100:
            require(sha(self.read_app(version + "/manifest.sig", 4096)) == release["signatureSha256"],
                    "Guest cached signature differs from the signed candidate")
        records = []
        for item in release["manifest"]["files"]:
            path = f"{version}/{item['path']}"
            size, digest = int(self.app("stat", "-c", "%s", path)), self.app("sha256sum", path, timeout=150).split()[0]
            require(size == item["size"] and digest == item["sha256"], "Guest native/PAK bytes differ: " + item["path"])
            records.append(dict(path=item["path"], size=size, sha256=digest))
        return records

    def save_hash(self, root):
        path = str(PurePosixPath(root) / SAVE)
        digest = self.app("sha256sum", path).split()[0]
        require(HEX.fullmatch(digest), "Invalid real guest SaveGame SHA256")
        return digest

    def await_boot(self, name, number, release, start, seen_attempts, fault=False):
        role = RELEASES[number]
        library_marker = f"SAMPLEGAME_RELEASE_LIBRARY_LOADED release={number} native={release['manifest']['nativeSourceHash']}"
        pak_count = sum(item["role"] == "content" for item in release["manifest"]["files"])
        end = time.monotonic() + TIMEOUT
        while time.monotonic() < end:
            logs = self.logs(start)
            pids = {pid for pid, line in logs if library_marker in line}
            require(len(pids) <= 1, "Unexpected multiple native processes loaded the same test launch")
            if not pids:
                time.sleep(1)
                continue
            pid = next(iter(pids))
            require(sum(p == pid and library_marker in line for p, line in logs) == 1,
                    "UE native library loaded more than once in the same sample launch")
            lines = [line for p, line in logs if p == pid]
            require(not any("only supports OpenGL ES" in line or "LogAndroid: Error: Fatal error:" in line for line in lines),
                    f"Unreal failed before reporting {name} readiness. See {self.log_path.name}.")
            progress = 997 if fault else 731
            markers = [f"UE_ADOPTION_RELEASE_ANDROID_PAYLOAD_READY release={number} paks={pak_count}",
                       f"UE_ADOPTION_RELEASE_PAIR_READY native={role} content={role}",
                       f"UE_ADOPTION_RELEASE_SAVE_READY native={role} progress={progress}",
                       "UE_ADOPTION_RELEASE_FAULT_BEFORE_HEALTH" if fault else f"UE_ADOPTION_RELEASE_HEALTH release={number} native={role}"]
            if not all(any(marker in line for line in lines) for marker in markers):
                time.sleep(1)
                continue
            state = self.state()
            if fault:
                boot = state["boot"]
                require(boot is not None, "Fault cleared its pending selection before recovery")
                if self.is_alive(pid):
                    time.sleep(1)
                    continue
                attempt = boot["attemptId"]
            else:
                if state["boot"] is not None:
                    time.sleep(1)
                    continue
                paths = self.app("find", self.store + "/boots", "-mindepth", "2", "-maxdepth", "2", "-name", "health.json").splitlines()
                require(len(paths) <= 32, "Unexpected number of sample boot attempts")
                matches = []
                for path in paths:
                    match = re.fullmatch(re.escape(self.store) + r"/boots/([a-f0-9]{32})/health\.json", path)
                    require(match, "Unexpected sample health evidence path")
                    health = self.app_json(path)
                    if health.get("pid") == pid and health.get("releaseId") == number and match[1] not in seen_attempts:
                        matches.append(match[1])
                require(len(matches) == 1, "Could not bind the actual healthy Java acknowledgement to this process")
                attempt = matches[0]
            require(attempt not in seen_attempts, "Cold launch reused an old boot attempt")
            ticket, root = self.ticket(number, state, dict(attemptId=attempt))
            require(ticket["manifestSha256"] == release["manifestSha256"] and ticket["buildId"] == release["manifest"]["buildId"],
                    "Actual boot selected unexpected signed build bytes")
            health = self.app_json(root + "/health.json", missing=fault)
            if fault:
                require(health is None and not any("UE_ADOPTION_RELEASE_HEALTH" in line for line in lines), "Fault unexpectedly acknowledged health")
                require(boot["selection"] == state["active"], "Fault pending selection and active reference differ")
                process = dict(pid=pid, gone=True)
            else:
                require(health is not None and health["pid"] == pid and health["luaVersion"] == "not-applicable"
                        and all(health[key] == ticket[key] for key in ("attemptId", "releaseId", "manifestSha256", "buildId", "userRoot", "saveSchema")),
                        "Real health acknowledgement differs from the Java ticket")
                process = self.check_process(pid, ticket, name)
            seen_attempts.add(attempt)
            evidence = dict(name=name, role=role, release=number, process=process, ticket=ticket, state=state, health=health,
                            nativeAndPak=self.file_hashes(number, release), saveSha256=self.save_hash(ticket["userRoot"]),
                            actualMarkers=[line for line in lines if any(marker in line for marker in [library_marker, *markers])])
            save_json(self.output / (name + ".json"), evidence)
            return evidence
        raise RuntimeError(f"Timed out waiting for real {name} native/content/save and {'fault' if fault else 'health'} evidence")

    def await_ready(self, current, target, release):
        end = time.monotonic() + TIMEOUT
        while time.monotonic() < end:
            ready = self.app_json(self.store + "/ready.json", missing=True)
            if ready is not None:
                if ready == dict(format=1, releaseId=current["release"], manifestSha256=current["ticket"]["manifestSha256"]):
                    # Java retains the ready marker after activation. Wait for its exact replacement.
                    time.sleep(1)
                    continue
                require(ready == dict(format=1, releaseId=target, manifestSha256=release["manifestSha256"]),
                        "Guest ready marker belongs to a different signed candidate")
                state = self.state()
                require(state["active"] == current["state"]["active"] and state["boot"] is None,
                        "Downloading changed the confirmed running selection")
                process = self.check_process(current["process"]["pid"], current["ticket"], f"ready-{target}")
                require(process == current["process"], "Actual confirmed process changed during candidate download")
                return dict(ready=ready, process=process, artifacts=self.file_hashes(target, release))
            time.sleep(1)
        raise RuntimeError(f"Timed out waiting for actual verified Android stage {target}")


def run(args, output, report):
    apk, digest, trust, releases, context, tls_certificate = read_inputs(args.prepared, args.tls)
    device = Device(args, output, trust)
    report.update(device=device.preflight(args), apk=dict(path=str(apk), size=apk.stat().st_size, sha256=digest),
                  manifestUrl=ORIGIN + PREFIX + "manifest.json", tlsCertificateSha256=tls_certificate, phases=[])
    seen = set()
    main_pids = set()
    log = None
    with TestOrigin(context, releases) as origin:
        try:
            report["applicationUid"] = device.install(apk, digest)
            report["sampleRemainsInstalled"] = True
            log = device.start_log()
            device.await_log(log)

            def boot(name, release, fault=False):
                report["phase"] = name
                require(log.poll() is None, "Owned logcat observer exited")
                evidence = device.await_boot(name, release, releases[release], device.launch(name), seen, fault)
                pid = evidence["process"]["pid"]
                require(pid not in main_pids, "Cold launch reused a previous game main PID")
                main_pids.add(pid)
                report["phases"].append(evidence)
                return evidence

            baseline = boot("fresh-baseline", 100)
            device.stop(baseline)
            origin.current = 101
            checking = boot("baseline-checks-candidate", 100)
            require(checking["ticket"]["userRoot"] == baseline["ticket"]["userRoot"] and checking["saveSha256"] == baseline["saveSha256"],
                    "Baseline cold restart changed original save")
            report["phase"] = "candidate-101-ready"
            report["candidateStage"] = device.await_ready(checking, 101, releases[101])
            save_json(output / "candidate-101-ready.json", report["candidateStage"])
            device.stop(checking)
            candidate = boot("candidate-activated", 101)
            device.stop(candidate)
            origin.current = 102
            checking = boot("candidate-checks-fault", 101)
            require(checking["ticket"]["userRoot"] == candidate["ticket"]["userRoot"] and checking["saveSha256"] == candidate["saveSha256"],
                    "Candidate cold restart changed the known-good save")
            report["phase"] = "fault-102-ready"
            report["faultStage"] = device.await_ready(checking, 102, releases[102])
            save_json(output / "fault-102-ready.json", report["faultStage"])
            device.stop(checking)
            fault = boot("fault-before-health", 102, fault=True)
            recovered = boot("rollback-recovered", 101)
            require(recovered["state"]["active"] == candidate["state"]["active"] and recovered["state"]["boot"] is None
                    and recovered["state"]["previous"] is None and recovered["state"]["blocked"] == [102]
                    and recovered["state"]["highestReleaseId"] == 102 and device.state()["active"] == recovered["state"]["active"],
                    "Rollback did not durably restore the previous complete selection and block the failed release")
            require(baseline["saveSha256"] == candidate["saveSha256"] == recovered["saveSha256"] != fault["saveSha256"]
                    and recovered["ticket"]["userRoot"] == candidate["ticket"]["userRoot"]
                    and len({baseline["ticket"]["userRoot"], candidate["ticket"]["userRoot"], fault["ticket"]["userRoot"]}) == 3
                    and device.save_hash(baseline["ticket"]["userRoot"]) == baseline["saveSha256"]
                    and device.save_hash(fault["ticket"]["userRoot"]) == fault["saveSha256"],
                    "Rollback failed to preserve original, known-good and isolated fault SaveGame bytes")
            for number in (101, 102):
                expected = {f"versions/{number}/payload/{item['path']}": item["size"] for item in releases[number]["manifest"]["files"]}
                require(all(any(record["release"] == number and record["method"] == "GET" and record["status"] == 200
                                and record["file"] == name and record["bytes"] == size for record in origin.requests)
                            for name, size in expected.items()), "Owned HTTPS origin did not record a complete candidate file transfer")
            report.update(actualAndroidInstallUpdateRollbackPassed=True, phase="complete")
        finally:
            if log is not None:
                if log.poll() is None:
                    log.terminate()
                log.wait(timeout=10)
            report["actualHttpsRequests"] = list(origin.requests)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("adb", "prepared", "tls", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--avd", default="ProfileSampleAdoptionQA", help="Exact name of the owned disposable ProfileSample AVD")
    args = parser.parse_args()
    output = args.output.resolve()
    require(not output.is_relative_to(Path(__file__).resolve().parents[2]), "Write runtime evidence outside the public checkout")
    output.mkdir(parents=True, exist_ok=False)
    report = dict(status="running", actualAndroidInstallUpdateRollbackPassed=False, emulatorStarted=False, productionContacted=False,
                  existingUserDataChanged=False, physicalPhoneValidated=False, hostFpsValidated=False, sixteenKiBDeviceValidated=False)
    try:
        run(args, output, report)
        report["status"] = "passed"
    except BaseException as error:
        report.update(status="failed", error=str(error))
        raise
    finally:
        save_json(output / "report.json", report)
    print(json.dumps(dict(status="passed", report=str(output / "report.json"))))


if __name__ == "__main__":
    main()
