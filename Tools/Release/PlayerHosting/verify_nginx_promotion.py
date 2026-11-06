"""Verify the release gateway with disposable signed versions on POSIX loopback HTTPS."""

import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import time
from unittest.mock import patch
from urllib.error import HTTPError, URLError
from urllib.request import HTTPSHandler, ProxyHandler, Request, build_opener
from zipfile import ZipFile

from cryptography.hazmat.primitives.asymmetric import ed25519

import deploy_players
import deploy_release_sets as publisher
import remote_release_sets as remote
from test_release_sets_publication import fixture


HERE = Path(__file__).resolve().parent
sets = publisher.sets
OLD, NEW = 401, 402


def gateway_config(output, port):
    public = output / "public"
    certificate, key = output / "tls.pem", output / "tls.key"
    with (output / "certificate.log").open("xb") as log:
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                        "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1",
                        "-out", certificate, "-keyout", key], stdout=log, stderr=subprocess.STDOUT,
                       check=True, timeout=15)
    key.chmod(0o600)
    sources = {
        "samplegame-player.locations.conf": HERE / "nginx-player.locations.conf",
        "samplegame-native.locations.conf": HERE.parent / "NativeHosting/nginx-native.locations.conf",
    }
    vhost = (HERE / "nginx-gateway.example.conf").read_text(encoding="utf-8")
    substitutions = {
        "listen 443 ssl;": f"listen 127.0.0.1:{port} ssl;",
        "server_name updates.example.com;": "server_name 127.0.0.1;",
        "/etc/nginx/tls/updates.example.com.fullchain.pem": str(certificate),
        "/etc/nginx/tls/updates.example.com.key": str(key),
    }
    for name, source in sources.items():
        fragment = source.read_text(encoding="utf-8").replace("/srv/ue-game-updates", str(public))
        (output / name).write_text(fragment, encoding="utf-8")
        substitutions["/etc/nginx/snippets/" + name] = str(output / name)
    for original, replacement in substitutions.items():
        sets.require(vhost.count(original) == 1, "Gateway template changed at " + original)
        vhost = vhost.replace(original, replacement)
    gateway = output / "gateway.conf"
    gateway.write_text(vhost.replace("/srv/ue-game-updates", str(public)), encoding="utf-8")
    config = output / "nginx.conf"
    temp = "\n".join(f"    {name}_temp_path {output / name};"
                     for name in ("client_body", "proxy", "fastcgi", "uwsgi", "scgi"))
    config.write_text(f"""daemon off;
master_process off;
pid {output / 'nginx.pid'};
error_log {output / 'nginx-error.log'} notice;
events {{ worker_connections 32; }}
http {{
    access_log {output / 'nginx-access.log'};
{temp}
    include {gateway};
}}
""", encoding="utf-8")
    return config, gateway, certificate, public


def local_request(port, certificate):
    base = f"https://127.0.0.1:{port}"
    opener = build_opener(ProxyHandler({}), deploy_players.NoRedirect(),
                          HTTPSHandler(context=ssl.create_default_context(cafile=certificate)))

    def request(path, method="GET", headers=None):
        sets.require(path.startswith("/samplegame/") and not path.startswith("//"), "Expected a local test route")
        return opener.open(Request(base + path, method=method,
                                   headers={"Accept-Encoding": "identity", **(headers or {})}), timeout=5)

    return request


@contextmanager
def nginx_server(nginx, output, config, request):
    command = [nginx, "-p", str(output) + "/", "-c", config, "-e", "stderr"]
    with (output / "nginx-start.log").open("xb") as log:
        subprocess.run([*command, "-t"], stdout=log, stderr=subprocess.STDOUT, check=True, timeout=10)
        process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 8
            while True:
                sets.require(process.poll() is None and time.monotonic() < deadline, "Isolated Nginx did not start")
                try:
                    with request("/samplegame/players/manifest.json") as stream:
                        sets.require(stream.read(256) == b'{"protected":true}', "Unexpected protected installer fixture")
                    break
                except URLError:
                    time.sleep(0.1)
            yield
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


def prepare(output, release, key, config=None):
    source, prepared = output / f"source-{release}", output / f"prepared-{release}"
    _, installed, _ = fixture(source, release=release, signing_key=key,
                              content_overrides={"content": bytes([release % 256]) * (1024**2 + 3)})
    if config is not None:
        (source / "config.json").write_bytes(sets.canonical(config))
    plan = publisher.prepare(source, source / "config.json", source / "display.json", prepared)
    return installed, plan, prepared / "payload"


def stage(plan, payload):
    owner = remote.execute("stage", dict(plan=plan))
    destination = remote.ROOT / plan["channel"] / "releases" / owner["stageName"]
    for name in plan["files"]:
        shutil.copyfile(payload / name, destination / name)
    remote.execute("commit", dict(plan=plan, **owner))
    return dict(plan=plan, **owner)


def immutable(proof, request, route, plan, payload):
    proof.mkdir()
    with patch.object(deploy_players, "response", request):
        verified = publisher.public_verify(plan, payload, proof, 15)
    for item in verified:
        length, path = item["size"], route + item["path"]
        with request(path, "HEAD") as stream:
            sets.require(stream.status == 200 and int(stream.headers["Content-Length"]) == length
                         and stream.read(1) == b"", "HEAD did not expose the exact immutable object size")
        end = min(4096, length) - 1
        with (payload / item["path"]).open("rb") as source, request(path, headers={"Range": f"bytes=0-{end}"}) as stream:
            sets.require(stream.status == 206 and stream.headers["Content-Range"] == f"bytes 0-{end}/{length}"
                         and stream.read(end + 2) == source.read(end + 1), "Range did not match the immutable object")
        item["headAndRangeVerified"] = True
    sets.write_new(proof / "get-head-range.json", sets.canonical(verified))
    return len(verified)


def current(request, route, name):
    bound = 4096 if name.endswith(".sig") else sets.MAX_MANIFEST
    with request(route + name) as stream:
        raw = stream.read(bound + 1)
        sets.require(stream.status == 200 and 0 < len(raw) <= bound
                     and stream.headers["Cache-Control"] == "no-store", "Invalid current metadata response")
    return raw


def reject_mixed(verify, manifest, signature):
    try:
        verify(manifest, signature)
    except ValueError as error:
        sets.require(str(error) == "Release-set signature rejected", "Mixed generations failed unexpectedly")
    else:
        raise ValueError("Mixed generations passed signature verification")


def installer_fixture(installed):
    filename = "SampleGame-Windows-QA.zip"
    archive = installed / filename
    with ZipFile(archive, "x") as package:
        package.writestr("fixture.bin", b"installer fixture" * 65537)
    digest = sets.digest(archive)
    (installed / (filename + ".sha256")).write_bytes(f"{digest}  {filename}\n".encode("ascii"))
    path = "/samplegame/players/releases/protected/" + filename
    return dict(filename=filename, url=path, sha256Url=path + ".sha256", size=archive.stat().st_size, sha256=digest)


def verify_installer(request, package, installed, output, port):
    def immutable_response(path, method="GET", headers=None):
        response = request(path, method, headers)
        if response.headers.get_all("Cache-Control") != ["public, max-age=31536000, immutable"]:
            response.close()
            raise ValueError(f"Unexpected installer cache policy for {method} {path}")
        return response

    with patch.object(deploy_players.players, "ORIGIN", f"https://127.0.0.1:{port}"), \
         patch.object(deploy_players, "response", immutable_response):
        return deploy_players.verify_package(package, installed, output / package["filename"], 15)


def denied(request, method, path, expected):
    try:
        with request(path, method):
            raise ValueError(f"Unexpected successful {method} {path}")
    except HTTPError as error:
        with error:
            sets.require(error.code == expected and error.headers.get_all("Cache-Control") == ["no-store"]
                         and (method != "HEAD" or error.read(1) == b""),
                         f"Unexpected gateway status or caching for {method} {path}")
            return dict(method=method, path=path, status=error.code, cacheControl=error.headers["Cache-Control"])


def run(args, output, report):
    config, gateway, certificate, public = gateway_config(output, args.port)
    request = local_request(args.port, certificate)
    site = public / "site/index.html"
    site.parent.mkdir(parents=True)
    site.write_bytes(b"protected site fixture")
    players = public / "players"
    installed = players / "releases/protected"
    installed.mkdir(parents=True)
    (installed / "manifest.json").write_bytes(b'{"protected":true}')
    installer = installer_fixture(installed)
    (players / "current").symlink_to("releases/protected", target_is_directory=True)
    channels = public / "channels"
    for channel in (channels / "prod", channels / "v107-release-pc", public / "native/v105-pc"):
        protected_release = channel / "releases/protected"
        protected_release.mkdir(parents=True)
        (protected_release / "manifest.json").write_bytes(sets.canonical({"protectedChannel": channel.name}))
        (protected_release / "manifest.json.sig").write_bytes(b"protected signature fixture")
        (channel / "current").symlink_to("releases/protected", target_is_directory=True)
    key = ed25519.Ed25519PrivateKey.generate()
    installed_config, old_plan, old_payload = prepare(output, OLD, key)
    _, new_plan, new_payload = prepare(output, NEW, key, installed_config)
    route = f"/samplegame/{old_plan['channel']}/updates/"
    verify = sets.ed25519_verifier(installed_config["publicKeyHex"])
    with patch.multiple(remote, ROOT=channels, SITE=site, PLAYERS=players / "current", NGINX=gateway,
                        NATIVE=public / "native"), nginx_server(args.nginx, output, config, request):
        old_stage = stage(old_plan, old_payload)
        report["fullDownloads"] = immutable(output / f"verified-{OLD}", request, route, old_plan, old_payload)
        remote.execute("activate", old_stage)
        remote.execute("release-lock", old_stage)
        new_stage = stage(new_plan, new_payload)
        protected = new_stage["before"]["protected"]
        report["fullDownloads"] += immutable(output / f"verified-{NEW}", request, route, new_plan, new_payload)
        sets.require(remote.snapshot(new_plan) == new_stage["before"], "Verification changed the active pointer")
        old_raw = current(request, route, "manifest.json")
        old_sig = current(request, route, "manifest.json.sig")
        verify(old_raw, old_sig)
        sets.require(old_raw == (old_payload / "manifest.json").read_bytes(), "Invalid initial generation")
        activated = remote.execute("activate", new_stage)
        new_sig = current(request, route, "manifest.json.sig")
        reject_mixed(verify, old_raw, new_sig)
        new_raw = current(request, route, "manifest.json")
        verify(new_raw, new_sig)
        sets.require(activated == {"current": f"releases/{NEW}", "protected": protected}
                     and new_raw == (new_payload / "manifest.json").read_bytes(), "Invalid promoted generation")
        report["previousImmutableDownloads"] = immutable(output / f"previous-while-active-{NEW}", request,
                                                         route, old_plan, old_payload)
        sets.require(remote.snapshot(new_plan) == activated, "Reading the previous release changed the active pointer")
        rolled_back = remote.execute("rollback", new_stage)
        rollback_sig = current(request, route, "manifest.json.sig")
        reject_mixed(verify, new_raw, rollback_sig)
        rollback_raw = current(request, route, "manifest.json")
        verify(rollback_raw, rollback_sig)
        sets.require(rolled_back == {"current": f"releases/{OLD}", "protected": protected}
                     and (rollback_raw, rollback_sig) == (old_raw, old_sig), "Rollback changed the original metadata")
        missing = (route + "versions/401/payload/missing.pak",
                   "/samplegame/players/releases/protected/SampleGame-Missing.zip")
        report["missingResponses"] = [denied(request, method, path, 404)
                                      for path in missing for method in ("GET", "HEAD")]
        report["writeDenied"] = denied(request, "PUT", route + "manifest.json", 403)
        report["installerDownload"] = verify_installer(request, installer, installed, output, args.port)
        with request("/samplegame/players/manifest.json") as stream:
            sets.require(stream.headers.get_all("Cache-Control") == ["no-cache"]
                         and stream.read(256) == b'{"protected":true}', "Protected installer catalog changed")
        sets.require(remote.snapshot(new_plan) == rolled_back, "Protected publication state changed after rollback")
        remote.execute("release-lock", new_stage)
        report.update(mixedPromotionRejected=True, mixedRollbackRejected=True, current=rolled_back["current"],
                      protected=protected, oldManifestSha256=hashlib.sha256(old_raw).hexdigest(),
                      newManifestSha256=hashlib.sha256(new_raw).hexdigest(), status="passed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nginx", type=Path, required=True, help="Absolute path to a disposable or existing Nginx binary")
    parser.add_argument("--output", type=Path, required=True, help="Fresh POSIX scratch path outside the checkout")
    parser.add_argument("--port", type=int, default=18443)
    args = parser.parse_args()
    args.nginx = args.nginx.resolve(strict=True)
    output = args.output.resolve()
    sets.require(os.name == "posix" and 1024 <= args.port <= 65535 and not output.exists()
                 and not output.is_relative_to(HERE.parents[2]) and str(output).isascii()
                 and all(char.isalnum() or char in "/._-" for char in str(output)), "Use fresh ASCII POSIX scratch and a high port")
    output.mkdir(mode=0o700)
    report = dict(status="failed", scope="loopback-nginx-posix", port=args.port, nginxSha256=sets.digest(args.nginx))
    try:
        report["nginxVersion"] = subprocess.check_output([args.nginx, "-v"], stderr=subprocess.STDOUT,
                                                        timeout=5, text=True).strip()
        run(args, output, report)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        report["error"] = str(error)
    sets.write_new(output / "report.json", sets.canonical(report))
    print(json.dumps(report, indent=2))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
