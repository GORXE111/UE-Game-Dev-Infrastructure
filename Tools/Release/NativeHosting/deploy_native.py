"""Verify, publish and inspect native-only static releases; no content/website mutations."""
import argparse
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import uuid
from urllib.request import Request, build_opener

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "Tools/Release/NativeWindows"))
import native_launcher as client

CERTIFICATE_SHA256 = "0000000000000000000000000000000000000000000000000000000000000000"
WINDOWS_PUBLIC_KEY = "0000000000000000000000000000000000000000000000000000000000000000"
ANDROID_BINDINGS = ("format", "platform", "packageName", "channel", "abi", "baseReleaseId", "baseNativeSourceHash", "nativeApiVersion", "engineBuildId", "contentCompatibilityId")


def channel(value):
    client.require(type(value) is str and re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", value), "Invalid fixed native channel")
    return value


def release_id(value):
    client.require(type(value) is int and 0 < value < 1000000000, "Native release ID must be positive and below 1e9")
    return value


def record(path, relative):
    path = Path(path).resolve(strict=True)
    return {"path": relative, "size": path.stat().st_size, "sha256": client.digest(path), "source": str(path)}


def public_url(origin, name):
    client.https_origin(origin)
    client.require(origin.endswith("/") is False and __import__("urllib.parse", fromlist=["urlsplit"]).urlsplit(origin).path in ("", "/"), "Public origin must not contain a path")
    return origin + "/samplegame/" + channel(name) + "/native/"


def verify_android(source, base_record, certificate_der, destination_channel, origin, certificate_pin=CERTIFICATE_SHA256):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    source = Path(source).resolve(strict=True)
    raw = client.inside(source, "manifest.json").read_bytes()
    envelope = client.parse_json(raw)
    client.require(type(envelope) is dict and set(envelope) == {"format", "payloadBase64", "signatureBase64", "signatureAlgorithm"} and envelope["format"] == 1 and envelope["signatureAlgorithm"] == "SHA256withRSA", "Unsupported Android native envelope")
    payload_raw = base64.b64decode(envelope["payloadBase64"], validate=True)
    signature = base64.b64decode(envelope["signatureBase64"], validate=True)
    client.require(0 < len(payload_raw) <= 32768, "Android native payload size is invalid")
    certificate = Path(certificate_der).read_bytes()
    client.require(hashlib.sha256(certificate).hexdigest() == certificate_pin, "Android release certificate differs from pinned APK certificate")
    key = x509.load_der_x509_certificate(certificate).public_key()
    client.require(isinstance(key, rsa.RSAPublicKey), "Android signing key must be RSA")
    key.verify(signature, payload_raw, padding.PKCS1v15(), hashes.SHA256())
    payload = client.parse_json(payload_raw, 32768)
    expected_fields = set(ANDROID_BINDINGS) | {"releaseId", "nativeSourceHash", "soSha256", "soSize", "soUrl", "versionLabel"}
    client.require(type(payload) is dict and set(payload) == expected_fields, "Android signed payload fields differ from loader protocol")
    base = client.parse_json(Path(base_record).read_bytes(), 16 * 1024 * 1024)
    bootstrap = base["bootstrap"]
    client.require(base["signingCertificateSha256"] == certificate_pin, "Android base certificate binding differs")
    for name in ANDROID_BINDINGS:
        client.require(payload[name] == bootstrap[name], "Android native base mismatch: " + name)
    client.require(payload["channel"] == channel(destination_channel) and payload["platform"] == "Android_ARM64" and payload["abi"] == "arm64-v8a", "Android native destination identity differs")
    version = release_id(payload["releaseId"])
    client.require(version > payload["baseReleaseId"], "Android native release must follow its base")
    expected_url = public_url(origin, destination_channel) + f"versions/{version}/libUnreal.so"
    client.require(payload["soUrl"] == expected_url and bootstrap["manifestUrl"] == public_url(origin, destination_channel) + "manifest.json", "Android native public URL differs from frozen bootstrap")
    so = client.inside(source, "libUnreal.so")
    client.require(type(payload["soSize"]) is int and 64 <= payload["soSize"] <= 1024**3 and client.SHA.fullmatch(payload["soSha256"]) and client.SHA.fullmatch(payload["nativeSourceHash"]), "Android native size/hash is invalid")
    client.require(so.stat().st_size == payload["soSize"] and client.digest(so) == payload["soSha256"], "Android native SO failed signed hash/size")
    spec = importlib.util.spec_from_file_location("hosting_android_validator", ROOT / "Tools/Release/NativeAndroid/native_android.py")
    validator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(validator)
    validator.loader_elf(so)
    return version, [record(source / "manifest.json", "manifest.json"), record(so, f"versions/{version}/libUnreal.so")]


def verify_windows(source, config_path, public_key, destination_channel, origin):
    source = Path(source).resolve(strict=True)
    config = client.read_config(config_path)
    client.require(config["publicKeyHex"] == public_key and config["channel"] == channel(destination_channel), "Windows native public key/channel differs from frozen player")
    client.require(config["manifestUrl"] == public_url(origin, destination_channel) + "manifest.json", "Windows native URL differs from frozen player")
    raw = client.inside(source, "manifest.json").read_bytes()
    signature = client.inside(source, "manifest.json.sig").read_bytes()
    manifest = client.signed_manifest(raw, signature, config)
    version = release_id(manifest["nativeVersion"])
    archive = client.inside(source, manifest["archive"]["path"])
    client.require(archive.stat().st_size == manifest["archive"]["size"] and client.digest(archive) == manifest["archive"]["sha256"], "Windows native ZIP failed signed hash/size")
    import tempfile
    with tempfile.TemporaryDirectory(prefix="native-hosting-verify-") as directory:
        client.extract_verified(archive, Path(directory), manifest)
    return version, [record(source / "manifest.json", "manifest.json"), record(source / "manifest.json.sig", "manifest.json.sig"), record(archive, manifest["archive"]["path"])]


REMOTE_RELEASE = r'''
import base64,hashlib,json,os,pathlib,re,sys,uuid
p=json.loads(base64.b64decode(sys.argv[1]));channel=p['channel'];version=p['version'];phase=p['phase'];files=p['files']
assert re.fullmatch(r'[a-z][a-z0-9_-]{0,31}',channel) and type(version)is int and 0<version<10**9
root=pathlib.Path('/srv/ue-game-updates/native')/channel;releases=root/'releases';final=releases/str(version)
for parent in (pathlib.Path('/srv/ue-game-updates/native'),root,releases):
 assert not parent.is_symlink();parent.mkdir(parents=True,exist_ok=True)
expected={f['path']:f for f in files}
assert len(expected)in(2,3)
for name,r in expected.items():
 assert name in ('manifest.json','manifest.json.sig',f'versions/{version}/libUnreal.so',f'versions/{version}/native-windows.zip')
 assert type(r['size'])is int and 0<r['size']<=2**30 and re.fullmatch('[a-f0-9]{64}',r['sha256'])
def verify(directory):
 assert directory.is_dir() and not directory.is_symlink()
 actual=set()
 for entry in directory.rglob('*'):
  assert not entry.is_symlink()
  if entry.is_file():actual.add(entry.relative_to(directory).as_posix())
 assert actual==set(expected),'remote public file set differs'
 for name,r in expected.items():
  file=directory/name;h=hashlib.sha256()
  with file.open('rb')as stream:
   for block in iter(lambda:stream.read(1<<20),b''):h.update(block)
  assert file.stat().st_size==r['size'] and h.hexdigest()==r['sha256'],'remote byte verification failed'
def current():
 link=root/'current'
 if not link.exists() and not link.is_symlink():return None
 assert link.is_symlink();target=os.readlink(link);assert re.fullmatch(r'releases/[1-9][0-9]{0,8}',target)
 return target
if phase=='prepare':
 if final.exists():verify(final);print(json.dumps({'present':True,'staging':None}));sys.exit(0)
 token=p['token'];assert re.fullmatch('[a-f0-9]{32}',token)
 staging=releases/f'.upload-{version}-{token}';staging.mkdir()
 for name in expected:(staging/name).parent.mkdir(parents=True,exist_ok=True)
 print(json.dumps({'present':False,'staging':str(staging)}))
elif phase=='commit':
 if not final.exists():
  token=p['token'];assert re.fullmatch('[a-f0-9]{32}',token)
  staging=releases/f'.upload-{version}-{token}';verify(staging)
  for entry in staging.rglob('*'):os.chmod(entry,0o755 if entry.is_dir()else 0o644)
  os.chmod(staging,0o755);os.rename(staging,final)
 verify(final);previous=current()
 assert previous is None or int(previous.split('/')[-1])<=version,'native current downgrade rejected'
 next_link=root/('current.next-'+uuid.uuid4().hex);os.symlink(f'releases/{version}',next_link);os.replace(next_link,root/'current')
 print(json.dumps({'previous':previous,'current':f'releases/{version}'}))
elif phase=='restore':
 assert current()==f'releases/{version}','current changed concurrently; refusing rollback'
 previous=p['previous']
 if previous is None:os.rename(root/'current',root/('current.failed-'+uuid.uuid4().hex))
 else:
  assert re.fullmatch(r'releases/[1-9][0-9]{0,8}',previous) and (root/previous).is_dir()
  next_link=root/('current.restore-'+uuid.uuid4().hex);os.symlink(previous,next_link);os.replace(next_link,root/'current')
 print(json.dumps({'restored':previous}))
else:raise ValueError('unknown native operation')
'''


class Host:
    def __init__(self, host, identity, port=22):
        client.require(re.fullmatch(r"[A-Za-z0-9_-]+@[A-Za-z0-9.-]+", host) and 0 < port <= 65535, "Invalid SSH target")
        self.host, self.port = host, str(port)
        self.options = ["-i", str(Path(identity).resolve(strict=True)), "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=20", "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=6"]
    def run(self, script, payload):
        encoded = base64.b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode()
        result = subprocess.run(["ssh", *self.options, "-p", self.port, self.host, "python3", "-", encoded], input=script, text=True, capture_output=True, timeout=1800, check=False)
        client.require(result.returncode == 0, "Remote native operation failed: " + result.stderr[-2000:])
        return json.loads(result.stdout)
    def upload(self, source, destination):
        client.require(re.fullmatch(r"/srv/ue-game-updates/native/[a-z][a-z0-9_-]{0,31}/releases/\.upload-[0-9]+-[a-f0-9]{32}/(?:manifest\.json(?:\.sig)?|versions/[0-9]+/(?:libUnreal\.so|native-windows\.zip))", destination), "Unsafe remote upload destination")
        result = subprocess.run(["scp", "-C", *self.options, "-P", self.port, "-q", str(source), self.host + ":" + destination], timeout=1800, check=False)
        client.require(result.returncode == 0, "Native public file upload failed")


def verify_https(plan):
    opener = build_opener(client.NoRedirect())
    base = public_url(plan["origin"], plan["channel"])
    for item in plan["files"]:
        url = base + item["path"]
        with opener.open(Request(url, method="HEAD"), timeout=30) as response:
            client.require(response.status == 200 and int(response.headers.get("Content-Length", -1)) == item["size"], "HTTPS HEAD differs from native artifact")
            cache = response.headers.get("Cache-Control", "")
            client.require(("no-store" if item["path"].startswith("manifest") else "immutable") in cache, "Native cache policy is incorrect")
        hashed = hashlib.sha256()
        count = 0
        with opener.open(Request(url, headers={"Accept-Encoding": "identity"}), timeout=30) as response:
            client.require(response.status == 200, "HTTPS native GET failed")
            for block in iter(lambda: response.read(1024 * 1024), b""):
                count += len(block)
                client.require(count <= item["size"], "HTTPS payload exceeds signed size")
                hashed.update(block)
        client.require(count == item["size"] and hashed.hexdigest() == item["sha256"], "HTTPS served bytes differ from verified local native release")
        if item["path"].startswith("versions/"):
            end = min(15, item["size"] - 1)
            with opener.open(Request(url, headers={"Range": f"bytes=0-{end}"}), timeout=30) as response:
                client.require(response.status == 206 and response.headers.get("Content-Range") == f"bytes 0-{end}/{item['size']}", "Native HTTPS Range response is incorrect")
                with Path(item["source"]).open("rb") as local:
                    client.require(response.read(end + 2) == local.read(end + 1), "Native HTTPS Range bytes differ")
    return {"manifestAndPayloadHashes": True, "head": True, "range206": True}


def deploy(plan, host):
    token = uuid.uuid4().hex
    payload = {"channel": plan["channel"], "version": plan["version"], "files": [{key: item[key] for key in ("path", "size", "sha256")} for item in plan["files"]], "token": token}
    prepared = host.run(REMOTE_RELEASE, {**payload, "phase": "prepare"})
    if not prepared["present"]:
        for item in plan["files"]:
            host.upload(item["source"], prepared["staging"] + "/" + item["path"])
    switched = host.run(REMOTE_RELEASE, {**payload, "phase": "commit"})
    try:
        verification = verify_https(plan)
    except Exception:
        host.run(REMOTE_RELEASE, {**payload, "phase": "restore", "previous": switched["previous"]})
        raise
    return {"published": True, "channel": plan["channel"], "version": plan["version"], "previous": switched["previous"], "https": verification}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("plan", "publish", "verify"))
    parser.add_argument("--platform", choices=("windows", "android"), required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--channel", required=True)
    parser.add_argument("--origin", default="https://updates.example.com")
    parser.add_argument("--windows-config", type=Path)
    parser.add_argument("--public-key-hex", default=WINDOWS_PUBLIC_KEY)
    parser.add_argument("--base-record", type=Path)
    parser.add_argument("--certificate-der", type=Path)
    parser.add_argument("--host")
    parser.add_argument("--identity", type=Path)
    parser.add_argument("--port", type=int, default=22)
    args = parser.parse_args()
    channel(args.channel)
    if args.platform == "windows":
        client.require(args.windows_config, "Windows deployment requires frozen --windows-config")
        version, files = verify_windows(args.source, args.windows_config, args.public_key_hex, args.channel, args.origin)
    else:
        client.require(args.base_record and args.certificate_der, "Android deployment requires immutable base record and public DER certificate")
        version, files = verify_android(args.source, args.base_record, args.certificate_der, args.channel, args.origin)
    plan = {"platform": args.platform, "channel": args.channel, "origin": args.origin, "version": version, "files": files}
    if args.action == "publish":
        client.require(args.host and args.identity, "Publishing requires explicit SSH target and identity")
        result = deploy(plan, Host(args.host, args.identity, args.port))
    elif args.action == "verify":
        result = verify_https(plan)
    else:
        result = plan
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
