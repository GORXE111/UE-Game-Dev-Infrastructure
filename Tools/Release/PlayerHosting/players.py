"""Prepare immutable, byte-for-byte player downloads; never modify an APK/ZIP."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import zipfile

from remote_players import validate

ORIGIN = "https://updates.example.com"
ID = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}\Z")
NAME = re.compile(r"SampleGame-[A-Za-z0-9][A-Za-z0-9._-]{0,150}\.(?:zip|apk)\Z")
SHA = re.compile(r"[a-f0-9]{64}\Z")
CHANNEL = re.compile(r"[a-z][a-z0-9_-]{0,31}\Z")
MAX_ARCHIVE = 8 * 1024**3


def require(value, message):
    if not value:
        raise ValueError(message)


def digest(path):
    result = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024**2), b""):
            result.update(block)
    return result.hexdigest()


def read_json(path):
    path = Path(path)
    require(path.is_file() and path.stat().st_size <= 1024**2, "Invalid bounded JSON input")
    return json.loads(path.read_text(encoding="utf-8-sig"))


def canonical(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def write_new(path, data):
    with Path(path).open("xb") as stream:
        stream.write(data)


def valid_id(value):
    return isinstance(value, str) and ID.fullmatch(value) and ".." not in value


def valid_name(value):
    return isinstance(value, str) and NAME.fullmatch(value) and ".." not in value


def inspect_archive(path, platform, base_id, channel):
    """Check publication hygiene; this does not replace APK signing/runtime audits."""
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        require(1 <= len(entries) <= 100_000, "Invalid archive entry count")
        seen = set()
        for entry in entries:
            name = entry.filename
            pure = PurePosixPath(name)
            require(name and "\\" not in name and not pure.is_absolute()
                    and ":" not in name and ".." not in pure.parts, "Unsafe archive path")
            require(name not in seen, "Duplicate archive path")
            seen.add(name)
            require(not stat.S_ISLNK(entry.external_attr >> 16), "Archive contains a symbolic link")
            require(pure.suffix.lower() not in (".pem", ".key", ".jks", ".keystore", ".p12", ".pfx")
                    and not any(part.lower() in (".git", ".ssh", "id_rsa", "id_ed25519") for part in pure.parts),
                    "Private credentials cannot be published")
        if platform == "Windows":
            require(all(name.startswith("Windows/") for name in seen), "Expected Windows/ archive root")
            for name in ("Windows/native-player.json", "Windows/sample-player.json"):
                info = archive.getinfo(name)
                require(info.file_size <= 65536, "Player trust config is too large")
                settings = json.loads(archive.read(info))
                require(settings.get("baseReleaseId") == base_id and settings.get("channel") == channel,
                        "Archive trust differs from frozen package receipt")
                require(settings.get("manifestUrl") == f"{ORIGIN}/samplegame/{channel}/"
                        + ("native/manifest.json" if name.endswith("native-player.json") else "updates/manifest.json"),
                        "Archive has an unexpected update endpoint")
        else:
            require("AndroidManifest.xml" in seen and "lib/arm64-v8a/libUnreal.so" in seen,
                    "Expected self-contained ARM64 APK")


def package_record(package_path, download_path, platform, distribution):
    package, download = read_json(package_path), read_json(download_path)
    require(package.get("platform", "Windows") == platform, "Package platform mismatch")
    base = package.get("baseReleaseId")
    require(type(base) is int and 0 < base < 10**9, "Invalid base ID")
    channel = package.get("channel")
    require(isinstance(channel, str) and CHANNEL.fullmatch(channel), "Invalid content channel")
    archive = Path(download["path"]).resolve(strict=True)
    require(archive.is_file() and not Path(download["path"]).is_symlink(), "Archive must be a regular file")
    name = archive.name
    require(valid_name(name) and re.search(r"-Base" + str(base) + r"(?:[-.]|$)", name), "Archive filename/base identity differs")
    require(archive.suffix == (".zip" if platform == "Windows" else ".apk"), "Wrong archive extension")
    size, sha = download.get("size"), download.get("sha256")
    require(type(size) is int and 0 < size <= MAX_ARCHIVE and archive.stat().st_size == size,
            "Archive size differs from producer receipt")
    require(isinstance(sha, str) and SHA.fullmatch(sha) and digest(archive) == sha,
            "Archive SHA differs from producer receipt")
    if platform != "Windows":
        certificate = package.get("signingCertificateSha256")
        require(isinstance(certificate, str) and SHA.fullmatch(certificate)
                and download.get("signingCertificateSha256") == certificate
                and download.get("baseReleaseId") == base, "APK certificate/base evidence differs")
    inspect_archive(archive, platform, base, channel)
    url = f"/samplegame/players/releases/{distribution}/{name}"
    public = dict(platform=platform, baseReleaseId=base, channel=channel, filename=name,
                  size=size, sha256=sha, url=url, sha256Url=url + ".sha256")
    return archive, public


def prepare(output, distribution, version, headline, windows_package, windows_download,
            android_package, android_download, android_native_channel, baseline_revision=3, target_revision=4):
    require(valid_id(distribution), "Invalid immutable distribution ID")
    require(re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version or ""), "Invalid display version")
    require(isinstance(headline, str) and 0 < len(headline) <= 160 and headline.strip() == headline
            and not any(ord(char) < 32 for char in headline), "Invalid headline")
    require(CHANNEL.fullmatch(android_native_channel or ""), "Invalid Android native channel")
    require(type(baseline_revision) is int and type(target_revision) is int
            and 0 < baseline_revision <= target_revision, "Native target revision must not precede its baseline")
    output = Path(output).resolve()
    require(not output.is_relative_to(Path(__file__).resolve().parents[3]), "Keep prepared downloads outside repository")
    require(not output.exists(), "Prepared output already exists; never overwrite a candidate")
    items = [package_record(windows_package, windows_download, "Windows", distribution),
             package_record(android_package, android_download, "Android_ASTC_arm64", distribution)]
    channels = [["content", item[1]["channel"]] for item in items]
    channels.extend([["native", items[0][1]["channel"]], ["native", android_native_channel]])
    return write_prepared(output, distribution, version, headline, items, channels, baseline_revision, target_revision,
                          (windows_package, windows_download, android_package, android_download))


def prepare_release_sets(output, distribution, version, headline, windows_producer, windows_download,
                         android_producer, android_download, baseline_revision, target_revision):
    """Use real release-set producer/archive schemas without legacy conversions."""
    import release_set_archives
    require(valid_id(distribution), "Invalid immutable distribution ID")
    require(isinstance(version, str) and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version), "Invalid display version")
    require(isinstance(headline, str) and 0 < len(headline) <= 160 and headline.strip() == headline
            and not any(ord(char) < 32 for char in headline), "Invalid headline")
    require(type(baseline_revision) is int and type(target_revision) is int
            and 0 < baseline_revision <= target_revision, "Native target revision must not precede baseline")
    output = Path(output).resolve()
    require(not output.is_relative_to(Path(__file__).resolve().parents[3]) and not output.exists(), "Use fresh external prepared output")
    records = [release_set_archives.package_record(windows_producer, windows_download, "Windows", distribution),
               release_set_archives.package_record(android_producer, android_download, "Android_ARM64", distribution)]
    require(all(item[2] == version for item in records), "Producer archive display versions differ")
    # Equal source identities are required; a new shared-code Android build must
    # never be advertised alongside a PC artifact from older native inputs.
    require(all(records[0][1][key] == records[1][1][key] for key in ("sourceCommit", "nativeSourceHash")),
            "PC and Android producer source identities differ")
    items = [(archive, record) for archive, record, _ in records]
    return write_prepared(output, distribution, version, headline, items,
                          [["content", item[1]["channel"]] for item in items], baseline_revision, target_revision,
                          (windows_producer, windows_download, android_producer, android_download))


def write_prepared(output, distribution, version, headline, items, channels, baseline_revision, target_revision, input_paths):
    output = Path(output)
    output.mkdir(parents=True)
    payload = output / "payload"
    payload.mkdir()
    files = {}
    for source, record in items:
        destination = payload / source.name
        shutil.copy2(source, destination)
        require(digest(destination) == record["sha256"], "Archive copy changed bytes")
        sidecar = (record["sha256"] + "  " + source.name + "\n").encode("ascii")
        write_new(payload / (source.name + ".sha256"), sidecar)
    catalog = dict(schemaVersion=1, projectId="SampleGame", distributionId=distribution,
                   version=version, headline=headline, nativeBaselineRevision=baseline_revision,
                   nativeTargetRevision=target_revision, packages=[item[1] for item in items])
    write_new(payload / "manifest.json", canonical(catalog))
    for path in sorted(payload.iterdir()):
        files[path.name] = dict(size=path.stat().st_size, sha256=digest(path))
    plan = dict(schemaVersion=1, distributionId=distribution, files=files, catalog=catalog,
                protectedAdditionalChannels=channels, payloadBytes=sum(x["size"] for x in files.values()),
                remoteScriptSha256=digest(Path(__file__).with_name("remote_players.py")),
                inputReceipts=[dict(path=str(Path(path).resolve()), size=Path(path).stat().st_size, sha256=digest(path))
                               for path in input_paths],
                publicationExecuted=False, replacesGameTrust=False)
    validate(plan)
    write_new(output / "prepared.json", canonical(plan))
    return plan


def load_plan(output):
    output = Path(output)
    plan = read_json(output / "prepared.json")
    validate(plan)
    require(valid_id(plan.get("distributionId")), "Invalid prepared distribution")
    require(plan["remoteScriptSha256"] == digest(Path(__file__).with_name("remote_players.py")),
            "Remote implementation changed after candidate preparation")
    payload = output / "payload"
    require({p.name for p in payload.iterdir()} == set(plan["files"]), "Prepared inventory changed")
    for name, record in plan["files"].items():
        path = payload / name
        require(path.is_file() and not path.is_symlink() and path.stat().st_size == record["size"]
                and digest(path) == record["sha256"], "Prepared public bytes changed")
    require((payload / "manifest.json").read_bytes() == canonical(plan["catalog"]), "Prepared catalog changed")
    return plan
