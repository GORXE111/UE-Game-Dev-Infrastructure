"""Validate real new-protocol producer receipts and unchanged full archives.

No receipt is synthesized or relabeled. Runtime acceptance and APK signing
evidence remain separate original records; publication metadata never upgrades
their conservative runtimeValidated/published fields.
"""
from __future__ import annotations

import base64
import hashlib
from pathlib import Path
import re
import sys
import zipfile

import players

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "ReleaseSets"))
import release_set as sets


def bounded(archive, name, maximum=sets.MAX_MANIFEST):
    info = archive.getinfo(name)
    players.require(0 < info.file_size <= maximum, "Invalid archive metadata size")
    return archive.read(info)


def stream_record(archive, name, record):
    info = archive.getinfo(name)
    players.require(info.file_size == record["size"], "Archive payload size differs: " + name)
    result = hashlib.sha256()
    with archive.open(info) as stream:
        for block in iter(lambda: stream.read(1024**2), b""):
            result.update(block)
    players.require(result.hexdigest() == record["sha256"], "Archive payload SHA differs: " + name)


def inspect(path, platform, receipt):
    # Reuse credential/path/link hygiene. New PC archives have their own root,
    # unlike legacy Windows/ ZIPs; do not force them into an old schema.
    with zipfile.ZipFile(path) as archive:
        names = set()
        for info in archive.infolist():
            name = info.filename
            players.require(name and "\\" not in name and not name.startswith("/") and ":" not in name
                            and all(part not in (".", "..") for part in name.split("/"))
                            and name not in names, "Unsafe or duplicate archive path")
            players.require(not (info.external_attr >> 16) & 0o170000 == 0o120000, "Archive contains symbolic link")
            pure = Path(name)
            players.require(pure.suffix.lower() not in (".pem", ".key", ".jks", ".keystore", ".p12", ".pfx")
                            and not any(part.lower() in (".git", ".ssh", "id_rsa", "id_ed25519") for part in name.split("/")),
                            "Private credentials cannot be published")
            names.add(name)
        players.require(1 <= len(names) <= 100_000, "Invalid archive entry count")
        config_name = "release-player.json" if platform == "Windows" else "assets/release-player.json"
        manifest_name = "base/manifest.json" if platform == "Windows" else "assets/release-base-manifest.json"
        config = sets.parse(bounded(archive, config_name))
        trust = config["trust"]
        raw = bounded(archive, manifest_name)
        value = sets.manifest(raw, trust)
        players.require(value["platform"] == platform and value["releaseId"] == value["baseReleaseId"]
                        and hashlib.sha256(raw).hexdigest() == trust["baseManifestSha256"], "Archive base pin differs")
        players.require(config["manifestUrl"] == f"{players.ORIGIN}/samplegame/{value['channel']}/updates/manifest.json",
                        "Archive update endpoint differs")
        for key in ("baseReleaseId", "engineBuildId", "shellCompatibilityId", "sourceCommit", "nativeSourceHash", "buildId"):
            players.require(receipt.get(key) == value[key], "Producer/archive identity differs: " + key)
        players.require(receipt.get("manifestSha256") == trust["baseManifestSha256"], "Producer base manifest differs")
        if platform == "Windows":
            players.require("SampleGame.exe" in names and any(name.startswith("_release_internal/") for name in names)
                            and not any(name.startswith((".release-sets/", "Windows/")) for name in names), "Unexpected new PC player layout")
            expected = {"base/payload/" + item["path"] for item in value["files"]}
            players.require({name for name in names if name.startswith("base/payload/")} == expected, "PC archive base inventory differs")
            for item in value["files"]:
                stream_record(archive, "base/payload/" + item["path"], item)
            wrapper = archive.getinfo("SampleGame.exe")
            stream_record(archive, "SampleGame.exe", {"size": wrapper.file_size, "sha256": receipt["frozenPlayerSha256"]})
            players.require(isinstance(config.get("publicKeyHex"), str) and players.SHA.fullmatch(config["publicKeyHex"]), "Invalid frozen PC public key")
        else:
            players.require("AndroidManifest.xml" in names and config.get("packageName") == "com.example.samplegame"
                            and config.get("signatureAlgorithm") == "SHA256withRSA", "Invalid new Android shell")
            certificate = base64.b64decode(config["certificateBase64"], validate=True)
            players.require(hashlib.sha256(certificate).hexdigest() == config.get("certificateSha256")
                            == receipt.get("signingCertificateSha256"), "Android pinned certificate differs")
            entries = config.get("baseArchiveEntries")
            players.require(isinstance(entries, list) and len(entries) == len(value["files"])
                            and {item.get("path") for item in entries} == {item["path"] for item in value["files"]}, "APK baseline map differs")
            records = {item["path"]: item for item in value["files"]}
            for item in entries:
                players.require(type(item) is dict and set(item) == {"path", "apkPath", "obbPath"}, "Invalid APK baseline entry")
                if item["path"] == "libUnreal.so":
                    players.require(item["apkPath"] == "lib/arm64-v8a/libUnreal.so" and item["obbPath"] == "", "Invalid APK native map")
                    stream_record(archive, item["apkPath"], records[item["path"]])
                else:
                    players.require(item["apkPath"] == "assets/main.obb.png", "Unexpected embedded OBB")
                    sets.relative(item["obbPath"])
                    with archive.open(item["apkPath"]) as obb_stream, zipfile.ZipFile(obb_stream) as obb:
                        players.require(len([info for info in obb.infolist() if info.filename == item["obbPath"]]) == 1, "Ambiguous embedded PAK")
                        stream_record(obb, item["obbPath"], records[item["path"]])
        return value, config


def package_record(producer_path, download_path, platform, distribution):
    producer, download = players.read_json(producer_path), players.read_json(download_path)
    expected_kind = "samplegame-windows-release-set-player" if platform == "Windows" else "samplegame-android-release-set-player"
    players.require(producer.get("kind") == expected_kind and download.get("platform") == platform,
                    "Expected original new-protocol producer/archive receipts")
    base = download.get("baseReleaseId")
    players.require(type(base) is int and 0 < base < 10**9 and producer.get("baseReleaseId") == base, "Archive base identity differs")
    archive = Path(download["path"]).resolve(strict=True)
    players.require(archive.is_file() and not Path(download["path"]).is_symlink(), "Archive must be regular")
    name = archive.name
    players.require(players.valid_name(name) and re.search(r"-Base" + str(base) + r"(?:[-.]|$)", name)
                    and name.endswith(".zip" if platform == "Windows" else ".apk"), "Archive name/base/platform differs")
    size, sha = download.get("size"), download.get("sha256")
    players.require(type(size) is int and 0 < size <= players.MAX_ARCHIVE and archive.stat().st_size == size
                    and isinstance(sha, str) and players.SHA.fullmatch(sha) and players.digest(archive) == sha, "Archive size/SHA differs")
    if platform == "Android_ARM64":
        players.require(download.get("signingCertificateSha256") == producer.get("signingCertificateSha256")
                        and isinstance(producer.get("signingCertificateSha256"), str)
                        and players.SHA.fullmatch(producer["signingCertificateSha256"]), "APK signing identity differs")
    manifest, config = inspect(archive, platform, producer)
    url = f"/samplegame/players/releases/{distribution}/{name}"
    record = dict(platform=platform, baseReleaseId=base, channel=manifest["channel"], filename=name,
                  size=size, sha256=sha, url=url, sha256Url=url + ".sha256", updateProtocol="release-set-v1",
                  releaseManifestSha256=config["trust"]["baseManifestSha256"],
                  **{key: manifest[key] for key in ("buildId", "sourceCommit", "nativeSourceHash")})
    return archive, record, download.get("version")
