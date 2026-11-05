"""Self-contained SSH worker. Owns only /srv/ue-game-updates/players; never signs or deletes releases."""
from __future__ import annotations

import base64
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sys
import uuid

ROOT = Path("/srv/ue-game-updates/players")
SITE = Path("/srv/ue-game-updates/site/index.html")
NGINX = Path("/etc/nginx/sites-available/updates.example.com")
CONTENT = Path("/srv/ue-game-updates/channels")
NATIVE = Path("/srv/ue-game-updates/native")
OLD = (("content", "prod"), ("content", "prod-android"), ("content", "v104-pc"),
       ("content", "v104-android"), ("native", "v104-pc"), ("native", "v104-native-android"),
       ("content", "v104r2-pc"), ("content", "v104r2-android"), ("native", "v104r2-pc"),
       ("native", "v104r2-native-android"), ("content", "v105-pc"), ("content", "v105-android"),
       ("native", "v105-pc"), ("native", "v105-native-android"),
       ("content", "v106-release-pc"), ("content", "v106-release-android"),
       ("content", "v107-release-pc"), ("content", "v107-release-android"))
ID = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}\Z")
NAME = re.compile(r"SampleGame-[A-Za-z0-9][A-Za-z0-9._-]{0,150}\.(?:zip|apk)\Z")
CHANNEL = re.compile(r"[a-z][a-z0-9_-]{0,31}\Z")
SHA = re.compile(r"[a-f0-9]{64}\Z")
RESERVE = 2 * 1024**3


def check(condition, reason):
    if not condition:
        raise ValueError(reason)


def canonical(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()


def digest(path):
    result = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024**2), b""):
            result.update(block)
    return result.hexdigest()


def sync_directory(path):
    if os.name == "posix":
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def validate(plan):
    check(plan.get("schemaVersion") == 1, "Unsupported prepared format")
    identifier = plan.get("distributionId")
    check(isinstance(identifier, str) and ID.fullmatch(identifier) and ".." not in identifier, "Unsafe distribution ID")
    catalog = plan["catalog"]
    check(catalog["schemaVersion"] == 1 and catalog["projectId"] == "SampleGame"
          and catalog["distributionId"] == identifier, "Catalog identity differs")
    check(isinstance(catalog.get("version"), str) and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", catalog["version"]), "Invalid display version")
    headline = catalog.get("headline")
    check(isinstance(headline, str) and 0 < len(headline) <= 160 and headline.strip() == headline
          and not any(ord(c) < 32 for c in headline), "Invalid headline")
    check(type(catalog.get("nativeBaselineRevision")) is int and type(catalog.get("nativeTargetRevision")) is int
          and 0 < catalog["nativeBaselineRevision"] <= catalog["nativeTargetRevision"], "Native baseline/target identity differs")
    packages = catalog["packages"]
    check(len(packages) == 2 and {p["platform"] for p in packages} in
          ({"Windows", "Android_ASTC_arm64"}, {"Windows", "Android_ARM64"}), "Expected two platforms")
    if any(package["platform"] == "Android_ARM64" for package in packages):
        check(all(package.get("updateProtocol") == "release-set-v1" for package in packages), "New player protocol pair differs")
        check(all(packages[0].get(key) == packages[1].get(key) for key in ("sourceCommit", "nativeSourceHash")),
              "New player source pair differs")
    allowed = {"manifest.json"}
    for package in packages:
        name, base = package["filename"], package["baseReleaseId"]
        check(isinstance(name, str) and NAME.fullmatch(name) and ".." not in name, "Unsafe package filename")
        check(type(base) is int and 0 < base < 10**9 and re.search(r"-Base" + str(base) + r"(?:[-.]|$)", name), "Invalid base identity")
        check(name.endswith(".zip" if package["platform"] == "Windows" else ".apk"), "Wrong platform extension")
        if package.get("updateProtocol") == "release-set-v1":
            check(package["platform"] in ("Windows", "Android_ARM64")
                  and isinstance(package.get("channel"), str) and CHANNEL.fullmatch(package["channel"])
                  and all(isinstance(package.get(key), str) and SHA.fullmatch(package[key])
                          for key in ("releaseManifestSha256", "buildId", "nativeSourceHash"))
                  and isinstance(package.get("sourceCommit"), str) and re.fullmatch(r"[a-f0-9]{40}", package["sourceCommit"]),
                  "Invalid release-set player identity")
        check(package["url"] == f"/samplegame/players/releases/{identifier}/{name}"
              and package["sha256Url"] == package["url"] + ".sha256", "Unsafe package URL")
        check(plan["files"][name] == {"size": package["size"], "sha256": package["sha256"]}, "Catalog inventory differs")
        allowed.update((name, name + ".sha256"))
    check(set(plan["files"]) == allowed, "Public upload allowlist differs")
    for name, record in plan["files"].items():
        maximum = 65536 if name == "manifest.json" else 256 if name.endswith(".sha256") else 8 * 1024**3
        check(type(record["size"]) is int and 0 < record["size"] <= maximum
              and isinstance(record["sha256"], str) and SHA.fullmatch(record["sha256"]), "Invalid file size/SHA")
    check(plan["files"]["manifest.json"] == {"size": len(canonical(catalog)), "sha256": hashlib.sha256(canonical(catalog)).hexdigest()}, "Catalog bytes differ")
    check(plan["payloadBytes"] == sum(record["size"] for record in plan["files"].values()), "Payload accounting differs")
    check(len(plan["protectedAdditionalChannels"]) <= 8, "Too many protected channel inputs")
    for kind, channel in plan["protectedAdditionalChannels"]:
        check(kind in ("content", "native") and isinstance(channel, str) and CHANNEL.fullmatch(channel), "Unsafe protected channel")
    return plan


def small(path):
    if not path.exists():
        return {"exists": False}
    check(path.is_file() and path.stat().st_size <= 1024**2, "Protected metadata is not a small regular file")
    return {"exists": True, "size": path.stat().st_size, "sha256": digest(path)}


def current_target():
    current = ROOT / "current"
    check(current.is_symlink() or not current.exists(), "Unknown players/current type")
    if not current.is_symlink():
        return None
    target = os.readlink(current)
    check(re.fullmatch(r"releases/[a-z0-9][a-z0-9._-]{0,63}", target) and ".." not in target,
          "Unsafe existing players pointer")
    check((ROOT / target).is_dir() and not (ROOT / target).is_symlink(), "Existing player release is missing or linked")
    return target


def protected(plan):
    result = {"site": small(SITE), "nginx": small(NGINX), "channels": {}}
    for kind, channel in sorted(set(OLD) | {tuple(x) for x in plan["protectedAdditionalChannels"]}):
        current = (CONTENT if kind == "content" else NATIVE) / channel / "current"
        result["channels"][kind + "/" + channel] = {
            "kind": "symlink" if current.is_symlink() else "directory" if current.is_dir() else "missing",
            "target": os.readlink(current) if current.is_symlink() else None,
            "manifest": small(current / "manifest.json"), "signature": small(current / "manifest.json.sig")}
    return result


def roots():
    check(ROOT.parent.is_dir() and not ROOT.parent.is_symlink(), "Unexpected player parent")
    ROOT.mkdir(exist_ok=True)
    check(ROOT.is_dir() and not ROOT.is_symlink(), "Players root must not be linked")
    releases = ROOT / "releases"
    releases.mkdir(exist_ok=True)
    check(releases.is_dir() and not releases.is_symlink(), "Release root must not be linked")


@contextmanager
def locked():
    path = ROOT / ".transaction-lock"
    path.mkdir()  # Exclusive, fail closed; a stale lock requires explicit review.
    try:
        yield
    finally:
        path.rmdir()  # Only this call's exact empty lock, never a recursive deletion.


def verify(directory, plan):
    check(directory.is_dir() and not directory.is_symlink(), "Missing regular candidate directory")
    check({p.name for p in directory.iterdir()} == set(plan["files"]), "Remote allowlist differs")
    for name, record in plan["files"].items():
        path = directory / name
        check(path.is_file() and not path.is_symlink() and path.stat().st_size == record["size"]
              and digest(path) == record["sha256"], "Remote file bytes differ: " + name)
    check((directory / "manifest.json").read_bytes() == canonical(plan["catalog"]), "Remote catalog differs")
    for package in plan["catalog"]["packages"]:
        expected = (package["sha256"] + "  " + package["filename"] + "\n").encode("ascii")
        check((directory / (package["filename"] + ".sha256")).read_bytes() == expected, "Sidecar bytes differ")


def execute(action, parameters):
    check(action in ("inspect", "stage", "commit", "recover-commit", "activate", "rollback"), "Unsupported remote action")
    plan = validate(parameters["plan"])
    if action == "inspect":
        return {"protected": protected(plan), "current": current_target(), "availableBytes": shutil.disk_usage(ROOT.parent).free}
    roots()
    identifier = plan["distributionId"]
    final = ROOT / "releases" / identifier
    if action == "stage":
        check(b"# SampleGame player downloads" in NGINX.read_bytes(), "Reviewed player nginx route is not installed")
        check(not final.exists() and not final.is_symlink(), "Immutable distribution already exists")
        required = plan["payloadBytes"] * 2 + RESERVE + 1024**2
        free = shutil.disk_usage(ROOT).free
        check(free >= required, "Insufficient retained-candidate/backup/reserve space")
        before = {"protected": protected(plan), "current": current_target()}
        name = ".upload-" + identifier + "-" + uuid.uuid4().hex
        (ROOT / name).mkdir()
        return {"stageName": name, "before": before, "availableBytes": free, "requiredFreeBytes": required}
    before = parameters["before"]
    with locked():
        check(protected(plan) == before["protected"], "Website/nginx/game channels changed; refusing player promotion")
        if action in ("commit", "recover-commit"):
            current = current_target()
            check(current == before["current"] or action == "recover-commit" and current == "releases/" + identifier,
                  "Concurrent players/current change")
            if action == "recover-commit" and final.exists():
                verify(final, plan)
                return {"committed": True, "recoveredExistingImmutableRelease": True, "release": str(final), "current": current}
            name = parameters["stageName"]
            check(re.fullmatch(r"\.upload-" + re.escape(identifier) + r"-[a-f0-9]{32}", name), "Unsafe staging identity")
            stage = ROOT / name
            verify(stage, plan)
            check(not final.exists() and not final.is_symlink(), "Immutable release cannot be overwritten")
            for path in stage.iterdir():
                if os.name == "posix":
                    with path.open("rb") as stream:
                        os.fsync(stream.fileno())
                path.chmod(0o444)
            stage.chmod(0o555)
            sync_directory(stage)
            os.rename(stage, final)
            sync_directory(final.parent)
            sync_directory(ROOT)
            check(protected(plan) == before["protected"], "Protected state changed")
            return {"committed": True, "release": str(final), "currentUnchanged": current_target() == before["current"]}
        if action == "activate":
            check(current_target() == before["current"], "Concurrent players/current change")
            verify(final, plan)
            temporary = ROOT / (".current-" + uuid.uuid4().hex)
            temporary.symlink_to("releases/" + identifier, target_is_directory=True)
            os.replace(temporary, ROOT / "current")
            sync_directory(ROOT)
            check(protected(plan) == before["protected"], "Protected state changed during activation")
            return {"activated": True, "current": current_target(), "previousCurrent": before["current"], "protectedUnchanged": True}
        if action == "rollback":
            check(current_target() == "releases/" + identifier, "Concurrent pointer changed; refusing rollback")
            if before["current"] is None:
                os.rename(ROOT / "current", ROOT / (".failed-current-" + uuid.uuid4().hex))
            else:
                target = before["current"]
                check(re.fullmatch(r"releases/[a-z0-9][a-z0-9._-]{0,63}", target) and ".." not in target
                      and (ROOT / target).is_dir() and not (ROOT / target).is_symlink(), "Unsafe previous player release")
                temporary = ROOT / (".rollback-" + uuid.uuid4().hex)
                temporary.symlink_to(target, target_is_directory=True)
                os.replace(temporary, ROOT / "current")
            sync_directory(ROOT)
            return {"rolledBack": True, "current": current_target(), "archivesRetained": True}
    raise ValueError("Unsupported remote action")


if __name__ == "__main__":
    check(len(sys.argv) == 2, "Expected one encoded public parameter object")
    payload = json.loads(base64.b64decode(sys.argv[1], validate=True))
    print(json.dumps(execute(payload["action"], payload), ensure_ascii=False))
