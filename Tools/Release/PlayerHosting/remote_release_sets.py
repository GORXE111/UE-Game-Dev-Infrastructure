"""SSH worker for reviewed release-set channels; immutable files and CAS pointers.

The caller sends the exact SHA-pinned shared protocol implementation with this
worker. No keys, passwords, producer receipts or source project are uploaded.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import uuid

ROOT = Path("/srv/ue-game-updates/channels")
SITE = Path("/srv/ue-game-updates/site/index.html")
PLAYERS = Path("/srv/ue-game-updates/players/current")
NGINX = Path("/etc/nginx/sites-available/updates.example.com")
NATIVE = Path("/srv/ue-game-updates/native")
CHANNELS = {"v106-release-pc": "Windows", "v106-release-android": "Android_ARM64",
            "v107-release-pc": "Windows", "v107-release-android": "Android_ARM64"}
OLD = ("prod", "prod-android", "v104-pc", "v104-android", "v104r2-pc", "v104r2-android", "v105-pc", "v105-android")
NATIVE_OLD = ("v104-pc", "v104-native-android", "v104r2-pc", "v104r2-native-android", "v105-pc", "v105-native-android")
SHA = re.compile(r"[a-f0-9]{64}\Z")
CORE = None


def require(ok, message):
    if not ok:
        raise ValueError(message)


def digest(path):
    result = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024**2), b""):
            result.update(block)
    return result.hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def fsync_dir(path):
    if os.name == "posix":
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def small(path):
    if not path.exists():
        return {"exists": False}
    require(path.is_file() and path.stat().st_size <= 1024**2, "Protected metadata exceeds limit")
    return {"exists": True, "size": path.stat().st_size, "sha256": digest(path)}


def pointer(path):
    require(path.is_symlink() or not path.exists(), "Unknown current pointer type")
    if not path.is_symlink():
        return None
    target = os.readlink(path)
    require(re.fullmatch(r"releases/[a-zA-Z0-9._-]{1,80}", target) and ".." not in target, "Unsafe existing pointer")
    require((path.parent / target).is_dir() and not (path.parent / target).is_symlink(), "Current release is missing or aliased")
    return target


def snapshot(plan):
    protected = {"site": small(SITE), "nginx": small(NGINX), "playersPointer": pointer(PLAYERS),
                 "playersCatalog": small(PLAYERS / "manifest.json")}
    observed = [("content", ROOT, channel) for channel in OLD]
    observed += [("native", NATIVE, channel) for channel in NATIVE_OLD]
    observed += [("content", ROOT, channel) for channel in CHANNELS if channel != plan["channel"]]
    for kind, root, channel in observed:
        current = root / channel / "current"
        protected[f"{kind}:{channel}"] = {"pointer": pointer(current), "manifest": small(current / "manifest.json"),
                                           "signature": small(current / "manifest.json.sig")}
    return {"current": pointer(ROOT / plan["channel"] / "current"), "protected": protected}


def validate(plan):
    require(plan.get("schemaVersion") == 1 and plan.get("kind") == "samplegame-release-set-publication", "Invalid publication format")
    channel, release = plan.get("channel"), plan.get("releaseId")
    require(channel in CHANNELS and plan["trust"]["platform"] == CHANNELS[channel]
            and plan["trust"]["channel"] == channel and type(release) is int and 0 < release < 10**9, "Only exact reviewed release-set channels are writable")
    require(plan["verification"]["algorithm"] == ("Ed25519" if CHANNELS[channel] == "Windows" else "SHA256withRSA"),
            "Signature algorithm differs from the fixed platform")
    require(SHA.fullmatch(plan["manifestSha256"]) and SHA.fullmatch(plan["coreSha256"])
            and SHA.fullmatch(plan["remoteScriptSha256"]), "Invalid publication digest")
    files = plan["files"]
    require(type(files) is dict and 5 <= len(files) <= 8198, "Invalid upload inventory")
    prefix = f"versions/{release}/"
    required = {"manifest.json", "manifest.json.sig", prefix + "manifest.json", prefix + "manifest.json.sig", prefix + "release-display.json"}
    require(required <= set(files), "Incomplete public metadata")
    for name, record in files.items():
        CORE["relative"](name)
        require(name in required or name.startswith(prefix + "payload/"), "Unexpected public upload path")
        # Existing nginx has a bounded tail route; reject an unreachable upload.
        require(not name.startswith(prefix) or len(name[len(prefix):]) <= 200, "Artifact exceeds installed nginx route limit")
        require(type(record) is dict and set(record) == {"size", "sha256"}
                and type(record["size"]) is int and 0 < record["size"] <= 8 * 1024**3
                and SHA.fullmatch(record["sha256"]), "Invalid public file size/SHA")
    require(plan["payloadBytes"] == sum(record["size"] for record in files.values()), "Payload accounting differs")
    return plan


def verify_signature(raw, signature, verification):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa
    if verification["algorithm"] == "Ed25519":
        key = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(verification["publicKeyHex"]))
        require(len(signature) == 64, "Invalid Ed25519 signature size")
        key.verify(signature, raw)
    else:
        require(verification["algorithm"] == "SHA256withRSA", "Unsupported pinned signature algorithm")
        certificate = base64.b64decode(verification["certificateBase64"], validate=True)
        require(hashlib.sha256(certificate).hexdigest() == verification["certificateSha256"], "Pinned certificate SHA differs")
        key = x509.load_der_x509_certificate(certificate).public_key()
        require(isinstance(key, rsa.RSAPublicKey) and key.key_size >= 2048, "Expected pinned RSA public key")
        key.verify(signature, raw, padding.PKCS1v15(), hashes.SHA256())


def verify(directory, plan):
    CORE["plain"](directory, True)
    actual = set()
    for root, children, names in os.walk(directory, followlinks=False):
        for name in children:
            CORE["plain"](Path(root) / name, True)
        for name in names:
            path = Path(root) / name
            CORE["plain"](path)
            actual.add(path.relative_to(directory).as_posix())
    require(actual == set(plan["files"]), "Remote upload inventory differs")
    for name, record in plan["files"].items():
        path = directory / name
        require(path.stat().st_size == record["size"] and digest(path) == record["sha256"], "Remote public bytes differ: " + name)
    raw = (directory / "manifest.json").read_bytes()
    require(hashlib.sha256(raw).hexdigest() == plan["manifestSha256"], "Remote manifest differs")
    value = CORE["manifest"](raw, plan["trust"])
    require(value["releaseId"] == plan["releaseId"], "Remote release ID differs")
    verify_signature(raw, (directory / "manifest.json.sig").read_bytes(), plan["verification"])
    prefix = f"versions/{plan['releaseId']}/"
    require((directory / (prefix + "manifest.json")).read_bytes() == raw
            and (directory / (prefix + "manifest.json.sig")).read_bytes() == (directory / "manifest.json.sig").read_bytes(), "Immutable metadata copies differ")
    CORE["verify_tree"](directory / (prefix + "payload"), value["files"])
    display = json.loads((directory / (prefix + "release-display.json")).read_bytes())
    require(display["manifestSha256"] == plan["manifestSha256"] and display["buildId"] == value["buildId"], "Remote display binding differs")


def guard(plan, before):
    now = snapshot(plan)
    require(now["protected"] == before["protected"], "Protected website, players or other channels changed")
    require(now["current"] == before["current"], "Concurrent new-channel pointer change")


def reuse_current_payload(final, directory, plan, before):
    """Deduplicate verified immutable bytes only within this channel's current set.

    The independent stage is verified and renamed to final before reuse. Final
    files are never uploaded/truncated, including resume after a worker dies.
    Atomic replacements only change inodes with identical verified bytes. Never
    chmod/write an old inode, link metadata or search another channel/release.
    """
    result = {"reusedFiles": 0, "reusedBytes": 0, "sourceCurrent": before["current"]}
    if before["current"] is None:
        return result
    old_root = CORE["child"](directory, before["current"])
    CORE["plain"](old_root, True)
    old_raw = CORE["read_bounded"](CORE["child"](old_root, "manifest.json"), 1024**2)
    old_manifest = CORE["manifest"](old_raw, plan["trust"])
    old_release = old_manifest["releaseId"]
    require(before["current"] == "releases/" + str(old_release) and old_release < plan["releaseId"], "Reuse source is not the preceding current release")
    verify_signature(old_raw, CORE["read_bounded"](CORE["child"](old_root, "manifest.json.sig"), 4096), plan["verification"])
    old_payload = CORE["child"](old_root, f"versions/{old_release}/payload")
    CORE["plain"](old_payload, True)
    index = {}
    for item in old_manifest["files"]:
        index.setdefault((item["role"], item["size"], item["sha256"]), item["path"])
    value = CORE["manifest"]((final / "manifest.json").read_bytes(), plan["trust"])
    payload = CORE["child"](final, f"versions/{plan['releaseId']}/payload")
    for item in value["files"]:
        matching = index.get((item["role"], item["size"], item["sha256"]))
        if matching is None:
            continue
        source = CORE["child"](old_payload, matching)
        destination = CORE["child"](payload, item["path"])
        CORE["plain"](source); CORE["plain"](destination)
        # Keep the short-lived link outside final's signed inventory. An abrupt
        # death between link and replace must not make final fail resume checks.
        temporary = final.parent / (".reuse-link-" + str(plan["releaseId"]) + "-" + uuid.uuid4().hex)
        descriptor = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            with os.fdopen(descriptor, "rb") as stream:
                original = os.fstat(stream.fileno())
                require(stat.S_ISREG(original.st_mode) and not original.st_mode & 0o222
                        and original.st_size == item["size"], "Reuse source must be a read-only regular file")
                checksum = hashlib.sha256()
                for block in iter(lambda: stream.read(1024**2), b""):
                    checksum.update(block)
                require(checksum.hexdigest() == item["sha256"], "Reuse source SHA differs")
                os.link(source, temporary, follow_symlinks=False)
                linked = temporary.lstat()
                current = source.lstat()
                require(stat.S_ISREG(linked.st_mode) and not linked.st_mode & 0o222
                        and (linked.st_dev, linked.st_ino) == (original.st_dev, original.st_ino)
                        == (current.st_dev, current.st_ino) and linked.st_size == item["size"]
                        and digest(temporary) == item["sha256"], "Read-only reuse changed during linking")
                os.replace(temporary, destination)
                fsync_dir(destination.parent)
                result["reusedFiles"] += 1
                result["reusedBytes"] += item["size"]
        finally:
            if temporary.exists() or temporary.is_symlink():
                temporary.unlink()
    return result


def owner(directory, token, plan):
    path = directory / ".publication.lock" / "owner.json"
    require(path.is_file(), "Publication lease is missing")
    value = json.loads(path.read_bytes())
    require(value["token"] == token and value["planSha256"] == hashlib.sha256(canonical(plan)).hexdigest(),
            "Publication lease belongs to another operation")


def replace_pointer(directory, target):
    next_path = directory / (".current-" + uuid.uuid4().hex)
    next_path.symlink_to(target, target_is_directory=True)
    os.replace(next_path, directory / "current")
    fsync_dir(directory)


def execute(action, args):
    plan = validate(args["plan"])
    directory = ROOT / plan["channel"]
    final = directory / "releases" / str(plan["releaseId"])
    if action == "inspect":
        return {**snapshot(plan), "availableBytes": shutil.disk_usage(ROOT).free,
                "releaseExists": final.exists(), "requiredFreeBytes": plan["payloadBytes"] * 2 + 2 * 1024**3}
    if action == "stage":
        require(NGINX.is_file() and b"/updates/versions/" in NGINX.read_bytes(), "Installed immutable update route is required")
        require(shutil.disk_usage(ROOT).free >= plan["payloadBytes"] * 2 + 2 * 1024**3, "Insufficient server stage/reserve space")
        directory.mkdir(exist_ok=True)
        CORE["plain"](directory, True)
        (directory / "releases").mkdir(exist_ok=True)
        CORE["plain"](directory / "releases", True)
        require(not final.exists(), "Immutable release ID already exists")
        previous = pointer(directory / "current")
        require(previous is None or re.fullmatch(r"releases/[1-9][0-9]{0,8}", previous)
                and plan["releaseId"] > int(previous.split("/")[1]), "A publication must advance the current release ID")
        lock = directory / ".publication.lock"
        lock.mkdir()
        token = uuid.uuid4().hex
        with (lock / "owner.json").open("xb") as stream:
            stream.write(canonical({"token": token, "planSha256": hashlib.sha256(canonical(plan)).hexdigest()}))
            stream.flush(); os.fsync(stream.fileno())
        stage_name = ".upload-" + str(plan["releaseId"]) + "-" + token
        stage = directory / "releases" / stage_name
        stage.mkdir()
        for name in plan["files"]:
            (stage / name).parent.mkdir(parents=True, exist_ok=True)
        fsync_dir(lock); fsync_dir(directory)
        return {"token": token, "stageName": stage_name, "before": snapshot(plan)}
    token, before = args["token"], args["before"]
    require(isinstance(token, str) and re.fullmatch(r"[a-f0-9]{32}", token), "Invalid publication token")
    owner(directory, token, plan)
    stage_name = ".upload-" + str(plan["releaseId"]) + "-" + token
    stage = directory / "releases" / stage_name
    if action in ("commit", "resume"):
        if action == "resume":
            now = snapshot(plan)
            require(now["protected"] == before["protected"] and now["current"] in
                    (before["current"], "releases/" + str(plan["releaseId"])), "Resume protected state or pointer changed")
            require(now["current"] == before["current"] or final.exists(), "Activated release is missing")
        else:
            guard(plan, before)
        if final.exists():
            verify(final, plan)
            return {"immutablePresent": True, "uploadedAgain": False,
                    "alreadyActivated": pointer(directory / "current") == "releases/" + str(plan["releaseId"])}
        if action == "resume":
            CORE["plain"](stage, True)
            return {"immutablePresent": False, "stageName": stage_name}
        verify(stage, plan)
        prefix = f"versions/{plan['releaseId']}/payload/"
        for root, children, names in os.walk(stage):
            os.chmod(root, 0o755)
            for name in names:
                path = Path(root) / name
                # Set new uploads read-only before any hardlink operation. Do
                # not chmod linked files afterward: they share old inodes.
                os.chmod(path, 0o444 if path.relative_to(stage).as_posix().startswith(prefix) else 0o644)
                if os.name == "posix":
                    with path.open("rb") as stream:
                        os.fsync(stream.fileno())
            fsync_dir(root)
        guard(plan, before)
        # Final is complete before reuse, so a process/power interruption can
        # only leave partially deduplicated, identical bytes. Resume never SCPs
        # into final; it re-verifies and reuses that immutable directory.
        os.rename(stage, final)
        fsync_dir(final.parent)
        reuse = reuse_current_payload(final, directory, plan, before)
        verify(final, plan)
        guard(plan, before)
        return {"immutablePresent": True, "manifestSha256": plan["manifestSha256"], "storageReuse": reuse}
    if action == "activate":
        guard(plan, before)
        verify(final, plan)
        replace_pointer(directory, "releases/" + str(plan["releaseId"]))
        return snapshot(plan)
    if action == "rollback":
        now = snapshot(plan)
        require(now["protected"] == before["protected"], "Protected state changed during rollback")
        if now["current"] == before["current"]:
            return {"alreadyOriginal": True}
        require(now["current"] == "releases/" + str(plan["releaseId"]), "Concurrent pointer change blocks rollback")
        if before["current"] is not None:
            replace_pointer(directory, before["current"])
        else:
            os.rename(directory / "current", directory / (".failed-current-" + token))
            fsync_dir(directory)
        return snapshot(plan)
    if action == "release-lock":
        (directory / ".publication.lock" / "owner.json").unlink()
        (directory / ".publication.lock").rmdir()
        fsync_dir(directory)
        return {"released": True}
    raise ValueError("Unknown remote publication action")


def main():
    global CORE
    args = globals().get("REQUEST") or json.loads(base64.b64decode(sys.argv[1], validate=True))
    source = base64.b64decode(args.pop("core"), validate=True)
    require(hashlib.sha256(source).hexdigest() == args["plan"]["coreSha256"], "Shared protocol source changed")
    CORE = {"__name__": "verified_release_set_core", "__file__": "<verified-release-set-core>"}
    exec(compile(source, "<verified-release-set-core>", "exec"), CORE)
    print(json.dumps(execute(args.pop("action"), args), sort_keys=True))


if __name__ == "__main__":
    main()
