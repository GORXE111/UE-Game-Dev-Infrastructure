"""Sign an installer's exact baseline as the initial channel feed; never force a redundant update."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
from types import SimpleNamespace

import release_identity
import release_notes
import release_set as sets

REPO = Path(__file__).resolve().parents[3]


def prepare(args):
    producer_path = args.producer.absolute()
    producer = sets.parse(sets.read_bounded(producer_path, sets.MAX_MANIFEST))
    windows = producer.get("kind") == "samplegame-windows-release-set-player"
    sets.require(windows or producer.get("kind") == "samplegame-android-release-set-player", "Expected an actual full-installer producer")
    if windows:
        import windows_player
        player = Path(producer["playerRoot"])
        config = windows_player.read_config(player)
        sets.require(not (player / ".release-sets").exists(), "Use the pristine full installer, never an acceptance installation")
        raw = sets.read_bounded(player / "base/manifest.json", sets.MAX_MANIFEST)
        value = sets.manifest(raw, config["trust"])
        sets.require(sets.digest(player / "SampleGame.exe") == producer["frozenPlayerSha256"], "Frozen installer launcher changed")
        source = player / "base/payload"
        sets.verify_tree(source, value["files"])
    else:
        import android_pipeline as android
        player = Path(producer["playerPath"])
        sets.require(player.stat().st_size == producer["playerSize"] and sets.digest(player) == producer["playerSha256"], "Signed installer APK changed")
        config, value, raw = android.read_player(player)
    release = value["releaseId"]
    sets.require(release == value["baseReleaseId"] == config["trust"]["baseReleaseId"], "Initial feed must be the installed baseline")
    sets.require(hashlib.sha256(raw).hexdigest() == config["trust"]["baseManifestSha256"], "Installer baseline pin differs")
    version = release_identity.archive_version(producer_path, value)
    proof = sets.parse(sets.read_bounded(Path(producer["buildProofPath"]), sets.MAX_MANIFEST))
    sets.require(proof.get("fullCook") is True and proof.get("kind") == ("samplegame-complete-windows-build" if windows else "samplegame-complete-android-build"),
                 "Initial channel requires an actual full build proof")
    notes, binding = release_notes.load(args.notes, version)
    sets.require(binding == proof.get("luaIdentity", {}).get("releaseNotes"), "Initial announcement differs from the frozen Cook")
    if windows:
        sets.require(value["files"] == proof["files"], "Installer payload differs from the full build")
    output = args.output.absolute()
    sets.require(not output.exists() and not output.resolve().is_relative_to(REPO)
                 and not output.resolve().is_relative_to(player.resolve())
                 and not output.resolve().is_relative_to(producer_path.parent.resolve()), "Use a fresh external baseline-feed directory")
    output.mkdir(parents=True)
    payload = output / "versions" / str(release) / "payload"
    payload.mkdir(parents=True)
    if windows:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        sets.require(args.private_key is not None, "Windows initial feed requires its installed Ed25519 key")
        key_path = args.private_key.resolve(strict=True)
        sets.require(not key_path.is_relative_to(REPO) and not key_path.is_relative_to(output.resolve()), "Keep the signing key outside source and distribution")
        key = serialization.load_pem_private_key(sets.read_bounded(key_path, 8192), password=None)
        sets.require(isinstance(key, Ed25519PrivateKey), "Expected an Ed25519 signing key")
        public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
        sets.require(public == config["publicKeyHex"], "Signing key differs from installed trust")
        signature = key.sign(raw)
        sets.ed25519_verifier(public)(raw, signature)
        for item in value["files"]:
            target = sets.child(payload, item["path"])
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(sets.child(source, item["path"]), target)
    else:
        sets.require(args.sdk_root and args.java_home and args.keystore, "Android initial feed requires the established APK signing tools")
        signing = SimpleNamespace(**vars(args))
        signing.project = REPO / "Project/SampleGame"
        android.verify_signed_apk(player, signing, output, "baseline-apk")
        signature = android.sign_manifest(signing, raw, output)
        records, _ = android.payload_records(player, release, payload)
        sets.require(records == value["files"], "Initial feed differs from the signed APK payload")
    sets.verify_tree(payload, value["files"])
    display = dict(schemaVersion=1, kind="samplegame-release-set-display", projectId=value["projectId"], platform=value["platform"],
                   channel=value["channel"], baseReleaseId=release, releaseId=release, buildId=value["buildId"],
                   manifestSha256=config["trust"]["baseManifestSha256"], version=version, headline=notes["headline"], changes=notes["changes"])
    for name, data in (("manifest.json", raw), ("manifest.json.sig", signature), ("release-player.json", sets.canonical(config)),
                       ("release-display.json", sets.canonical(display))):
        sets.write_new(output / name, data)
    receipt = dict(kind="samplegame-initial-baseline-feed", status="signed-baseline-not-published", platform=value["platform"],
                   channel=value["channel"], baseReleaseId=release, releaseId=release, version=version,
                   manifestSha256=config["trust"]["baseManifestSha256"], buildId=value["buildId"],
                   producerPath=str(producer_path), producerSha256=sets.digest(producer_path),
                   buildProofSha256=producer["buildProofSha256"], runtimeValidated=False, published=False)
    sets.write_new(output / "baseline-feed-receipt.json", sets.canonical(receipt))
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("producer", "notes", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("private-key", "sdk-root", "java-home", "keystore"):
        parser.add_argument("--" + name, type=Path)
    parser.add_argument("--key-alias", default="samplegame")
    parser.add_argument("--store-password-env", default="SAMPLEGAME_ANDROID_STORE_PASSWORD")
    parser.add_argument("--key-password-env", default="SAMPLEGAME_ANDROID_KEY_PASSWORD")
    print(json.dumps(prepare(parser.parse_args()), ensure_ascii=False))


if __name__ == "__main__":
    main()
