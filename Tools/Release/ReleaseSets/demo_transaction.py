"""Exercise real release-set transactions with disposable, non-executable files."""
import argparse
import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from time import perf_counter

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

import release_set as sets


LAYOUTS = {
    "Windows": ("SampleGame/Binaries/Win64/SampleGame.exe", "SampleGame/Content/Paks/Demo.pak"),
    "Android_ARM64": ("libUnreal.so", "Content/Paks/Demo.pak"),
}
SAVE_NAME = "progress.sav"


def product(directory, trust, release, layout):
    files = []
    for role, path in zip(("native", "content"), layout):
        target = directory / path
        target.parent.mkdir(parents=True, exist_ok=True)
        payload = f"Demonstration fixture {release} {role}\n".encode()
        target.write_bytes(payload)
        files.append(dict(path=path, role=role, size=len(payload), sha256=sets.digest(target)))
    manifest = dict(format=1, kind="samplegame-release-set", **{key: trust[key] for key in sets.BINDINGS},
                    releaseId=release, minLoaderVersion=1, sourceCommit="1" * 40,
                    nativeSourceHash="2" * 64, files=sorted(files, key=lambda item: item["path"]),
                    save=dict(schema=1, readable=[1], migrations=[]))
    manifest["buildId"] = sets.build_id(manifest)
    return sets.canonical(manifest)


def confirm(store, selected):
    reference = selected["reference"]
    store.confirm(selected["attemptId"], reference["releaseId"], reference["manifestSha256"],
                  selected["manifest"]["save"]["schema"])


def reject_stage(store, directory, manifest, signature, expected):
    try:
        store.stage(directory, manifest, signature)
    except ValueError as error:
        sets.require(expected in str(error), f"Unexpected rejection: {error}")
    else:
        raise ValueError("Invalid candidate was accepted")


def run(root, platform):
    layout = LAYOUTS[platform]
    key = Ed25519PrivateKey.generate()
    trust = dict(projectId="SampleGame", platform=platform, channel="demo", baseReleaseId=100,
                 engineBuildId="fixture", shellCompatibilityId="3" * 64, loaderVersion=1)
    base = product(root / "base", trust, 100, layout)
    trust["baseManifestSha256"] = hashlib.sha256(base).hexdigest()
    verifier = sets.ed25519_verifier(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex())

    legacy = root / "legacy-saves"
    legacy.mkdir()
    (legacy / SAVE_NAME).write_bytes(b"original progress")
    store_root = root / "store"
    with sets.ReleaseSetStore(store_root, trust, verifier).lease() as store:
        store.initialize(root / "base", base, legacy)

    first = root / "first"
    candidate = product(first, trust, 101, layout)
    signature = key.sign(candidate)
    with sets.ReleaseSetStore(store_root, trust, verifier).lease() as store:
        reject_stage(store, first, candidate, b"x" * 64, "signature rejected")
        pak = first / layout[1]
        original = pak.read_bytes()
        pak.write_bytes(b"x" * len(original))
        reject_stage(store, first, candidate, signature, "size/hash mismatch")
        pak.write_bytes(original)
        store.stage(first, candidate, signature)
        store.activate(101)
        selected = store.boot()
        sets.require(selected["reference"]["releaseId"] == 101, "Expected first candidate")
        (Path(selected["savesRoot"]) / SAVE_NAME).write_bytes(b"progress from unconfirmed candidate")
        # Leave the boot unconfirmed. The next independent store recovers from disk.

    with sets.ReleaseSetStore(store_root, trust, verifier).lease() as store:
        recovered = store.boot()
        sets.require(recovered["reference"]["releaseId"] == 100, "Expected installed baseline after recovery")
        sets.require((Path(recovered["savesRoot"]) / SAVE_NAME).read_bytes() == b"original progress",
                     "Recovery did not preserve the prior save generation")
        confirm(store, recovered)

    next_source = root / "next"
    next_manifest = product(next_source, trust, 102, layout)
    with sets.ReleaseSetStore(store_root, trust, verifier).lease() as store:
        reject_stage(store, first, candidate, signature, "stale or blocked")
        store.stage(next_source, next_manifest, key.sign(next_manifest))
        store.activate(102)
        confirm(store, store.boot())

    with sets.ReleaseSetStore(store_root, trust, verifier).lease() as store:
        selected = store.boot()
        sets.require(selected["reference"]["releaseId"] == 102, "Confirmed version was not retained")
        for path in layout:
            sets.require((Path(selected["payloadRoot"]) / path).read_bytes() == (next_source / path).read_bytes(),
                         f"Confirmed payload differs: {path}")
        sets.require((Path(selected["savesRoot"]) / SAVE_NAME).read_bytes() == b"original progress",
                     "Confirmed version did not inherit the recovered save")
        confirm(store, selected)
    return dict(platformLayout=platform, rejectedSignature=True, rejectedModifiedPayload=True,
                rolledBackTo=100, preservedPriorSave=True, rejectedFailedRelease=101, confirmedRelease=102)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", choices=tuple(LAYOUTS), help="Omit to exercise both manifest layouts")
    args = parser.parse_args()
    start = perf_counter()
    platforms = (args.platform,) if args.platform else LAYOUTS
    with TemporaryDirectory(prefix="ue-release-demo-") as directory:
        results = [run(Path(directory) / platform, platform) for platform in platforms]
    print(json.dumps(dict(status="passed", implementation="Python release-set store", fixturePayloads=True,
                          unrealLaunched=False, androidRuntimeUsed=False, networkUsed=False,
                          elapsedSeconds=round(perf_counter() - start, 3), results=results), indent=2))


if __name__ == "__main__":
    main()
