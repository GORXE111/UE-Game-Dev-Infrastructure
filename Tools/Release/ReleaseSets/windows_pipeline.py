"""Build and prepare a complete Windows release set from one real native/full-Cook input."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import posixpath
import re
import shutil
import struct
import subprocess
import sys
import zipfile
from contextlib import contextmanager

import compatibility
import content_plan
import release_identity
import release_set as sets

HERE = Path(__file__).resolve().parent
COOK_MAPS = content_plan.LEGACY_MAPS


def check_cook_maps(project, maps=COOK_MAPS):
    """Fail before starting any build when a required source map is missing/aliased."""
    content = sets.child(project, "Content")
    sets.plain(content, True)
    for name in maps:
        path = sets.child(content, name.removeprefix("/Game/") + ".umap")
        sets.require(path.is_file(), "Required Cook map is missing: " + name)
        sets.plain(path)


def listed_maps(log, maps=COOK_MAPS):
    text = Path(log).read_text(encoding="utf-8-sig", errors="replace")
    mounts = re.findall(r'LogPakFile:\s+(?:Display|Log):\s+Listing .+ with mount point "([^"\r\n]+)"', text)
    sets.require(len(mounts) == 1, "UnrealPak listing must identify one actual mount point")
    entries = re.findall(r'LogPakFile:\s+(?:Display|Log):\s+"([^"\r\n]+)" offset: [0-9]+, size: [0-9]+ bytes, sha1: [a-fA-F0-9]{40}, compression: [^\r\n]+', text)
    paths = {posixpath.normpath(mounts[0] + "/" + name) for name in entries}
    matches = [dict(map=name, cookedPath="../../../SampleGame/Content/" + name.removeprefix("/Game/") + ".umap")
               for name in maps]
    return mounts[0], [item for item in matches if item["cookedPath"] in paths]


def validate_map_inventory(value, engine, paks, maps=COOK_MAPS):
    """Bind the successful actual -List logs to this exact full PAK set, including repackaging."""
    sets.require(value and value.get("format") == 1 and value.get("requiredMaps") == list(maps), "Complete actual PAK map inventory is required")
    tool = Path(engine) / "Engine/Binaries/Win64/UnrealPak.exe"
    sets.plain(tool)
    recorded_tool = value["unrealPak"]
    sets.plain(recorded_tool["path"])
    sets.require(Path(recorded_tool["path"]).resolve() == tool.resolve() and recorded_tool["size"] == tool.stat().st_size
                 and recorded_tool["sha256"] == sets.digest(tool), "UnrealPak inventory tool changed")
    expected = {str(Path(path).absolute()): Path(path) for path in paks}
    sets.require(expected and len(expected) == len(paks), "Full PAK map inventory is missing or ambiguous")
    records = value["paks"]
    sets.require(len(records) == len(expected) and {item["path"] for item in records} == set(expected), "PAK map inventory differs from the complete payload")
    found = set()
    for item in records:
        pak = expected[item["path"]]; sets.plain(pak)
        sets.require(item["size"] == pak.stat().st_size and item["sha256"] == sets.digest(pak), "Listed PAK changed after inventory")
        log = item["listing"]; sets.plain(log["path"])
        sets.require(log["exitCode"] == 0 and sets.digest(log["path"]) == log["sha256"], "Actual UnrealPak listing failed or changed")
        mount, matches = listed_maps(log["path"], maps)
        sets.require(item["mountPoint"] == mount and item["maps"] == matches, "PAK map matches differ from the actual listing")
        found.update(match["map"] for match in matches)
    sets.require(found == set(maps), "Required maps missing from actual PAK inventory: " + ", ".join(sorted(set(maps) - found)))
    return value


def map_inventory(engine, paks, output, run=None, maps=COOK_MAPS):
    """Execute UnrealPak for every real PAK; no Cook argument/log can substitute for entries."""
    tool = Path(engine) / "Engine/Binaries/Win64/UnrealPak.exe"
    sets.plain(tool)
    paks = sorted([Path(path).absolute() for path in paks])
    sets.require(paks and len(set(paks)) == len(paks), "Full PAK map inventory is missing or ambiguous")
    result = dict(format=1, requiredMaps=list(maps), unrealPak=dict(path=str(tool.absolute()), size=tool.stat().st_size, sha256=sets.digest(tool)), paks=[])
    for index, pak in enumerate(paks):
        sets.plain(pak)
        before = dict(path=str(pak), size=pak.stat().st_size, sha256=sets.digest(pak))
        log = (execute if run is None else run)([tool, pak, "-List"], Path(output) / ("pak-map-inventory-%03d.log" % index))
        sets.require(log["exitCode"] == 0, "Actual UnrealPak listing failed")
        mount, matches = listed_maps(log["path"], maps)
        result["paks"].append(dict(**before, listing=log, mountPoint=mount, maps=matches))
    return validate_map_inventory(result, engine, paks, maps)


def execute(arguments, log):
    with Path(log).open("xb") as output:
        result = subprocess.run([str(item) for item in arguments], stdout=output, stderr=subprocess.STDOUT, check=False)
    sets.require(result.returncode == 0, "Actual operation failed; preserve " + str(log))
    return dict(path=str(Path(log).absolute()), sha256=sets.digest(log), exitCode=result.returncode)


def current_commit(project, clean=True):
    value = subprocess.run(["git", "-C", str(project), "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
    if clean:
        status = subprocess.run(["git", "-C", str(project), "status", "--porcelain=v1", "--untracked-files=all"], capture_output=True, text=True, check=True)
        sets.require(not status.stdout.strip(), "Commit source changes before freezing a deliverable build")
    return value


def identity(project, engine):
    modules = json.loads((Path(engine) / "Engine/Binaries/Win64/UnrealEditor.modules").read_text(encoding="utf-8-sig"))
    frozen = compatibility.freeze(project, modules["BuildId"])
    repo = Path(project).resolve().parents[1]
    native = subprocess.run(["pwsh", "-NoProfile", "-File", str(repo / "Tools/Release/Read-NativeSourceHash.ps1")],
                            capture_output=True, text=True, encoding="utf-8", check=True).stdout.strip().lstrip("\ufeff")
    return dict(sourceCommit=current_commit(project), nativeSourceHash=sets.sha(native), engineBuildId=modules["BuildId"],
                shellCompatibilityId=frozen["shellCompatibilityId"], sourceInventorySha256=hashlib.sha256(sets.canonical(frozen["files"])).hexdigest()), frozen


def fresh_output(path, project, engine):
    path = Path(path).absolute()
    sets.require(not path.exists(), "Output exists; use a fresh directory")
    for root in (Path(project).resolve().parents[1], Path(engine).resolve()):
        sets.require(not path.resolve().is_relative_to(root), "Build outputs must stay outside source and engine")
    path.mkdir(parents=True)
    return path


def pe64(path):
    with Path(path).open("rb") as stream:
        header = stream.read(64)
        sets.require(len(header) == 64 and header[:2] == b"MZ", "Expected a genuine Win64 PE image")
        offset = struct.unpack_from("<I", header, 60)[0]
        sets.require(64 <= offset <= Path(path).stat().st_size - 26, "Invalid PE header offset")
        stream.seek(offset)
        pe = stream.read(26)
        sets.require(pe[:4] == b"PE\0\0" and struct.unpack_from("<H", pe, 4)[0] == 0x8664
                     and struct.unpack_from("<H", pe, 24)[0] == 0x20B, "Expected AMD64 PE32+")


def archive_root(archive):
    """Accept the two UAT archive layouts, never guess an executable recursively."""
    archive = Path(archive)
    sets.plain(archive, True)
    matches = []
    for root in (archive, archive / "Windows"):
        if os.path.lexists(root):
            sets.plain(root, True)
        game = root / "SampleGame/Binaries/Win64/SampleGame.exe"
        if game.exists():
            for folder in (root / "SampleGame", root / "SampleGame/Binaries", game.parent):
                sets.plain(folder, True)
            sets.plain(game)
            matches.append(root)
    sets.require(len(matches) == 1, "Expected exactly one complete Windows archive layout")
    return matches[0]


def build(args):
    project, engine = args.project.resolve(), args.engine.resolve()
    plan = content_plan.snapshot()
    cook_maps = tuple(plan["plan"]["requiredMaps"])
    check_cook_maps(project, cook_maps)
    lua_identity = release_identity.snapshot(project)
    before, frozen = identity(project, engine)
    output = fresh_output(args.output, project, engine)
    sets.write_new(output / "source-inputs.json", sets.canonical(before))
    sets.write_new(output / "shell-freeze.json", sets.canonical(frozen))
    sets.write_new(output / "content-plan.json", sets.canonical(plan))
    repo = project.parents[1]
    common = ["-EngineRoot", engine, "-Compiler", "Clang", "-LLVMRoot", args.llvm_root, "-MaxParallelActions", "1", "-NoDebugSymbols"]
    editor = execute(["pwsh", "-NoProfile", "-File", repo / "Tools/Build-Project.ps1", "-Target", "Editor", *common], output / "editor-build.log")
    native = execute(["pwsh", "-NoProfile", "-File", repo / "Tools/Build-Project.ps1", "-Target", "Game", *common], output / "game-build.log")
    archive = output / "Archive"
    cook = execute(["pwsh", "-NoProfile", "-File", repo / "Tools/Package-Project.ps1", "-EngineRoot", engine,
                    "-Compiler", "Clang", "-LLVMRoot", args.llvm_root, "-ArchiveDirectory", archive, "-Platform", "Win64",
                    "-Configuration", "Development", "-MapList", "+".join(cook_maps),
                    "-CreateReleaseVersion", str(args.base_release_id), "-ReleaseVersionRoot", output / "CookReleases",
                    "-SkipEditorBuild", "-SkipGameBuild", "-NoDebugSymbols", "-AppLocalPrerequisites"], output / "full-cook.log")
    after, after_frozen = identity(project, engine)
    sets.write_new(output / "source-inputs-after.json", sets.canonical(after))
    sets.write_new(output / "shell-freeze-after.json", sets.canonical(after_frozen))
    sets.require(before == after, "Source or engine changed during the real native/full-Cook build")
    sets.require(plan == content_plan.snapshot(), "Release content plan changed during native/full-Cook build")
    sets.require(lua_identity == release_identity.snapshot(project), "Lua release identity changed during native/full-Cook build")
    root = archive_root(archive)
    game = root / "SampleGame/Binaries/Win64/SampleGame.exe"
    original = project / "Binaries/Win64/SampleGame.exe"
    pe64(game)
    sets.require(sets.digest(game) == sets.digest(original), "Staged game differs from the actual native build")
    files = payload_records(root)
    maps = map_inventory(engine, [root / item["path"] for item in files if item["path"].endswith(".pak")], output, maps=cook_maps)
    proof = dict(format=1, kind="samplegame-complete-windows-build", **before, configuration="Development", fullCook=True,
                 editorBuild=editor, nativeBuild=native, cook=cook, archiveRoot=str(root),
                 gameExe=dict(size=game.stat().st_size, sha256=sets.digest(game)), files=files, luaIdentity=lua_identity, contentPlan=plan, mapInventory=maps, runtimeValidated=False)
    sets.write_new(output / "build-proof.json", sets.canonical(proof))
    return proof


def validate_build(proof, project, engine):
    release_identity.proof_identity(proof, project)
    current, frozen = identity(project, engine)
    sets.require(proof.get("format") == 1 and proof.get("kind") == "samplegame-complete-windows-build"
                 and proof.get("fullCook") is True and proof.get("configuration") == "Development", "Complete Windows build proof is required")
    if proof.get("sourceCommit") != current["sourceCommit"]:
        # Repackaging after a tools/docs-only commit preserves the genuine game build provenance.
        # Never relabel the old proof. Both the actual source inventory and tracked project tree must agree.
        ancestor = subprocess.run(["git", "-C", str(project), "merge-base", "--is-ancestor", str(proof.get("sourceCommit")), current["sourceCommit"]], capture_output=True)
        unchanged = subprocess.run(["git", "-C", str(project), "diff", "--quiet", str(proof.get("sourceCommit")), current["sourceCommit"], "--", "."], capture_output=True)
        sets.require(ancestor.returncode == 0 and unchanged.returncode == 0, "Game project changed since the genuine build commit")
    for key, value in current.items():
        if key == "sourceCommit":
            continue
        sets.require(proof.get(key) == value, "Actual build input changed: " + key)
    for key, marker in (("editorBuild", "Result: Succeeded"), ("nativeBuild", "Result: Succeeded"), ("cook", "BUILD SUCCESSFUL")):
        log = proof[key]
        sets.require(log["exitCode"] == 0 and sets.digest(log["path"]) == log["sha256"], "Build evidence was changed")
        sets.require(marker in Path(log["path"]).read_text(encoding="utf-8", errors="replace"), "Actual successful build marker is missing")
    root = Path(proof["archiveRoot"])
    game = root / "SampleGame/Binaries/Win64/SampleGame.exe"
    pe64(game)
    sets.require(game.stat().st_size == proof["gameExe"]["size"] and sets.digest(game) == proof["gameExe"]["sha256"], "Built game was replaced")
    sets.require(payload_records(root) == proof["files"], "Cooked/native/support files changed after the actual build")
    validate_map_inventory(proof.get("mapInventory"), engine, [root / item["path"] for item in proof["files"] if item["path"].endswith(".pak")], content_plan.proof_maps(proof))
    built_identity = dict(current, sourceCommit=proof["sourceCommit"])
    return root, built_identity, frozen


def payload_records(source):
    records = []
    for folder in ("SampleGame", "Engine"):
        base = source / folder
        if not base.exists():
            continue
        for directory, children, files in os.walk(base, followlinks=False):
            for name in children:
                sets.plain(Path(directory) / name, True)
                sets.require(name.lower() not in ("saved", "savegames"), "Mutable runtime outputs are present in the archive")
            for name in files:
                path = Path(directory) / name
                sets.plain(path)
                relative = sets.relative(path.relative_to(source).as_posix())
                role = "native" if path.suffix.lower() in (".exe", ".dll") else "content" if relative.startswith("SampleGame/Content/Paks/") and path.suffix == ".pak" else "support"
                records.append(dict(path=relative, role=role, size=path.stat().st_size, sha256=sets.digest(path)))
    return sorted(records, key=lambda item: item["path"])


def prepare(args):
    proof = sets.parse(sets.read_bounded(args.build_proof, sets.MAX_MANIFEST))
    sets.require("luaIdentity" in proof, "A new installer requires the frozen Lua identity from an actual full build")
    source, current, frozen = validate_build(proof, args.project.resolve(), args.engine.resolve())
    output = fresh_output(args.output, args.project, args.engine)
    records = proof["files"]
    trust = dict(projectId="SampleGame", platform="Windows", channel=args.channel, baseReleaseId=args.base_release_id,
                 engineBuildId=current["engineBuildId"], shellCompatibilityId=current["shellCompatibilityId"], loaderVersion=1)
    value = {key: trust[key] for key in sets.BINDINGS}
    value.update(format=1, kind="samplegame-release-set", releaseId=args.base_release_id, minLoaderVersion=1,
                 sourceCommit=current["sourceCommit"], nativeSourceHash=current["nativeSourceHash"], files=records,
                 save=compatibility.CURRENT_SAVE_POLICY)
    value["buildId"] = sets.build_id(value)
    raw = sets.canonical(value)
    trust["baseManifestSha256"] = hashlib.sha256(raw).hexdigest()
    sets.manifest(raw, trust)
    root = output / "Windows"
    payload = root / "base/payload"
    payload.mkdir(parents=True)
    for item in records:
        target = sets.child(payload, item["path"])
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(sets.child(source, item["path"]), target)
    sets.verify_tree(payload, records)
    sets.write_new(root / "base/manifest.json", raw)
    player = args.player_build.resolve()
    for path in player.iterdir():
        sets.plain(path, path.is_dir())
        if path.name == "SampleGameReleasePlayer.exe":
            shutil.copy2(path, root / "SampleGame.exe")
        elif path.name == "_release_internal" and path.is_dir():
            shutil.copytree(path, root / path.name)
        else:
            raise ValueError("Unexpected frozen player file: " + path.name)
    sets.require((root / "SampleGame.exe").is_file() and (root / "_release_internal").is_dir(), "Frozen player build is incomplete")
    import windows_player
    config = dict(format=2, trust=trust, publicKeyHex=sets.sha(args.public_key_hex), manifestUrl=args.manifest_url, allowOffline=True)
    sets.write_new(root / "release-player.json", sets.canonical(config))
    windows_player.read_config(root)
    sets.write_new(output / "shell-freeze.json", sets.canonical(frozen))
    receipt = dict(status="prepared-not-runtime-validated", kind="samplegame-windows-release-set-player", **current,
                   baseReleaseId=args.base_release_id, manifestSha256=trust["baseManifestSha256"], buildId=value["buildId"],
                   playerRoot=str(root), frozenPlayerSha256=sets.digest(root / "SampleGame.exe"),
                   luaIdentity=proof["luaIdentity"], buildProofPath=str(args.build_proof.resolve()), buildProofSha256=sets.digest(args.build_proof),
                   runtimeValidated=False, published=False)
    sets.write_new(output / "producer-receipt.json", sets.canonical(receipt))
    return receipt


def archive(args):
    root = args.player_root.resolve()
    import windows_player
    config = windows_player.read_config(root)
    sets.require(not (root / ".release-sets").exists(), "Archive a pristine player, never a used test installation")
    raw = sets.read_bounded(root / "base/manifest.json", sets.MAX_MANIFEST)
    sets.require(hashlib.sha256(raw).hexdigest() == config["trust"]["baseManifestSha256"], "Installed manifest changed")
    value = sets.manifest(raw, config["trust"])
    version = release_identity.archive_version(root.parent / "producer-receipt.json", value)
    sets.verify_tree(root / "base/payload", value["files"])
    sets.require(not args.output.exists(), "Archive already exists")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(args.output, "x", zipfile.ZIP_DEFLATED, compresslevel=6) as output:
        for path in sorted(root.rglob("*")):
            sets.plain(path, path.is_dir())
            if path.is_file():
                output.write(path, path.relative_to(root).as_posix())
    receipt = dict(path=str(args.output.absolute()), size=args.output.stat().st_size, sha256=sets.digest(args.output),
                   version=version, platform="Windows", baseReleaseId=config["trust"]["baseReleaseId"], runtimeValidated=False, published=False)
    sets.write_new(args.output.with_suffix(".json"), sets.canonical(receipt))
    return receipt


@contextmanager
def producer_lease(root):
    root.mkdir(parents=True, exist_ok=True)
    sets.plain(root, True)
    path = sets.child(root, "producer.lock")
    with path.open("a+b") as stream:
        if not path.stat().st_size:
            stream.write(b"0"); stream.flush()
        stream.seek(0)
        if os.name == "nt":
            import msvcrt
            msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            yield root
        finally:
            stream.seek(0)
            if os.name == "nt":
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


def candidate(args):
    """Sign only a complete rebuilt pair compatible with the installed shell; never deploy."""
    import windows_player
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    root = args.player_root.resolve()
    config = windows_player.read_config(root)
    trust = config["trust"]
    base_raw = sets.read_bounded(root / "base/manifest.json", sets.MAX_MANIFEST)
    sets.require(hashlib.sha256(base_raw).hexdigest() == trust["baseManifestSha256"], "Installed baseline was replaced")
    base = sets.manifest(base_raw, trust)
    proof = sets.parse(sets.read_bounded(args.build_proof, sets.MAX_MANIFEST))
    source, current, _ = validate_build(proof, args.project.resolve(), args.engine.resolve())
    frozen = sets.parse(sets.read_bounded(args.shell_freeze, 16 * 1024**2), 16 * 1024**2)
    policy = compatibility.CURRENT_SAVE_POLICY
    result = compatibility.compare(frozen, args.project.resolve(), current["engineBuildId"], base["save"], policy)
    sets.require(not result["requiresNewBase"] and frozen["shellCompatibilityId"] == trust["shellCompatibilityId"]
                 and current["shellCompatibilityId"] == trust["shellCompatibilityId"], "Frozen installation shell changed; rebuild the base")
    # Full game EXE may change; independently shipped Engine files remain part of the installation shell.
    sets.require([item for item in proof["files"] if item["path"].startswith("Engine/")]
                 == [item for item in base["files"] if item["path"].startswith("Engine/")], "Shipped engine payload changed; rebuild the base")
    sets.number(args.release_id, trust["baseReleaseId"] + 1)
    key = serialization.load_pem_private_key(sets.read_bounded(args.private_key, 16384), password=None)
    sets.require(isinstance(key, Ed25519PrivateKey), "Expected the installed Ed25519 signing key")
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    sets.require(public == config["publicKeyHex"], "Signing key differs from installed trust")
    value = {name: trust[name] for name in sets.BINDINGS}
    value.update(format=1, kind="samplegame-release-set", releaseId=args.release_id, minLoaderVersion=1,
                 sourceCommit=current["sourceCommit"], nativeSourceHash=current["nativeSourceHash"], files=proof["files"], save=policy)
    value["buildId"] = sets.build_id(value)
    raw = sets.canonical(value); signature = key.sign(raw)
    sets.manifest(raw, trust); sets.ed25519_verifier(public)(raw, signature)
    output = Path(args.output).absolute()
    registry = Path(args.registry_root).absolute()
    sets.require(not registry.resolve().is_relative_to(output.resolve()) and not output.resolve().is_relative_to(registry.resolve()), "Private producer registry cannot be inside a distribution")
    family = sets.child(registry, trust["channel"] + "-" + str(trust["baseReleaseId"])) if registry.exists() else registry / (trust["channel"] + "-" + str(trust["baseReleaseId"]))
    with producer_lease(family):
        state_path = family / "state.json"
        state = sets.parse(sets.read_bounded(state_path, 65536), 65536) if state_path.exists() else dict(trust=trust, highestReleaseId=trust["baseReleaseId"])
        sets.require(state["trust"] == trust and args.release_id > state["highestReleaseId"], "Producer release ID is reserved or belongs to another baseline")
        # Reserve before copying/signing output; interrupted publication never reuses this identity.
        sets.atomic(state_path, dict(trust=trust, highestReleaseId=args.release_id))
        output = fresh_output(output, args.project, args.engine)
        payload = output / "versions" / str(args.release_id) / "payload"
        payload.mkdir(parents=True)
        for item in value["files"]:
            target = sets.child(payload, item["path"]); target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(sets.child(source, item["path"]), target)
        sets.verify_tree(payload, value["files"])
        sets.write_new(output / "manifest.json", raw); sets.write_new(output / "manifest.json.sig", signature)
        receipt = dict(status="signed-candidate-not-runtime-validated", **current, releaseId=args.release_id,
                       manifestSha256=hashlib.sha256(raw).hexdigest(), buildId=value["buildId"], runtimeValidated=False, published=False)
        sets.write_new(family / (str(args.release_id) + ".json"), sets.canonical(receipt))
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    build_cmd = sub.add_parser("build")
    prepare_cmd = sub.add_parser("prepare")
    for command in (build_cmd, prepare_cmd):
        command.add_argument("--project", type=Path, required=True)
        command.add_argument("--engine", type=Path, required=True)
        command.add_argument("--output", type=Path, required=True)
        command.add_argument("--base-release-id", type=int, required=True)
    build_cmd.add_argument("--llvm-root", type=Path, required=True)
    prepare_cmd.add_argument("--build-proof", type=Path, required=True)
    prepare_cmd.add_argument("--player-build", type=Path, required=True)
    prepare_cmd.add_argument("--channel", required=True)
    prepare_cmd.add_argument("--public-key-hex", required=True)
    prepare_cmd.add_argument("--manifest-url", required=True)
    archive_cmd = sub.add_parser("archive")
    archive_cmd.add_argument("--player-root", type=Path, required=True)
    archive_cmd.add_argument("--output", type=Path, required=True)
    candidate_cmd = sub.add_parser("candidate")
    for flag in ("project", "engine", "build-proof", "player-root", "shell-freeze", "private-key", "registry-root", "output"):
        candidate_cmd.add_argument("--" + flag, type=Path, required=True)
    candidate_cmd.add_argument("--release-id", type=int, required=True)
    args = parser.parse_args()
    print(json.dumps(dict(build=build, prepare=prepare, archive=archive, candidate=candidate)[args.command](args), ensure_ascii=False))


if __name__ == "__main__":
    main()
