"""Produce complete Development ARM64/ASTC release sets from a real native/full Cook.

Build evidence is immutable. Preparing an APK injects pinned public trust only,
then aligns and signs a new file; it never rewrites the genuine native/Cook proof.
No command in this module uploads, activates, or claims device acceptance.
"""
from __future__ import annotations

import argparse
import base64
import copy
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile

import compatibility
import release_set as sets
from windows_pipeline import COOK_MAPS, check_cook_maps, fresh_output, identity, map_inventory, producer_lease, validate_map_inventory
import content_plan
import release_identity

HERE = Path(__file__).resolve().parent
CERTIFICATE = HERE.parent / "NativeAndroid/release-certificate.der"
CERTIFICATE_SHA256 = "0000000000000000000000000000000000000000000000000000000000000000"
NATIVE_ENTRY = "lib/arm64-v8a/libUnreal.so"
OBB_ENTRY = "assets/main.obb.png"
CONFIG_ENTRY = "assets/release-player.json"
MANIFEST_ENTRY = "assets/release-base-manifest.json"
LEGACY_NATIVE_ENTRY = "assets/native-bootstrap.json"
PACKAGE = "com.example.samplegame"
MAX_PROOF = 16 * 1024**2
POLICY = compatibility.CURRENT_SAVE_POLICY
STAGE_METADATA = {"UECommandLine.txt", "NOTICES.txt", "Manifest_UFSFiles_Android.txt", "Manifest_NonUFSFiles_Android.txt", "Manifest_DebugFiles_Android.txt"}
STAGE_LIBRARIES = {"Engine/Binaries/ThirdParty/Vulkan/Android/" + abi + "/libVkLayer_khronos_validation.so"
                   for abi in ("arm64-v8a", "armeabi-v7a", "x86", "x86_64")}


def execute(arguments, log, env=None):
    """Capture the actual return code without putting password values in arguments."""
    with Path(log).open("xb") as output:
        result = subprocess.run([str(item) for item in arguments], stdout=output, stderr=subprocess.STDOUT,
                                check=False, env=env)
    sets.require(result.returncode == 0, "Actual operation failed; preserve " + str(log))
    return dict(path=str(Path(log).absolute()), sha256=sets.digest(log), exitCode=result.returncode,
                arguments=[str(item) for item in arguments])


def read_proof(path):
    return sets.parse(sets.read_bounded(path, MAX_PROOF), MAX_PROOF)


def process_path(path):
    # Preserve an ASCII junction for NDK/UAT subprocesses. Resolving its target
    # can reintroduce non-ASCII toolchain paths. Safety containment checks in
    # fresh_output still resolve the actual source/engine/output destinations.
    return Path(os.path.abspath(path))


def ordinary_chain(root, path):
    """Validate every existing component before moving a generated cache."""
    root, path = Path(root).absolute(), Path(path).absolute()
    sets.require(path.is_relative_to(root) and root.resolve() == root, "Cache path is outside its ordinary real root")
    sets.plain(root, True)
    cursor = root
    for component in path.relative_to(root).parts:
        cursor = cursor / component
        if os.path.lexists(cursor):
            sets.plain(cursor, cursor.is_dir())
        sets.require(cursor.resolve().is_relative_to(root), "Cache path escaped its checked root")


def cache_inventory(root):
    """Inventory ordinary old cache bytes without following aliases."""
    root = Path(root)
    result, folded = [], set()
    pending = [root]
    while pending:
        path = pending.pop()
        info = path.lstat()
        directory = stat.S_ISDIR(info.st_mode)
        sets.plain(path, directory)
        sets.require(directory or info.st_nlink == 1, "Hard-linked cache files are forbidden")
        name = path.relative_to(root.parent).as_posix()
        sets.require(name.casefold() not in folded, "Case-aliased cache entry")
        folded.add(name.casefold())
        result.append(dict(path=name, type="directory" if directory else "file",
                           size=0 if directory else info.st_size,
                           sha256=hashlib.sha256(b"").hexdigest() if directory else sets.digest(path)))
        if directory:
            pending.extend(path.iterdir())
    return sorted(result, key=lambda item: item["path"])


def quarantine_default_stage(project, output):
    """Preserve only this platform's old default Stage/OBBs by same-volume rename.

    UEDeployAndroid reads this exact default OBB even when UAT stages elsewhere.
    Validate the complete move plan before touching any source; no old bytes are
    deleted, restored over a new build, or silently accepted as current output.
    """
    project, output = Path(project).absolute(), Path(output).absolute()
    saved = project / "Saved/StagedBuilds"
    ordinary_chain(project, saved)
    ordinary_chain(output, output)
    sets.require(not output.resolve().is_relative_to(project.resolve()), "Cache quarantine must stay outside the project")
    sources = []
    if saved.exists():
        for path in sorted(saved.iterdir()):
            name = path.name
            if name.casefold() != "android_astc" and not name.casefold().startswith("android_astc."):
                continue
            sets.require(name == "Android_ASTC" or re.fullmatch(r"Android_ASTC\.(?:obb|patch\.obb|overflow[1-9][0-9]*\.obb)", name),
                         "Unknown or case-aliased Android_ASTC cache; review it before building")
            ordinary_chain(project, path)
            sets.plain(path, name == "Android_ASTC")
            sets.require(path.stat().st_dev == output.stat().st_dev, "Cache quarantine needs an external output on the same volume")
            sources.append((path, cache_inventory(path)))
    quarantine = output / "quarantine"
    sets.require(not os.path.lexists(quarantine), "Cache quarantine output already exists")
    quarantine.mkdir()
    plan = []
    for path, inventory in sources:
        destination = quarantine / path.name
        ordinary_chain(output, destination)
        sets.require(not os.path.lexists(destination), "Cache quarantine destination exists")
        plan.append(dict(originalPath=str(path), quarantinePath=str(destination), inventory=inventory,
                         bytes=sum(item["size"] for item in inventory), moved=False, verified=False))
    receipt_path = output / "stage-quarantine.json"
    receipt = dict(format=1, kind="samplegame-android-default-stage-quarantine", stageRoot=str(saved / "Android_ASTC"),
                   status="planned", entries=plan, deletesOldBytes=False)
    sets.write_new(receipt_path, sets.canonical(receipt))
    try:
        for item in plan:
            source, destination = Path(item["originalPath"]), Path(item["quarantinePath"])
            ordinary_chain(project, source)
            ordinary_chain(output, destination)
            sets.require(not os.path.lexists(destination), "Cache quarantine destination appeared")
            source.rename(destination)
            item["moved"] = True
            receipt["status"] = "moving"
            sets.atomic(receipt_path, receipt)
            sets.require(cache_inventory(destination) == item["inventory"], "Cache bytes changed while moving; preserve the quarantine")
            item["verified"] = True
            sets.atomic(receipt_path, receipt)
        sets.require(not saved.exists() or not any(path.name.casefold() == "android_astc" or path.name.casefold().startswith("android_astc.")
                                                  for path in saved.iterdir()), "Default Android_ASTC cache reappeared during quarantine")
        receipt["status"] = "quarantined"
        sets.atomic(receipt_path, receipt)
    except BaseException:
        receipt["status"] = "incomplete-preserved"
        sets.atomic(receipt_path, receipt)
        raise
    return dict(path=str(receipt_path), sha256=sets.digest(receipt_path))


def stream_digest(stream, maximum=sets.MAX_FILE, target=None):
    digest = hashlib.sha256()
    size = 0
    for block in iter(lambda: stream.read(1024 * 1024), b""):
        size += len(block)
        sets.require(size <= maximum, "Archive entry exceeds its allowed size")
        digest.update(block)
        if target is not None:
            target.write(block)
    return size, digest.hexdigest()


def zip_entries(archive):
    """Do not extract ambiguous names, encrypted entries, links, or traversal."""
    found, folded = {}, set()
    total = 0
    for item in archive.infolist():
        name = item.filename
        normalized = name[:-1] if item.is_dir() else name
        parts = PurePosixPath(normalized).parts
        sets.require(name and name == item.orig_filename and "\\" not in name and "\0" not in name and parts
                     and "/".join(parts) == normalized and not normalized.startswith("/")
                     and not any(part in (".", "..") or ":" in part for part in parts), "Unsafe APK/OBB entry")
        sets.require(name not in found and name.lower() not in folded, "Duplicate or case-aliased archive entry")
        sets.require(not item.flag_bits & 1 and item.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED),
                     "Encrypted or unsupported APK/OBB entry")
        mode = item.external_attr >> 16
        sets.require(not stat.S_ISLNK(mode) and stat.S_IFMT(mode) in (0, stat.S_IFREG, stat.S_IFDIR),
                     "Archive links/special files are forbidden")
        sets.require(0 <= item.file_size <= sets.MAX_FILE, "Oversized APK/OBB entry")
        total += item.file_size
        sets.require(total <= sets.MAX_TOTAL, "APK/OBB exceeds total size limit")
        found[name] = item
        folded.add(name.lower())
    return found


@contextmanager
def apk_payload(apk):
    """The OBB remains a seekable stream, avoiding a second ~500 MB RAM copy."""
    sets.plain(apk)
    with zipfile.ZipFile(apk) as outer:
        outer_entries = zip_entries(outer)
        sets.require(NATIVE_ENTRY in outer_entries and OBB_ENTRY in outer_entries, "APK lacks ARM64 native library or embedded OBB")
        sets.require([name for name in outer_entries if re.fullmatch(r"lib/[^/]+/libUnreal\.so", name)] == [NATIVE_ENTRY],
                     "Expected an ARM64-only game APK")
        sets.require(not any(name.endswith(".pak") for name in outer_entries), "PAKs must belong to the one embedded full-Cook OBB")
        with outer.open(OBB_ENTRY) as embedded:
            with zipfile.ZipFile(embedded) as inner:
                entries = zip_entries(inner)
                pak_names = sorted(name for name in entries if name.endswith(".pak"))
                sets.require(pak_names and all(re.fullmatch(r"SampleGame/Content/Paks/[A-Za-z0-9_.-]+\.pak", name)
                                               for name in pak_names), "OBB PAKs must be complete project PAK entries")
                sets.require(not any(name.endswith((".utoc", ".ucas")) for name in entries), "IoStore requires a different frozen loader")
                yield outer, inner, pak_names


def payload_records(apk, release_id=None, destination=None):
    """Bind every delivered native/PAK byte to its exact APK/OBB entry."""
    if release_id is not None:
        sets.number(release_id, 1)
    records, mapping = [], []
    with apk_payload(apk) as (outer, inner, pak_names):
        sources = [("libUnreal.so", outer, NATIVE_ENTRY, "native", "")]
        for entry in pak_names:
            basename = PurePosixPath(entry).name
            name = "Content/Paks/" + ("r" + str(release_id) + "_" if release_id is not None else "") + basename
            sources.append((name, inner, entry, "content", entry))
        for name, archive, entry, role, obb_path in sources:
            sets.relative(name)
            if destination is None:
                with archive.open(entry) as stream:
                    size, digest = stream_digest(stream)
            else:
                target = sets.child(destination, name)
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(entry) as stream, target.open("xb") as output:
                    size, digest = stream_digest(stream, target=output)
            sets.require(size > 0, "Empty native/PAK entry")
            records.append(dict(path=name, role=role, size=size, sha256=digest))
            mapping.append(dict(path=name, apkPath=OBB_ENTRY if obb_path else NATIVE_ENTRY, obbPath=obb_path))
    return sorted(records, key=lambda item: item["path"]), sorted(mapping, key=lambda item: item["path"])


def obsolete_signature(name):
    return bool(re.fullmatch(r"META-INF/(?:MANIFEST\.MF|[^/]+\.(?:SF|RSA|DSA|EC))", name, re.IGNORECASE))


def apk_shell_inventory(apk):
    """Freeze APK dependencies and every OBB entry outside the switched PAK set."""
    result = []
    def record(archive, item, path):
        with archive.open(item) as stream:
            size, digest = stream_digest(stream)
        result.append(dict(path=path, type="directory" if item.is_dir() else "file", size=size, sha256=digest))

    with apk_payload(apk) as (archive, inner, pak_names):
        entries = zip_entries(archive)
        for name, item in sorted(entries.items()):
            if name in (NATIVE_ENTRY, OBB_ENTRY, CONFIG_ENTRY, MANIFEST_ENTRY, LEGACY_NATIVE_ENTRY) or obsolete_signature(name):
                continue
            record(archive, item, name)
        # Only the exact complete PAK set moves with libUnreal.so. Movies,
        # engine tables/configuration and other loose OBB entries are still
        # read from the installed APK and therefore belong to its frozen shell.
        paks = set(pak_names)
        for name, item in sorted(zip_entries(inner).items()):
            if name not in paks:
                record(inner, item, OBB_ENTRY + "!" + name)
    return sorted(result, key=lambda item: item["path"])


def stage_inventory(root):
    """Snapshot the entire fresh stage, not only UAT's incomplete NonUFS list."""
    root = Path(root); sets.plain(root, True)
    result, names = [], set()
    for path in sorted(root.rglob("*")):
        sets.plain(path, path.is_dir())
        name = sets.relative(path.relative_to(root).as_posix())
        sets.require(name.lower() not in names, "Case-aliased staged entry")
        names.add(name.lower())
        sets.require(name.split("/")[0] in ("Engine", "SampleGame") or name in STAGE_METADATA,
                     "Unknown staged root entry; review its installed routing")
        sets.require(not any(part.lower() in ("saved", "savegames") for part in name.split("/")), "Mutable staged outputs are forbidden")
        if path.is_dir():
            sets.require(any(path.iterdir()), "Unexpected empty staged directory")
            result.append(dict(path=name, type="directory", size=0, sha256=hashlib.sha256(b"").hexdigest()))
        else:
            result.append(dict(path=name, type="file", size=path.stat().st_size, sha256=sets.digest(path)))
    return result


def stage_obb_inventory(root, inventory=None):
    """Match AndroidPlatform.Automation.cs: files under Engine/project, except .so.

    The actual baseline OBB comparison below rejects custom filters that change
    this closed rule. UAT creates ZIP entries from files, not directory entries.
    """
    inventory = stage_inventory(root) if inventory is None else inventory
    result = []
    paks = []
    for item in inventory:
        name = item["path"]
        if item["type"] != "file" or not name.startswith(("Engine/", "SampleGame/")):
            continue
        sets.require(not name.endswith((".utoc", ".ucas")), "IoStore requires a new frozen loader")
        if name.endswith(".so"):
            sets.require(name in STAGE_LIBRARIES, "New staged native dependency requires a new APK baseline")
        elif name.endswith(".pak"):
            sets.require(re.fullmatch(r"SampleGame/Content/Paks/[A-Za-z0-9_.-]+\.pak", name), "Staged PAK is outside the complete project set")
            paks.append(item)
        else:
            result.append(dict(item, path=OBB_ENTRY + "!" + name))
    sets.require(paks, "Full staged PAK set is missing")
    return sorted(result, key=lambda item: item["path"])


def verify_stage_shell(root, apk, inventory=None):
    """Reject any new/changed/missing loose resource and any new SO dependency."""
    root = Path(root)
    inventory = stage_inventory(root) if inventory is None else inventory
    installed = apk_shell_inventory(apk)
    expected = [item for item in installed if item["path"].startswith(OBB_ENTRY + "!")]
    loose = stage_obb_inventory(root, inventory)
    sets.require(loose == expected, "Staged loose OBB files differ from the installed APK; a new baseline is required")
    installed_files = {item["path"]: item for item in installed}
    for item in inventory:
        if item["type"] != "file":
            continue
        name = item["path"]
        if name.startswith("Engine/") and name.endswith(".so"):
            sets.require(name in STAGE_LIBRARIES, "Unknown staged native dependency")
            if "/arm64-v8a/" in name:
                target = installed_files.get("lib/arm64-v8a/" + PurePosixPath(name).name)
                sets.require(target and target["type"] == "file" and target["size"] == item["size"]
                             and target["sha256"] == item["sha256"], "Staged ARM64 dependency differs from the installed APK")
        if name == "UECommandLine.txt":
            target = installed_files.get("assets/UECommandLine.txt")
            sets.require(target and target["size"] == item["size"] and target["sha256"] == item["sha256"],
                         "Staged command line differs from the installed APK")
    for name in ("Manifest_UFSFiles_Android.txt", "Manifest_NonUFSFiles_Android.txt"):
        sets.require((root / name).is_file(), "Real stage manifest is missing: " + name)
    if "assets/UECommandLine.txt" in installed_files:
        sets.require((root / "UECommandLine.txt").is_file(), "Staged command line disappeared from the installed shell")
    return loose


def stage_payload_records(root, native, release_id=None, destination=None):
    root, native = Path(root), Path(native)
    inventory = stage_inventory(root)
    stage_obb_inventory(root, inventory)
    sources = [("libUnreal.so", native, "native")]
    for item in inventory:
        if item["type"] == "file" and item["path"].endswith(".pak"):
            basename = PurePosixPath(item["path"]).name
            name = "Content/Paks/" + ("r" + str(sets.number(release_id, 1)) + "_" if release_id is not None else "") + basename
            sources.append((name, sets.child(root, item["path"]), "content"))
    records = []
    for name, source, role in sources:
        sets.plain(source)
        record = dict(path=sets.relative(name), role=role, size=source.stat().st_size, sha256=sets.digest(source))
        sets.require(record["size"] > 0, "Empty staged payload file")
        if destination is not None:
            target = sets.child(destination, name); target.parent.mkdir(parents=True, exist_ok=True)
            with source.open("rb") as input_file, target.open("xb") as output:
                size, digest = stream_digest(input_file, target=output)
            sets.require(size == record["size"] and digest == record["sha256"], "Staged payload changed while copying")
        records.append(record)
    return sorted(records, key=lambda item: item["path"])


def loader_elf(path):
    sys.path.insert(0, str(HERE.parent / "NativeAndroid"))
    import native_android
    return native_android.loader_elf(Path(path))


def native_derivation(project, ndk, apk, work):
    source = Path(project) / "Binaries/Android/SampleGame-arm64.so"
    receipt = Path(project) / "Binaries/Android/SampleGame.target"
    sets.plain(source); sets.plain(receipt)
    target = json.loads(receipt.read_text(encoding="utf-8-sig"))
    sets.require(target.get("TargetName") == "SampleGame" and target.get("Platform") == "Android"
                 and target.get("Configuration") == "Development", "Expected the genuine Android Development target receipt")
    binary_paths = [str(item.get("Path", "")).replace("\\", "/") for item in target.get("BuildProducts", [])]
    sets.require(any(name.endswith("/SampleGame-arm64.so") or name == "$(ProjectDir)/Binaries/Android/SampleGame-arm64.so"
                     for name in binary_paths), "Target receipt does not identify the built ARM64 library")
    source_elf = loader_elf(source)
    strip = Path(ndk) / "toolchains/llvm/prebuilt/windows-x86_64/bin/llvm-strip.exe"
    sets.plain(strip)
    metadata = Path(ndk) / "source.properties"
    sets.plain(metadata)
    derived = Path(work) / "derived-libUnreal.so"
    operation = execute([strip, "--strip-unneeded", "-o", derived, source], Path(work) / "native-strip.log")
    delivery = derived
    if apk is not None:
        delivery = Path(work) / "apk-libUnreal.so"
        with zipfile.ZipFile(apk) as archive, archive.open(NATIVE_ENTRY) as stream, delivery.open("xb") as output:
            stream_digest(stream, target=output)
        sets.require(sets.digest(derived) == sets.digest(delivery) and derived.stat().st_size == delivery.stat().st_size,
                     "APK native bytes differ from the actual target's deterministic UE strip derivation")
    delivery_elf = loader_elf(delivery)
    return dict(sourceBinary=str(source.absolute()), sourceSize=source.stat().st_size, sourceSha256=sets.digest(source),
                sourceElf=source_elf, targetReceipt=str(receipt.absolute()), targetReceiptSha256=sets.digest(receipt),
                deliveryBinary=str(delivery.absolute()), deliverySize=delivery.stat().st_size, deliverySha256=sets.digest(delivery), deliveryElf=delivery_elf,
                stripTool=str(strip.absolute()), stripToolSha256=sets.digest(strip), ndkMetadata=str(metadata.absolute()),
                ndkMetadataSha256=sets.digest(metadata), operation=operation)


def build(args):
    project, engine = args.project.resolve(), process_path(args.engine)
    # A trimmed Windows editor runtime can share the exact Editor BuildId but
    # lacks Android UPL/Java/Gradle sources. Never use it for the full APK Cook.
    for relative in ("Engine/Build/Android/Java/src/com/epicgames/unreal/GameActivity.java.template",
                     "Engine/Build/BatchFiles/Build.bat", "Engine/Build/BatchFiles/RunUAT.bat"):
        sets.require((engine / relative).is_file(), "Android build/Cook needs the complete engine: " + relative)
    plan = content_plan.snapshot()
    cook_maps = tuple(plan["plan"]["requiredMaps"])
    check_cook_maps(project, cook_maps)
    lua_identity = release_identity.snapshot(project)
    before, frozen = identity(project, engine)
    editor_engine = process_path(args.editor_engine or engine)
    editor_id = json.loads((editor_engine / "Engine/Binaries/Win64/UnrealEditor.modules").read_text(encoding="utf-8-sig"))["BuildId"]
    sets.require(editor_id == before["engineBuildId"], "Editor engine identity differs from the Android engine")
    output = fresh_output(args.output, project, engine)
    sets.write_new(output / "source-inputs.json", sets.canonical(before))
    sets.write_new(output / "shell-freeze.json", sets.canonical(frozen))
    sets.write_new(output / "content-plan.json", sets.canonical(plan))
    candidate_base = getattr(args, "candidate_base", None)
    base_identity = None
    if candidate_base is not None:
        candidate_base = candidate_base.resolve()
        config, base, _ = read_player(candidate_base)
        trust = config["trust"]
        sets.require(args.base_release_id == trust["baseReleaseId"] and before["engineBuildId"] == trust["engineBuildId"]
                     and before["shellCompatibilityId"] == trust["shellCompatibilityId"], "Candidate build changed the installed APK shell identity")
        sets.require(getattr(args, "candidate_shell_freeze", None), "Candidate build requires the original installed shell freeze")
        base_freeze = read_proof(args.candidate_shell_freeze)
        compared = compatibility.compare(base_freeze, project, before["engineBuildId"], base["save"], POLICY)
        sets.require(not compared["requiresNewBase"] and base_freeze["shellCompatibilityId"] == trust["shellCompatibilityId"],
                     "Candidate build needs a new APK baseline")
        verification = verify_signed_apk(candidate_base, args, output, "candidate-base")
        base_identity = dict(path=str(candidate_base), size=candidate_base.stat().st_size, sha256=sets.digest(candidate_base),
                             trust=trust, buildId=base["buildId"], verification=verification)
    # MakeApk hardcodes the default Saved/StagedBuilds/Android_ASTC.obb path.
    # Baselines must stage there from an empty platform cache; candidates never
    # invoke MakeApk and retain their fresh external StageOnly output.
    quarantine = None if candidate_base is not None else quarantine_default_stage(project, output)
    repo = project.parents[1]
    editor = execute(["pwsh", "-NoProfile", "-File", repo / "Tools/Build-Project.ps1", "-Target", "Editor",
                      "-EngineRoot", editor_engine, "-Compiler", "Clang", "-LLVMRoot", args.llvm_root,
                      "-MaxParallelActions", "1", "-NoDebugSymbols"], output / "editor-build.log")
    env = dict(os.environ, ANDROID_HOME=str(args.sdk_root), ANDROID_SDK_ROOT=str(args.sdk_root),
               NDKROOT=str(args.ndk_root), ANDROID_NDK_ROOT=str(args.ndk_root), JAVA_HOME=str(args.java_home))
    native = execute([engine / "Engine/Build/BatchFiles/Build.bat", "SampleGame", "Android", "Development",
                      "-Project=" + str(project / "SampleGame.uproject"), "-rootdirectory=" + str(engine),
                      "-remoteini=" + str(project), "-architecture=arm64", "-NoUBA", "-MaxParallelActions=1",
                      "-NoDebugInfo", "-NoLinkerDebugInfo", "-skipdeploy"], output / "android-native-build.log", env)
    archive = output / "Archive"
    cook_arguments = ["pwsh", "-NoProfile", "-File", repo / "Tools/Package-Project.ps1", "-EngineRoot", engine,
                    "-Compiler", "Clang", "-LLVMRoot", args.llvm_root, "-Platform", "Android", "-AndroidTextureFormat", "ASTC",
                    "-AndroidSdkRoot", args.sdk_root, "-AndroidNdkRoot", args.ndk_root, "-JavaHome", args.java_home,
                    "-ArchiveDirectory", archive, "-Configuration", "Development",
                    "-MapList", "+".join(cook_maps),
                    "-CreateReleaseVersion", str(args.base_release_id), "-ReleaseVersionRoot", output / "CookReleases",
                    "-SkipEditorBuild", "-SkipGameBuild", "-NoDebugSymbols"]
    if candidate_base is not None:
        cook_arguments.extend(["-StagingDirectory", output / "Stage", "-StageOnly"])
    cook = execute(cook_arguments, output / "full-cook.log", env)
    after, after_frozen = identity(project, engine)
    sets.write_new(output / "source-inputs-after.json", sets.canonical(after))
    sets.write_new(output / "shell-freeze-after.json", sets.canonical(after_frozen))
    sets.require(before == after, "Source or engine changed during the real Android native/full-Cook build")
    sets.require(plan == content_plan.snapshot(), "Release content plan changed during Android native/full-Cook build")
    sets.require(lua_identity == release_identity.snapshot(project), "Lua release identity changed during Android native/full-Cook build")
    stage = output / "Stage/Android_ASTC" if candidate_base is not None else project / "Saved/StagedBuilds/Android_ASTC"
    staged = stage_inventory(stage)
    maps = map_inventory(engine, [sets.child(stage, item["path"]) for item in staged if item["type"] == "file" and item["path"].endswith(".pak")], output, execute, maps=cook_maps)
    if candidate_base is not None:
        sets.require(not archive.exists() and not any(output.rglob("*.apk")) and not any(output.rglob("*.obb")),
                     "Stage-only candidate unexpectedly packaged an APK/OBB")
        cook_text = Path(cook["path"]).read_text(encoding="utf-8", errors="replace")
        sets.require("STAGE COMMAND COMPLETED" in cook_text and "COOK COMMAND COMPLETED" in cook_text
                     and "PACKAGE COMMAND STARTED" not in cook_text and "ARCHIVE COMMAND STARTED" not in cook_text,
                     "Candidate requires a real complete Cook/Stage/Pak with no packaging or archive")
        native_proof = native_derivation(project, args.ndk_root.resolve(), None, output)
        files = stage_payload_records(stage, native_proof["deliveryBinary"])
        loose = verify_stage_shell(stage, candidate_base, staged)
        proof = dict(format=1, kind="samplegame-staged-android-candidate-build", **before, configuration="Development", fullCook=True,
                     textureFormat="ASTC", architecture="arm64", packageBuilt=False, editorBuild=editor, nativeBuild=native, cook=cook,
                     stageRoot=str(stage.absolute()), stageFiles=staged, looseObbFiles=loose, nativeDerivation=native_proof,
                     files=files, candidateBase=base_identity, luaIdentity=lua_identity, contentPlan=plan, mapInventory=maps, runtimeValidated=False)
        sets.write_new(output / "build-proof.json", sets.canonical(proof))
        return proof
    apks = sorted(archive.rglob("*.apk"))
    sets.require(len(apks) == 1, "Actual full-Cook archive must contain exactly one ARM64 APK")
    raw_apk = apks[0]
    native_proof = native_derivation(project, args.ndk_root.resolve(), raw_apk, output)
    files, entries = payload_records(raw_apk)
    sets.require(files == stage_payload_records(stage, native_proof["deliveryBinary"]), "APK payload differs from the genuine complete stage")
    loose = verify_stage_shell(stage, raw_apk, staged)
    proof = dict(format=1, kind="samplegame-complete-android-build", **before, configuration="Development", fullCook=True,
                 textureFormat="ASTC", architecture="arm64", editorBuild=editor, nativeBuild=native, cook=cook,
                 rawApk=str(raw_apk.absolute()), rawApkSize=raw_apk.stat().st_size, rawApkSha256=sets.digest(raw_apk),
                 nativeDerivation=native_proof, files=files, archiveEntries=entries,
                 stageRoot=str(stage.absolute()), stageFiles=staged, looseObbFiles=loose,
                 stageQuarantine=quarantine, apkShellFiles=apk_shell_inventory(raw_apk), luaIdentity=lua_identity, contentPlan=plan, mapInventory=maps, runtimeValidated=False)
    sets.write_new(output / "build-proof.json", sets.canonical(proof))
    return proof


def validate_build_inputs(proof, project, engine, kind):
    release_identity.proof_identity(proof, project)
    current, frozen = identity(project, engine)
    sets.require(proof.get("format") == 1 and proof.get("kind") == kind
                 and proof.get("fullCook") is True and proof.get("configuration") == "Development"
                 and proof.get("architecture") == "arm64" and proof.get("textureFormat") == "ASTC",
                 "A real complete Development ARM64/ASTC build proof is required")
    if proof.get("sourceCommit") != current["sourceCommit"]:
        ancestor = subprocess.run(["git", "-C", str(project), "merge-base", "--is-ancestor", str(proof.get("sourceCommit")), current["sourceCommit"]], capture_output=True)
        unchanged = subprocess.run(["git", "-C", str(project), "diff", "--quiet", str(proof.get("sourceCommit")), current["sourceCommit"], "--", "."], capture_output=True)
        sets.require(ancestor.returncode == 0 and unchanged.returncode == 0, "Game project changed since the genuine build commit")
    for key, value in current.items():
        if key != "sourceCommit":
            sets.require(proof.get(key) == value, "Actual build input changed: " + key)
    for key, marker in (("editorBuild", "Result: Succeeded"), ("nativeBuild", "Result: Succeeded"), ("cook", "BUILD SUCCESSFUL")):
        log = proof[key]
        sets.require(log["exitCode"] == 0 and sets.digest(log["path"]) == log["sha256"], "Actual build evidence was changed")
        sets.require(marker in Path(log["path"]).read_text(encoding="utf-8", errors="replace"), "Successful actual build marker is absent")
    return dict(current, sourceCommit=proof["sourceCommit"]), frozen


def validate_build(proof, project, engine):
    current, frozen = validate_build_inputs(proof, project, engine, "samplegame-complete-android-build")
    apk = Path(proof["rawApk"])
    sets.plain(apk)
    sets.require(apk.stat().st_size == proof["rawApkSize"] and sets.digest(apk) == proof["rawApkSha256"], "Actual cooked APK was replaced")
    derived = proof["nativeDerivation"]
    for path_key, hash_key in (("sourceBinary", "sourceSha256"), ("targetReceipt", "targetReceiptSha256"),
                               ("stripTool", "stripToolSha256"), ("ndkMetadata", "ndkMetadataSha256")):
        sets.require(sets.digest(derived[path_key]) == derived[hash_key], "Native derivation evidence was replaced: " + path_key)
    sets.require(Path(derived["sourceBinary"]).resolve() == (project / "Binaries/Android/SampleGame-arm64.so").resolve()
                 and Path(derived["targetReceipt"]).resolve() == (project / "Binaries/Android/SampleGame.target").resolve(),
                 "Native evidence belongs to another project")
    operation = derived["operation"]
    sets.require(operation["exitCode"] == 0 and sets.digest(operation["path"]) == operation["sha256"], "Actual native strip evidence changed")
    records, mapping = payload_records(apk)
    sets.require(records == proof["files"] and mapping == proof["archiveEntries"], "Full native/PAK inventory differs from actual build")
    sets.require(apk_shell_inventory(apk) == proof["apkShellFiles"], "APK shell differs from the actual full-Cook output")
    native = next(item for item in records if item["role"] == "native")
    sets.require(native["size"] == derived["deliverySize"] and native["sha256"] == derived["deliverySha256"],
                 "Embedded native bytes differ from the genuine strip derivation")
    sets.require(loader_elf(Path(derived["sourceBinary"])) == derived["sourceElf"], "Built native ELF no longer matches")
    if "stageRoot" in proof:
        stage = Path(proof["stageRoot"])
        sets.require(stage_inventory(stage) == proof["stageFiles"], "The genuine complete stage was replaced")
        sets.require(stage_payload_records(stage, derived["deliveryBinary"]) == records, "APK payload differs from the complete stage")
        sets.require(verify_stage_shell(stage, apk, proof["stageFiles"]) == proof["looseObbFiles"], "Original staged loose inventory changed")
    sets.require("stageRoot" in proof, "Complete Android stage is required for actual PAK map inventory")
    validate_map_inventory(proof.get("mapInventory"), engine, [sets.child(stage, item["path"]) for item in proof["stageFiles"] if item["type"] == "file" and item["path"].endswith(".pak")], content_plan.proof_maps(proof))
    if proof.get("stageQuarantine"):
        evidence = proof["stageQuarantine"]
        sets.require(sets.digest(evidence["path"]) == evidence["sha256"], "Default-stage quarantine evidence changed")
    return apk, current, frozen


def validate_staged_build(proof, project, engine, baseline_apk):
    current, frozen = validate_build_inputs(proof, project, engine, "samplegame-staged-android-candidate-build")
    sets.require(proof.get("packageBuilt") is False and "rawApk" not in proof, "A staged candidate cannot claim a packaged APK")
    text = Path(proof["cook"]["path"]).read_text(encoding="utf-8", errors="replace")
    sets.require("COOK COMMAND COMPLETED" in text and "STAGE COMMAND COMPLETED" in text
                 and "PACKAGE COMMAND STARTED" not in text and "ARCHIVE COMMAND STARTED" not in text,
                 "A complete stage-only candidate requires no APK package or archive step")
    base = proof["candidateBase"]
    sets.require(baseline_apk.stat().st_size == base["size"] and sets.digest(baseline_apk) == base["sha256"], "Installed baseline APK differs from the verified candidate input")
    config, manifest, _ = read_player(baseline_apk)
    sets.require(config["trust"] == base["trust"] and manifest["buildId"] == base["buildId"], "Candidate baseline trust changed")
    for entry in (base["verification"]["signature"], base["verification"]["alignment"]):
        sets.require(entry["exitCode"] == 0 and sets.digest(entry["path"]) == entry["sha256"], "Original baseline APK verification evidence changed")
    derived = proof["nativeDerivation"]
    for path_key, hash_key in (("sourceBinary", "sourceSha256"), ("targetReceipt", "targetReceiptSha256"),
                               ("stripTool", "stripToolSha256"), ("ndkMetadata", "ndkMetadataSha256"),
                               ("deliveryBinary", "deliverySha256")):
        sets.require(sets.digest(derived[path_key]) == derived[hash_key], "Actual staged native derivation changed: " + path_key)
    sets.require(Path(derived["sourceBinary"]).resolve() == (project / "Binaries/Android/SampleGame-arm64.so").resolve()
                 and Path(derived["targetReceipt"]).resolve() == (project / "Binaries/Android/SampleGame.target").resolve(), "Staged native receipt belongs to another project")
    operation = derived["operation"]
    sets.require(operation["exitCode"] == 0 and sets.digest(operation["path"]) == operation["sha256"], "Actual strip operation evidence changed")
    sets.require(operation["arguments"] == [derived["stripTool"], "--strip-unneeded", "-o", derived["deliveryBinary"], derived["sourceBinary"]], "Native derivation command differs from the exact NDK strip rule")
    sets.require(loader_elf(Path(derived["sourceBinary"])) == derived["sourceElf"]
                 and loader_elf(Path(derived["deliveryBinary"])) == derived["deliveryElf"], "Actual staged native ELF changed")
    stage = Path(proof["stageRoot"])
    inventory = stage_inventory(stage)
    sets.require(inventory == proof["stageFiles"], "Full candidate stage changed after actual Cook")
    sets.require(stage_payload_records(stage, derived["deliveryBinary"]) == proof["files"], "Complete candidate native/PAK bytes changed")
    validate_map_inventory(proof.get("mapInventory"), engine, [sets.child(stage, item["path"]) for item in inventory if item["type"] == "file" and item["path"].endswith(".pak")], content_plan.proof_maps(proof))
    sets.require(verify_stage_shell(stage, baseline_apk, inventory) == proof["looseObbFiles"], "Candidate loose stage differs from the installed baseline")
    return stage, current, frozen


def certificate(path=CERTIFICATE):
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import rsa
    raw = sets.read_bounded(path, 16384)
    sets.require(hashlib.sha256(raw).hexdigest() == CERTIFICATE_SHA256, "Pinned public signing certificate differs")
    parsed = x509.load_der_x509_certificate(raw)
    sets.require(isinstance(parsed.public_key(), rsa.RSAPublicKey) and parsed.public_key().key_size >= 2048,
                 "Release-set trust requires the fixed RSA certificate")
    return raw


def https(value):
    from urllib.parse import urlsplit
    uri = urlsplit(value)
    sets.require(uri.scheme == "https" and uri.hostname and uri.port in (None, 443) and not uri.username and not uri.password
                 and not uri.query and not uri.fragment and uri.path.endswith("/manifest.json")
                 and re.fullmatch(r"/[A-Za-z0-9_./-]+", uri.path) and "//" not in uri.path
                 and not any(part in (".", "..") for part in uri.path.split("/")) and "%" not in uri.path and "\\" not in uri.path,
                 "Expected a fixed HTTPS manifest URL on port 443")
    return value


def make_manifest(current, files, trust, release_id):
    value = {key: trust[key] for key in sets.BINDINGS}
    value.update(format=1, kind="samplegame-release-set", releaseId=release_id, minLoaderVersion=1,
                 sourceCommit=current["sourceCommit"], nativeSourceHash=current["nativeSourceHash"], files=files, save=POLICY)
    value["buildId"] = sets.build_id(value)
    raw = sets.canonical(value)
    sets.manifest(raw, trust)
    return value, raw


def read_player(apk):
    """Validate embedded public configuration and all baseline payload bytes."""
    with zipfile.ZipFile(apk) as archive:
        entries = zip_entries(archive)
        sets.require(CONFIG_ENTRY in entries and MANIFEST_ENTRY in entries and LEGACY_NATIVE_ENTRY not in entries,
                     "Prepared APK trust is absent or still carries the independent native loader config")
        for name in (CONFIG_ENTRY, MANIFEST_ENTRY):
            sets.require(entries[name].file_size <= sets.MAX_MANIFEST, "Embedded trust metadata is oversized")
        config = sets.parse(archive.read(CONFIG_ENTRY))
        raw = archive.read(MANIFEST_ENTRY)
    fields = {"format", "trust", "packageName", "manifestUrl", "allowOffline", "signatureAlgorithm", "certificateBase64", "certificateSha256", "baseArchiveEntries"}
    sets.require(type(config) is dict and set(config) == fields and type(config["format"]) is int and config["format"] == 1
                 and config["packageName"] == PACKAGE and type(config["allowOffline"]) is bool
                 and config["signatureAlgorithm"] == "SHA256withRSA", "Unsupported APK player configuration")
    https(config["manifestUrl"])
    trust = config["trust"]
    sets.require(type(trust) is dict and set(trust) == {*sets.BINDINGS, "loaderVersion", "baseManifestSha256"}
                 and trust["platform"] == "Android_ARM64" and type(trust["loaderVersion"]) is int and trust["loaderVersion"] == 1,
                 "Invalid Android pinned trust")
    sets.require(config["certificateSha256"] == CERTIFICATE_SHA256
                 and base64.b64decode(config["certificateBase64"], validate=True) == certificate(), "APK certificate differs from fixed update trust")
    sets.require(hashlib.sha256(raw).hexdigest() == trust["baseManifestSha256"], "APK baseline manifest changed")
    value = sets.manifest(raw, trust)
    sets.require(value["releaseId"] == trust["baseReleaseId"], "APK must contain its exact baseline release")
    records, mapping = payload_records(apk, value["releaseId"])
    sets.require(records == value["files"] and mapping == config["baseArchiveEntries"], "APK extraction entries differ from the pinned complete baseline")
    return config, value, raw


def rewrite_apk(source, target, config, raw):
    """Preserve uncompressed bytes/methods; drop obsolete signatures and native config."""
    removed = []
    with zipfile.ZipFile(source) as archive, zipfile.ZipFile(target, "x", allowZip64=True) as output:
        entries = zip_entries(archive)
        sets.require(CONFIG_ENTRY not in entries and MANIFEST_ENTRY not in entries, "Never prepare an already wrapped APK")
        for item in archive.infolist():
            name = item.filename
            obsolete = name == LEGACY_NATIVE_ENTRY or obsolete_signature(name)
            if obsolete:
                with archive.open(item) as stream:
                    size, digest = stream_digest(stream)
                removed.append(dict(path=name, size=size, sha256=digest))
                continue
            info = copy.copy(item)
            with archive.open(item) as stream, output.open(info, "w", force_zip64=item.file_size >= 2**31) as destination:
                size, _ = stream_digest(stream, target=destination)
            sets.require(size == item.file_size, "APK source entry changed during preparation")
        output.writestr(CONFIG_ENTRY, sets.canonical(config), compress_type=zipfile.ZIP_STORED)
        output.writestr(MANIFEST_ENTRY, raw, compress_type=zipfile.ZIP_STORED)
    return removed


def signing_tools(sdk, java_home):
    java = Path(java_home) / "bin" / ("java.exe" if os.name == "nt" else "java")
    candidates = sorted((Path(sdk) / "build-tools").glob("*/lib/apksigner.jar"),
                        key=lambda item: tuple(int(value) for value in re.findall(r"\d+", item.parent.parent.name)))
    sets.require(candidates, "Android SDK apksigner is absent")
    signer = candidates[-1]
    align = signer.parent.parent / ("zipalign.exe" if os.name == "nt" else "zipalign")
    for path in (java, signer, align):
        sets.plain(path)
    return java, signer, align


def signing_environment(args, output):
    for name in (args.store_password_env, args.key_password_env):
        sets.require(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name or "") and os.environ.get(name), "Required signing password environment variable is absent")
    key = args.keystore.resolve(strict=True)
    sets.plain(key)
    repo = args.project.resolve().parents[1]
    sets.require(not key.is_relative_to(repo) and not key.is_relative_to(output.resolve()), "Keystore must stay outside source and distribution")
    sets.require(re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", args.key_alias), "Invalid signing alias")
    return key


def verify_signed_apk(apk, args, output, prefix="apk"):
    java, signer, align = signing_tools(args.sdk_root, args.java_home)
    signature = execute([java, "-jar", signer, "verify", "--verbose", "--print-certs", apk], output / (prefix + "-signature-verification.log"))
    text = Path(signature["path"]).read_text(encoding="utf-8", errors="replace")
    fingerprints = re.findall(r"^Signer #\d+ certificate SHA-256 digest:\s*([0-9a-fA-F]+)\s*$", text, re.MULTILINE)
    sets.require([value.lower() for value in fingerprints] == [CERTIFICATE_SHA256], "Actual APK signer is not the fixed formal release certificate")
    sets.require(re.search(r"Verified using v[23](?:\.1)? scheme.*:\s*true", text), "APK requires an authenticated v2/v3 signature")
    alignment = execute([align, "-c", "-P", "16", "4", apk], output / (prefix + "-alignment-verification.log"))
    return dict(signature=signature, alignment=alignment, signingCertificateSha256=CERTIFICATE_SHA256,
                apksignerSha256=sets.digest(signer), zipalignSha256=sets.digest(align))


def prepare(args):
    proof = read_proof(args.build_proof)
    sets.require("luaIdentity" in proof, "A new installer requires the frozen Lua identity from an actual full build")
    source, current, frozen = validate_build(proof, args.project.resolve(), args.engine.resolve())
    sets.number(args.base_release_id, 1)
    output = fresh_output(args.output, args.project, args.engine)
    key = signing_environment(args, output)
    files, mapping = payload_records(source, args.base_release_id)
    trust = dict(projectId="SampleGame", platform="Android_ARM64", channel=args.channel, baseReleaseId=args.base_release_id,
                 engineBuildId=current["engineBuildId"], shellCompatibilityId=current["shellCompatibilityId"], loaderVersion=1)
    value, raw = make_manifest(current, files, trust, args.base_release_id)
    trust["baseManifestSha256"] = hashlib.sha256(raw).hexdigest()
    config = dict(format=1, trust=trust, packageName=PACKAGE, manifestUrl=https(args.manifest_url), allowOffline=True,
                  signatureAlgorithm="SHA256withRSA", certificateBase64=base64.b64encode(certificate()).decode("ascii"),
                  certificateSha256=CERTIFICATE_SHA256, baseArchiveEntries=mapping)
    unsigned = output / "prepared-unsigned.apk"
    removed = rewrite_apk(source, unsigned, config, raw)
    read_player(unsigned)
    java, signer, align = signing_tools(args.sdk_root, args.java_home)
    aligned = output / "prepared-aligned.apk"
    align_record = execute([align, "-P", "16", "4", unsigned, aligned], output / "apk-zipalign.log")
    root = output / "Android"; root.mkdir()
    apk = root / ("SampleGame-Android-arm64-V" + proof["luaIdentity"]["version"] + "-Base" + str(args.base_release_id) + ".apk")
    sign_record = execute([java, "-jar", signer, "sign", "--ks", key, "--ks-key-alias", args.key_alias,
                           "--ks-pass", "env:" + args.store_password_env, "--key-pass", "env:" + args.key_password_env,
                           "--v1-signing-enabled", "true", "--v2-signing-enabled", "true", "--out", apk, aligned], output / "apk-sign.log")
    signed_config, signed_manifest, _ = read_player(apk)
    sets.require(signed_config == config and signed_manifest == value, "Signing changed the pinned APK identity")
    sets.require(apk_shell_inventory(apk) == proof["apkShellFiles"], "APK wrapping changed an installed shell file")
    verification = verify_signed_apk(apk, args, output)
    # Keep proof paths private; public APK contains only canonical public trust.
    sets.write_new(output / "shell-freeze.json", sets.canonical(frozen))
    receipt = dict(status="prepared-not-runtime-validated", kind="samplegame-android-release-set-player", **current,
                   baseReleaseId=args.base_release_id, manifestSha256=trust["baseManifestSha256"], buildId=value["buildId"],
                   playerPath=str(apk.absolute()), playerSize=apk.stat().st_size, playerSha256=sets.digest(apk),
                   rawApkSha256=proof["rawApkSha256"], signingCertificateSha256=CERTIFICATE_SHA256,
                   removedArchiveEntries=removed, alignment=align_record, signing=sign_record, apkVerification=verification,
                   buildProofPath=str(args.build_proof.resolve()), buildProofSha256=sets.digest(args.build_proof), luaIdentity=proof["luaIdentity"],
                   runtimeValidated=False, published=False)
    sets.write_new(output / "producer-receipt.json", sets.canonical(receipt))
    # Only intermediates created in this fresh output are removed; the real Cook/APK remains immutable.
    unsigned.unlink(); aligned.unlink()
    return receipt


def archive(args):
    source = args.player_apk.resolve()
    config, value, _ = read_player(source)
    version = release_identity.archive_version(source.parent.parent / "producer-receipt.json", value)
    output = args.output.absolute()
    sets.require(output.suffix.lower() == ".apk" and not output.exists(), "Use a fresh APK archive path")
    output.parent.mkdir(parents=True, exist_ok=True)
    evidence = output.parent / (output.stem + "-verification")
    sets.require(not evidence.exists(), "Archive evidence exists; use a fresh output")
    evidence.mkdir()
    verification = verify_signed_apk(source, args, evidence)
    shutil.copy2(source, output)
    sets.require(sets.digest(source) == sets.digest(output) and source.stat().st_size == output.stat().st_size, "Archived APK differs from verified source")
    receipt = dict(kind="samplegame-release-set-android-archive", path=str(output), size=output.stat().st_size, sha256=sets.digest(output),
                   version=version, platform="Android_ARM64", baseReleaseId=config["trust"]["baseReleaseId"],
                   signingCertificateSha256=CERTIFICATE_SHA256, manifestSha256=config["trust"]["baseManifestSha256"],
                   buildId=value["buildId"], sourceCommit=value["sourceCommit"], nativeSourceHash=value["nativeSourceHash"],
                   engineBuildId=config["trust"]["engineBuildId"], shellCompatibilityId=config["trust"]["shellCompatibilityId"],
                   apkVerification=verification, runtimeValidated=False, published=False)
    sets.write_new(output.with_suffix(".json"), sets.canonical(receipt))
    return receipt


def sign_manifest(args, raw, output):
    """Use the established JKS signer; never export a private key into Python."""
    sets.require(0 < len(raw) <= 32768, "The certificate signer supports up to 32 KiB manifest payloads")
    key = signing_environment(args, output)
    javac = args.java_home / "bin" / ("javac.exe" if os.name == "nt" else "javac")
    java = args.java_home / "bin" / ("java.exe" if os.name == "nt" else "java")
    with tempfile.TemporaryDirectory(prefix="samplegame-release-set-sign-") as temporary:
        work = Path(temporary)
        compiled = subprocess.run([str(javac), "-J-Xmx192m", "-encoding", "UTF-8", "-d", str(work),
                                   str(HERE.parent / "NativeAndroid/NativeManifestSigner.java")], capture_output=True)
        sets.require(compiled.returncode == 0, "Public JKS signer compilation failed")
        (work / "manifest.json").write_bytes(raw)
        result = subprocess.run([str(java), "-Xmx192m", "-cp", str(work), "NativeManifestSigner", str(key), args.key_alias,
                                 str(work / "manifest.json"), str(work / "signature.bin"), str(work / "certificate.der"),
                                 str(work / "certificate.sha256"), args.store_password_env, args.key_password_env,
                                 CERTIFICATE_SHA256], capture_output=True)
        sets.require(result.returncode == 0, "JKS release-set signing failed; no private key was exported")
        sets.require((work / "certificate.der").read_bytes() == certificate(), "Actual signing certificate differs from installed update trust")
        signature = (work / "signature.bin").read_bytes()
    verify_manifest(raw, signature)
    return signature


def verify_manifest(raw, signature):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    x509.load_der_x509_certificate(certificate()).public_key().verify(signature, raw, padding.PKCS1v15(), hashes.SHA256())


def candidate(args):
    config, base, _ = read_player(args.player_apk.resolve())
    trust = config["trust"]
    proof = read_proof(args.build_proof)
    staged = proof.get("kind") == "samplegame-staged-android-candidate-build"
    if staged:
        source, current, _ = validate_staged_build(proof, args.project.resolve(), args.engine.resolve(), args.player_apk.resolve())
    else:
        source, current, _ = validate_build(proof, args.project.resolve(), args.engine.resolve())
    frozen = read_proof(args.shell_freeze)
    compared = compatibility.compare(frozen, args.project.resolve(), current["engineBuildId"], base["save"], POLICY)
    sets.require(not compared["requiresNewBase"] and frozen["shellCompatibilityId"] == trust["shellCompatibilityId"]
                 and current["shellCompatibilityId"] == trust["shellCompatibilityId"], "Frozen APK shell changed; build a new baseline")
    if not staged:
        sets.require(apk_shell_inventory(args.player_apk) == proof["apkShellFiles"],
                     "Candidate needs changed APK Java/resources/dependencies; build a new baseline")
    sets.number(args.release_id, trust["baseReleaseId"] + 1)
    output = args.output.absolute()
    registry = args.registry_root.absolute()
    sets.require(not registry.resolve().is_relative_to(output.resolve()) and not output.resolve().is_relative_to(registry.resolve()),
                 "Stable private producer registry must be outside distribution output")
    family = registry / (trust["channel"] + "-" + str(trust["baseReleaseId"]))
    with producer_lease(family):
        state_path = family / "state.json"
        state = sets.parse(sets.read_bounded(state_path, 65536), 65536) if state_path.exists() else dict(trust=trust, highestReleaseId=trust["baseReleaseId"])
        sets.require(state["trust"] == trust and args.release_id > state["highestReleaseId"], "Release ID is already reserved or belongs to another baseline")
        sets.atomic(state_path, dict(trust=trust, highestReleaseId=args.release_id))
        evidence = family / (str(args.release_id) + "-base-apk-verification")
        evidence.mkdir()
        baseline_verification = verify_signed_apk(args.player_apk.resolve(), args, evidence, "baseline")
        output = fresh_output(output, args.project, args.engine)
        payload = output / "versions" / str(args.release_id) / "payload"; payload.mkdir(parents=True)
        if staged:
            files = stage_payload_records(source, proof["nativeDerivation"]["deliveryBinary"], args.release_id, payload)
        else:
            files, _ = payload_records(source, args.release_id, payload)
        value, raw = make_manifest(current, files, trust, args.release_id)
        signature = sign_manifest(args, raw, output)
        sets.verify_tree(payload, value["files"])
        sets.write_new(output / "manifest.json", raw)
        sets.write_new(output / "manifest.json.sig", signature)
        receipt = dict(status="signed-candidate-not-runtime-validated", kind="samplegame-android-release-set-candidate", **current,
                       releaseId=args.release_id, manifestSha256=hashlib.sha256(raw).hexdigest(), buildId=value["buildId"],
                       signingCertificateSha256=CERTIFICATE_SHA256, buildProofSha256=sets.digest(args.build_proof),
                       baselineApkVerification=baseline_verification, buildProofKind=proof.get("kind"),
                       runtimeValidated=False, published=False)
        sets.write_new(family / (str(args.release_id) + ".json"), sets.canonical(receipt))
    return receipt


def signing_arguments(parser):
    parser.add_argument("--java-home", type=Path, required=True)
    parser.add_argument("--keystore", type=Path, required=True)
    parser.add_argument("--key-alias", default="samplegame")
    parser.add_argument("--store-password-env", default="SAMPLEGAME_ANDROID_STORE_PASSWORD")
    parser.add_argument("--key-password-env", default="SAMPLEGAME_ANDROID_KEY_PASSWORD")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    build_cmd = sub.add_parser("build")
    prepare_cmd = sub.add_parser("prepare")
    candidate_cmd = sub.add_parser("candidate")
    for command in (build_cmd, prepare_cmd, candidate_cmd):
        for flag in ("project", "engine", "output"):
            command.add_argument("--" + flag, type=Path, required=True)
    for command in (build_cmd, prepare_cmd):
        command.add_argument("--base-release-id", type=int, required=True)
        command.add_argument("--sdk-root", type=Path, required=True)
    build_cmd.add_argument("--editor-engine", type=Path)
    build_cmd.add_argument("--llvm-root", type=Path, required=True)
    build_cmd.add_argument("--ndk-root", type=Path, required=True)
    build_cmd.add_argument("--java-home", type=Path, required=True)
    build_cmd.add_argument("--candidate-base", type=Path, help="Signed installed baseline APK; build native/full Cook/Stage/Pak without packaging a new APK")
    build_cmd.add_argument("--candidate-shell-freeze", type=Path, help="Original baseline shell-freeze.json; required with --candidate-base")
    for command in (prepare_cmd, candidate_cmd):
        command.add_argument("--build-proof", type=Path, required=True)
        signing_arguments(command)
    prepare_cmd.add_argument("--channel", required=True)
    prepare_cmd.add_argument("--manifest-url", required=True)
    candidate_cmd.add_argument("--player-apk", type=Path, required=True)
    candidate_cmd.add_argument("--sdk-root", type=Path, required=True)
    candidate_cmd.add_argument("--shell-freeze", type=Path, required=True)
    candidate_cmd.add_argument("--registry-root", type=Path, required=True)
    candidate_cmd.add_argument("--release-id", type=int, required=True)
    archive_cmd = sub.add_parser("archive")
    for flag in ("player-apk", "output", "sdk-root", "java-home"):
        archive_cmd.add_argument("--" + flag, type=Path, required=True)
    args = parser.parse_args()
    result = dict(build=build, prepare=prepare, archive=archive, candidate=candidate)[args.command](args)
    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()
