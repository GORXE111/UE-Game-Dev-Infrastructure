"""Freeze and recheck the Windows base ABI/content inventory before native signing."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess

import native_launcher as native

REPO = Path(__file__).resolve().parents[3]
POLICY = "windows-headers-build-plugin-java-upl-config-content-v1"
SKIP = {"Binaries", "Intermediate", "Saved", "DerivedDataCache", ".git", "__pycache__"}
GENERATED = {"Content/Release/native-bootstrap.json", "Content/Release/update-bootstrap.json"}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def files_under(root):
    if not root.exists():
        return
    for directory, children, files in os.walk(root, followlinks=False):
        kept = []
        for name in sorted(children):
            path = Path(directory) / name
            if name in SKIP:
                continue
            info = path.lstat()
            native.require(not path.is_symlink() and not getattr(info, "st_file_attributes", 0) & 0x400, "Compatibility inputs cannot use directory links/reparse points")
            kept.append(name)
        children[:] = kept
        for name in sorted(files):
            path = Path(directory) / name
            info = path.lstat()
            native.require(stat.S_ISREG(info.st_mode) and not getattr(info, "st_file_attributes", 0) & 0x400, "Compatibility inputs must be ordinary files")
            yield path


def inventory(project):
    project = Path(project).resolve(strict=True)
    paths = {project / "SampleGame.uproject"}
    native.require((project / "SampleGame.uproject").is_file(), "Expected the actual SampleGame project directory")
    for folder in ("Source", "Plugins"):
        for path in files_under(project / folder):
            name = path.name.lower()
            relative_parts = path.relative_to(project).parts
            contract = path.suffix.lower() in (".h", ".hpp", ".inl", ".java", ".uplugin") or name.endswith((".build.cs", ".target.cs")) or "upl" in name and path.suffix.lower() == ".xml"
            plugin_data = folder == "Plugins" and any(part in ("Content", "Config", "Shaders") for part in relative_parts[2:-1])
            if contract or plugin_data:
                paths.add(path)
    for folder in ("Config", "Content"):
        for path in files_under(project / folder):
            relative = path.relative_to(project).as_posix()
            if relative not in GENERATED and not relative.startswith("Content/Developers/"):
                paths.add(path)
    records = []
    for path in sorted(paths, key=lambda item: item.relative_to(project).as_posix()):
        records.append({"path": path.relative_to(project).as_posix(), "size": path.stat().st_size, "sha256": native.digest(path)})
    return records


def identity(project, engine, base_release_id, channel):
    project = Path(project).resolve(strict=True)
    engine = Path(engine).resolve(strict=True)
    native.require(type(base_release_id) is int and 0 < base_release_id < 10**9, "Invalid frozen Windows base ID")
    native.require(re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", channel), "Invalid frozen Windows channel")
    native.require((project / "SampleGame.uproject").is_file(), "Expected SampleGame.uproject")
    build = native.parse_json((engine / "Engine/Binaries/Win64/UnrealEditor.modules").read_bytes(), 4 * 1024 * 1024)
    native.require(type(build.get("BuildId")) is str and re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", build["BuildId"]), "Invalid engine Build ID")
    return {"format": 1, "platform": "Windows", "projectId": "SampleGame", "baseReleaseId": base_release_id,
            "channel": channel, "engineBuildId": build["BuildId"], "nativeApiVersion": 2}


def commit(project):
    result = subprocess.run(["git", "-C", str(project), "rev-parse", "HEAD"], capture_output=True, text=True, check=False)
    return result.stdout.strip() if result.returncode == 0 else None


def freeze(project, engine, base_release_id, channel, output):
    project = Path(project).resolve(strict=True)
    engine = Path(engine).resolve(strict=True)
    output = Path(output).absolute()
    native.require(not output.exists() and not any(output.resolve().is_relative_to(parent) for parent in (REPO, project, engine)), "Compatibility record must be new and outside source/engine directories")
    frozen_identity = identity(project, engine, base_release_id, channel)
    files = inventory(project)
    compatibility_id = hashlib.sha256(canonical({"identity": frozen_identity, "files": files})).hexdigest()
    record = {"format": 1, "policy": POLICY, "identity": frozen_identity, "files": files,
              "compatibilityId": compatibility_id, "sourceCommitAtFreeze": commit(project)}
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("xb") as stream:
        stream.write(canonical(record) + b"\n")
        stream.flush()
        os.fsync(stream.fileno())
    return {"record": str(output), "recordSha256": native.digest(output), "compatibilityId": compatibility_id, "fileCount": len(files)}


def validate(record_path, project, engine, config_path):
    record_path = Path(record_path).resolve(strict=True)
    record = native.parse_json(record_path.read_bytes(), 64 * 1024 * 1024)
    native.require(type(record) is dict and set(record) == {"format", "policy", "identity", "files", "compatibilityId", "sourceCommitAtFreeze"} and record["format"] == 1 and record["policy"] == POLICY, "Unsupported frozen Windows compatibility record")
    config = native.read_config(config_path)
    expected = identity(project, engine, config["baseReleaseId"], config["channel"])
    native.require(record["identity"] == expected, "Windows compatibility identity/engine/API differs from the frozen base")
    for field in ("platform", "projectId", "channel", "baseReleaseId", "engineBuildId"):
        native.require(config[field] == expected[field], "Windows player differs from compatibility identity: " + field)
    content = native.parse_json((Path(config_path).resolve().parent / "sample-player.json").read_bytes())
    native.require(content.get("nativeApiVersion") == 2 and type(content["nativeApiVersion"]) is int, "Frozen content/native player API must remain 2")
    for field in ("platform", "projectId", "channel", "baseReleaseId", "engineBuildId"):
        native.require(content.get(field) == expected[field], "Frozen SampleContent content identity differs: " + field)
    digest = hashlib.sha256(canonical({"identity": record["identity"], "files": record["files"]})).hexdigest()
    native.require(digest == record["compatibilityId"] == config["compatibilityId"], "Frozen record/player compatibilityId mismatch")
    native.require(inventory(project) == record["files"], "Headers, Build/Target, plugins, Java/UPL, configuration or content changed; create a new base")
    return {"recordSha256": native.digest(record_path), "compatibilityId": digest, "fileCount": len(record["files"]),
            "currentCommit": commit(project), "sourceCommitAtFreeze": record["sourceCommitAtFreeze"], "buildProofValidated": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("freeze-native-compat",))
    parser.add_argument("--project", required=True, type=Path)
    parser.add_argument("--engine", required=True, type=Path)
    parser.add_argument("--base-release-id", required=True, type=int)
    parser.add_argument("--channel", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(freeze(args.project, args.engine, args.base_release_id, args.channel, args.output), indent=2))


if __name__ == "__main__":
    main()
