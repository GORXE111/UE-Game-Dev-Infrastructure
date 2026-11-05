"""Wrap a verified Windows player package; never edits its content trust or actual game EXE."""
import argparse
import json
from pathlib import Path
import shutil

import native_launcher as native


def configure(install, launcher_build, manifest_url, compatibility_id, extra_files=()):
    install = Path(install).resolve(strict=True)
    launcher_build = Path(launcher_build).resolve(strict=True)
    original = native.inside(install, "SampleGame.exe")
    content_config = native.inside(install, "sample-player.json")
    settings_raw = content_config.read_bytes()
    settings = native.parse_json(settings_raw)
    native.require(settings.get("platform") == "Windows", "This wrapper accepts a Windows player package only")
    for key in (*native.IDENTITY[:-1], "publicKeyHex", "gameExe"):
        native.require(key in settings, f"Existing frozen player configuration missing {key}")
    native.https_origin(manifest_url)
    native.require(manifest_url.endswith("/manifest.json"), "Native manifest endpoint must end in /manifest.json")
    native_files = []
    game_exe = native.relative_path(settings["gameExe"])
    for name in dict.fromkeys((game_exe, *extra_files)):
        path = native.inside(install, name)
        native.require(path.is_file(), "Configured native allowlist file is missing")
        native_files.append({"path": name, "size": path.stat().st_size, "sha256": native.digest(path)})
    native.file_records(native_files)
    config = {key: settings[key] for key in native.IDENTITY[:-1]}
    config.update(format=1, compatibilityId=compatibility_id, manifestUrl=manifest_url,
                  publicKeyHex=settings["publicKeyHex"], nativeFiles=native_files,
                  contentLauncher="SampleContent.exe", contentConfig="sample-player.json", allowOffline=True)
    native.validate_identity(config)
    executable = native.inside(launcher_build, "SampleGameNativeLauncher.exe")
    internal = native.inside(launcher_build, "_native_internal")
    native.require(original.is_file() and executable.is_file() and internal.is_dir(), "Player bootstrap or frozen native launcher build is incomplete")
    config_path = native.inside(install, "native-player.json")
    delegate = native.inside(install, "SampleContent.exe")
    installed_internal = native.inside(install, "_native_internal")
    for path in (config_path, delegate, installed_internal, native.inside(install, ".native-update")):
        native.require(not path.exists(), "This package is already configured or has native runtime state; use a fresh player package")
    game_hash_before = native.digest(native.inside(install, game_exe))
    delegate_hash = native.digest(original)
    shutil.copyfile(original, delegate)
    shutil.copytree(internal, installed_internal)
    native.atomic_json(config_path, config)
    native.read_config(config_path)
    temporary = native.inside(install, "SampleGameNativeLauncher.pending.exe")
    native.require(not temporary.exists(), "Pending bootstrap replacement already exists")
    shutil.copyfile(executable, temporary)
    temporary.replace(original)
    native.require(native.digest(delegate) == delegate_hash, "Frozen content launcher changed during wrapping")
    native.require(native.digest(native.inside(install, game_exe)) == game_hash_before and content_config.read_bytes() == settings_raw, "Actual game binary or original content trust was modified")
    return {"entry": str(original), "nativeConfig": str(config_path), "contentDelegateSha256": delegate_hash,
            "nativeLauncherSha256": native.digest(original), "nativeFiles": native_files, "compatibilityId": compatibility_id}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--install-root", required=True, type=Path)
    parser.add_argument("--launcher-build", required=True, type=Path)
    parser.add_argument("--manifest-url", required=True)
    parser.add_argument("--compatibility-id", required=True)
    parser.add_argument("--native-file", action="append", default=[], help="Additional exact same-version game Win64 DLL/EXE; actual game EXE is automatic")
    args = parser.parse_args()
    print(json.dumps(configure(args.install_root, args.launcher_build, args.manifest_url, args.compatibility_id, args.native_file), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
