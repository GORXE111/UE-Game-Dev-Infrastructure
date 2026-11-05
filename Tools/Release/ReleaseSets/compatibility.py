"""Read-only V1.0.6 shell freeze and explicit gameplay/save change classification.

This is a planning gate. It never substitutes a producer's native build, full
Cook, migration implementation, or runtime acceptance evidence.
"""
from __future__ import annotations

import os
from pathlib import Path
import re

import release_set as sets

POLICY = "gameplay-release-set-shell-v1"
CURRENT_SAVE_POLICY = dict(schema=1, readable=[0, 1], migrations=[{"from": 0, "to": 1, "id": "colalab-v0-to-v1"}])
SKIP = {"Binaries", "Intermediate", "Saved", "DerivedDataCache", ".git", "__pycache__"}
GENERATED = {"Content/Release/native-bootstrap.json", "Content/Release/update-bootstrap.json"}
# Exact engine-written outputs only. Custom Java, templates, recorded game
# ordering and PSO inputs under the same Build subtrees remain frozen shell.
GENERATED_COOK_LOGS = {"Build/Windows/FileOpenOrder/CookerOpenOrder.log", "Build/Windows/FileOpenOrder/EditorOpenOrder.log",
                       "Build/Android_ASTC/FileOpenOrder/CookerOpenOrder.log", "Build/Android_ASTC/FileOpenOrder/EditorOpenOrder.log"}
GENERATED_ANDROID_JAVA = {"Build/Android/src/com/epicgames/unreal/DownloadShim.java",
                          "Build/Android/src/com/team/samplegame/AlarmReceiver.java",
                          "Build/Android/src/com/team/samplegame/DownloaderActivity.java",
                          "Build/Android/src/com/team/samplegame/OBBData.java",
                          "Build/Android/src/com/team/samplegame/OBBDownloaderService.java"}


def files(root):
    root = Path(root)
    if not root.exists():
        return
    sets.plain(root, True)
    for directory, children, names in os.walk(root, followlinks=False):
        children[:] = sorted(name for name in children if name not in SKIP)
        for name in children:
            sets.plain(Path(directory) / name, True)
        for name in sorted(names):
            path = Path(directory) / name
            sets.plain(path)
            yield path


def classify(name):
    """Only explicitly recognized gameplay inputs can enter the broader family."""
    parts = name.split("/")
    lowered = name.lower()
    filename = parts[-1].lower()
    if name in GENERATED:
        return "generated-bootstrap"
    if name in GENERATED_COOK_LOGS:
        return "generated-cook-output"
    if name in GENERATED_ANDROID_JAVA:
        return "generated-java-output"
    if name.startswith("Content/Developers/"):
        return "developer-only"
    if lowered.endswith((".java", ".kt", ".cs", ".uplugin", ".uproject", ".aar", ".jar", ".so", ".dll", ".lib")):
        return "shell"
    if name.startswith(("Config/", "Build/")) or filename == "androidmanifest.xml" or "upl" in filename:
        return "shell"
    if name.startswith("Source/") or name.startswith("Plugins/") and "/Source/" in name:
        if lowered.endswith((".cpp", ".c", ".h", ".hpp", ".inl")):
            return "gameplay-native"
        return "shell"
    if name.startswith("Content/") or name.startswith("Plugins/") and "/Content/" in name:
        return "cooked-content"
    # Shader/compiler or plugin configuration changes affect the frozen shell.
    return "shell"


def inventory(project):
    project = Path(project)
    descriptor = project / "SampleGame.uproject"
    sets.require(descriptor.is_file(), "Expected the authoritative SampleGame project")
    paths = [descriptor]
    for name in ("Source", "Plugins", "Content", "Config", "Build"):
        paths.extend(files(project / name))
    result = []
    for path in sorted(paths, key=lambda item: item.relative_to(project).as_posix()):
        name = path.relative_to(project).as_posix()
        kind = classify(name)
        if kind in ("developer-only", "generated-bootstrap", "generated-cook-output", "generated-java-output"):
            continue
        result.append(dict(path=name, kind=kind, size=path.stat().st_size, sha256=sets.digest(path)))
    return result


def freeze(project, engine_build_id):
    sets.require(type(engine_build_id) is str and sets.TOKEN.fullmatch(engine_build_id), "Invalid engine identity")
    records = inventory(project)
    shell = dict(policy=POLICY, engineBuildId=engine_build_id, files=[item for item in records if item["kind"] == "shell"])
    import hashlib
    return dict(format=1, policy=POLICY, engineBuildId=engine_build_id,
                shellCompatibilityId=hashlib.sha256(sets.canonical(shell)).hexdigest(), files=records)


def compare(base, project, engine_build_id, old_save, new_save):
    sets.require(type(base) is dict and set(base) == {"format", "policy", "engineBuildId", "shellCompatibilityId", "files"}
                 and type(base["format"]) is int and base["format"] == 1 and base["policy"] == POLICY,
                 "Invalid frozen shell record")
    # Recompute the baseline ID too; do not trust a caller-edited compatibility string.
    import hashlib
    baseline_shell = dict(policy=POLICY, engineBuildId=base["engineBuildId"], files=[item for item in base["files"] if item["kind"] == "shell"])
    sets.require(hashlib.sha256(sets.canonical(baseline_shell)).hexdigest() == sets.sha(base["shellCompatibilityId"]), "Frozen shell digest differs")
    current = freeze(project, engine_build_id)
    sets.save_policy(old_save)
    sets.save_policy(new_save)
    old = {item["path"]: item for item in base["files"]}
    sets.require(len(old) == len(base["files"]), "Duplicate frozen input path")
    new = {item["path"]: item for item in current["files"]}
    changes = []
    for path in sorted(old.keys() | new.keys()):
        before, after = old.get(path), new.get(path)
        if before == after:
            continue
        changes.append(dict(path=path, kind=classify(path), change="added" if before is None else "deleted" if after is None else "modified",
                            before=before, after=after))
    shell_changed = current["shellCompatibilityId"] != base["shellCompatibilityId"]
    save_compatible = old_save["schema"] in new_save["readable"]
    reasons = []
    if shell_changed:
        reasons.append("frozen-shell-or-engine-changed")
    if not save_compatible:
        reasons.append("save-schema-has-no-declared-migration-path")
    return dict(format=1, policy=POLICY, requiresNewBase=bool(reasons), reasons=reasons, changes=changes,
                shellCompatibilityId=current["shellCompatibilityId"],
                requiredEvidence=["same-commit-native-build", "same-commit-full-cook", "complete-cooked-inventory",
                                  "implemented-save-migrations", "native-content-pair-startup", "failure-recovery"],
                productionQualified=False, deviceRuntimeValidated=False)
