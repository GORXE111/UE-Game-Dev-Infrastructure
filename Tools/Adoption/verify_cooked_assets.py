"""Check declared Unreal packages against complete UnrealPak listings."""

import argparse
import json
from pathlib import Path
import re


PACKAGE = re.compile(r"/(Game|Engine)/([\w-]+(?:/[\w-]+)*)")
SEGMENT = re.compile(r"[\w-]+")
LISTING = re.compile(r'LogPakFile: Display: Listing (.+\.pak) with mount point "([^"\r\n]+)"$')
ENTRY = re.compile(r'LogPakFile: Display: "([^"\r\n]+)" offset: (-?\d+), size: (\d+) bytes, '
                   r'sha1: [a-fA-F0-9]{40}, compression: [^\r\n]+\.$')
FOOTER = re.compile(r'LogPakFile: Display: (\d+) files \((\d+) bytes\), \((\d+) filtered bytes\)\.$')
STAGED_ROOT = "../../../"


def declared_paths(project, kind, declared):
    package = declared
    if kind == "object":
        package, separator, name = declared.partition(".")
        if not separator or not SEGMENT.fullmatch(name):
            raise ValueError(f"Expected a top-level /Game or /Engine object path: {declared}")
    match = PACKAGE.fullmatch(package)
    if not match:
        raise ValueError(f"Expected a /Game or /Engine package path: {declared}")
    root = project if match[1] == "Game" else "Engine"
    path = f"{root}/Content/{match[2]}"
    return [path + ".umap"] if kind == "map" else [path + ".uasset", path + ".umap"]


def read_inventory(path, expected):
    pak = mount = footer = None
    file_count = byte_count = 0
    matches = {}
    with path.open(encoding="utf-8-sig") as stream:
        for line in stream:
            line = line.rstrip("\r\n")
            if match := LISTING.search(line):
                if pak is not None or footer is not None:
                    raise ValueError(f"{path}: list exactly one PAK per inventory")
                pak, mount = match[1], match[2].replace("\\", "/")
                if not mount.startswith(STAGED_ROOT):
                    raise ValueError(f"{path}: expected a staged PAK mount under {STAGED_ROOT}")
            elif match := ENTRY.search(line):
                mounted_path = match[1].replace("\\", "/")
                if mount is None or footer is not None or not mounted_path.startswith(mount):
                    raise ValueError(f"{path}: expected mounted paths from -ExtractToMountPoint")
                offset, size = int(match[2]), int(match[3])
                if offset < 0:
                    raise ValueError(f"{path}: list live files only with -ExcludeDeleted")
                file_count += 1
                byte_count += size
                relative = mounted_path.removeprefix(STAGED_ROOT)
                if relative in expected and size > 0:
                    matches[relative] = size
            elif match := FOOTER.search(line):
                if pak is None or footer is not None:
                    raise ValueError(f"{path}: unexpected PAK listing footer")
                footer = tuple(map(int, match.groups()))
    if not file_count or footer != (file_count, byte_count, 0):
        raise ValueError(f"{path}: expected a complete unfiltered UnrealPak -List inventory")
    return dict(path=str(path), pak=pak, mountPoint=mount, fileCount=file_count), matches


def verify(project, inventories, maps, objects, report):
    if not SEGMENT.fullmatch(project) or project.casefold() == "engine":
        raise ValueError("Expected a staged project name other than Engine")
    if not maps and not objects:
        raise ValueError("Declare at least one --map or --object")
    checks = report["checks"]
    for kind, values in (("map", maps), ("object", objects)):
        for declared in values:
            checks.append(dict(kind=kind, declared=declared, expectedPaths=declared_paths(project, kind, declared),
                               foundIn=[], status="failed"))
    expected = {name for check in checks for name in check["expectedPaths"]}
    found = {name: [] for name in expected}
    for path in inventories:
        inventory, matches = read_inventory(path, expected)
        report["inventories"].append(inventory)
        for name, size in matches.items():
            found[name].append(dict(pak=inventory["pak"], path=name, size=size))
    for check in checks:
        check["foundIn"] = [hit for name in check["expectedPaths"] for hit in found[name]]
        if check["foundIn"]:
            check["status"] = "passed"
    missing = [check["declared"] for check in checks if check["status"] == "failed"]
    if missing:
        raise ValueError("Cooked packages missing from the staged PAKs: " + ", ".join(missing))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-name", required=True, help="Project name used in the staged directory")
    parser.add_argument("--inventory", action="append", type=Path, required=True,
                        help="One UTF-8 log from UnrealPak -List -ExtractToMountPoint -ExcludeDeleted")
    parser.add_argument("--map", action="append", default=[], help="Long map package path")
    parser.add_argument("--object", action="append", default=[], help="Top-level object path in a cooked package")
    args = parser.parse_args()
    report = dict(schemaVersion=1, status="failed", inventories=[], checks=[])
    try:
        verify(args.project_name, args.inventory, args.map, args.object, report)
    except (OSError, ValueError) as error:
        report["error"] = str(error)
    else:
        report["status"] = "passed"
    print(json.dumps(report, ensure_ascii=True, indent=2))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
