"""Validate and normalize the inputs for the Win64 UE adoption checks."""

import argparse
import json
from pathlib import Path
import re


MAX_PROFILE_SIZE = 64 * 1024
MAX_ASSET_PLAN_SIZE = 1024 * 1024
REQUIRED_FIELDS = {"version", "project", "configSource", "assetPlan", "dataTables", "build", "startup"}
BUILD_FIELDS = {"target", "platform", "configuration", "maps"}
TARGET = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}")
TABLE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,62}")
MAP = re.compile(r"/(?:[A-Za-z0-9_]+/)+[A-Za-z0-9_]+")
OBJECT_PATH = re.compile(r"/[\w-]+(?:/[\w-]+)+\.[\w-]+")
ROW_STRUCT = re.compile(r"/Script/[A-Za-z0-9_]+\.[A-Za-z0-9_]+")
DATA_TABLE_CLASS = "/Script/Engine.DataTable"
READY_MARKER = re.compile(r"[ -~]{1,160}")
INVALID_PATH_CHARACTERS = re.compile(r'[:<>"|?*\x00-\x1f]')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unique_keys(pairs):
    values = {}
    for key, value in pairs:
        require(key not in values, f"Repeated JSON key {key!r}")
        values[key] = value
    return values


def profile_input(root, value, name, suffix=None):
    message = f"{name} must be a path relative to the profile directory"
    require(isinstance(value, str) and not INVALID_PATH_CHARACTERS.search(value), message)
    parts = value.replace("\\", "/").split("/")
    if suffix is None and parts == ["."]:
        parts = []
    require(all(part not in {"", ".", ".."} and not part.endswith((" ", ".")) for part in parts), message)
    declared = root.joinpath(*parts)
    if suffix is not None:
        require(declared.suffix.lower() == suffix, f"{name} must name a {suffix} file")
    try:
        resolved = declared.resolve(strict=True)
    except OSError as error:
        raise ValueError(f"{name} does not resolve to an existing path: {value!r}") from error
    require(resolved.is_relative_to(root), f"{name} resolves outside the profile directory")
    if suffix is None:
        require(resolved.is_dir(), f"{name} must name a directory")
    else:
        require(resolved.is_file() and resolved.suffix.lower() == suffix, f"{name} must resolve to a {suffix} file")
    return str(resolved)


def read_json(path, maximum, label):
    with path.open("rb") as stream:
        raw = stream.read(maximum + 1)
    require(len(raw) <= maximum, f"{label} exceeds {maximum // 1024} KiB")
    return json.loads(raw.decode("utf-8-sig"), object_pairs_hook=unique_keys)


def validate_data_tables(data_tables, asset_plan):
    plan = read_json(Path(asset_plan), MAX_ASSET_PLAN_SIZE, "assetPlan")
    require(isinstance(plan, dict) and plan.keys() == {"version", "assets"}
            and type(plan["version"]) is int and plan["version"] == 1
            and isinstance(plan["assets"], list) and plan["assets"], "Expected a version 1 assetPlan with assets")
    assets = {}
    seen_assets = set()
    for entry in plan["assets"]:
        require(isinstance(entry, dict) and entry.keys() == {"path", "class"}
                and all(isinstance(value, str) and OBJECT_PATH.fullmatch(value) for value in entry.values())
                and entry["path"].startswith(("/Game/", "/Engine/")),
                "assetPlan needs top-level object paths in /Game or /Engine and a class path for each asset")
        path = entry["path"]
        require(path.casefold() not in seen_assets, f"assetPlan contains a repeated asset {path!r}")
        seen_assets.add(path.casefold())
        assets[path] = entry["class"]

    require(isinstance(data_tables, list) and data_tables, "dataTables must contain at least one mapping")
    tables = set()
    destinations = set()
    for entry in data_tables:
        require(isinstance(entry, dict) and entry.keys() == {"table", "asset", "rowStruct"},
                "dataTables entries need table, asset and rowStruct")
        table, asset, row_struct = entry["table"], entry["asset"], entry["rowStruct"]
        require(isinstance(table, str) and TABLE.fullmatch(table) and table.lower() not in {"none", "manifest"},
                "Invalid dataTables table name")
        require(isinstance(asset, str) and OBJECT_PATH.fullmatch(asset) and asset.startswith("/Game/"),
                "dataTables asset must be a /Game object path")
        package, object_name = asset.rsplit(".", 1)
        require(package.rsplit("/", 1)[1] == object_name, "dataTables asset must use the package leaf as its object name")
        require(isinstance(row_struct, str) and ROW_STRUCT.fullmatch(row_struct),
                "dataTables rowStruct must use /Script/Module.Struct")
        require(table.lower() not in tables and asset.casefold() not in destinations,
                "dataTables contains a repeated table or asset")
        require(assets.get(asset) == DATA_TABLE_CLASS, f"Declare {asset!r} as {DATA_TABLE_CLASS} in assetPlan")
        tables.add(table.lower())
        destinations.add(asset.casefold())


def read_profile(path):
    path = Path(path).absolute()
    require(path.is_file(), "Choose an existing project profile file")
    profile = read_json(path, MAX_PROFILE_SIZE, "Project profile")
    require(isinstance(profile, dict) and REQUIRED_FIELDS <= profile.keys() <= REQUIRED_FIELDS | {"serverTarget"},
            "Profile needs version, project, configSource, assetPlan, dataTables, build and startup, with optional serverTarget")
    require(type(profile["version"]) is int and profile["version"] == 1, "Expected project profile version 1")

    build = profile["build"]
    require(isinstance(build, dict) and BUILD_FIELDS <= build.keys() <= BUILD_FIELDS | {"editorTarget"},
            "build needs target, platform, configuration and maps, with optional editorTarget")
    require(isinstance(build["target"], str) and TARGET.fullmatch(build["target"]), "Invalid build target name")
    editor_target = build.get("editorTarget", build["target"] + "Editor")
    require(isinstance(editor_target, str) and TARGET.fullmatch(editor_target), "Invalid build editorTarget name")
    require(build["platform"] == "Win64" and build["configuration"] == "Development",
            "This adoption check accepts a Win64 Development build")
    maps = build["maps"]
    require(isinstance(maps, list) and maps and all(isinstance(item, str) and MAP.fullmatch(item) for item in maps),
            "build.maps must contain Unreal long package paths such as /Game/Maps/Main")
    require(len({item.lower() for item in maps}) == len(maps), "build.maps contains a repeated map")

    if "serverTarget" in profile:
        target = profile["serverTarget"]
        require(isinstance(target, str) and TARGET.fullmatch(target), "Invalid serverTarget name")

    startup = profile["startup"]
    require(isinstance(startup, dict) and startup.keys() == {"map", "readyMarker"},
            "startup needs map and readyMarker")
    require(startup["map"] in maps, "startup.map must match a build.maps entry")
    marker = startup["readyMarker"]
    require(isinstance(marker, str) and READY_MARKER.fullmatch(marker) and marker == marker.strip(),
            "startup.readyMarker must be a single visible ASCII line of 1–160 characters")

    root = path.parent.resolve(strict=True)
    project = profile_input(root, profile["project"], "project", ".uproject")
    config_source = profile_input(root, profile["configSource"], "configSource")
    asset_plan = profile_input(root, profile["assetPlan"], "assetPlan", ".json")
    validate_data_tables(profile["dataTables"], asset_plan)
    return {**profile,
            "project": project, "configSource": config_source, "assetPlan": asset_plan,
            "build": {**build, "editorTarget": editor_target}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", type=Path, required=True, help="Path to the version 1 project profile")
    args = parser.parse_args()
    try:
        profile = read_profile(args.profile)
    except (OSError, RuntimeError, ValueError) as error:
        print(json.dumps({"status": "blocked", "error": str(error)}))
        return 1
    print(json.dumps({"status": "validated", **profile}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
