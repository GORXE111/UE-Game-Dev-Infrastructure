"""Check declared top-level Unreal assets in a PythonScript commandlet."""

import json
import os
from pathlib import Path
import re

import unreal


OBJECT_PATH = re.compile(r"/[\w-]+(?:/[\w-]+)+\.[\w-]+")


def absolute_path(variable):
    path = Path(os.environ.get(variable, ""))
    if not path.is_absolute():
        raise ValueError(f"Set {variable} to an absolute path")
    return path


def unique_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Repeated JSON key {key!r}")
        result[key] = value
    return result


def read_plan(path):
    plan = json.loads(path.read_text(encoding="utf-8-sig"), object_pairs_hook=unique_keys)
    if (not isinstance(plan, dict) or set(plan) != {"version", "assets"}
            or type(plan["version"]) is not int or plan["version"] != 1
            or not isinstance(plan["assets"], list) or not plan["assets"]):
        raise ValueError("Expected a version 1 asset plan with a nonempty assets list")

    paths = set()
    for entry in plan["assets"]:
        if (not isinstance(entry, dict) or set(entry) != {"path", "class"}
                or any(not isinstance(value, str) or not OBJECT_PATH.fullmatch(value) for value in entry.values())):
            raise ValueError("Every asset must declare a top-level object path and class path")
        normalized = entry["path"].casefold()
        if normalized in paths:
            raise ValueError(f"Repeated asset path {entry['path']!r}")
        paths.add(normalized)
    return plan["assets"]


def check_asset(registry, entry):
    path, expected_class = entry["path"], entry["class"]
    result = dict(path=path, expectedClass=expected_class, actualClass=None, status="failed", error=None)
    try:
        candidates = registry.get_assets_by_package_name(path.split(".", 1)[0], True) or ()
        data = next((asset for asset in candidates if f"{asset.package_name}.{asset.asset_name}" == path), None)
        if data is None:
            raise ValueError("Exact asset path is absent from the on-disk Asset Registry")
        class_path = data.asset_class_path
        result["actualClass"] = f"{class_path.package_name}.{class_path.asset_name}"
        if unreal.AssetRegistryHelpers.is_redirector(data):
            raise ValueError("Asset path is a redirector; declare the destination object")
        if result["actualClass"] != expected_class:
            raise ValueError("Asset Registry class differs from the declared class")
        asset = unreal.AssetRegistryHelpers.get_asset(data)
        if asset is None or asset.get_path_name() != path or asset.get_class().get_path_name() != expected_class:
            raise ValueError("Could not load the declared asset and class")
    except (RuntimeError, ValueError) as error:
        result["error"] = str(error)
    else:
        result["status"] = "passed"
    return result


def main():
    report_path = absolute_path("UE_ADOPTION_ASSET_REPORT")
    if not report_path.parent.is_dir() or os.path.lexists(report_path):
        raise ValueError("Choose a new asset report in an existing directory")
    report = dict(version=1, status="failed", assets=[])
    try:
        entries = read_plan(absolute_path("UE_ADOPTION_ASSET_PLAN"))
        registry = unreal.AssetRegistryHelpers.get_asset_registry()
        registry.scan_paths_synchronous(sorted({entry["path"].rsplit("/", 1)[0] for entry in entries}))
        report["assets"] = [check_asset(registry, entry) for entry in entries]
        if all(asset["status"] == "passed" for asset in report["assets"]):
            report["status"] = "passed"
    except Exception as error:
        report["error"] = str(error)

    with report_path.open("x", encoding="utf-8", newline="\n") as output:
        output.write(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    if report["status"] != "passed":
        raise RuntimeError(f"Declared asset checks failed; see {report_path}")
    unreal.log(f"UE_ADOPTION_ASSET_CHECK_PASSED assets={len(report['assets'])}")


main()
