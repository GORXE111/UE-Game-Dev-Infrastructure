"""Inspect a UE engine tree for the Win64 Development dedicated-server gate."""

import argparse
import json
from pathlib import Path
import re


PLATFORM_INI = "Engine/Config/BaseEngine.ini"
INSTALLED_MARKER = "Engine/Build/InstalledBuild.txt"
SERVER_RULES = "Engine/Source/UnrealServer.Target.cs"
BUILD_TOOL = "Engine/Binaries/DotNET/UnrealBuildTool/UnrealBuildTool.dll"
BUILD_SCRIPT = "Engine/Build/BatchFiles/Build.bat"
SERVER_DIRECTORY = "Engine/Binaries/Win64/"
SERVER_RECEIPTS = ("UnrealServer.target", "UnrealServer-Win64-Development.target")
SERVER_EXES = ("UnrealServer.exe", "UnrealServer-Win64-Development.exe")
MAX_INPUT_SIZE = 16 * 1024 * 1024
INI_ENTRY = re.compile(r"([+!-]?)\s*InstalledPlatformConfigurations(?:\s*=\s*(.*))?", re.IGNORECASE)
INI_FIELD = re.compile(r'\s*([A-Za-z][A-Za-z0-9_]*)=\s*(?:"([^"]*)"|([A-Za-z0-9_.-]+))\s*(?:,|$)')


def evidence_path(root, relative):
    path = (root / relative).resolve()
    if not path.is_relative_to(root):
        raise ValueError(f"Engine evidence escapes its root: {relative}")
    return path


def evidence_text(root, relative):
    with evidence_path(root, relative).open("rb") as stream:
        raw = stream.read(MAX_INPUT_SIZE + 1)
    if len(raw) > MAX_INPUT_SIZE:
        raise ValueError(f"Engine evidence exceeds its size budget: {relative}")
    return raw.decode("utf-8-sig")


def fields(raw):
    if not raw.startswith("(") or not raw.endswith(")"):
        raise ValueError("Expected a parenthesized InstalledPlatformConfigurations entry")
    text = raw[1:-1]
    result = {}
    offset = 0
    while offset < len(text):
        match = INI_FIELD.match(text, offset)
        if not match or match[1] in result:
            raise ValueError("Invalid InstalledPlatformConfigurations field")
        result[match[1]] = match[2] if match[2] is not None else match[3]
        offset = match.end()
    return result


def installed_platforms(text):
    entries = []
    active = False
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("["):
            active = line.casefold() == "[installedplatforms]"
        elif active and (match := INI_ENTRY.fullmatch(line)):
            operator, value = match.groups()
            if operator == "!":
                entries.clear()
            elif value is None:
                continue
            elif operator == "-":
                entries = [entry for entry in entries if entry.casefold() != value.casefold()]
            elif operator == "+":
                entries.append(value)
            else:
                entries = [value]
    return [fields(entry) for entry in entries]


def unique_json_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Repeated target receipt key {key!r}")
        result[key] = value
    return result


def engine_filename(value, names):
    if not isinstance(value, str):
        raise ValueError("Missing dedicated-server path")
    value = value.replace("\\", "/")
    if value not in {SERVER_DIRECTORY + name for name in names}:
        raise ValueError(f"Unexpected dedicated-server path: {value}")
    return value


def inspect_receipt(root, relative):
    receipt = json.loads(evidence_text(root, relative), object_pairs_hook=unique_json_keys)
    expected = {"TargetName": "UnrealServer", "TargetType": "Server", "Platform": "Win64",
                "Configuration": "Development", "Architecture": "x64"}
    if not isinstance(receipt, dict) or any(receipt.get(key) != value for key, value in expected.items()):
        raise ValueError(f"Target receipt does not identify UnrealServer Win64 Development x64: {relative}")
    launch = receipt.get("Launch")
    if not isinstance(launch, str) or not launch.replace("\\", "/").startswith("$(EngineDir)/"):
        raise ValueError(f"Target receipt lacks an engine-relative launch executable: {relative}")
    executable = engine_filename("Engine/" + launch.replace("\\", "/").removeprefix("$(EngineDir)/"), SERVER_EXES)
    path = evidence_path(root, executable)
    if not path.is_file() or path.stat().st_size == 0:
        raise ValueError(f"Dedicated-server launch executable is missing: {executable}")
    return executable


def inspect_engine(engine, report):
    root = engine.resolve(strict=True)
    report["engineRoot"] = str(root)
    if not root.is_dir():
        raise ValueError("Choose the UE root that contains the Engine directory")
    installed = evidence_path(root, INSTALLED_MARKER).is_file()
    report["engineKind"] = "installed" if installed else "source"
    for tool in (BUILD_SCRIPT, BUILD_TOOL):
        if not evidence_path(root, tool).is_file():
            raise ValueError(f"Engine build tool is missing: {tool}")

    if installed:
        candidates = [entry for entry in installed_platforms(evidence_text(root, PLATFORM_INI))
                      if entry.get("PlatformName") == "Win64" and entry.get("Configuration") == "Development"
                      and entry.get("PlatformType") == "Server" and entry.get("Architecture") == "x64"
                      and entry.get("ProjectType", "Any") in {"Any", "Code"}
                      and entry.get("bCanBeDisplayed", "false").casefold() in {"true", "false"}]
        report["installedPlatformEntry"] = bool(candidates)
        if not candidates:
            raise ValueError("Installed build lacks a Win64 Development x64 Server platform entry")
        failures = []
        for entry in candidates:
            try:
                receipt = engine_filename(entry.get("RequiredFile"), SERVER_RECEIPTS)
                executable = inspect_receipt(root, receipt)
            except (OSError, ValueError) as error:
                failures.append(str(error))
            else:
                report.update(status="installed-ready", precompiledServer=True,
                              serverReceipt=receipt, serverExecutable=executable)
                return
        raise ValueError("No usable Win64 Server receipt: " + "; ".join(failures))

    if not evidence_path(root, SERVER_RULES).is_file():
        raise ValueError(f"Source engine server target rules are missing: {SERVER_RULES}")
    for name in SERVER_RECEIPTS:
        receipt = SERVER_DIRECTORY + name
        if not evidence_path(root, receipt).is_file():
            continue
        try:
            executable = inspect_receipt(root, receipt)
        except (OSError, ValueError) as error:
            report["serverReceiptError"] = str(error)
        else:
            report.pop("serverReceiptError", None)
            report.update(precompiledServer=True, serverReceipt=receipt, serverExecutable=executable)
            break
    report["status"] = "source-ready-to-plan"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", type=Path, required=True, help="UE root containing Engine/")
    args = parser.parse_args()
    report = dict(status="blocked", engineKind=None, engineRoot=None, target="UnrealServer", platform="Win64",
                  configuration="Development", architecture="x64", installedPlatformEntry=False,
                  precompiledServer=False, serverReceipt=None, serverExecutable=None)
    try:
        inspect_engine(args.engine, report)
    except (OSError, RuntimeError, ValueError) as error:
        report["error"] = str(error)
    print(json.dumps(report, ensure_ascii=True))
    return 1 if report["status"] == "blocked" else 0


if __name__ == "__main__":
    raise SystemExit(main())
