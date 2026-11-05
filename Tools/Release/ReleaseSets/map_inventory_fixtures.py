"""Tiny synthetic map/PAK/listing fixtures for producer tests; never runs UnrealPak/UE."""
from pathlib import Path
import hashlib
from unittest.mock import patch

import release_set as sets
import content_plan
import release_identity
import windows_pipeline


def source_maps(project, maps=windows_pipeline.COOK_MAPS):
    version = Path(project) / release_identity.SOURCE
    version.parent.mkdir(parents=True, exist_ok=True)
    version.write_text('local version = "1.0.6"\n', encoding="utf-8")
    for name in maps:
        path = Path(project) / "Content" / (name.removeprefix("/Game/") + ".umap")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"synthetic source map, not a UE asset")


def isolate_content_plan(test):
    """Producer unit fixtures must not depend on future real release-map additions."""
    value = dict(format=1, requiredMaps=list(content_plan.LEGACY_MAPS))
    snapshot = dict(plan=value, sha256=hashlib.sha256(sets.canonical(value)).hexdigest())
    guard = patch.object(content_plan, "snapshot", return_value=snapshot)
    guard.start()
    test.addCleanup(guard.stop)
    version_guard = patch.object(release_identity, "snapshot", return_value=dict(file=release_identity.SOURCE, version="1.0.6", sha256="0" * 64))
    version_guard.start()
    test.addCleanup(version_guard.stop)


def unrealpak_tool(engine):
    path = Path(engine) / "Engine/Binaries/Win64/UnrealPak.exe"
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.write_bytes(b"synthetic UnrealPak executable placeholder; never executed")
    return path


def listing(arguments, log, maps=windows_pipeline.COOK_MAPS, exit_code=0):
    command = [str(part) for part in arguments]
    assert len(command) == 3 and command[-1] == "-List"
    lines = ['LogPakFile: Display: Listing ' + Path(command[1]).name + ' with mount point "../../../"']
    for name in maps:
        entry = "SampleGame/Content/" + name.removeprefix("/Game/") + ".umap"
        lines.append('LogPakFile: Display: "' + entry + '" offset: 0, size: 8 bytes, sha1: ' + "a" * 40 + ', compression: None.')
    Path(log).write_text("\n".join(lines) + "\n", encoding="utf-8")
    return dict(path=str(Path(log).absolute()), sha256=sets.digest(log), exitCode=exit_code, arguments=command)


def map_proof(engine, paks, output):
    unrealpak_tool(engine)
    Path(output).mkdir(parents=True, exist_ok=True)
    return windows_pipeline.map_inventory(engine, paks, output, listing)
