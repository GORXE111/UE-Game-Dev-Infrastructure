"""Bind the explicit Lua identity and optional release-local notes before building."""
from __future__ import annotations

import hashlib
from pathlib import Path
import re

import release_set as sets
import release_notes

SOURCE = "Content/Lua/game/release_status.lua"
VERSION = re.compile(r"(?:0|[1-9][0-9]{0,2})\.(?:0|[1-9][0-9]{0,2})\.(?:0|[1-9][0-9]{0,2})(?:\+[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*)?\Z")


def validate_version(value):
    sets.require(type(value) is str and len(value) <= 96 and VERSION.fullmatch(value),
                 "Lua version is unsupported by the installed Android health protocol; use e.g. 1.0.7+dev.1")
    return value


def snapshot(project):
    raw = sets.read_bounded(Path(project) / SOURCE, 64 * 1024)
    declarations = [line.strip() for line in raw.decode("utf-8").splitlines() if re.match(r"\s*local\s+version\b", line)]
    sets.require(len(declarations) == 1, "Release Lua must have one explicit local version declaration")
    match = re.fullmatch(r'''local\s+version\s*=\s*(["'])([^"']+)\1\s*''', declarations[0])
    sets.require(match is not None, "Release Lua version must be a literal string, not an expression")
    result = dict(file=SOURCE, version=validate_version(match.group(2)), sha256=hashlib.sha256(raw).hexdigest())
    notes = Path(project) / release_notes.SOURCE
    if notes.exists():
        _, result["releaseNotes"] = release_notes.load(notes, result["version"])
    return result


def proof_identity(proof, project):
    current = snapshot(project)
    if "luaIdentity" in proof:
        sets.require(proof["luaIdentity"] == current, "Lua release identity changed since the actual Cook")
    # Historical proofs remain readable, but unsupported current identities cannot be signed.
    return current


def archive_version(receipt_path, value):
    """Name a new installer from its frozen Cook evidence, never the current checkout."""
    receipt = sets.parse(sets.read_bounded(receipt_path, sets.MAX_MANIFEST))
    for key in ("baseReleaseId", "sourceCommit", "nativeSourceHash", "buildId", "engineBuildId", "shellCompatibilityId"):
        sets.require(receipt.get(key) == value[key], "Archive producer identity differs: " + key)
    sets.require(receipt.get("manifestSha256") == hashlib.sha256(sets.canonical(value)).hexdigest(), "Archive producer base pin differs")
    if "luaIdentity" not in receipt:
        legacy = {420: "0000000000000000000000000000000000000000000000000000000000000000",
                  430: "0000000000000000000000000000000000000000000000000000000000000000"}
        sets.require(legacy.get(value["baseReleaseId"]) == receipt["manifestSha256"], "New installer requires frozen Lua identity")
        return "1.0.6"
    path = Path(receipt["buildProofPath"])
    sets.require(sets.digest(path) == receipt["buildProofSha256"], "Archive build proof changed")
    proof = sets.parse(sets.read_bounded(path, sets.MAX_MANIFEST))
    sets.require(proof.get("luaIdentity") == receipt["luaIdentity"], "Archive Lua identity differs from actual Cook")
    for key in ("sourceCommit", "nativeSourceHash", "engineBuildId", "shellCompatibilityId"):
        sets.require(proof.get(key) == value[key], "Archive build proof identity differs: " + key)
    return validate_version(receipt["luaIdentity"]["version"])
