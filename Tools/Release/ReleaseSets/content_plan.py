"""Versioned Cook roots for both producers; never an engine/APK compatibility exemption."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re

import release_set as sets

LEGACY_MAPS = ("/Game/SampleGame/Maps/UI/SettingsPreview", "/Game/LD/level/PrototypeArena", "/Game/Maps/CombatArena")
PLAN_PATH = Path(__file__).with_name("release-content.json")
MAP_PATH = re.compile(r"/Game/(?:[A-Za-z0-9_]+/)*[A-Za-z0-9_]+\Z")


def validate(value):
    sets.require(type(value) is dict and set(value) == {"format", "requiredMaps"}
                 and type(value["format"]) is int and value["format"] == 1, "Invalid release content plan")
    maps = value["requiredMaps"]
    sets.require(type(maps) is list and 3 <= len(maps) <= 256, "Invalid release map count")
    sets.require(all(type(name) is str and len(name) <= 256 and MAP_PATH.fullmatch(name) for name in maps),
                 "Release maps must be unambiguous /Game package paths without extensions")
    sets.require(len({name.casefold() for name in maps}) == len(maps), "Duplicate or case-colliding release map")
    sets.require(set(LEGACY_MAPS).issubset(maps), "The three baseline entry maps must remain in the content plan")
    return value


def snapshot():
    # This tracked producer input intentionally lives outside Config/: adding a
    # Cook root must not silently change the installed engine/APK configuration.
    raw = sets.read_bounded(PLAN_PATH, 128 * 1024)
    def pairs(items):
        result = {}
        for key, value in items:
            sets.require(key not in result, "Duplicate release content plan key")
            result[key] = value
        return result
    value = validate(json.loads(raw.decode("utf-8"), object_pairs_hook=pairs))
    return dict(plan=value, sha256=hashlib.sha256(sets.canonical(value)).hexdigest())


def proof_maps(proof):
    record = proof.get("contentPlan")
    if record is None:
        # Original V1.0.6 evidence is immutable and always used exactly these
        # roots. Never reinterpret an old proof with today's expanded plan.
        return LEGACY_MAPS
    sets.require(type(record) is dict and set(record) == {"plan", "sha256"}, "Invalid recorded content plan")
    value = validate(record["plan"])
    sets.require(record["sha256"] == hashlib.sha256(sets.canonical(value)).hexdigest(), "Recorded content plan digest differs")
    sets.require(record == snapshot(), "Release content plan changed since the actual Cook")
    return tuple(value["requiredMaps"])
