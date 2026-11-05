"""One bounded, release-local announcement source shared by client and website."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import release_set as sets

SOURCE = "Content/Release/release-notes.json"


def text(value, maximum):
    return (type(value) is str and 0 < len(value.encode("utf-16-le")) <= maximum * 2 and value.strip() == value
            and not any(ord(char) < 32 or 127 <= ord(char) <= 159 for char in value))


def load(path, expected_version=None):
    raw = sets.read_bounded(Path(path), 16 * 1024)
    def unique_pairs(items):
        result = {}
        for key, value in items:
            sets.require(key not in result, "Duplicate announcement key")
            result[key] = value
        return result
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_pairs)
    sets.require(type(value) is dict and set(value) == {"schemaVersion", "version", "headline", "changes"}
                 and type(value["schemaVersion"]) is int and value["schemaVersion"] == 1, "Invalid announcement schema")
    sets.require(text(value["version"], 64) and (expected_version is None or value["version"] == expected_version),
                 "Announcement version does not match this release's Lua identity")
    sets.require(text(value["headline"], 160), "Invalid announcement headline")
    changes = value["changes"]
    sets.require(type(changes) is list and 1 <= len(changes) <= 12 and all(type(item) is dict
                 and set(item) == {"title", "text"} and text(item["title"], 80) and text(item["text"], 400)
                 for item in changes), "Invalid announcement sections")
    return value, dict(file=SOURCE, version=value["version"], sha256=hashlib.sha256(raw).hexdigest())
