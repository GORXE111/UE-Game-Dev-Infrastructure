"""Write fresh protocol vectors for Java/Python parity tests; dummy files only."""
import argparse
import copy
import hashlib
from pathlib import Path

import release_set as sets


def export(destination):
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=False)
    trust = dict(projectId="SampleGame", platform="Android_ARM64", channel="v106-host", baseReleaseId=100,
                 engineBuildId="engine-build", shellCompatibilityId="a" * 64, loaderVersion=1)
    policy0 = dict(schema=0, readable=[0], migrations=[])
    policy1 = dict(schema=1, readable=[0, 1], migrations=[{"from": 0, "to": 1, "id": "colalab-v0-to-v1"}])
    def product(release, policy):
        source = destination / ("payload-" + str(release))
        source.mkdir()
        records = []
        for name, role in (("Content/Paks/SampleGame-Android.pak", "content"), ("libUnreal.so", "native")):
            path = source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((role + "-host-fixture-" + str(release)).encode("ascii"))
            records.append(dict(path=name, role=role, size=path.stat().st_size, sha256=sets.digest(path)))
        value = dict(trust, format=1, kind="samplegame-release-set", releaseId=release, minLoaderVersion=1,
                     sourceCommit="b" * 40, nativeSourceHash="c" * 64, files=records, save=policy)
        value.pop("loaderVersion")
        value["buildId"] = sets.build_id(value)
        raw = sets.canonical(value)
        sets.manifest(raw, trust)
        sets.write_new(destination / (str(release) + ".json"), raw)
        return value
    base = product(100, policy0)
    target = product(101, policy1)
    trust["baseManifestSha256"] = hashlib.sha256(sets.canonical(base)).hexdigest()
    sets.write_new(destination / "trust.json", sets.canonical(trust))
    outcomes = []
    vectors = [("valid", sets.canonical(target))]
    for name, key, changed in (("engine", "engineBuildId", "other"), ("shell", "shellCompatibilityId", "e" * 64),
                               ("base", "baseReleaseId", 99), ("loader", "minLoaderVersion", 2),
                               ("boolean-version", "releaseId", True), ("build", "buildId", "f" * 64)):
        value = copy.deepcopy(target)
        value[key] = changed
        vectors.append((name, sets.canonical(value)))
    for name, path in (("traversal", "../escape.pak"), ("absolute", "C:/evil.pak"), ("device", "CON.txt")):
        value = copy.deepcopy(target)
        value["files"][0]["path"] = path
        value["buildId"] = sets.build_id(value)
        vectors.append((name, sets.canonical(value)))
    value = copy.deepcopy(target)
    value["files"].append(copy.deepcopy(value["files"][0]))
    value["buildId"] = sets.build_id(value)
    vectors.append(("duplicate-file", sets.canonical(value)))
    value = copy.deepcopy(target)
    value["save"]["migrations"] = []
    value["buildId"] = sets.build_id(value)
    vectors.append(("missing-migration", sets.canonical(value)))
    raw = sets.canonical(target)
    vectors.extend((("whitespace", b" " + raw), ("duplicate-key", raw[:-1] + b',"releaseId":101}')))
    for name, raw in vectors:
        accepted = True
        try:
            sets.manifest(raw, trust)
        except (ValueError, KeyError, TypeError):
            accepted = False
        sets.write_new(destination / ("vector-" + name + ".json"), raw)
        outcomes.append(dict(name=name, accepted=accepted))
    sets.write_new(destination / "outcomes.json", sets.canonical(dict(vectors=outcomes)))
    return outcomes


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    print(export(parser.parse_args().output))
