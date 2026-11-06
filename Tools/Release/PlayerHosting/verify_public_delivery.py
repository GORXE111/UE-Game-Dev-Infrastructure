"""Read-only HTTPS delivery verification against a pinned publication plan."""

import argparse
from contextlib import contextmanager
import hashlib
from http.client import HTTPException
import json
from pathlib import Path
import re
import time
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import ProxyHandler, Request, build_opener

from cryptography.exceptions import InvalidSignature

from deploy_players import NoRedirect
from deploy_release_sets import remote, sets

MAX_PLAN = 4 * sets.MAX_MANIFEST
SAMPLE_BYTES = 4096
ROUTE_SEGMENT = re.compile(r"[a-z][a-z0-9_-]{0,63}\Z")
RECORD_FIELDS = {"size", "sha256"}
REPORT_HEADERS = ("Cache-Control", "Accept-Ranges", "ETag", "Age", "Via", "X-Cache", "CF-Cache-Status", "Server")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def origin(value):
    parsed = urlsplit(value)
    sets.require(value == "https://" + parsed.netloc and parsed.scheme == "https"
                 and parsed.hostname and not parsed.username and not parsed.password
                 and not parsed.path and not parsed.query and not parsed.fragment and parsed.port in (None, 443)
                 and re.fullmatch(r"[A-Za-z0-9.-]+(?::443)?", parsed.netloc), "Expected an exact HTTPS origin")
    return value


def record(value):
    sets.require(type(value) is dict and set(value) == RECORD_FIELDS, "Invalid publication inventory record")
    sets.number(value["size"], 1, sets.MAX_FILE)
    sets.sha(value["sha256"])
    return value


def same_bytes(raw, expected):
    return len(raw) == expected["size"] and sha(raw) == expected["sha256"]


def read_plan(path, expected):
    raw = sets.read_bounded(path, MAX_PLAN)
    sets.require(sha(raw) == sets.sha(expected), "Prepared publication plan SHA-256 differs")
    # Existing installer plans use pretty JSON. The trusted hash covers the exact encoding.
    def unique(pairs):
        result = dict(pairs)
        sets.require(len(result) == len(pairs), "Duplicate publication plan key")
        return result

    plan = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=unique)
    sets.require(type(plan) is dict and plan.get("schemaVersion") == 1 and type(plan.get("files")) is dict,
                 "Invalid publication plan")
    inventory = plan["files"]
    sets.require(0 < len(inventory) <= sets.MAX_FILES + 5 and
                 len({name.lower() for name in inventory}) == len(inventory), "Invalid or case-aliased inventory")
    for name, item in inventory.items():
        sets.relative(name)
        record(item)
    sets.require(sum(item["size"] for item in inventory.values()) == plan["payloadBytes"], "Publication byte accounting differs")
    return plan


def joint_paths(path, plan, prefix):
    channel, number = plan["channel"], sets.number(plan["releaseId"], 1, 999_999_999)
    sets.require(ROUTE_SEGMENT.fullmatch(channel), "Invalid release channel")
    route = f"{prefix}/{channel}/updates/"
    version = f"versions/{number}/"
    files = plan["files"]
    payload = path.parent / "payload"
    raw = sets.read_bounded(payload / "manifest.json", sets.MAX_MANIFEST)
    signature = sets.read_bounded(payload / "manifest.json.sig", 4096)
    sets.require(sha(raw) == plan["manifestSha256"], "Pinned release manifest differs")
    expected_algorithm = {"Windows": "Ed25519", "Android_ARM64": "SHA256withRSA"}.get(plan["trust"]["platform"])
    sets.require(expected_algorithm and plan["verification"]["algorithm"] == expected_algorithm, "Invalid platform signing policy")
    remote.verify_signature(raw, signature, plan["verification"])
    value = sets.parse(raw)
    sets.require(value["kind"] + "-publication" == plan["kind"] and value["releaseId"] == number
                 and value["channel"] == channel and value["buildId"] == sets.build_id(value)
                 and all(value[key] == plan["trust"][key] and type(value[key]) is type(plan["trust"][key])
                         for key in sets.BINDINGS), "Signed release identity differs from the plan")
    expected = {version + "release-display.json"}
    for name, data in (("manifest.json", raw), ("manifest.json.sig", signature)):
        sets.require(same_bytes(data, files[name]) and same_bytes(data, files[version + name]), "Metadata inventory differs")
        expected.update((name, version + name))
    artifact_paths = []
    for item in value["files"]:
        name = version + "payload/" + sets.relative(item["path"])
        sets.require(name not in expected and files[name] == {key: item[key] for key in RECORD_FIELDS},
                     "Signed payload inventory differs")
        expected.add(name)
        artifact_paths.append(route + name)
    sets.require(artifact_paths and set(files) == expected, "Publication contains unbound files")
    immutable = {route + name: item for name, item in files.items() if name.startswith(version)}
    current = {route + "manifest.json": files["manifest.json"], route + "manifest.json.sig": files["manifest.json.sig"]}
    return immutable, current, artifact_paths, route + version + "payload/delivery-readback-missing", "release-set"


def installer_paths(plan, prefix):
    distribution = sets.relative(plan["distributionId"])
    sets.require("/" not in distribution, "Invalid installer distribution ID")
    catalog, files = plan["catalog"], plan["files"]
    sets.require(catalog["distributionId"] == distribution and catalog["schemaVersion"] == 1, "Invalid installer catalog")
    route = f"{prefix}/players/"
    version = route + "releases/" + distribution + "/"
    catalog_raw = (json.dumps(catalog, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
    sets.require(same_bytes(catalog_raw, files["manifest.json"]), "Installer catalog differs from pinned inventory")
    expected, artifact_paths = {"manifest.json"}, []
    for package in catalog["packages"]:
        filename = sets.relative(package["filename"])
        sidecar = filename + ".sha256"
        sets.require("/" not in filename and filename not in expected and package["url"] == version + filename
                     and package["sha256Url"] == version + sidecar
                     and files[filename] == {key: package[key] for key in RECORD_FIELDS}, "Invalid installer path or identity")
        sets.require(same_bytes((package["sha256"] + "  " + filename + "\n").encode("ascii"), files[sidecar]),
                     "Installer checksum sidecar differs")
        expected.update((filename, sidecar))
        artifact_paths.append(version + filename)
    sets.require(artifact_paths and expected == set(files), "Unbound installer inventory")
    missing = catalog["packages"][0]["filename"].split("-", 1)[0] + "-DeliveryReadbackMissing.zip"
    return ({version + name: item for name, item in files.items() if name != "manifest.json"},
            {route + "manifest.json": files["manifest.json"]}, artifact_paths, version + missing, "installers")


def cache_tokens(headers):
    return {entry.strip().lower() for entry in headers.get("Cache-Control", "").split(",")}


class Readback:
    def __init__(self, endpoint, timeout):
        self.endpoint, self.timeout = endpoint, timeout
        self.opener = build_opener(ProxyHandler({}), NoRedirect())

    @contextmanager
    def response(self, path, method="GET", *, byte_range=None, current=False):
        url = self.endpoint + path
        headers = {"Accept-Encoding": "identity"}
        if current:
            headers["Cache-Control"] = "no-cache"
        if byte_range:
            headers["Range"] = byte_range
        with self.opener.open(Request(url, headers=headers, method=method), timeout=min(30, self.timeout)) as stream:
            sets.require(stream.geturl() == url and stream.headers.get("Content-Encoding", "identity").lower() == "identity",
                         f"Unexpected HTTPS route or encoding: {path}")
            yield stream

    def current(self, path, expected, kind):
        with self.response(path, current=True) as stream:
            allowed = {"no-store"} if kind == "release-set" else {"no-store", "no-cache"}
            sets.require(stream.status == 200 and cache_tokens(stream.headers) & allowed
                         and "immutable" not in cache_tokens(stream.headers), f"Unexpected current metadata cache policy: {path}")
            raw = stream.read(expected["size"] + 1)
            sets.require(same_bytes(raw, expected), f"Current metadata differs from the pinned publication: {path}")
            return dict(path=path, size=len(raw), sha256=sha(raw), cacheControl=stream.headers["Cache-Control"])

    def full(self, path, expected):
        digest, count, started = hashlib.sha256(), 0, time.monotonic()
        prefix, tail = b"", b""
        with self.response(path) as stream:
            sets.require(stream.status == 200 and stream.headers.get("Content-Length") == str(expected["size"])
                         and not stream.headers.get("Content-Range") and "immutable" in cache_tokens(stream.headers),
                         f"Unexpected immutable full GET response: {path}")
            headers = {key: stream.headers[key] for key in REPORT_HEADERS if key in stream.headers}
            for block in iter(lambda: stream.read1(1024 * 1024), b""):
                count += len(block)
                sets.require(count <= expected["size"] and time.monotonic() - started <= self.timeout,
                             f"HTTPS transfer exceeded its frozen limit: {path}")
                digest.update(block)
                if len(prefix) < SAMPLE_BYTES:
                    prefix += block[:SAMPLE_BYTES - len(prefix)]
                tail = block[-SAMPLE_BYTES:] if len(block) >= SAMPLE_BYTES else (tail + block)[-SAMPLE_BYTES:]
        sets.require(count == expected["size"] and digest.hexdigest() == expected["sha256"],
                     f"Complete HTTPS size/SHA-256 differs: {path} ({count}/{expected['size']} bytes)")
        return dict(path=path, size=count, sha256=digest.hexdigest(), responseHeaders=headers,
                    seconds=round(time.monotonic() - started, 3)), prefix, tail

    def range_checks(self, path, size, prefix, tail):
        with self.response(path, "HEAD") as stream:
            sets.require(stream.status == 200 and stream.headers.get("Content-Length") == str(size)
                         and "immutable" in cache_tokens(stream.headers), f"Unexpected immutable HEAD: {path}")
        samples = {0: prefix, size - len(tail): tail}
        for start, data in sorted(samples.items()):
            end = start + len(data) - 1
            with self.response(path, byte_range=f"bytes={start}-{end}") as stream:
                sets.require(stream.status == 206 and stream.headers.get("Content-Range") == f"bytes {start}-{end}/{size}"
                             and stream.headers.get("Content-Length") == str(len(data))
                             and stream.read(len(data) + 1) == data, f"HTTPS Range bytes differ: {path}")
        return dict(path=path, head=True, verifiedRanges=len(samples))

    def missing(self, path):
        try:
            with self.response(path) as stream:
                raise ValueError(f"Unexpected missing-file status {stream.status}: {path}")
        except HTTPError as error:
            with error:
                observed = error.headers.get("Cache-Control")
                sets.require(error.code == 404 and "no-store" in cache_tokens(error.headers)
                             and "immutable" not in cache_tokens(error.headers),
                             f"Unexpected missing-file cache policy: {path} (HTTP {error.code}, Cache-Control {observed!r})")
                return dict(path=path, status=error.code, cacheControl=observed)


def verify(args, output, report):
    plan = read_plan(args.prepared, args.expected_plan_sha256)
    immutable, current, artifacts, missing, kind = (joint_paths(args.prepared, plan, args.prefix) if "kind" in plan
                                                    else installer_paths(plan, args.prefix))
    report.update(kind=kind, plannedFiles=len(immutable), plannedBytes=sum(item["size"] for item in immutable.values()))
    web = Readback(args.origin, args.timeout)
    report["phase"] = "current-before"
    if args.check_current:
        report["currentBefore"] = [web.current(path, item, kind) for path, item in current.items()]
    report["phase"] = "immutable-downloads"
    probes = set(artifacts if kind == "installers" else [max(artifacts, key=lambda path: immutable[path]["size"])])
    report.update(files=[], rangeChecks=[])
    with (output / "public-progress.jsonl").open("xb") as progress:
        for path, item in sorted(immutable.items()):
            report["lastRequestedPath"] = path
            result, prefix, tail = web.full(path, item)
            report["files"].append(result)
            progress.write(sets.canonical(result) + b"\n")
            progress.flush()
            if path in probes:
                report["rangeChecks"].append(web.range_checks(path, item["size"], prefix, tail))
    if args.check_current:
        report["phase"] = "current-after"
        report["currentAfter"] = [web.current(path, item, kind) for path, item in current.items()]
    report["phase"] = "missing-file"
    report["missing"] = web.missing(missing)
    report.update(status="passed", phase="complete")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepared", type=Path, required=True, help="Pinned prepared.json file")
    parser.add_argument("--expected-plan-sha256", required=True, help="Digest from a trusted build or publication receipt")
    parser.add_argument("--origin", type=origin, required=True)
    parser.add_argument("--prefix", default="/samplegame")
    parser.add_argument("--report-dir", type=Path, required=True)
    parser.add_argument("--check-current", action="store_true", help="Require current metadata to match before and after readback")
    parser.add_argument("--timeout", type=int, default=900, help="Maximum seconds per full transfer")
    args = parser.parse_args()
    sets.require(re.fullmatch(r"/[a-z][a-z0-9_-]{0,63}", args.prefix) and 5 <= args.timeout <= 21600,
                 "Invalid public route prefix or timeout")
    output = args.report_dir.resolve()
    sets.require(not output.is_relative_to(Path(__file__).resolve().parents[3])
                 and not output.is_relative_to(args.prepared.resolve().parent), "Keep reports outside source and prepared inputs")
    output.mkdir()
    report = dict(status="failed", phase="plan", origin=args.origin, prefix=args.prefix,
                  preparedPlanSha256=args.expected_plan_sha256, readOnly=True)
    try:
        verify(args, output, report)
    except (ValueError, OSError, KeyError, HTTPException, InvalidSignature) as error:
        report["error"] = str(error) or type(error).__name__
    report["verifiedFiles"] = len(report.get("files", []))
    report["verifiedBytes"] = sum(item["size"] for item in report.get("files", []))
    sets.write_new(output / "report.json", sets.canonical(report))
    print(json.dumps({key: report[key] for key in ("status", "phase", "verifiedFiles", "verifiedBytes", "error") if key in report}
                     | {"report": str(output / "report.json")}, ensure_ascii=False))
    return int(report["status"] != "passed")


if __name__ == "__main__":
    raise SystemExit(main())
