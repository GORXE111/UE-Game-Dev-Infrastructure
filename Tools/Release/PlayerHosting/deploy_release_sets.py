"""Prepare and publish actual signed V106 native/content cohorts, with CAS recovery.

Only the reviewed release-set channels are writable. Private signing/build evidence
stays local. Every published byte is verified locally, over SSH and through HTTPS
before the active channel pointer is atomically promoted.
"""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time

import deploy_players
import players
import remote_release_sets as remote

CORE_PATH = Path(__file__).resolve().parents[1] / "ReleaseSets/release_set.py"
sys.path.insert(0, str(CORE_PATH.parent))
import release_set as sets
remote.CORE = vars(sets)


def verification(config):
    if config["trust"]["platform"] == "Windows":
        return dict(algorithm="Ed25519", publicKeyHex=sets.sha(config["publicKeyHex"]))
    players.require(config.get("signatureAlgorithm") == "SHA256withRSA", "Expected fixed Android RSA algorithm")
    return {key: config[key] for key in ("certificateBase64", "certificateSha256")} | {"algorithm": "SHA256withRSA"}


def validate_display(raw, value, manifest_sha):
    players.require(0 < len(raw) <= 16 * 1024, "Display metadata exceeds limit")
    display = json.loads(raw)
    players.require(display.get("schemaVersion") == 1 and display.get("kind") == "samplegame-release-set-display"
                    and display.get("manifestSha256") == manifest_sha
                    and all(display.get(key) == value[key] for key in ("projectId", "platform", "channel", "baseReleaseId", "releaseId", "buildId")),
                    "Display identity differs from signed release set")
    text = lambda item, maximum: (isinstance(item, str) and 0 < len(item) <= maximum and item.strip() == item
                                  and not any(ord(char) < 32 or 127 <= ord(char) <= 159 for char in item))
    players.require(text(display.get("version"), 64) and re.fullmatch(
                    r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:[-+][A-Za-z0-9][A-Za-z0-9.-]*)?", display["version"])
                    and text(display.get("headline"), 160), "Invalid display text")
    changes = display.get("changes")
    players.require(isinstance(changes, list) and len(changes) <= 12
                    and all(type(item) is dict and set(item) == {"title", "text"}
                            and text(item["title"], 80) and text(item["text"], 400) for item in changes), "Invalid display notes")


def prepare(source, config_path, display_path, prepared):
    source, prepared = Path(source).resolve(), Path(prepared).resolve()
    players.require(not prepared.exists() and not prepared.is_relative_to(Path(__file__).resolve().parents[3]), "Use fresh external publication directory")
    config = sets.parse(sets.read_bounded(config_path, sets.MAX_MANIFEST))
    raw = sets.read_bounded(source / "manifest.json", sets.MAX_MANIFEST)
    value = sets.manifest(raw, config["trust"])
    channel, release = value["channel"], value["releaseId"]
    players.require(channel in remote.CHANNELS and value["platform"] == remote.CHANNELS[channel], "Only reviewed release-set channels may be published")
    players.require(config["manifestUrl"] == f"{players.ORIGIN}/samplegame/{channel}/updates/manifest.json", "Installed endpoint differs")
    signature = sets.read_bounded(source / "manifest.json.sig", 4096)
    verifier = verification(config)
    remote.verify_signature(raw, signature, verifier)
    payload_source = source / f"versions/{release}/payload"
    sets.verify_tree(payload_source, value["files"])
    manifest_sha = hashlib.sha256(raw).hexdigest()
    display = sets.read_bounded(display_path, 16 * 1024)
    validate_display(display, value, manifest_sha)
    prefix = f"versions/{release}/"
    file_sources = {prefix + "payload/" + item["path"]: payload_source / item["path"] for item in value["files"]}
    metadata = {"manifest.json": raw, "manifest.json.sig": signature,
                prefix + "manifest.json": raw, prefix + "manifest.json.sig": signature, prefix + "release-display.json": display}
    records = {name: dict(size=path.stat().st_size, sha256=sets.digest(path)) for name, path in file_sources.items()}
    records.update({name: dict(size=len(data), sha256=hashlib.sha256(data).hexdigest()) for name, data in metadata.items()})
    plan = dict(schemaVersion=1, kind="samplegame-release-set-publication", channel=channel, releaseId=release,
                trust=config["trust"], verification=verifier, manifestSha256=manifest_sha, files=records,
                payloadBytes=sum(item["size"] for item in records.values()), coreSha256=sets.digest(CORE_PATH),
                remoteScriptSha256=sets.digest(Path(remote.__file__)), publicationExecuted=False,
                inputReceipts=[dict(path=str(Path(path).resolve()), sha256=sets.digest(path))
                               for path in (config_path, source / "manifest.json", source / "manifest.json.sig", display_path)])
    remote.validate(plan)
    prepared.mkdir(parents=True)
    public = prepared / "payload"
    public.mkdir()
    for name, path in file_sources.items():
        destination = public / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, destination)
    for name, data in metadata.items():
        destination = public / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        sets.write_new(destination, data)
    remote.verify(public, plan)
    sets.write_new(prepared / "prepared.json", sets.canonical(plan))
    return plan


def load(prepared):
    prepared = Path(prepared)
    plan = sets.parse(sets.read_bounded(prepared / "prepared.json", 4 * sets.MAX_MANIFEST), 4 * sets.MAX_MANIFEST)
    remote.validate(plan)
    players.require(plan["coreSha256"] == sets.digest(CORE_PATH)
                    and plan["remoteScriptSha256"] == sets.digest(Path(remote.__file__)), "Publisher/protocol changed after preparation")
    remote.verify(prepared / "payload", plan)
    return plan


class Host(deploy_players.Host):
    def run(self, action, plan, **parameters):
        players.require(sets.digest(CORE_PATH) == plan["coreSha256"]
                        and sets.digest(Path(remote.__file__)) == plan["remoteScriptSha256"], "Verified remote implementation changed")
        request = dict(action=action, plan=plan, core=base64.b64encode(CORE_PATH.read_bytes()).decode(), **parameters)
        encoded = base64.b64encode(sets.canonical(request)).decode()
        # Put the request in stdin; real complete manifests may exceed SSH's
        # shell argument limits. The worker has only public inputs.
        worker = Path(remote.__file__).read_bytes().replace(b"from __future__ import annotations\n", b"")
        program = ("import base64,json\nREQUEST=json.loads(base64.b64decode('" + encoded + "'))\n").encode() + worker
        result = subprocess.run(["ssh", *self.options, "-p", str(self.port), self.host, "python3", "-"],
                                input=program, capture_output=True, timeout=1800)
        players.require(result.returncode == 0, "Release-set SSH action failed: " + result.stderr.decode("utf-8", "replace"))
        return json.loads(result.stdout)

    def copy(self, source, plan, token, name, timeout):
        players.require(re.fullmatch(r"[a-f0-9]{32}", token), "Invalid stage token")
        sets.relative(name)
        destination = f"/srv/ue-game-updates/channels/{plan['channel']}/releases/.upload-{plan['releaseId']}-{token}/{name}"
        result = subprocess.run(["scp", *self.options, "-P", str(self.port), "-q", str(source), f"{self.host}:{destination}"],
                                capture_output=True, timeout=timeout)
        players.require(result.returncode == 0, "Release-set upload failed: " + result.stderr.decode("utf-8", "replace"))


def public_verify(plan, payload, report_dir, timeout):
    verified = []
    prefix = f"versions/{plan['releaseId']}/"
    for name, item in sorted(plan["files"].items()):
        if not name.startswith(prefix):
            continue
        count, result, started = 0, hashlib.sha256(), time.monotonic()
        path = f"/samplegame/{plan['channel']}/updates/{name}"
        with deploy_players.response(path) as stream:
            players.require(stream.status == 200 and int(stream.headers.get("Content-Length", -1)) == item["size"]
                            and "immutable" in stream.headers.get("Cache-Control", "")
                            and stream.headers.get("Content-Encoding", "identity") == "identity", "Public release-set headers differ")
            while True:
                block = stream.read(min(1024**2, item["size"] - count + 1))
                if not block:
                    break
                count += len(block); result.update(block)
                players.require(count <= item["size"] and time.monotonic() - started <= timeout, "Public transfer exceeded frozen bound")
        players.require(count == item["size"] and result.hexdigest() == item["sha256"], "Complete public release-set size/SHA differs")
        verified.append(dict(path=name, size=count, sha256=result.hexdigest(), fullPublicGetVerified=True))
        # Persist progress without altering original producer records. A failed
        # later file must not erase already completed byte observations.
        (report_dir / "public-progress.json").write_bytes(sets.canonical(verified))
    return verified


def publish(prepared, report_dir, host, timeout=21600, previous_report=None):
    plan = load(prepared)
    report_dir = Path(report_dir).resolve()
    players.require(not report_dir.exists() and not report_dir.is_relative_to(Path(__file__).resolve().parents[3])
                    and not report_dir.is_relative_to(Path(prepared).resolve()), "Use fresh external evidence directory")
    report_dir.mkdir(parents=True)
    report = dict(status="running", channel=plan["channel"], releaseId=plan["releaseId"],
                  preparedPlanSha256=sets.digest(Path(prepared) / "prepared.json"), startedUtc=datetime.now(timezone.utc).isoformat(),
                  currentPromotionAttempted=False, producerEvidenceModified=False)
    stage = None
    try:
        if previous_report:
            previous = players.read_json(previous_report)
            players.require(previous["preparedPlanSha256"] == report["preparedPlanSha256"]
                            and previous["channel"] == plan["channel"] and previous["releaseId"] == plan["releaseId"], "Resume inputs differ")
            stage = previous["stage"]
            progress = host.run("resume", plan, token=stage["token"], before=stage["before"])
            report["recoveryFrom"] = dict(path=str(previous_report), sha256=sets.digest(previous_report))
        else:
            stage = host.run("stage", plan)
            progress = {"immutablePresent": False}
        report["stage"] = stage
        sets.write_new(report_dir / "stage.json", sets.canonical(stage))
        if not progress["immutablePresent"]:
            for name in sorted(plan["files"]):
                host.copy(Path(prepared) / "payload" / name, plan, stage["token"], name, timeout)
            report["immutableCommit"] = host.run("commit", plan, token=stage["token"], before=stage["before"])
        else:
            report["immutableCommit"] = progress
        report["fullPublicFiles"] = public_verify(plan, Path(prepared) / "payload", report_dir, timeout)
        report["currentPromotionAttempted"] = True
        report["activation"] = ({"recoveredAlreadyActivated": True} if progress.get("alreadyActivated") else
                                host.run("activate", plan, token=stage["token"], before=stage["before"]))
        manifest_path = f"/samplegame/{plan['channel']}/updates/manifest.json"
        players.require(deploy_players.bounded(manifest_path, sets.MAX_MANIFEST) == (Path(prepared) / "payload/manifest.json").read_bytes()
                        and deploy_players.bounded(manifest_path + ".sig", 4096) == (Path(prepared) / "payload/manifest.json.sig").read_bytes(),
                        "Public active manifest/signature differ")
        after = host.run("inspect", plan)
        players.require(after["protected"] == stage["before"]["protected"]
                        and after["current"] == "releases/" + str(plan["releaseId"]), "Published pointer/protected state differs")
        report["leaseReleased"] = host.run("release-lock", plan, token=stage["token"], before=stage["before"])
        report.update(status="passed", fullPublicDeliveryVerified=True, protectedChanged=False, finishedUtc=datetime.now(timezone.utc).isoformat())
    except Exception as error:
        report.update(status="failed", error=repr(error))
        if stage and report["currentPromotionAttempted"]:
            try:
                report["pointerRollback"] = host.run("rollback", plan, token=stage["token"], before=stage["before"])
            except Exception as rollback_error:
                report["rollbackError"] = repr(rollback_error)
        report["failedFilesAndLeaseRetained"] = True
    finally:
        sets.write_new(report_dir / "report.json", sets.canonical(report))
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "plan", "inspect", "publish", "resume"))
    parser.add_argument("--prepared", type=Path, required=True)
    parser.add_argument("--source", type=Path)
    parser.add_argument("--config", type=Path)
    parser.add_argument("--display", type=Path)
    parser.add_argument("--host")
    parser.add_argument("--identity", type=Path)
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--report-dir", type=Path)
    parser.add_argument("--previous-report", type=Path)
    parser.add_argument("--transfer-timeout", type=int, default=21600)
    args = parser.parse_args()
    players.require(60 <= args.transfer_timeout <= 86400, "Invalid transfer timeout")
    if args.action == "prepare":
        result = prepare(args.source, args.config, args.display, args.prepared)
    elif args.action == "plan":
        plan = load(args.prepared)
        result = dict(channel=plan["channel"], releaseId=plan["releaseId"], payloadBytes=plan["payloadBytes"],
                      conservativeServerFreeBytes=plan["payloadBytes"] * 2 + 2 * 1024**3, networkExecuted=False, publicationExecuted=False)
    else:
        players.require(args.host and args.identity, "Explicit SSH host and deployment identity are required")
        host = Host(args.host, args.identity, args.port)
        if args.action == "inspect":
            result = host.run("inspect", load(args.prepared))
        else:
            players.require(args.report_dir and (args.action != "resume" or args.previous_report), "Fresh report directory and resume evidence are required")
            result = publish(args.prepared, args.report_dir, host, args.transfer_timeout,
                             args.previous_report if args.action == "resume" else None)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    if result.get("status") == "failed":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
