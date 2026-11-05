"""Publish original player archives in an independent immutable namespace."""
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
import time
import urllib.error
import urllib.request

import players


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, url):
        raise ValueError("Player verification forbids redirects")


class Host:
    def __init__(self, host, identity, port=22):
        players.require(isinstance(host, str) and re.fullmatch(r"[A-Za-z0-9_@.][A-Za-z0-9_@.-]{0,253}", host), "Invalid SSH host")
        players.require(0 < port < 65536, "Invalid SSH port")
        self.host, self.port = host, port
        self.options = ["-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=yes",
                        "-o", "ConnectTimeout=20", "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=6",
                        "-i", str(Path(identity).expanduser().resolve())]

    def run(self, action, plan, **parameters):
        payload = dict(action=action, plan=plan, **parameters)
        encoded = base64.b64encode(players.canonical(payload)).decode("ascii")
        command = ["ssh", *self.options, "-p", str(self.port), self.host, "python3", "-", encoded]
        source = Path(__file__).with_name("remote_players.py").read_bytes()
        players.require(hashlib.sha256(source).hexdigest() == plan["remoteScriptSha256"], "Remote worker changed after preparation")
        result = subprocess.run(command, input=source,
                                capture_output=True, timeout=600)
        players.require(result.returncode == 0, "Player SSH action failed: " + result.stderr.decode("utf-8", "replace"))
        return json.loads(result.stdout)

    def copy(self, source, stage_name, timeout):
        players.require(re.fullmatch(r"\.upload-[a-z0-9][a-z0-9._-]{0,63}-[a-f0-9]{32}", stage_name)
                        and ".." not in stage_name, "Invalid remote staging name")
        # Archives are already compressed. Keep bytes unchanged and use keepalive, not recompression.
        command = ["scp", *self.options, "-P", str(self.port), "-q", str(source),
                   f"{self.host}:/srv/ue-game-updates/players/{stage_name}/{source.name}"]
        result = subprocess.run(command, capture_output=True, timeout=timeout)
        players.require(result.returncode == 0, "Player upload failed: " + result.stderr.decode("utf-8", "replace"))


def opener():
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())


def response(path, method="GET", headers=None):
    request = urllib.request.Request(players.ORIGIN + path, method=method,
                                     headers={"Cache-Control": "no-cache", "Accept-Encoding": "identity", **(headers or {})})
    return opener().open(request, timeout=30)


def bounded(path, limit):
    with response(path) as stream:
        data = stream.read(limit + 1)
        players.require(stream.status == 200 and len(data) <= limit and stream.url == players.ORIGIN + path,
                        "Invalid bounded public response")
        return data


def verify_package(package, payload, destination, timeout):
    path, size, sha = package["url"], package["size"], package["sha256"]
    with response(path, "HEAD") as stream:
        players.require(stream.status == 200 and int(stream.headers.get("Content-Length", -1)) == size
                        and "immutable" in stream.headers.get("Cache-Control", ""), "Public package HEAD/cache differs")
    end = min(size, 65536) - 1
    with response(path, headers={"Range": f"bytes=0-{end}"}) as stream:
        prefix = stream.read(end + 2)
        with (payload / package["filename"]).open("rb") as local:
            expected = local.read(end + 1)
        players.require(stream.status == 206 and stream.headers.get("Content-Range") == f"bytes 0-{end}/{size}"
                        and prefix == expected, "Public package Range bytes differ")
    expected_sidecar = (sha + "  " + package["filename"] + "\n").encode("ascii")
    players.require(bounded(package["sha256Url"], 256) == expected_sidecar, "Public sidecar differs")
    temporary = destination.with_name(destination.name + ".partial")
    result, count, start = hashlib.sha256(), 0, time.monotonic()
    with response(path) as stream, temporary.open("xb") as output:
        players.require(stream.status == 200 and int(stream.headers.get("Content-Length", -1)) == size
                        and stream.headers.get("Content-Encoding", "identity") == "identity", "Public raw archive headers differ")
        while True:
            block = stream.read(min(1024**2, size - count + 1))
            if not block:
                break
            count += len(block)
            players.require(count <= size, "Public archive exceeds frozen size")
            output.write(block)
            result.update(block)
            players.require(time.monotonic() - start <= timeout, "External player verification observation timed out")
    players.require(count == size and result.hexdigest() == sha, "Complete public archive size/SHA differs")
    temporary.rename(destination)
    return {"filename": package["filename"], "size": count, "sha256": result.hexdigest(),
            "seconds": time.monotonic() - start, "fullPublicGetVerified": True,
            "verifiedDownload": str(destination), "headAndRangeVerified": True}


def publish(prepared, report_dir, host, timeout=21600, previous_report=None):
    plan = players.load_plan(prepared)
    report_dir = Path(report_dir).resolve()
    players.require(not report_dir.is_relative_to(Path(__file__).resolve().parents[3])
                    and not report_dir.is_relative_to(Path(prepared).resolve()), "Keep publication evidence outside repository/candidate")
    report_dir.mkdir(parents=True, exist_ok=False)
    report = dict(status="running", distributionId=plan["distributionId"], currentPromotionAttempted=False,
                  protectedGameChannelsChanged=None, fullPublicArchiveDownloads=[], prepared=str(prepared))
    report["preparedPlanSha256"] = players.digest(Path(prepared) / "prepared.json")
    report["startedUtc"] = datetime.now(timezone.utc).isoformat()
    stage = None
    try:
        required_local = sum(p["size"] for p in plan["catalog"]["packages"]) + 1024**3
        report["localAvailableBytes"] = shutil.disk_usage(report_dir).free
        report["localRequiredFreeBytes"] = required_local
        players.require(report["localAvailableBytes"] >= required_local, "Insufficient local verified-download/reserve space")
        previous = players.read_json(previous_report) if previous_report else None
        if previous is not None:
            players.require(previous["distributionId"] == plan["distributionId"]
                            and previous["preparedPlanSha256"] == report["preparedPlanSha256"], "Recovery candidate identity differs")
            stage = previous["stage"]
            report["stage"] = stage
            report["recoveryFrom"] = dict(path=str(previous_report), sha256=players.digest(previous_report), noArchiveReupload=True)
            report["immutableCommit"] = host.run("recover-commit", plan, stageName=stage["stageName"], before=stage["before"])
        else:
            stage = host.run("stage", plan)
            report["stage"] = stage
            players.write_new(report_dir / "stage.json", players.canonical(stage))
            for name in sorted(plan["files"]):
                host.copy(Path(prepared) / "payload" / name, stage["stageName"], timeout)
            report["immutableCommit"] = host.run("commit", plan, stageName=stage["stageName"], before=stage["before"])
        report["stage"] = stage
        report["commitAcknowledgedUtc"] = datetime.now(timezone.utc).isoformat()
        downloads = report_dir / "verified-downloads"
        downloads.mkdir()
        for package in plan["catalog"]["packages"]:
            prior = next((p for p in (previous or {}).get("fullPublicArchiveDownloads", [])
                          if p.get("filename") == package["filename"] and p.get("fullPublicGetVerified") is True), None)
            if prior:
                expected = Path(previous_report).resolve().parent / "verified-downloads" / package["filename"]
                original = Path(prior["verifiedDownload"])
                players.require(original.resolve() == expected and original.is_file() and not original.is_symlink()
                                and original.stat().st_size == package["size"] and players.digest(original) == package["sha256"],
                                "Prior completed public download changed")
                players.require(prior.get("size") == package["size"] and prior.get("sha256") == package["sha256"]
                                and prior.get("headAndRangeVerified") is True, "Prior public verification identity differs")
                report["fullPublicArchiveDownloads"].append({**prior, "reusedPriorCompletePublicVerification": True})
                continue
            report["fullPublicArchiveDownloads"].append(verify_package(package, Path(prepared) / "payload",
                                                                      downloads / package["filename"], timeout))
        report["currentPromotionAttempted"] = True
        recovered_current = report["immutableCommit"].get("current")
        if previous is not None and recovered_current == "releases/" + plan["distributionId"]:
            report["activation"] = {"recoveredAlreadyActivated": True, "current": recovered_current}
        else:
            report["activation"] = host.run("activate", plan, before=stage["before"])
        report["activationAcknowledgedUtc"] = datetime.now(timezone.utc).isoformat()
        players.require(bounded("/samplegame/players/manifest.json", 65536) == players.canonical(plan["catalog"]),
                        "Public active player catalog differs")
        after = host.run("inspect", plan)
        players.require(after["protected"] == stage["before"]["protected"], "Protected website/game channels changed")
        players.require(after["current"] == "releases/" + plan["distributionId"], "Public player pointer differs")
        report.update(status="passed", fullPublicDeliveryVerified=True, protectedAfter=after["protected"],
                      protectedGameChannelsChanged=False)
    except Exception as error:
        report.update(status="failed", error=repr(error))
        if stage and report["currentPromotionAttempted"]:
            try:
                report["playersPointerRollback"] = host.run("rollback", plan, before=stage["before"])
            except Exception as rollback_error:
                report["rollbackError"] = repr(rollback_error)
        if stage:
            try:
                after = host.run("inspect", plan)
                report["protectedGameChannelsChanged"] = after["protected"] != stage["before"]["protected"]
                report["failureCurrent"] = after["current"]
            except Exception as inspect_error:
                report["failureInspectionError"] = repr(inspect_error)
    finally:
        report["failedStageAndReleasesRetained"] = True
        players.write_new(report_dir / "report.json", players.canonical(report))
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "prepare-release-sets", "plan", "publish", "resume"))
    parser.add_argument("--prepared", type=Path, required=True)
    parser.add_argument("--distribution-id")
    parser.add_argument("--version")
    parser.add_argument("--headline")
    parser.add_argument("--windows-package", type=Path)
    parser.add_argument("--windows-download", type=Path)
    parser.add_argument("--android-package", type=Path)
    parser.add_argument("--android-download", type=Path)
    parser.add_argument("--android-native-channel")
    parser.add_argument("--windows-producer", type=Path)
    parser.add_argument("--android-producer", type=Path)
    parser.add_argument("--baseline-revision", type=int, default=3)
    parser.add_argument("--target-revision", type=int, default=4)
    parser.add_argument("--report-dir", type=Path)
    parser.add_argument("--previous-report", type=Path)
    parser.add_argument("--host")
    parser.add_argument("--identity", type=Path)
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--transfer-timeout", type=int, default=21600)
    args = parser.parse_args()
    players.require(60 <= args.transfer_timeout <= 86400, "Invalid external transfer observation limit")
    if args.action == "prepare":
        result = players.prepare(args.prepared, args.distribution_id, args.version, args.headline,
                                 args.windows_package, args.windows_download, args.android_package,
                                 args.android_download, args.android_native_channel, args.baseline_revision, args.target_revision)
    elif args.action == "prepare-release-sets":
        result = players.prepare_release_sets(args.prepared, args.distribution_id, args.version, args.headline,
                                              args.windows_producer, args.windows_download, args.android_producer,
                                              args.android_download, args.baseline_revision, args.target_revision)
    elif args.action == "plan":
        plan = players.load_plan(args.prepared)
        result = dict(distributionId=plan["distributionId"], payloadBytes=plan["payloadBytes"],
                      conservativeServerFreeBytes=plan["payloadBytes"] * 2 + 2 * 1024**3 + 1024**2,
                      remoteWritesExecuted=False, networkExecuted=False, files=plan["files"])
    else:
        players.require(args.host and args.identity and args.report_dir, "Publish requires explicit SSH and fresh evidence directory")
        players.require(args.action != "resume" or args.previous_report, "Resume requires an immutable previous report")
        result = publish(args.prepared, args.report_dir, Host(args.host, args.identity, args.port), args.transfer_timeout,
                         args.previous_report if args.action == "resume" else None)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    if result.get("status") == "failed":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
