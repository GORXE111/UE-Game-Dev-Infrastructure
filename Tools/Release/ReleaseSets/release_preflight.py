"""Read-only release planning: classify actual changes, never sign, activate or publish."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess

import compatibility
import content_plan
import release_identity
import release_set as sets

# This is the implemented migration contract, not a caller-supplied promise.
CURRENT_SAVE_POLICY = compatibility.CURRENT_SAVE_POLICY


def assess(base, project, engine_id, base_save, plan):
    content_plan.validate(plan["plan"])
    sets.require(plan["sha256"] == hashlib.sha256(sets.canonical(plan["plan"])).hexdigest(), "Content plan digest differs")
    result = compatibility.compare(base, project, engine_id, base_save, CURRENT_SAVE_POLICY)
    identity, identity_errors = None, []
    try:
        identity = release_identity.snapshot(project)
    except (OSError, ValueError) as error:
        identity_errors.append(str(error))
    maps = plan["plan"]["requiredMaps"]
    missing = []
    from windows_pipeline import check_cook_maps
    for name in maps:
        try:
            check_cook_maps(project, (name,))
        except (OSError, ValueError) as error:
            missing.append(dict(map=name, error=str(error)))
    changes = result["changes"]
    native = [item["path"] for item in changes if item["kind"] == "gameplay-native"]
    headers = [path for path in native if Path(path).suffix.lower() in (".h", ".hpp", ".inl")]
    deleted_content = [item["path"] for item in changes if item["kind"] == "cooked-content" and item["change"] == "deleted"]
    changed_maps = [item for item in changes if item["kind"] == "cooked-content" and item["path"].lower().endswith(".umap")]
    # Plugin mount points need their own explicit policy; never guess /Game for them.
    unplanned_maps = [item["path"] for item in changed_maps
                      if not item["path"].startswith("Content/") or "/Game/" + item["path"][8:-5] not in maps]
    reviews = ["save-contract-and-historical-sample-review"] if changes else []
    if native:
        reviews.extend(["native-gameplay-behavior-review", "native-performance-impact-review"])
    if headers:
        reviews.append("reflection-blueprint-and-serialized-layout-review")
    if deleted_content:
        reviews.append("asset-redirects-and-persistent-reference-review")
    if unplanned_maps:
        reviews.append("changed-map-shipping-intent-review")
    if result["requiresNewBase"]:
        decision = "new-baseline-required"
    elif identity_errors:
        decision = "blocked-invalid-lua-identity"
    elif missing:
        decision = "blocked-missing-cook-roots"
    elif changes:
        decision = "review-and-runtime-evidence-required"
    else:
        decision = "no-project-input-changes"
    return dict(format=1, kind="samplegame-release-preflight", decision=decision,
                baselineEngineBuildId=base["engineBuildId"], engineBuildId=engine_id,
                shellCompatibilityId=result["shellCompatibilityId"], requiresNewBase=result["requiresNewBase"],
                reasons=result["reasons"], contentPlan=plan, missingSourceMaps=missing,
                luaIdentity=identity, identityErrors=identity_errors,
                changes=changes, changedNative=native, changedHeaders=headers,
                deletedContent=deleted_content, unplannedChangedMaps=unplanned_maps,
                savePolicy=CURRENT_SAVE_POLICY, requiredReviews=reviews,
                requiredEvidence=result["requiredEvidence"],
                requiredRuntimeChecks=["map-load:" + name for name in maps] + [
                    "native-content-save-pair-cold-start", "download-interruption-retry", "corrupt-payload-rejection",
                    "unconfirmed-start-whole-set-rollback", "previous-save-generation-restoration"],
                limitations=["Source classification does not prove ABI, reflection or save compatibility.",
                             "Headers are conservatively flagged; this is not a UHT/ABI parser.",
                             "Local baseline metadata is not signature-verified by this planning command.",
                             "Observed Engine BuildId is not a complete toolchain or engine-input freeze.",
                             "No UE process or device was run and no runtime evidence was accepted."],
                releaseReady=False, productionQualified=False, deviceRuntimeValidated=False,
                publicChannelsChanged=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ("project", "engine", "shell-freeze", "base-manifest", "output"):
        parser.add_argument("--" + flag, type=Path, required=True)
    args = parser.parse_args()
    project, engine = args.project.resolve(), args.engine.resolve()
    from windows_pipeline import current_commit, fresh_output
    base_raw = sets.read_bounded(args.shell_freeze, 16 * 1024**2)
    manifest_raw = sets.read_bounded(args.base_manifest, sets.MAX_MANIFEST)
    base = sets.parse(base_raw, 16 * 1024**2)
    manifest = sets.parse(manifest_raw)
    sets.require(manifest.get("kind") == "samplegame-release-set" and manifest.get("projectId") == "SampleGame"
                 and manifest.get("platform") in ("Windows", "Android_ARM64")
                 and type(manifest.get("baseReleaseId")) is int and manifest.get("releaseId") == manifest["baseReleaseId"],
                 "Use an original SampleGame baseline manifest, not a candidate or another project")
    sets.require(manifest["engineBuildId"] == base["engineBuildId"]
                 and manifest["shellCompatibilityId"] == base["shellCompatibilityId"], "Baseline manifest and freeze differ")
    modules = engine / "Engine/Binaries/Win64/UnrealEditor.modules"
    modules_raw = sets.read_bounded(modules, 1024**2)
    engine_id = json.loads(modules_raw.decode("utf-8-sig"))["BuildId"]
    commit = current_commit(project, clean=False)
    status = subprocess.run(["git", "-C", str(project), "status", "--porcelain=v1", "--untracked-files=all"],
                            capture_output=True, text=True, encoding="utf-8", check=True).stdout
    report = assess(base, project, engine_id, manifest["save"], content_plan.snapshot())
    report.update(sourceCommit=commit, workingTreeClean=not status.strip(), workingTreeStatus=status,
                  baselinePlatform=manifest["platform"], baselineReleaseId=manifest["baseReleaseId"],
                  baselineBuildId=manifest["buildId"],
                  baselineFreezeSha256=hashlib.sha256(base_raw).hexdigest(),
                  baselineManifestSha256=hashlib.sha256(manifest_raw).hexdigest(),
                  observedEngineModulesSha256=hashlib.sha256(modules_raw).hexdigest())
    output = fresh_output(args.output, project, engine)
    sets.write_new(output / "report.json", sets.canonical(report))
    print(json.dumps(dict(decision=report["decision"], changes=len(report["changes"]),
                         requiredMaps=len(report["contentPlan"]["plan"]["requiredMaps"]),
                         releaseReady=False, report=str(output / "report.json")), ensure_ascii=False))
    # Dirty trees are useful for planning but never approve a deliverable.
    return 2 if report["requiresNewBase"] or report["missingSourceMaps"] or report["identityErrors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
