# Update and rollback model

The release unit combines native binaries and cooked content. For Windows that includes the launcher/game executable, required DLLs, and PAK files. For Android it includes the ARM64 native library and the complete cooked PAK set associated with the installed APK shell.

## Cold-start transaction

1. Fetch a bounded manifest over HTTPS and verify its signature against the public key embedded in the installed application.
2. Check platform, channel, base release, engine/build identity, native API, content compatibility, monotonic release number, and save migration policy.
3. Download into a fresh private generation. Reject duplicate paths, unsafe paths, missing files, unexpected files, size mismatches, and SHA-256 mismatches.
4. Prepare a separate save generation. Apply only a declared migration path; preserve the previous save generation for rollback.
5. Atomically select the candidate release and its matching save generation, then start a fresh game process.
6. Confirm health only when the new process reports the expected release, manifest digest, boot identity, and save schema. If confirmation never arrives, select the previous known-good pair on the next clean start.

Android uses a bootstrap activity to select the native library before Unreal starts. Windows uses an external launcher to select the payload root before creating the game process. Neither path replaces code inside a running process.

## Game readiness adapter

The producer embeds `assets/release-player.json` and `assets/release-base-manifest.json` for the Android managed launcher. Enable the Android bootstrap only in APKs with those matching assets. The Windows launcher passes `-SampleGameReleaseTicket` and `-UserDir` to the selected game.

The game adapter reads the current boot ticket, validates the selected world, content and Lua identity, and completes any save migration in the selected user directory. Only then does it report the matching attempt ID, release ID, manifest digest, build ID, process ID, user root, save schema and Lua version. Windows expects an atomic `health.json` at the ticket's acknowledgment path and commits after a normal game exit. Android acknowledges through the native subsystem and gates its update check on successful startup confirmation.

The independent Win64 ProfileSample implements this contract for its own map, PAK marker and Unreal SaveGame. Integrating projects supply their own readiness and migration checks. Keep simulated acknowledgments in the offline demo and host harness.

## Verify a real Win64 update on isolated HTTPS

Use three clean local checkouts of the sample. Leave the first as `baseline`. In the other two, change `ADOPTION_RELEASE_NATIVE_MARKER` in `Examples/ProjectProfile/ProfileSample/Source/ProfileSample/ProfileReleaseVariant.h` and `nativeMarker` in `Examples/ProjectProfile/ProfileSample/Content/ReleaseProof/release-sample.json` to `candidate` or `fault`. Commit both changes locally in each checkout. The source commit and archive bytes are bound into each build receipt.

From each checkout, run the [Win64 project profile](project-profile.md#运行验收) with `Examples/ProjectProfile/network-profile.json` and `-RequireBuildReceipt`. Use separate short ASCII output paths. The profile checks actual packaged startup and the matching native and PAK markers. The fault fixture only interrupts a managed launch with a boot ticket.

```powershell
python -X utf8 -B .\Tools\Adoption\verify_managed_win64.py `
  --baseline D:\UEWinRelease\Baseline\report.json `
  --candidate D:\UEWinRelease\Candidate\report.json `
  --fault D:\UEWinRelease\Fault\report.json `
  --output D:\UEWinRelease\Evidence
```

The verifier needs Python 3.11+, `cryptography` and a free local TCP port 443. It rechecks all files against each build receipt and signs the verified runtime payload with a disposable key. A temporary CA is scoped to the test. The HTTPS listener binds only to `127.0.0.1`. The test checks every immutable download against the producer digest, rejects a manifest and signature read across a version switch, installs the good candidate, then starts a fault candidate that writes only to its own save generation before exiting. A subsequent launch must recover the good candidate and the byte-identical original save. Keep the resulting `report.json`, HTTPS download inventory, launcher logs and game boot receipts for review.

This workflow covers the Win64 launcher from source and the actual packaged game on a local HTTPS origin. Production CDN, frozen installer, and Android APK and JNI readiness are separate qualification runs.

## Compatibility policy

The framework can deliver compatible game-level C++ implementation and cooked asset changes together after restart. Reflection layout, renamed types or properties, serialized data, and asset references still need compatibility review and, where needed, redirects or a real save migration. An unchanged module name or namespace is not proof that old references remain valid.

Changes to the installation shell—Android Java/manifest/permissions/UPL, signing identity, engine binaries, target/build setup, or bootstrap configuration—are outside the normal release-set update surface in this example and generally require a new full installation package.

The Android certificate pin in this sanitized snapshot is all zeroes. It intentionally prevents the sample from trusting any real APK signer until the application owner supplies and reviews the correct certificate identity.
