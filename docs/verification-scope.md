# Verification scope and roadmap

## Evidence from the source project

The private source project completed a V1.0.7 Development baseline and public update publication for Windows PC and an Android ARM64 emulator. Its local qualification covered fresh installation, update selection, code/content checks, save-generation handover, pre-health failure recovery, cached-content corruption recovery, announcement display, and public archive downloads checked against complete SHA-256 values.

The public export uses sample identifiers, an example domain and placeholder signing identities. Its checks cover generated source files, the offline release transaction and host tests. UE compilation, Cook and packaged game launches in a fresh project still require a separate run.

## Public repository checks

- PowerShell generated a C++ project and Runtime and Editor plugins at paths with spaces and Unicode. Two concurrent runs targeting one destination produced one complete tree and one refusal.
- The local entry called by `Jenkinsfile` passed on Windows with a fresh output path containing a space. It ran four config-table checks, exported two tables, created a project and ran the signed offline demo for both platform layouts.
- A local Jenkins 2.580.2 LTS controller with a Windows executor checked out a committed tree and ran the Win64 profile. The missing-profile run failed with archived diagnostics. A clean checkout in a short workspace built, cooked and launched the game and archived its build receipt. All 43 archive files passed independent verification. Flipping one byte in a copy of the PAK made verification fail. External agents and published signing are separate checks.
- A PRO Max 5.8.3 Editor commandlet imported the generated Gameplay Tags JSON in a blank content project and checked both rows and their Chinese comments. A separate commandlet run loaded the saved DataTable through the Asset Registry and rejected a missing asset and an incorrect declared class.
- Excel and WPS both saved native XLSX samples. The exporter produced matching JSON bytes for their Chinese text, boolean, integer and decimal cells. The Win64 project profile also consumed an XLSX fixture, Cooked the imported table, found the actual map and table in a PAK, then read both rows from the launched archive on PRO Max 5.8.3. The Jenkins controller and other engine and platform configurations are separate checks.
- The network profile Cooked the client enemy and wave tables and placed the shared configuration identity in the Win64 PAK. The packaged game loaded both typed rows. A real packaged listen host accepted a compatible client, rejected a changed configuration identity and accepted a reconnect on IPv4 loopback. The server-only fields were emitted in the separate JSON output. The equivalent three-sheet workbook matched all eight CSV outputs byte for byte and reported an invalid foreign key with its workbook, sheet, row and field. A separate UE source UBT run generated the Win64 Server target build plan. Dedicated binary packaging and loading the server JSON in that runtime are separate checks.
- The offline demo exercised Windows and Android file layouts through the Python release store. Both rejected a bad signature and modified content, recovered the previous save after an unconfirmed boot, and retained a later confirmed version.
- Windows release-tool tests cover the Python store, launcher, native signing and hosting. The platform-dependent and omitted-project cases are reported as skips. The Windows launcher test uses a real child process with a mismatched health record to verify that the startup timeout still applies.
- Ubuntu passed 46 gateway tests. An isolated Nginx 1.24.0 listener served real HTTPS responses for current manifests, full-file downloads, HEAD, Range and missing files. Write requests were denied.
- The Android Java source compiled against SDK 36 with AndroidX. Host doubles covered selection, recovery, download and the debuggable-APK gate. The host Java run used JDK 17 and org.json 20240205. Symlink-dependent host branches were skipped on Windows.

## Candidate staging I/O

The Python store now hashes candidate source files as it copies them into a private stage. It still verifies the complete signed inventory and reads back the destination. On one Windows host, three runs per version staged the same 64 MiB fixture. Bytes read by the application from the candidate source fell from 128 MiB to 64 MiB in every run. Median staging time was 0.256 s before and 0.257 s after. The fixture establishes one fewer source read and showed no elapsed-time improvement at that size. Android Java staging was outside this measurement.

## Known limits

- The example project targets the source project's UE 5.8 build environment. No full UE minor-version support matrix is claimed.
- Runtime update activation occurs at a cold start. It does not patch machine code in a running process.
- Compatible game-level native and cooked-content changes can share one release set, but arbitrary ABI, reflection, serialization, plugin, engine, Java, or APK-shell changes are not automatically compatible.
- The exported Android signer pin is deliberately unusable until configured.
- No physical phone FPS, thermal, or battery result is included.
- No 16 KiB Android-page device result or Shipping-configuration qualification is included.
- No real historical player save corpus is included or used to claim general save migration.

## Prioritized gaps

| Priority | Gap | Acceptance target |
| --- | --- | --- |
| P0 | Managed packaging needs project build scripts, Lua identity, and a UE readiness adapter. | Build an independent sample game on Windows and Android. Confirm a real updated game after Cook and recover its saves after a failed startup. |
| P1 | Project identity, public origin, paths and certificate pins still span several adapters. | Use one validated deployment profile and verify that an incorrect project, channel, signer or origin is rejected before upload. |
| P1 | Native and PAK files are hashed repeatedly during download, staging and cold boot. | Capture phase timings and bytes read, copied and hashed on equal payloads before and after a change. Preserve signed inventory verification before selection and after recovery. |
| P1 | The legacy native publisher uses a weaker promotion flow than joint releases. | Exercise two concurrent publications, a lost SSH session and a failed public readback against a disposable server. |
| P2 | Physical-phone, 16 KiB runtime, Shipping and historical-save coverage. | Collect matching build receipts and run the failure matrix with real device and save inputs. |

For further I/O investigation, separate network download, source validation, copy, destination validation, process start and health confirmation. Record candidate bytes, peak disk usage and cold boot latency for each run. Compare the same payload and storage conditions before deciding which additional reads to remove.
