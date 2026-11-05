# Export provenance

This repository was assembled from the project-owned SampleGame development and release tooling, then copied into a new repository without copying its Git history.

## Included source areas

- The C++/Java `SampleGameNativeUpdate` plugin source and its host-side Java harness.
- Release-set, native-update, archive, and hosting scripts from the project's `Tools/Release/` tree.
- A new small Unreal C++ plugin scaffold and public architecture/operations documentation.

## Sanitization and exclusions

- `SampleGame` project identifiers and Java application identifiers were changed to `SampleGame` / `com.example.samplegame`.
- The live update domain was replaced with `updates.example.com`; server storage was replaced with `/srv/ue-game-updates`.
- The Android signing-certificate fingerprint was replaced with an all-zero placeholder.
- The Windows native-update public-key pin and historical base-manifest digests were replaced with all-zero placeholders.
- Game assets, screenshots, website artwork, engine source, complete project files, binaries, archives, APK/PAK/ZIP files, caches, producer receipts, deployment journals, logs, and the actual DER certificate were excluded.
- Existing build outputs, editor runtime ZIPs, slua source archives, and launcher executables were excluded.
- Private project commit history and local machine paths were not copied.

These substitutions make the export safer to inspect; they do not turn every project adapter into a generic Unreal tool. The Android package identity and signer pin must be configured together, and the release scripts must be adapted to the target game's package layout and trust policy.
