# Verification scope and roadmap

## Evidence from the source project

The private source project completed a V1.0.7 Development baseline and public update publication for Windows PC and an Android ARM64 emulator. Its local qualification covered fresh installation, update selection, code/content checks, save-generation handover, pre-health failure recovery, cached-content corruption recovery, announcement display, and public archive downloads checked against complete SHA-256 values.

This public export changes project and package identifiers, replaces the live update domain and server paths, and replaces the real Android certificate digest with a zero placeholder. The exported snapshot has **not** been rebuilt or run in a fresh Unreal project. The private project's receipts do not transfer to this changed source.

## Known limits

- The example project targets the source project's UE 5.8 build environment. No full UE minor-version support matrix is claimed.
- Runtime update activation occurs at a cold start. It does not patch machine code in a running process.
- Compatible game-level native and cooked-content changes can share one release set, but arbitrary ABI, reflection, serialization, plugin, engine, Java, or APK-shell changes are not automatically compatible.
- The exported Android signer pin is deliberately unusable until configured.
- No physical phone FPS, thermal, or battery result is included.
- No 16 KiB Android-page device result or Shipping-configuration qualification is included.
- No real historical player save corpus is included or used to claim general save migration.

## Roadmap

1. Separate the protocol core from the `SampleGame` project adapter and make project identity/configuration explicit.
2. Turn Android certificate identity and server paths into validated external configuration rather than source constants.
3. Add a clean-template build matrix for supported UE versions and PC/Android targets.
4. Add a reproducible local gateway container and a disposable test deployment profile.
5. Add signed package fixtures and end-to-end failure injection against the exported source, with no production credentials.
6. Publish device and Shipping results only when matching artifacts and evidence exist.
