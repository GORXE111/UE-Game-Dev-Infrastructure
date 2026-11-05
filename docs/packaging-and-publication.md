# Packaging and publication

The release tooling is organized around explicit inputs and immutable outputs. A successful build is only one gate: the final archive must match the producer receipt, the signed manifest, and the platform package identity before publication.

## Project integration

The Windows and Android builders take a complete project checkout. The sample adapters expect a `SampleGame.uproject` under `Project/SampleGame`, the project's Lua version declaration, and the project-owned native source hashing, editor/game build, and cook scripts. The build commands report missing paths before creating output. Replace the sample target names, map plan, package name, archive layout and trust pins when adapting the producer.

The Android build also needs its matching public signer certificate and a UE/Android toolchain. The production signer digest is a zero placeholder in the export. The Windows managed base needs its own signing identity and readiness adapter. See [the health contract](update-and-rollback.md) for the matching runtime work.

## Build sequence

1. Freeze source commit, engine build, target platform, configuration, base release ID, application signing identity, and content plan.
2. Build the Windows player or Android ARM64 player and cook the complete required content set.
3. Construct the release manifest from observed package contents. Bind each file's role, path, byte size, and SHA-256. Do not edit generated manifests by hand.
4. Sign the release manifest using a private key stored outside the repository and protected by the build environment.
5. Inspect the prepared publication plan before upload. Confirm the release ID is unused and that unrelated current pointers and protected releases match the expected pre-state.
6. Upload to a unique private stage. The remote verifier checks the complete inventory before making an immutable release directory.
7. Download each final public file through the real public endpoint and compare its complete size and SHA-256. Check metadata and byte-range behavior before moving the public current pointer.
8. If the project has a download page, update it after the full packages and update feeds have passed their checks. The source project's website tooling is maintained separately.

The tool source contains project adapters for `SampleGame`; it is not a universal Unreal BuildGraph. A new game must supply its target names, archive layout, required maps, package identifiers, trust roots, and compatibility policy.

## Required secret handling

- Keep manifest signing keys, Android keystores, deployment SSH keys, tunnel credentials, and passwords in a secret store or outside the checkout.
- Pass secret environment-variable **names** where supported; never print secret values into command lines or build receipts.
- Do not reuse a published signing key for development fixtures.
- Treat signing key rotation as an installation compatibility change unless the installed trust model explicitly supports rotation.

The published scripts refuse to include common key-store extensions in player archives. That packaging guard complements repository secret scanning; it does not replace review of the final archive.
