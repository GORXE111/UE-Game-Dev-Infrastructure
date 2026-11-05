"""Create a fresh immutable, self-verified signed Windows native release directory."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import uuid
import zipfile

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key, Encoding, PublicFormat

import native_launcher as native


def verify_pe64(path):
    path = Path(path)
    with path.open("rb") as stream:
        header = stream.read(64)
        native.require(len(header) == 64 and header[:2] == b"MZ", "Native source must be an actual PE image: " + path.name)
        offset = struct.unpack_from("<I", header, 60)[0]
        native.require(64 <= offset <= path.stat().st_size - 26, "Invalid PE header location")
        stream.seek(offset)
        pe = stream.read(26)
        native.require(pe[:4] == b"PE\0\0" and struct.unpack_from("<H", pe, 4)[0] == 0x8664 and struct.unpack_from("<H", pe, 24)[0] == 0x20B, "Native source must be Windows x64 PE32+")
        flags = struct.unpack_from("<H", pe, 22)[0]
        native.require(flags & 2 and bool(flags & 0x2000) == (path.suffix.lower() == ".dll"), "PE executable/DLL type does not match native filename")


def publish(config_path, source_root, private_key, version, output, registry_root=None, *, compatibility_record=None, project=None, engine=None):
    config_path = Path(config_path).resolve(strict=True)
    config = native.read_config(config_path)
    compatibility_evidence = None
    if compatibility_record is not None or project is not None or engine is not None:
        native.require(compatibility_record is not None and project is not None and engine is not None, "Compatibility record, project and engine must be supplied together")
        import native_compatibility
        compatibility_evidence = native_compatibility.validate(compatibility_record, project, engine, config_path)
    source_root = Path(source_root).resolve(strict=True)
    private_key = Path(private_key).resolve(strict=True)
    output_requested = Path(output).absolute()
    output = output_requested.parent.resolve(strict=True) / output_requested.name
    repo = Path(__file__).resolve().parents[3]
    native.require(not output.exists() and not output.is_relative_to(repo) and not output.is_relative_to(source_root), "Native release output must be a fresh external directory")
    native.require(output.parent.is_dir() and not output.parent.is_symlink(), "Native release output parent must exist and not be a symlink")
    native.require(type(version) is int and 0 < version <= 2**53 - 1, "Native version must be positive")
    native.require(not private_key.is_relative_to(output) and not config_path.is_relative_to(output), "Private key/config cannot be inside public release output")
    key = load_pem_private_key(private_key.read_bytes(), password=None)
    native.require(isinstance(key, Ed25519PrivateKey), "Native producer requires an Ed25519 private key")
    native.require(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex() == config["publicKeyHex"], "Native signing key does not match the frozen player public key")
    allowed = native.file_records(config["nativeFiles"])
    records = []
    for name in allowed:
        source = native.inside(source_root, name)
        native.require(source.is_file(), "Native source missing allowlist file: " + name)
        verify_pe64(source)
        records.append({"path": name, "size": source.stat().st_size, "sha256": native.digest(source)})
    native.file_records(records)
    registry_root = Path(registry_root).absolute() if registry_root else output.parent / ".native-windows-producer"
    native.require(not registry_root.is_relative_to(output) and not registry_root.is_relative_to(repo), "Publication registry must remain outside public output and repository")
    registry_root.mkdir(parents=True, exist_ok=True)
    identity = {field: config[field] for field in (*native.IDENTITY, "publicKeyHex")}
    registry_name = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest() + ".json"
    registry_path = native.inside(registry_root, registry_name)
    with native.install_lock(registry_root):
        registry = native.parse_json(registry_path.read_bytes(), 4 * 1024 * 1024) if registry_path.exists() else {"highestVersion": 0, "versions": {}}
        native.require(version > registry["highestVersion"] and str(version) not in registry["versions"], "Native version was already reserved/published; use a strictly newer version")
        registry["highestVersion"] = version
        registry["versions"][str(version)] = {"status": "preparing", "output": str(output)}
        native.atomic_json(registry_path, registry)
    temporary = output.with_name(output.name + ".preparing-" + uuid.uuid4().hex)
    temporary.mkdir()
    archive_relative = f"versions/{version}/native-windows.zip"
    archive = temporary / archive_relative
    archive.parent.mkdir(parents=True)
    with zipfile.ZipFile(archive, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=1, allowZip64=True) as zipped:
        for record in records:
            source = native.inside(source_root, record["path"])
            zipped.write(source, record["path"])
    for record in records:
        source = native.inside(source_root, record["path"])
        native.require(source.stat().st_size == record["size"] and native.digest(source) == record["sha256"], "Native source changed while creating the archive")
    manifest = {field: config[field] for field in native.IDENTITY}
    manifest.update(format=1, kind="samplegame-native-windows", nativeVersion=version,
                    archive={"path": archive_relative, "size": archive.stat().st_size, "sha256": native.digest(archive)}, files=records)
    raw = (json.dumps(manifest, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8")
    if compatibility_evidence is not None:
        native.require(native_compatibility.validate(compatibility_record, project, engine, config_path) == compatibility_evidence, "Windows compatibility inputs changed during native archive preparation")
    signature = key.sign(raw)
    native.signed_manifest(raw, signature, config)
    verification = temporary / ".verify-extract"
    verification.mkdir()
    native.extract_verified(archive, verification, manifest)
    for record in records:
        verify_pe64(native.inside(verification, record["path"]))
    # Only this producer-created extraction directory is removed, after containment verification.
    native.require(verification.resolve().is_relative_to(temporary.resolve()) and verification.name == ".verify-extract", "Unsafe verification directory")
    shutil.rmtree(verification)
    (temporary / "manifest.json").write_bytes(raw)
    (temporary / "manifest.json.sig").write_bytes(signature)
    receipt = {"format": 1, "nativeVersion": version, "baseReleaseId": config["baseReleaseId"],
               "compatibilityId": config["compatibilityId"], "manifestSha256": hashlib.sha256(raw).hexdigest(),
               "signatureSha256": hashlib.sha256(signature).hexdigest(), "archive": manifest["archive"],
               "nativeFiles": records, "clientSignatureVerified": True, "clientExtractVerified": True,
               "realUERuntimeValidated": False, "publiclyPublished": False}
    receipt["frozenConfigurationSha256"] = native.digest(config_path)
    receipt["compatibilityGuard"] = compatibility_evidence or {"validated": False, "scope": "Internal fixture API; production CLI always requires the frozen guard"}
    native.atomic_json(temporary / "producer-receipt.json", receipt)
    native.require(not output.exists(), "Native version output appeared during publishing; refusing overwrite")
    os.rename(temporary, output)
    with native.install_lock(registry_root):
        registry = native.parse_json(registry_path.read_bytes(), 4 * 1024 * 1024)
        registry["versions"][str(version)].update(status="complete", manifestSha256=receipt["manifestSha256"])
        native.atomic_json(registry_path, registry)
    return {"output": str(output), **receipt}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument("--private-key", required=True, type=Path)
    parser.add_argument("--version", required=True, type=int)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--registry-root", type=Path, help="Stable private publication registry; defaults to the output parent/.native-windows-producer")
    parser.add_argument("--compatibility-record", required=True, type=Path)
    parser.add_argument("--project", required=True, type=Path)
    parser.add_argument("--engine", required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(publish(args.config, args.source_root, args.private_key, args.version, args.output, args.registry_root,
                             compatibility_record=args.compatibility_record, project=args.project, engine=args.engine), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
