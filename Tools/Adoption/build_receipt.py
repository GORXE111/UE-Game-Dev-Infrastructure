"""Create or verify a portable byte inventory for an accepted Win64 archive."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat


MAX_METADATA = 64 * 1024
MAX_RECEIPT = 16 * 1024 * 1024
NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}")
KEY = re.compile(r"[A-Za-z0-9_-]{1,80}")
GIT_ID = re.compile(r"(?:[a-f0-9]{40}|[a-f0-9]{64})")
SHA256 = re.compile(r"[a-f0-9]{64}")
UNSAFE = re.compile(r'[<>:"\\|?*\x00-\x1f]')
DEVICE = re.compile(r"(?:CON|PRN|AUX|NUL|CONIN\$|CONOUT\$|COM[1-9¹²³]|LPT[1-9¹²³])", re.IGNORECASE)
METADATA_FIELDS = {"project", "target", "platform", "configuration", "commit", "engine", "sdk",
                   "configManifestSha256", "tests"}
REQUIRED_TESTS = {"editor-assets", "cooked-assets", "packaged-startup"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def plain_file_info(path):
    info = path.lstat()
    require(not stat.S_ISLNK(info.st_mode) and not getattr(info, "st_file_attributes", 0) & 0x400,
            f"Links and reparse points are forbidden: {path.name}")
    return info


def validate_path(value):
    require(isinstance(value, str), "Archive path must be a string")
    for part in value.split("/"):
        require(part and not part.endswith((" ", ".")) and not UNSAFE.search(part)
                and not DEVICE.fullmatch(part.partition(".")[0].rstrip(" ")),
                f"Unsafe archive path: {value!r}")


def unique_keys(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f"Repeated JSON key {key!r}")
        result[key] = value
    return result


def read_json(path, limit):
    info = plain_file_info(path)
    require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= limit, f"Invalid JSON file: {path.name}")
    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    require(0 < len(raw) <= limit, f"JSON file exceeds its size budget: {path.name}")
    return json.loads(raw.decode("utf-8-sig"), object_pairs_hook=unique_keys), raw


def matches(pattern, value):
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def is_label(value):
    return isinstance(value, str) and 0 < len(value) <= 200 and value == value.strip() and value.isprintable()


def validate_metadata(metadata):
    require(isinstance(metadata, dict) and metadata.keys() == METADATA_FIELDS, "Invalid build metadata fields")
    require(matches(NAME, metadata["project"]) and matches(NAME, metadata["target"]), "Invalid project or target name")
    require(metadata["platform"] == "Win64" and metadata["configuration"] == "Development",
            "This receipt describes a Win64 Development archive")
    require(matches(GIT_ID, metadata["commit"]), "Expected a full lowercase Git commit ID")
    require(matches(SHA256, metadata["configManifestSha256"]), "Expected a lowercase SHA-256 config manifest digest")
    engine = metadata["engine"]
    require(isinstance(engine, dict) and engine.keys() == {"version", "buildId"}
            and all(is_label(value) for value in engine.values()), "Expected the UE version and build ID")
    sdk = metadata["sdk"]
    require(isinstance(sdk, dict) and {"windows", "compiler", "compilerVersion"} <= sdk.keys()
            and all(matches(KEY, key) and is_label(value) for key, value in sdk.items()),
            "Expected the Windows SDK and compiler name and version")
    tests = metadata["tests"]
    require(isinstance(tests, dict) and REQUIRED_TESTS <= tests.keys()
            and all(matches(KEY, key) and value == "passed" for key, value in tests.items()),
            "Expected successful editor-assets, cooked-assets and packaged-startup tests")


def file_record(path, relative, info):
    def identity(file_info):
        return file_info.st_dev, file_info.st_ino, file_info.st_size, file_info.st_mtime_ns

    with path.open("rb") as stream:
        require(identity(info) == identity(os.fstat(stream.fileno())), f"File changed while opening: {relative}")
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
        require(identity(info) == identity(os.fstat(stream.fileno())), f"File changed while hashing: {relative}")
    require(identity(info) == identity(plain_file_info(path)), f"File changed while hashing: {relative}")
    return {"path": relative, "size": info.st_size, "sha256": digest}


def archive_inventory(archive):
    files = []
    seen = set()
    directories = [archive]
    while directories:
        directory = directories.pop()
        require(stat.S_ISDIR(plain_file_info(directory).st_mode), f"Expected a directory: {directory.name}")
        for item in directory.iterdir():
            relative = item.relative_to(archive).as_posix()
            validate_path(relative)
            key = relative.casefold()
            require(key not in seen, f"Case-insensitive archive path collision: {relative}")
            seen.add(key)
            info = plain_file_info(item)
            if stat.S_ISDIR(info.st_mode):
                directories.append(item)
            else:
                require(stat.S_ISREG(info.st_mode), f"Not a regular archive file: {relative}")
                files.append(file_record(item, relative, info))
    return sorted(files, key=lambda record: record["path"])


def validate_records(records, metadata):
    require(isinstance(records, list) and records, "Expected a nonempty archive file inventory")
    seen = set()
    paths = set()
    for record in records:
        require(isinstance(record, dict) and record.keys() == {"path", "size", "sha256"}, "Invalid archive file record")
        path = record["path"]
        validate_path(path)
        require(type(record["size"]) is int and record["size"] >= 0 and matches(SHA256, record["sha256"]),
                f"Invalid archive file size or digest: {path}")
        key = path.casefold()
        require(key not in seen, f"Duplicate archive file record: {path}")
        seen.add(key)
        paths.add(path)
    require([record["path"] for record in records] == sorted(paths), "Archive inventory is not sorted")
    project, target = metadata["project"], metadata["target"]
    require(f"{project}/Binaries/Win64/{target}.exe" in paths, "Packaged Win64 executable missing")
    pak_directory = f"{project}/Content/Paks/"
    require(any(path.startswith(pak_directory) and path.lower().endswith(".pak") for path in paths),
            "Packaged PAK missing")


def canonical(receipt):
    return (json.dumps(receipt, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8")


def check_receipt_location(archive, receipt_path):
    require(not receipt_path.resolve().is_relative_to(archive.resolve(strict=True)),
            "Keep the build receipt outside its archive")


def create_receipt(archive, metadata_path, output):
    check_receipt_location(archive, output)
    metadata, _ = read_json(metadata_path, MAX_METADATA)
    validate_metadata(metadata)
    records = archive_inventory(archive)
    validate_records(records, metadata)
    raw = canonical({"version": 1, "metadata": metadata, "files": records})
    require(len(raw) <= MAX_RECEIPT, "Build receipt exceeds its size budget")
    with output.open("xb") as stream:
        stream.write(raw)
    return {"status": "created", "receiptSha256": hashlib.sha256(raw).hexdigest(), "fileCount": len(records)}


def verify_receipt(archive, receipt_path, expected_receipt_sha256=None):
    check_receipt_location(archive, receipt_path)
    receipt, raw = read_json(receipt_path, MAX_RECEIPT)
    receipt_hash = hashlib.sha256(raw).hexdigest()
    if expected_receipt_sha256 is not None:
        require(matches(SHA256, expected_receipt_sha256) and expected_receipt_sha256 == receipt_hash,
                "Build receipt digest differs from the trusted digest")
    require(isinstance(receipt, dict) and receipt.keys() == {"version", "metadata", "files"}
            and type(receipt["version"]) is int and receipt["version"] == 1, "Invalid build receipt format")
    validate_metadata(receipt["metadata"])
    validate_records(receipt["files"], receipt["metadata"])
    require(raw == canonical(receipt), "Build receipt encoding is not canonical")
    expected = {record["path"]: record for record in receipt["files"]}
    actual = {record["path"]: record for record in archive_inventory(archive)}
    for path in sorted(expected.keys() | actual.keys()):
        if path not in actual:
            raise ValueError(f"Archive file missing: {path}")
        if path not in expected:
            raise ValueError(f"Unexpected archive file: {path}")
        require(actual[path] == expected[path], f"Archive file changed: {path}")
    return {"status": "verified", "receiptSha256": receipt_hash, "fileCount": len(expected)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create", help="Record a passing archive with build metadata")
    create.add_argument("--archive", type=Path, required=True)
    create.add_argument("--metadata", type=Path, required=True)
    create.add_argument("--output", type=Path, required=True)
    verify = commands.add_parser("verify", help="Reject changed, added or missing archive files")
    verify.add_argument("--archive", type=Path, required=True)
    verify.add_argument("--receipt", type=Path, required=True)
    verify.add_argument("--expected-receipt-sha256", help="Trusted lowercase SHA-256 from the CI handoff")
    args = parser.parse_args()
    try:
        result = (create_receipt(args.archive, args.metadata, args.output) if args.command == "create" else
                  verify_receipt(args.archive, args.receipt, args.expected_receipt_sha256))
    except (OSError, RuntimeError, ValueError) as error:
        print(json.dumps({"status": "blocked", "error": str(error)}))
        return 1
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
