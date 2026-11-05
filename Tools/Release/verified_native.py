"""Read-only gate for reusing an independently built and validated Android game target."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import re
import struct


def require(ok, message):
    if not ok:
        raise ValueError('Verified native build: ' + message)


def digest(path):
    sha = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            sha.update(block)
    return sha.hexdigest()


def read_json(path):
    return json.loads(Path(path).read_text(encoding='utf-8-sig'))


def elf_arm64(path):
    """Check the actual ELF and every PT_LOAD, independently of the supplied proof."""
    size = path.stat().st_size
    with path.open('rb') as stream:
        header = stream.read(64)
        require(len(header) == 64 and header[:6] == b'\x7fELF\x02\x01', 'binary is not little-endian ELF64')
        require(struct.unpack_from('<HH', header, 16) == (3, 183), 'binary is not an AArch64 shared executable')
        offset = struct.unpack_from('<Q', header, 32)[0]
        entry_size, count = struct.unpack_from('<HH', header, 54)
        require(entry_size >= 56 and 0 < count <= 4096 and offset + entry_size * count <= size, 'invalid ELF program headers')
        loads = []
        for index in range(count):
            stream.seek(offset + index * entry_size)
            entry = stream.read(56)
            if struct.unpack_from('<I', entry)[0] != 1:
                continue
            file_offset, virtual_address = struct.unpack_from('<QQ', entry, 8)
            file_size = struct.unpack_from('<Q', entry, 32)[0]
            alignment = struct.unpack_from('<Q', entry, 48)[0]
            require(alignment >= 16384 and alignment & (alignment - 1) == 0,
                    'a LOAD segment does not support 16 KiB pages')
            require(file_offset % 16384 == virtual_address % 16384 and file_offset + file_size <= size,
                    'a LOAD segment has invalid 16 KiB layout')
            loads.append(alignment)
        require(loads, 'ELF contains no LOAD segments')
    return dict(bits=64, machine='AArch64', loadSegmentCount=len(loads), minimumLoadAlignmentBytes=min(loads))


def validate(proof_path, *, project, engine, native_source_hash, configuration, native_api_version, no_debug_symbols):
    """Validate existing evidence; never create/repair a target receipt or build anything."""
    proof_path = Path(proof_path).resolve(strict=True)
    proof = read_json(proof_path)
    require(proof.get('format') == 1, 'unsupported proof format')
    require(re.fullmatch(r'[0-9a-f]{64}', native_source_hash or ''), 'invalid expected source fingerprint')
    require(proof.get('nativeSourceHash') == native_source_hash, 'source fingerprint differs from the current build inputs')
    engine = Path(engine).resolve(strict=True)
    engine_id = read_json(engine / 'Engine/Binaries/Win64/UnrealEditor.modules')['BuildId']
    require(proof.get('engineBuildId') == engine_id, 'selected engine Build ID differs from the verified build')
    require(proof.get('platform') == 'Android' and proof.get('architecture') == 'arm64', 'proof is not Android ARM64')
    require(proof.get('configuration') == configuration, 'configuration differs from the verified build')
    require(proof.get('nativeApiVersion') == native_api_version, 'native API differs from the verified build')
    require(proof.get('noDebugSymbols') is bool(no_debug_symbols), 'debug-symbol options differ from the verified build')
    require(type(proof.get('nativeBuildExit')) is int and proof['nativeBuildExit'] == 0, 'the independent native build did not exit successfully')
    project = Path(project).resolve(strict=True)
    receipt_path = Path(proof['targetReceipt']).resolve(strict=True)
    binary = Path(proof['nativeBinary']).resolve(strict=True)
    require(receipt_path == (project / 'Binaries/Android/SampleGame.target').resolve(), 'receipt belongs to another project or target')
    require(binary == (project / 'Binaries/Android/SampleGame-arm64.so').resolve(), 'binary belongs to another project or ABI')
    require(digest(receipt_path) == proof.get('targetReceiptSha256'), 'actual target receipt hash changed')
    receipt = read_json(receipt_path)
    require(receipt.get('TargetName') == 'SampleGame' and receipt.get('TargetType') == 'Game'
            and receipt.get('IsTestTarget') is False, 'receipt is not the actual SampleGame Game target')
    require(receipt.get('Platform') == 'Android' and receipt.get('Architecture') == 'arm64'
            and receipt.get('Configuration') == configuration, 'receipt platform/configuration/ABI does not match')
    receipt_project = (receipt_path.parent / receipt.get('Project', '')).resolve(strict=True)
    require(receipt_project == (project / 'SampleGame.uproject').resolve(strict=True), 'receipt project path differs')
    def product_path(value):
        require(isinstance(value, str) and value.startswith('$(ProjectDir)/'), 'receipt launch/product must belong to this project')
        return (project / value.removeprefix('$(ProjectDir)/')).resolve(strict=True)
    require(product_path(receipt.get('Launch')) == binary, 'receipt launch does not reference the verified binary')
    products = [product for product in receipt.get('BuildProducts', []) if product.get('Type') == 'Executable']
    require(len(products) == 1 and product_path(products[0].get('Path')) == binary, 'receipt executable product does not match')
    version = read_json(engine / 'Engine/Build/Build.version')
    require(all(receipt.get('Version', {}).get(key) == version.get(key) for key in ('MajorVersion', 'MinorVersion', 'PatchVersion')),
            'receipt engine version differs from the selected engine')
    require(binary.is_file() and binary.stat().st_size == proof.get('nativeBinarySize'), 'actual native binary size changed')
    require(digest(binary) == proof.get('nativeBinarySha256'), 'actual native binary hash changed')
    elf = elf_arm64(binary)
    require(proof.get('elfMachine') == elf['machine'] and proof.get('loadSegmentAlignmentBytes') == elf['minimumLoadAlignmentBytes'],
            'actual ELF layout differs from the independent validation')
    build_log = Path(proof['nativeBuildLog']).resolve(strict=True)
    require('Result: Succeeded' in build_log.read_text(encoding='utf-8-sig', errors='replace'), 'independent native build log has no success result')
    return dict(proof=str(proof_path), proofSha256=digest(proof_path), targetReceipt=str(receipt_path),
                targetReceiptSha256=digest(receipt_path), nativeBinary=str(binary), nativeBinarySha256=digest(binary),
                nativeBinarySize=binary.stat().st_size, nativeSourceHash=native_source_hash, engineBuildId=engine_id,
                platform='Android', architecture='arm64', configuration=configuration, nativeApiVersion=native_api_version,
                noDebugSymbols=bool(no_debug_symbols), nativeBuildLog=str(build_log), nativeBuildLogSha256=digest(build_log), elf=elf)
