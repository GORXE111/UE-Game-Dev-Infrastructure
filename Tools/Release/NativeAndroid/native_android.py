"""Immutable, certificate-signed Android native releases; no private-key export."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tempfile
from urllib.parse import urlsplit

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
sys.path.insert(0, str(HERE.parent))
import verified_native

CERTIFICATE_SHA256 = '0000000000000000000000000000000000000000000000000000000000000000'
BINDINGS = ('format', 'platform', 'packageName', 'channel', 'abi', 'baseReleaseId',
            'baseNativeSourceHash', 'nativeApiVersion', 'engineBuildId', 'contentCompatibilityId')
SKIP_DIRS = {'Binaries', 'Intermediate', 'Saved', 'DerivedDataCache', '.git', '__pycache__'}


class IntegrationError(ValueError):
    """The selected project is missing a required release integration input."""


def require(ok, message):
    if not ok:
        raise ValueError('Native Android release: ' + message)


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')


def digest(path):
    return verified_native.digest(path)


def read(path):
    return json.loads(Path(path).read_text(encoding='utf-8-sig'))


def write_new(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as stream:
        stream.write(canonical(value) + b'\n')


def https(value):
    uri = urlsplit(value)
    require(uri.scheme == 'https' and uri.hostname and not uri.username and not uri.password
            and not uri.fragment and uri.port in (None, 443), 'expected an absolute HTTPS URL with no credentials or fragment')
    require('/../' not in uri.path and '/./' not in uri.path, 'URL path must be normalized')
    return uri


def hash_value(value):
    require(isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value), 'invalid SHA256')
    return value


def loader_elf(path):
    """Match the loader's additional program-header/range/W^X checks."""
    evidence = verified_native.elf_arm64(path)
    size = path.stat().st_size
    executable = False
    with path.open('rb') as stream:
        header = stream.read(64)
        require(header[6] == 1 and struct.unpack_from('<I', header, 20)[0] == 1, 'ELF version is unsupported by loader')
        offset = struct.unpack_from('<Q', header, 32)[0]
        header_size, entry_size, count = struct.unpack_from('<HHH', header, 52)
        require(header_size == 64 and entry_size == 56 and 0 < count <= 256 and offset >= 64, 'ELF header differs from loader contract')
        for index in range(count):
            stream.seek(offset + index * entry_size)
            kind, flags, file_offset, address, _, file_size, memory_size, alignment = struct.unpack('<IIQQQQQQ', stream.read(56))
            if kind != 1:
                continue
            require(file_offset % alignment == address % alignment and file_size <= memory_size
                    and file_offset <= size and file_size <= size - file_offset, 'ELF LOAD range differs from loader contract')
            require(flags & 3 != 3, 'writable executable ELF LOAD is forbidden')
            executable |= bool(flags & 1)
    require(executable, 'ELF has no executable LOAD for loader')
    return evidence


def current_native_hash(project):
    adapter = HERE / 'Read-NativeHash.ps1'
    if not adapter.is_file():
        raise IntegrationError(f'Install the project-owned Android native-source hash adapter at {adapter}.')
    shell = shutil.which('pwsh') or shutil.which('powershell')
    require(shell, 'PowerShell is required for the authoritative native-source fingerprint')
    result = subprocess.run([shell, '-NoProfile', '-File', str(adapter),
                             '-Project', str(project)], capture_output=True, text=True, encoding='utf-8', check=False)
    require(result.returncode == 0, 'authoritative native-source fingerprint failed')
    return hash_value(result.stdout.strip().lstrip('\ufeff'))


def files_under(root):
    if not root.exists():
        return
    for directory, children, names in os.walk(root, followlinks=False):
        children[:] = sorted(name for name in children if name not in SKIP_DIRS and not (Path(directory) / name).is_symlink())
        for name in sorted(names):
            path = Path(directory) / name
            require(not path.is_symlink(), 'compatibility inputs cannot be symlinks')
            if path.is_file():
                yield path


def compatibility_files(project, bootstrap):
    """Conservative ABI/build/Java/config and exact content-input baseline."""
    paths = set()
    for root in (project / 'Source', project / 'Plugins'):
        for path in files_under(root):
            name = path.name.lower()
            if path.suffix.lower() in ('.h', '.hpp', '.inl', '.java', '.uplugin') or name.endswith(('.build.cs', '.target.cs')) or 'upl' in name and path.suffix.lower() == '.xml':
                paths.add(path)
    for root in (project / 'Config', project / 'Content'):
        for path in files_under(root):
            relative = path.relative_to(project).as_posix()
            generated = relative in ('Content/Release/native-bootstrap.json', 'Content/Release/update-bootstrap.json')
            developer = relative.startswith('Content/Developers/')
            if not generated and not developer:
                paths.add(path)
    paths.add(project / 'SampleGame.uproject')
    records = []
    for path in sorted(paths, key=lambda item: item.relative_to(project).as_posix()):
        require(path.is_file(), 'compatibility input is missing')
        records.append(dict(path=path.relative_to(project).as_posix(), sha256=digest(path), size=path.stat().st_size))
    return records


def engine_id(engine):
    return read(engine / 'Engine/Binaries/Win64/UnrealEditor.modules')['BuildId']


def package_name(project):
    text = (project / 'Config/DefaultEngine.ini').read_text(encoding='utf-8-sig')
    matches = re.findall(r'^PackageName\s*=\s*([A-Za-z][A-Za-z0-9_.]+)\s*$', text, flags=re.MULTILINE)
    require(len(matches) == 1, 'Android PackageName must be explicit and unique')
    return matches[0]


def compatibility_id(identity, files):
    return hashlib.sha256(canonical(dict(identity=identity, files=files))).hexdigest()


def base_paths(args):
    project = args.project.resolve(strict=True)
    output = args.output.resolve()
    require(not output.is_relative_to(REPO), 'release output must be outside the source repository')
    bootstrap = (args.bootstrap or project / 'Content/Release/native-bootstrap.json').resolve()
    require(bootstrap == (project / 'Content/Release/native-bootstrap.json').resolve(), 'bootstrap must use the project release asset path')
    require(bootstrap.is_relative_to(project), 'bootstrap cannot resolve outside the project')
    record = (args.base_record or output / 'native-base.json').resolve()
    require(not record.is_relative_to(REPO), 'immutable base record must be outside the source repository')
    return project, output, bootstrap, record


def require_certificate_pin():
    if not re.fullmatch(r'[a-f0-9]{64}', CERTIFICATE_SHA256) or CERTIFICATE_SHA256 == '0' * 64:
        raise IntegrationError('Configure CERTIFICATE_SHA256 with the approved Android public signing certificate digest.')


def create_base(args):
    project, output, bootstrap_path, record_path = base_paths(args)
    require(not record_path.exists() and not bootstrap_path.exists(), 'base record/bootstrap already exist; allocate a new base instead of overwriting')
    require(type(args.base_release_id) is int and 0 < args.base_release_id <= 999999999, 'invalid base release ID')
    require(type(args.native_api_version) is int and args.native_api_version > 0, 'native API must be a positive integer')
    require(isinstance(args.version_label, str) and 0 < len(args.version_label) <= 512, 'invalid version label')
    require(re.fullmatch('[a-z][a-z0-9-]{0,63}', args.channel or ''), 'invalid channel')
    https(args.manifest_url)
    source_hash = hash_value(args.source_hash)
    require(current_native_hash(project) == source_hash, 'source hash differs from the current authoritative inputs')
    identity = dict(format=1, platform='Android_ARM64', packageName=package_name(project), channel=args.channel,
                    abi='arm64-v8a', baseReleaseId=args.base_release_id, baseNativeSourceHash=source_hash,
                    nativeApiVersion=args.native_api_version, engineBuildId=engine_id(args.engine.resolve(strict=True)))
    files = compatibility_files(project, bootstrap_path)
    identity['contentCompatibilityId'] = compatibility_id(identity, files)
    # Only the public release certificate enters the base APK. Keep update trust
    # stable when a cloud lab re-signs the APK with a different installer key.
    require_certificate_pin()
    certificate_path = HERE / 'release-certificate.der'
    if not certificate_path.is_file():
        raise IntegrationError(f'Install the matching public Android signing certificate in DER format at {certificate_path}.')
    certificate = certificate_path.read_bytes()
    require(hashlib.sha256(certificate).hexdigest() == CERTIFICATE_SHA256,
            'embedded public release certificate differs from the frozen signer')
    bootstrap = dict(identity, enabled=bool(args.enabled), manifestUrl=args.manifest_url,
                     nativeTrust=dict(format=1, certificateSha256=CERTIFICATE_SHA256,
                                      certificateBase64=base64.b64encode(certificate).decode('ascii')))
    record = dict(format=1, bootstrap=bootstrap, versionLabel=args.version_label, signingCertificateSha256=CERTIFICATE_SHA256,
                  compatibilityFiles=files, compatibilityPolicy='project-headers-build-java-config-content-inputs-v1')
    # Preflight both outputs before writing; neither existing file is ever repaired.
    write_new(record_path, record)
    write_new(bootstrap_path, bootstrap)
    return dict(baseRecord=str(record_path), baseRecordSha256=digest(record_path), bootstrap=str(bootstrap_path),
                contentCompatibilityId=identity['contentCompatibilityId'], compatibilityFileCount=len(files), enabled=bool(args.enabled))


def validate_base(args):
    require_certificate_pin()
    project, output, bootstrap_path, record_path = base_paths(args)
    record = read(record_path)
    require(record.get('format') == 1 and record.get('signingCertificateSha256') == CERTIFICATE_SHA256, 'invalid base record or certificate binding')
    bootstrap = record['bootstrap']
    require(read(bootstrap_path) == bootstrap, 'packaged bootstrap differs from the immutable base')
    require(bootstrap['engineBuildId'] == engine_id(args.engine.resolve(strict=True)), 'engine Build ID changed; create a new base')
    require(bootstrap['baseReleaseId'] == args.base_release_id and bootstrap['channel'] == args.channel, 'base release/channel mismatch')
    require(bootstrap['nativeApiVersion'] == args.native_api_version, 'native API changed; create a new base')
    require(bootstrap['manifestUrl'] == args.manifest_url, 'native manifest URL differs from bootstrap')
    require(package_name(project) == bootstrap['packageName'], 'application package changed')
    files = compatibility_files(project, bootstrap_path)
    require(files == record['compatibilityFiles'], 'headers, build inputs, Java, config or content baseline changed; create a new base')
    identity = {key: bootstrap[key] for key in BINDINGS if key != 'contentCompatibilityId'}
    require(compatibility_id(identity, files) == bootstrap['contentCompatibilityId'], 'immutable compatibility digest does not match')
    return project, output, bootstrap, record, record_path


def sign_payload(args, payload, certificate_out):
    require(len(payload) <= 32768, 'signed payload exceeds loader limit')
    for name in (args.store_password_env, args.key_password_env):
        require(re.fullmatch('[A-Za-z_][A-Za-z0-9_]*', name or '') and os.environ.get(name), 'required password environment variable is absent')
    key = args.keystore.resolve(strict=True)
    require(not key.is_relative_to(REPO) and not key.is_relative_to(args.output.resolve()), 'keystore must stay outside source and distribution output')
    java = args.java_home.resolve(strict=True) / 'bin' / ('java.exe' if os.name == 'nt' else 'java')
    javac = args.java_home.resolve(strict=True) / 'bin' / ('javac.exe' if os.name == 'nt' else 'javac')
    with tempfile.TemporaryDirectory(prefix='samplegame-native-sign-') as temporary:
        work = Path(temporary)
        compiled = subprocess.run([str(javac), '-encoding', 'UTF-8', '-d', str(work), str(HERE / 'NativeManifestSigner.java')],
                                  capture_output=True, check=False)
        require(compiled.returncode == 0, 'Java signer compile failed')
        payload_path = work / 'payload.json'
        payload_path.write_bytes(payload)
        result = subprocess.run([str(java), '-cp', str(work), 'NativeManifestSigner', str(key), args.key_alias,
                                 str(payload_path), str(work / 'signature.bin'), str(work / 'certificate.der'),
                                 str(work / 'certificate.sha256'), args.store_password_env, args.key_password_env, CERTIFICATE_SHA256],
                                capture_output=True, check=False)
        require(result.returncode == 0, 'Java KeyStore signing failed; no private key was exported')
        certificate = (work / 'certificate.der').read_bytes()
        require(hashlib.sha256(certificate).hexdigest() == CERTIFICATE_SHA256, 'actual signer certificate differs from the installed APK')
        signature = (work / 'signature.bin').read_bytes()
        certificate_out.write_bytes(certificate)
        return signature


def prepare_delivery(binary, destination, proof, strip_tool=None):
    """Derive only from the exact proved build output; never accept a delivery SO."""
    binary = Path(binary).resolve(strict=True)
    require(binary == Path(proof['nativeBinary']).resolve(strict=True), 'delivery source must be the verified project binary')
    source_sha = digest(binary)
    source_size = binary.stat().st_size
    require(source_sha == proof['nativeBinarySha256'] and source_size == proof['nativeBinarySize'], 'verified source changed before delivery preparation')
    require(not destination.exists() and destination.resolve() != binary, 'delivery must use a new independent file')
    derivation = dict(kind='byte-copy', sourceBinary=str(binary), sourceBinarySha256=source_sha,
                      sourceBinarySize=source_size)
    if strip_tool is None:
        shutil.copyfile(binary, destination)
        require(digest(destination) == source_sha, 'native library changed during copying')
    else:
        strip_tool = Path(strip_tool).resolve(strict=True)
        require(strip_tool.name.lower() in ('llvm-strip', 'llvm-strip.exe') and strip_tool.is_file(), 'strip tool must be the existing NDK llvm-strip executable')
        require(len(strip_tool.parents) >= 6 and strip_tool.parents[4].name == 'toolchains'
                and strip_tool.parents[3].name == 'llvm', 'strip tool must belong to an Android NDK toolchain')
        properties = strip_tool.parents[5] / 'source.properties'
        require(properties.is_file(), 'strip tool NDK source.properties is missing')
        build_log = Path(proof['nativeBuildLog']).read_text(encoding='utf-8-sig', errors='replace')
        installed = re.findall(r'InstalledDir:\s*([^\r\n]+)', build_log)
        require(any(Path(value.strip()).resolve() == strip_tool.parent for value in installed),
                'strip tool differs from the compiler directory recorded in the verified build log')
        tool_sha = digest(strip_tool)
        properties_sha = digest(properties)
        version = subprocess.run([str(strip_tool), '--version'], capture_output=True, text=True,
                                 encoding='utf-8', errors='replace', timeout=30, check=False)
        require(version.returncode == 0 and 'LLVM' in version.stdout, 'NDK strip tool version check failed')
        command = [str(strip_tool), '--strip-unneeded', '-o', str(destination), str(binary)]
        result = subprocess.run(command, capture_output=True, text=True, encoding='utf-8', errors='replace',
                                timeout=300, check=False)
        require(result.returncode == 0 and destination.is_file(), 'NDK strip failed; no native release may be signed')
        require(digest(strip_tool) == tool_sha and digest(properties) == properties_sha, 'NDK strip tool identity changed during derivation')
        derivation.update(kind='ndk-strip-unneeded', stripTool=str(strip_tool), stripToolSha256=tool_sha,
                          stripToolVersion=version.stdout.strip(), stripArguments=command,
                          ndkProperties=str(properties), ndkPropertiesSha256=properties_sha,
                          ndkPropertiesText=properties.read_text(encoding='utf-8-sig').strip(), stripExitCode=result.returncode)
    require(digest(binary) == source_sha and binary.stat().st_size == source_size, 'original verified binary changed during delivery preparation')
    elf = loader_elf(destination)
    derived_sha = digest(destination)
    derived_size = destination.stat().st_size
    require(64 <= derived_size <= 1024 ** 3, 'derived native payload size exceeds loader limit')
    derivation.update(deliveryFile='libUnreal.so', deliverySha256=derived_sha, deliverySize=derived_size, deliveryElf=elf)
    return derivation


def publish(args):
    project, output, bootstrap, base, record_path = validate_base(args)
    require(type(args.release_id) is int and bootstrap['baseReleaseId'] < args.release_id <= 999999999, 'release ID must follow this base')
    source_hash = hash_value(args.source_hash)
    require(current_native_hash(project) == source_hash, 'source hash differs from the current authoritative inputs')
    proof = verified_native.validate(args.proof, project=project, engine=args.engine, native_source_hash=source_hash,
                                     configuration=args.configuration, native_api_version=args.native_api_version,
                                     no_debug_symbols=not args.debug_symbols)
    binary = Path(proof['nativeBinary'])
    loader_elf(binary)
    destination = output / 'versions' / str(args.release_id)
    require(not destination.exists(), 'native release exists; published versions are immutable')
    manifest_uri = https(bootstrap['manifestUrl'])
    prefix = bootstrap['manifestUrl'].rsplit('/', 1)[0]
    so_url = prefix + '/versions/' + str(args.release_id) + '/libUnreal.so'
    require(https(so_url).hostname.lower() == manifest_uri.hostname.lower(), 'native payload origin changed')
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.native-release-', dir=output) as temporary:
        stage = Path(temporary)
        derivation = prepare_delivery(binary, stage / 'libUnreal.so', proof, getattr(args, 'strip_tool', None))
        payload = {key: bootstrap[key] for key in BINDINGS}
        payload.update(releaseId=args.release_id, nativeSourceHash=source_hash, soSha256=derivation['deliverySha256'],
                       soSize=derivation['deliverySize'], soUrl=so_url, versionLabel=args.version_label)
        encoded = canonical(payload)
        require(verified_native.validate(args.proof, project=project, engine=args.engine, native_source_hash=source_hash,
                    configuration=args.configuration, native_api_version=args.native_api_version,
                    no_debug_symbols=not args.debug_symbols) == proof, 'original proof or build output changed during delivery preparation')
        signature = sign_payload(args, encoded, stage / 'signer-certificate.der')
        envelope = dict(format=1, payloadBase64=base64.b64encode(encoded).decode('ascii'),
                        signatureBase64=base64.b64encode(signature).decode('ascii'), signatureAlgorithm='SHA256withRSA')
        require(len(canonical(envelope)) <= 65536, 'signed envelope exceeds loader limit')
        require(digest(stage / 'libUnreal.so') == payload['soSha256'] and (stage / 'libUnreal.so').stat().st_size == payload['soSize'],
                'derived delivery changed after signing')
        write_new(stage / 'manifest.json', envelope)
        write_new(stage / 'publish-receipt.json', dict(format=1, releaseId=args.release_id,
                  baseRecordSha256=digest(record_path), payload=payload, verifiedNative=proof,
                  deliveryDerivation=derivation,
                  signingCertificateSha256=CERTIFICATE_SHA256, deviceRuntimeValidated=False, remotelyPublished=False))
        # Detect source or compatibility changes while signing/copying, before activation.
        validate_base(args)
        require(current_native_hash(project) == source_hash, 'source changed during release preparation')
        require(verified_native.validate(args.proof, project=project, engine=args.engine, native_source_hash=source_hash,
                    configuration=args.configuration, native_api_version=args.native_api_version,
                    no_debug_symbols=not args.debug_symbols) == proof, 'original proof or build output changed before native release commit')
        destination.parent.mkdir(parents=True, exist_ok=True)
        stage.rename(destination)
    return dict(releaseDirectory=str(destination), manifest=str(destination / 'manifest.json'),
                soSha256=payload['soSha256'], soSize=payload['soSize'], remotelyPublished=False, deviceRuntimeValidated=False)


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument('action', choices=('create-base', 'publish', 'check-base'))
    for name in ('project', 'engine', 'output'):
        result.add_argument('--' + name, type=Path, required=True)
    for name in ('base-record', 'bootstrap', 'proof', 'keystore', 'java-home', 'strip-tool'):
        result.add_argument('--' + name, type=Path)
    result.add_argument('--source-hash', required=True)
    result.add_argument('--base-release-id', type=int, required=True)
    result.add_argument('--channel', required=True)
    result.add_argument('--manifest-url', required=True)
    result.add_argument('--version-label', required=True)
    result.add_argument('--release-id', type=int)
    result.add_argument('--native-api-version', type=int, default=2)
    result.add_argument('--configuration', choices=('Development', 'Shipping', 'Test'), default='Development')
    result.add_argument('--debug-symbols', action='store_true')
    result.add_argument('--enabled', action='store_true')
    result.add_argument('--key-alias', default='samplegame')
    result.add_argument('--store-password-env', default='SAMPLEGAME_ANDROID_STORE_PASSWORD')
    result.add_argument('--key-password-env', default='SAMPLEGAME_ANDROID_KEY_PASSWORD')
    return result


def main():
    arguments = parser()
    args = arguments.parse_args()
    try:
        if args.action == 'create-base':
            result = create_base(args)
        elif args.action == 'publish':
            require(all((args.proof, args.keystore, args.java_home)), 'publish requires proof, keystore and Java home')
            result = publish(args)
        else:
            _, _, bootstrap, _, _ = validate_base(args)
            result = dict(contentCompatibilityId=bootstrap['contentCompatibilityId'], compatible=True)
    except IntegrationError as error:
        arguments.error(str(error))
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    main()
