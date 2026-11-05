"""Release guards with temporary fixtures; never read real release credentials."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import native_android as tool


class NativeReleaseGuards(unittest.TestCase):
    CERTIFICATE_FIXTURE = b'public-certificate-test-fixture'

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='native-release-tests-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        # These tests exercise byte binding and use a fake signer. The optional
        # Java integration test below generates and signs with a temporary JKS.
        (self.root / 'release-certificate.der').write_bytes(self.CERTIFICATE_FIXTURE)
        for name, value in (
            ('HERE', self.root),
            ('CERTIFICATE_SHA256', hashlib.sha256(self.CERTIFICATE_FIXTURE).hexdigest()),
        ):
            patcher = patch.object(tool, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.project = self.root / 'project'
        self.engine = self.root / 'engine'
        for folder in ('Source/Game', 'Config', 'Content/Release', 'Content/Developers/Local',
                       'Plugins/Native/Source', 'Binaries/Android'):
            (self.project / folder).mkdir(parents=True)
        self.header = self.project / 'Source/Game/Component.h'
        self.header.write_text('class Component {};\n', encoding='utf-8')
        self.body = self.project / 'Source/Game/Component.cpp'
        self.body.write_text('int Calculate() { return 1; }\n', encoding='utf-8')
        (self.project / 'Plugins/Native/Source/Loader.java').write_text('class Loader {}\n', encoding='utf-8')
        (self.project / 'Plugins/Native/Native.uplugin').write_text('{}', encoding='utf-8')
        (self.project / 'Source/Game/Game.Build.cs').write_text('build-contract', encoding='utf-8')
        (self.project / 'Config/DefaultEngine.ini').write_text('PackageName=com.example.samplegame\n', encoding='utf-8')
        (self.project / 'SampleGame.uproject').write_text('{}', encoding='utf-8')
        (self.project / 'Content/Main.umap').write_bytes(b'cooked-input-fixture')
        (self.engine / 'Engine/Binaries/Win64').mkdir(parents=True)
        (self.engine / 'Engine/Build').mkdir(parents=True)
        (self.engine / 'Engine/Binaries/Win64/UnrealEditor.modules').write_text('{"BuildId":"test-engine"}', encoding='utf-8')
        (self.engine / 'Engine/Build/Build.version').write_text('{"MajorVersion":5,"MinorVersion":8,"PatchVersion":3}', encoding='utf-8')
        self.args = argparse.Namespace(project=self.project, engine=self.engine, output=self.root / 'distribution',
            base_record=self.root / 'native-base.json', bootstrap=self.project / 'Content/Release/native-bootstrap.json',
            source_hash='a' * 64, base_release_id=310, channel='v104-native-android',
            manifest_url='https://updates.example.com/native/manifest.json', version_label='1.0.4', native_api_version=2,
            enabled=True, release_id=311, configuration='Development', debug_symbols=False, proof=self.root / 'proof.json')
        self.hash_patch = patch.object(tool, 'current_native_hash', side_effect=lambda project: self.args.source_hash)
        self.hash_patch.start()
        self.addCleanup(self.hash_patch.stop)

    def create(self):
        return tool.create_base(self.args)

    def proof(self, padding=0):
        binary = self.project / 'Binaries/Android/SampleGame-arm64.so'
        header = bytearray(64)
        header[:7] = b'\x7fELF\x02\x01\x01'
        struct.pack_into('<HHI', header, 16, 3, 183, 1)
        struct.pack_into('<Q', header, 32, 64)
        struct.pack_into('<HHH', header, 52, 64, 56, 1)
        binary.write_bytes(header + struct.pack('<IIQQQQQQ', 1, 5, 0, 0, 0, 120, 120, 16384) + b'x' * padding)
        receipt = self.project / 'Binaries/Android/SampleGame.target'
        receipt.write_bytes(tool.canonical(dict(TargetName='SampleGame', TargetType='Game', IsTestTarget=False,
            Platform='Android', Architecture='arm64', Configuration='Development', Project='../../SampleGame.uproject',
            Launch='$(ProjectDir)/Binaries/Android/SampleGame-arm64.so',
            BuildProducts=[dict(Type='Executable', Path='$(ProjectDir)/Binaries/Android/SampleGame-arm64.so')],
            Version=dict(MajorVersion=5, MinorVersion=8, PatchVersion=3))))
        log = self.root / 'fixture-build.log'
        log.write_text('Synthetic unit-test fixture only\nResult: Succeeded\n', encoding='utf-8')
        self.args.proof.write_bytes(tool.canonical(dict(format=1, nativeSourceHash=self.args.source_hash, engineBuildId='test-engine',
            platform='Android', architecture='arm64', configuration='Development', nativeApiVersion=2, noDebugSymbols=True,
            nativeBuildExit=0, targetReceipt=str(receipt), targetReceiptSha256=tool.digest(receipt), nativeBinary=str(binary),
            nativeBinarySize=binary.stat().st_size, nativeBinarySha256=tool.digest(binary), elfMachine='AArch64',
            loadSegmentAlignmentBytes=16384, nativeBuildLog=str(log))))
        return binary

    def fake_sign(self, args, payload, certificate):
        certificate.write_bytes(self.CERTIFICATE_FIXTURE)
        return b'unit-test-signature-only'

    def strip_fixture(self):
        tool_path = self.root / 'ndk/toolchains/llvm/prebuilt/test-host/bin/llvm-strip.exe'
        tool_path.parent.mkdir(parents=True)
        tool_path.write_bytes(b'unit-test tool identity only; subprocess mocked')
        (self.root / 'ndk/source.properties').write_text('Pkg.Revision = 27.2.12479018\n', encoding='utf-8')
        log = self.root / 'fixture-build.log'
        log.write_text(log.read_text(encoding='utf-8') + 'InstalledDir: ' + str(tool_path.parent) + '\n', encoding='utf-8')
        self.args.strip_tool = tool_path
        return tool_path

    def fake_strip(self, command, **kwargs):
        if command[-1] == '--version':
            return subprocess.CompletedProcess(command, 0, stdout='llvm-strip\nLLVM version test-only\n', stderr='')
        self.assertEqual(command[1:3], ['--strip-unneeded', '-o'])
        Path(command[3]).write_bytes(Path(command[4]).read_bytes()[:120])
        return subprocess.CompletedProcess(command, 0, stdout='', stderr='')

    def test_base_and_bootstrap_are_immutable_and_identical(self):
        result = self.create()
        record = tool.read(self.args.base_record)
        self.assertEqual(tool.read(self.args.bootstrap), record['bootstrap'])
        self.assertTrue(result['enabled'])
        self.assertEqual(len(result['contentCompatibilityId']), 64)
        original = self.args.base_record.read_bytes()
        with self.assertRaisesRegex(ValueError, 'already exist'):
            self.create()
        self.assertEqual(self.args.base_record.read_bytes(), original)

    def test_only_cpp_body_changes_are_compatible(self):
        self.create()
        self.body.write_text('int Calculate() { return 2; }\n', encoding='utf-8')
        tool.validate_base(self.args)
        self.header.write_text('class Component { int newField; };\n', encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'baseline changed'):
            tool.validate_base(self.args)

    def test_generated_bootstraps_and_developer_content_do_not_self_invalidate(self):
        self.create()
        (self.project / 'Content/Release/update-bootstrap.json').write_text('{"generated":true}', encoding='utf-8')
        (self.project / 'Content/Developers/Local/scratch.umap').write_bytes(b'test-only')
        tool.validate_base(self.args)
        changed = tool.read(self.args.bootstrap)
        changed['baseReleaseId'] += 1
        self.args.bootstrap.write_bytes(tool.canonical(changed))
        with self.assertRaisesRegex(ValueError, 'bootstrap differs'):
            tool.validate_base(self.args)

    def test_added_headers_and_modified_content_java_config_force_new_base(self):
        self.create()
        targets = [self.project / 'Source/Game/New.h', self.project / 'Content/Main.umap',
                   self.project / 'Plugins/Native/Source/Loader.java', self.project / 'Config/DefaultEngine.ini']
        for target in targets:
            before = target.read_bytes() if target.exists() else None
            target.write_bytes((before or b'') + b'changed')
            with self.assertRaises(ValueError):
                tool.validate_base(self.args)
            if before is None:
                target.unlink()
            else:
                target.write_bytes(before)
        tool.validate_base(self.args)

    def test_publish_validates_actual_proof_and_locks_complete_version(self):
        self.create()
        self.args.source_hash = 'b' * 64
        binary = self.proof()
        with patch.object(tool, 'sign_payload', side_effect=self.fake_sign):
            result = tool.publish(self.args)
        release = Path(result['releaseDirectory'])
        self.assertEqual((release / 'libUnreal.so').read_bytes(), binary.read_bytes())
        envelope = tool.read(release / 'manifest.json')
        payload = json.loads(base64.b64decode(envelope['payloadBase64']))
        self.assertEqual(base64.b64decode(envelope['payloadBase64']), tool.canonical(payload))
        self.assertEqual(envelope['signatureAlgorithm'], 'SHA256withRSA')
        self.assertEqual(payload['baseNativeSourceHash'], 'a' * 64)
        self.assertEqual(payload['nativeSourceHash'], 'b' * 64)
        self.assertEqual(payload['soSha256'], tool.digest(binary))
        self.assertEqual(payload['soUrl'], 'https://updates.example.com/native/versions/311/libUnreal.so')
        self.assertFalse(result['remotelyPublished'])
        with self.assertRaisesRegex(ValueError, 'immutable'):
            tool.publish(self.args)

    def test_changed_or_failed_proof_is_rejected_before_signing(self):
        self.create()
        binary = self.proof()
        binary.write_bytes(binary.read_bytes() + b'tampered')
        with patch.object(tool, 'sign_payload') as signer:
            with self.assertRaisesRegex(ValueError, 'native binary size changed'):
                tool.publish(self.args)
            signer.assert_not_called()
        self.assertFalse((self.args.output / 'versions').exists())

    def test_replayed_id_and_signer_failure_never_publish_partial_version(self):
        self.create()
        self.proof()
        self.args.release_id = self.args.base_release_id
        with self.assertRaisesRegex(ValueError, 'must follow'):
            tool.publish(self.args)
        self.args.release_id += 1
        with patch.object(tool, 'sign_payload', side_effect=ValueError('test signer failure')):
            with self.assertRaisesRegex(ValueError, 'test signer failure'):
                tool.publish(self.args)
        self.assertFalse((self.args.output / 'versions' / str(self.args.release_id)).exists())
        self.assertFalse(any(self.args.output.glob('.native-release-*')))

    def test_insecure_urls_and_source_mismatch_are_rejected(self):
        self.args.manifest_url = 'http://updates.example.com/manifest.json'
        with self.assertRaisesRegex(ValueError, 'HTTPS'):
            self.create()
        self.args.manifest_url = 'https://updates.example.com/manifest.json'
        with patch.object(tool, 'current_native_hash', return_value='f' * 64):
            with self.assertRaisesRegex(ValueError, 'authoritative'):
                self.create()

    def test_strip_delivery_binds_manifest_to_derived_bytes_and_preserves_source(self):
        self.create()
        binary = self.proof(padding=64)
        original = binary.read_bytes()
        strip_tool = self.strip_fixture()
        with patch.object(tool.subprocess, 'run', side_effect=self.fake_strip), patch.object(tool, 'sign_payload', side_effect=self.fake_sign) as signer:
            result = tool.publish(self.args)
        release = Path(result['releaseDirectory'])
        receipt = tool.read(release / 'publish-receipt.json')
        envelope = tool.read(release / 'manifest.json')
        payload = json.loads(base64.b64decode(envelope['payloadBase64']))
        self.assertEqual(binary.read_bytes(), original)
        self.assertEqual(payload['soSize'], 120)
        self.assertEqual(payload['soSha256'], tool.digest(release / 'libUnreal.so'))
        self.assertNotEqual(payload['soSha256'], tool.digest(binary))
        self.assertEqual(receipt['verifiedNative']['nativeBinarySha256'], tool.digest(binary))
        derivation = receipt['deliveryDerivation']
        self.assertEqual(derivation['kind'], 'ndk-strip-unneeded')
        self.assertEqual(derivation['sourceBinarySize'], 184)
        self.assertEqual(derivation['deliverySize'], 120)
        self.assertEqual(derivation['stripToolSha256'], tool.digest(strip_tool))
        self.assertEqual(derivation['stripArguments'][1:3], ['--strip-unneeded', '-o'])
        self.assertEqual(derivation['stripArguments'][-1], str(binary.resolve()))
        self.assertEqual(signer.call_args.args[1], tool.canonical(payload))

    def test_strip_tool_must_match_the_verified_build_compiler_directory(self):
        self.create()
        self.proof(padding=64)
        strip_tool = self.strip_fixture()
        log = self.root / 'fixture-build.log'
        log.write_text('Result: Succeeded\nInstalledDir: ' + str(strip_tool.parent / 'different') + '\n', encoding='utf-8')
        with patch.object(tool, 'sign_payload') as signer:
            with self.assertRaisesRegex(ValueError, 'compiler directory'):
                tool.publish(self.args)
            signer.assert_not_called()

    def test_strip_failure_never_signs_or_publishes_partial_output(self):
        self.create()
        self.proof(padding=64)
        self.strip_fixture()
        def failing(command, **kwargs):
            if command[-1] == '--version':
                return self.fake_strip(command, **kwargs)
            Path(command[3]).write_bytes(b'partial')
            return subprocess.CompletedProcess(command, 1, stdout='', stderr='test strip failure')
        with patch.object(tool.subprocess, 'run', side_effect=failing), patch.object(tool, 'sign_payload') as signer:
            with self.assertRaisesRegex(ValueError, 'strip failed'):
                tool.publish(self.args)
            signer.assert_not_called()
        self.assertFalse((self.args.output / 'versions').exists())
        self.assertFalse(any(self.args.output.glob('.native-release-*')))

    def test_strip_cannot_change_original_or_emit_an_invalid_elf(self):
        self.create()
        binary = self.proof(padding=64)
        self.strip_fixture()
        def mutate(command, **kwargs):
            result = self.fake_strip(command, **kwargs)
            if command[-1] != '--version':
                binary.write_bytes(binary.read_bytes() + b'changed')
            return result
        with patch.object(tool.subprocess, 'run', side_effect=mutate), patch.object(tool, 'sign_payload') as signer:
            with self.assertRaisesRegex(ValueError, 'original verified binary changed'):
                tool.publish(self.args)
            signer.assert_not_called()
        self.proof(padding=64)
        # Recreate only the build's compiler-directory line after refreshing proof.
        log = self.root / 'fixture-build.log'
        log.write_text(log.read_text(encoding='utf-8') + 'InstalledDir: ' + str(self.args.strip_tool.parent) + '\n', encoding='utf-8')
        def invalid_elf(command, **kwargs):
            result = self.fake_strip(command, **kwargs)
            if command[-1] != '--version':
                derived = Path(command[3])
                data = bytearray(derived.read_bytes())
                struct.pack_into('<Q', data, 112, 4096)
                derived.write_bytes(data)
            return result
        with patch.object(tool.subprocess, 'run', side_effect=invalid_elf), patch.object(tool, 'sign_payload') as signer:
            with self.assertRaisesRegex(ValueError, '16 KiB'):
                tool.publish(self.args)
            signer.assert_not_called()

    def test_native_proof_is_revalidated_after_derivation_and_signing(self):
        self.create()
        self.proof(padding=64)
        self.strip_fixture()
        def change_proof(args, payload, certificate):
            signature = self.fake_sign(args, payload, certificate)
            value = tool.read(self.args.proof)
            value['nativeSourceHash'] = 'f' * 64
            self.args.proof.write_bytes(tool.canonical(value))
            return signature
        with patch.object(tool.subprocess, 'run', side_effect=self.fake_strip), patch.object(tool, 'sign_payload', side_effect=change_proof):
            with self.assertRaisesRegex(ValueError, 'source fingerprint differs'):
                tool.publish(self.args)
        self.assertFalse((self.args.output / 'versions').exists())

    def test_proof_metadata_change_during_strip_is_rejected_before_signing(self):
        self.create()
        self.proof(padding=64)
        self.strip_fixture()
        def change_proof(command, **kwargs):
            result = self.fake_strip(command, **kwargs)
            if command[-1] != '--version':
                value = tool.read(self.args.proof)
                value['projectCommit'] = 'changed-during-test-derivation'
                self.args.proof.write_bytes(tool.canonical(value))
            return result
        with patch.object(tool.subprocess, 'run', side_effect=change_proof), patch.object(tool, 'sign_payload') as signer:
            with self.assertRaisesRegex(ValueError, 'proof or build output changed during'):
                tool.publish(self.args)
            signer.assert_not_called()
        self.assertFalse((self.args.output / 'versions').exists())


class JavaSignerTest(unittest.TestCase):
    @unittest.skipUnless(os.environ.get('SAMPLEGAME_TEST_JAVA_HOME'), 'Set SAMPLEGAME_TEST_JAVA_HOME for temporary-key JKS integration test')
    def test_real_keystore_signing_and_wrong_certificate_refusal(self):
        java_home = Path(os.environ['SAMPLEGAME_TEST_JAVA_HOME'])
        suffix = '.exe' if os.name == 'nt' else ''
        with tempfile.TemporaryDirectory(prefix='native-signer-tests-') as temporary:
            work = Path(temporary)
            env = dict(os.environ)
            env['NATIVE_TEMP_STORE'] = 'temp-' + os.urandom(16).hex()
            env['NATIVE_TEMP_KEY'] = 'temp-' + os.urandom(16).hex()
            keytool = str(java_home / 'bin' / ('keytool' + suffix))
            key = work / 'temporary-test.jks'
            result = subprocess.run([keytool, '-genkeypair', '-alias', 'samplegame', '-keyalg', 'RSA', '-keysize', '2048',
                '-validity', '1', '-dname', 'CN=Temporary native signer unit test', '-keystore', str(key), '-storetype', 'JKS',
                '-storepass:env', 'NATIVE_TEMP_STORE', '-keypass:env', 'NATIVE_TEMP_KEY', '-noprompt'], env=env, capture_output=True)
            self.assertEqual(result.returncode, 0)
            certificate = work / 'expected.der'
            result = subprocess.run([keytool, '-exportcert', '-alias', 'samplegame', '-keystore', str(key),
                                     '-storepass:env', 'NATIVE_TEMP_STORE', '-file', str(certificate)], env=env, capture_output=True)
            self.assertEqual(result.returncode, 0)
            expected = hashlib.sha256(certificate.read_bytes()).hexdigest()
            result = subprocess.run([str(java_home / 'bin' / ('javac' + suffix)), '-d', str(work),
                                     str(tool.HERE / 'NativeManifestSigner.java')], capture_output=True)
            self.assertEqual(result.returncode, 0)
            payload = work / 'payload.json'
            payload.write_bytes(tool.canonical(dict(format=1, versionLabel='中文 test')))
            command = [str(java_home / 'bin' / ('java' + suffix)), '-cp', str(work), 'NativeManifestSigner', str(key),
                       'samplegame', str(payload), str(work / 'signature.bin'), str(work / 'actual.der'), str(work / 'actual.sha256'),
                       'NATIVE_TEMP_STORE', 'NATIVE_TEMP_KEY', expected]
            result = subprocess.run(command, env=env, capture_output=True)
            self.assertEqual(result.returncode, 0)
            self.assertEqual((work / 'actual.der').read_bytes(), certificate.read_bytes())
            self.assertGreater((work / 'signature.bin').stat().st_size, 128)
            self.assertFalse(any(work.glob('*.pem')))
            command[-1] = '0' * 64
            result = subprocess.run(command, env=env, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn(env['NATIVE_TEMP_STORE'].encode(), result.stdout + result.stderr)
            self.assertNotIn(env['NATIVE_TEMP_KEY'].encode(), result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
