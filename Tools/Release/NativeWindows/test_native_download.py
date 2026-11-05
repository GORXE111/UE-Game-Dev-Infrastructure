"""Real trusted loopback HTTPS/resume tests; no UE, production key or system trust changes."""
from datetime import datetime, timedelta, timezone
import hashlib
import http.server
import ipaddress
import json
import os
from pathlib import Path
import socket
import ssl
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from urllib.request import HTTPSHandler, ProxyHandler, build_opener
import zipfile

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat
from cryptography.x509.oid import NameOID

import native_launcher as native

GAME = 'SampleGame/Binaries/Win64/SampleGame.exe'


class NativeArchiveHTTPS(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tls_directory = tempfile.TemporaryDirectory(prefix='samplegame-native-test-ca-')
        folder = Path(cls.tls_directory.name)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.now(timezone.utc)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'SampleGame temporary loopback CA')])
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(days=1))
                .not_valid_after(now+timedelta(days=1))
                .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]), False)
                .add_extension(x509.BasicConstraints(ca=True, path_length=None), True).sign(key, hashes.SHA256()))
        cls.ca, cls.key = folder/'ca.pem', folder/'tls.pem'
        cls.ca.write_bytes(cert.public_bytes(Encoding.PEM))
        cls.key.write_bytes(key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))

    @classmethod
    def tearDownClass(cls):
        cls.tls_directory.cleanup()

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='samplegame-native-tls-range-')
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.requests, self.mode, self.etag = [], 'normal', '"fixture-v1"'
        self.payload = os.urandom(256*1024)
        self.archive = self.root/'candidate.zip'
        with zipfile.ZipFile(self.archive, 'w', zipfile.ZIP_DEFLATED) as zipped:
            zipped.writestr(GAME, self.payload)
        self.data = self.archive.read_bytes()
        fixture = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                fixture.requests.append(dict(path=self.path, range=self.headers.get('Range'),
                                             ifRange=self.headers.get('If-Range'), encoding=self.headers.get('Accept-Encoding')))
                if self.path == '/native/manifest.json':
                    body = fixture.raw
                elif self.path == '/native/manifest.json.sig':
                    body = fixture.signature
                elif self.path == '/native/versions/1/native-windows.zip':
                    body = fixture.data
                else:
                    self.send_error(404)
                    return
                archive = self.path.endswith('.zip')
                mode = fixture.mode if archive else 'normal'
                range_value = self.headers.get('Range')
                offset = int(range_value.removeprefix('bytes=').removesuffix('-')) if range_value else 0
                if mode == 'redirect':
                    self.send_response(302); self.send_header('Location', '/untrusted'); self.end_headers()
                    return
                if mode == 'status416':
                    self.send_error(416)
                    return
                resumed = bool(offset and mode != 'ignore-range')
                self.send_response(206 if resumed else 200)
                self.send_header('ETag', '"changed"' if mode == 'etag-changed' else fixture.etag)
                if resumed:
                    begin = offset+1 if mode == 'wrong-range' else offset
                    total = len(body)+1 if mode == 'wrong-total' else len(body)
                    self.send_header('Content-Range', f'bytes {begin}-{len(body)-1}/{total}')
                    body = body[offset:]
                elif mode == 'unsolicited-range':
                    self.send_header('Content-Range', f'bytes 0-{len(body)-1}/{len(body)}')
                if mode != 'no-length':
                    self.send_header('Content-Length', str(len(body)+(1 if mode == 'wrong-length' else 0)))
                if mode == 'gzip':
                    self.send_header('Content-Encoding', 'gzip')
                self.end_headers()
                if mode in ('disconnect', 'read-timeout'):
                    body = body[:65549]
                try:
                    self.wfile.write(body); self.wfile.flush()
                    if mode == 'read-timeout':
                        time.sleep(.25)
                    if mode == 'disconnect':
                        self.connection.shutdown(socket.SHUT_RDWR)
                except (OSError, ssl.SSLError):
                    pass  # Rejection tests deliberately close before reading the body.

        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.ca, self.key)
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.signing = ed25519.Ed25519PrivateKey.generate()
        origin = 'https://127.0.0.1:' + str(self.server.server_port)
        (self.root/GAME).parent.mkdir(parents=True)
        (self.root/GAME).write_bytes(b'baseline')
        self.config = dict(format=1, projectId='SampleGame', channel='loopback-test', platform='Windows', baseReleaseId=123,
                           engineBuildId='fixture-engine', compatibilityId='fixture-compat', manifestUrl=origin+'/native/manifest.json',
                           publicKeyHex=self.signing.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex(),
                           nativeFiles=[dict(path=GAME, size=8, sha256=hashlib.sha256(b'baseline').hexdigest())],
                           contentLauncher='SampleContent.exe', contentConfig='sample-player.json', allowOffline=True)
        self.manifest = {key: self.config[key] for key in native.IDENTITY}
        self.manifest.update(format=1, kind='samplegame-native-windows', nativeVersion=1,
                             archive=dict(path='versions/1/native-windows.zip', size=len(self.data), sha256=hashlib.sha256(self.data).hexdigest()),
                             files=[dict(path=GAME, size=len(self.payload), sha256=hashlib.sha256(self.payload).hexdigest())])
        self.raw = json.dumps(self.manifest, separators=(',', ':')).encode()
        self.signature = self.signing.sign(self.raw)
        self.url = origin+'/native/versions/1/native-windows.zip'
        self.install = native.NativeInstallation(self.root, self.config)
        self.install.recover()
        self.partial, self.sidecar = native.archive_partial_paths(self.install, 1)
        trusted = ssl.create_default_context(cafile=str(self.ca))
        opener_patch = patch.object(native, 'build_opener', side_effect=lambda *handlers:
                                   build_opener(ProxyHandler({}), HTTPSHandler(context=trusted), *handlers))
        opener_patch.start(); self.addCleanup(opener_patch.stop)

    def download(self):
        return native.download_archive(self.install, self.url, self.manifest, self.raw, self.signature)

    def interrupt(self):
        self.mode = 'disconnect'
        with self.assertRaises(native.DownloadInterrupted):
            self.download()
        self.assertGreater(self.partial.stat().st_size, 0)
        self.assertLess(self.partial.stat().st_size, len(self.data))
        self.assertEqual(self.partial.read_bytes(), self.data[:self.partial.stat().st_size])
        self.assertEqual((self.root/GAME).read_bytes(), b'baseline')
        self.assertEqual(self.install.state()['activeVersion'], 0)
        return self.partial.stat().st_size

    def test_real_tls_signed_download_stages_without_preactivating(self):
        self.assertEqual(native.check_update(self.install), 1)
        self.install.verify_version(1)
        self.assertEqual(self.install.state()['activeVersion'], 0)
        self.assertFalse(self.partial.exists()); self.assertFalse(self.sidecar.exists())
        self.assertEqual(self.requests[-1]['encoding'], 'identity')

    def test_real_network_interruption_then_new_install_instance_resumes_exact_206(self):
        offset = self.interrupt()
        self.mode = 'normal'
        self.install = native.NativeInstallation(self.root, self.config)
        self.assertEqual(native.check_update(self.install), 1)
        self.assertEqual(self.requests[-1]['range'], f'bytes={offset}-')
        self.assertEqual(self.requests[-1]['ifRange'], self.etag)
        self.install.verify_version(1)

    def test_range_ignored_200_safely_rewrites_from_zero(self):
        self.interrupt(); self.mode = 'ignore-range'
        self.assertEqual(self.download().read_bytes(), self.data)
        self.assertEqual(self.partial.stat().st_size, len(self.data))

    def test_complete_retained_partial_requires_whole_sha_without_another_http_request(self):
        self.download()
        count = len(self.requests)
        self.assertEqual(self.download(), self.partial)
        self.assertEqual(len(self.requests), count)
        corrupt = bytearray(self.partial.read_bytes()); corrupt[0] ^= 1; self.partial.write_bytes(corrupt)
        with self.assertRaisesRegex(ValueError, 'Complete native partial SHA'):
            self.download()
        self.assertEqual(len(self.requests), count)
        self.assertFalse(self.partial.exists()); self.assertFalse(self.sidecar.exists())

    def test_corrupt_existing_prefix_fails_final_whole_sha_and_discards(self):
        self.interrupt()
        bad = bytearray(self.partial.read_bytes()); bad[10] ^= 1; self.partial.write_bytes(bad)
        self.mode = 'normal'
        with self.assertRaisesRegex(ValueError, 'whole size/SHA'):
            self.download()
        self.assertFalse(self.partial.exists()); self.assertFalse(self.sidecar.exists())
        self.assertFalse(self.install.version(1).exists())

    def test_signed_metadata_change_does_not_reuse_old_prefix(self):
        self.interrupt(); self.raw += b' '; self.signature = self.signing.sign(self.raw)
        self.mode = 'normal'
        self.assertEqual(self.download().read_bytes(), self.data)
        self.assertIsNone(self.requests[-1]['range'])

    def test_malformed_or_oversized_sidecar_cannot_authorize_resume(self):
        for value in (b'{bad json', b'x'*(native.MAX_MANIFEST+1)):
            with self.subTest(length=len(value)):
                self.interrupt(); self.sidecar.write_bytes(value); self.mode = 'normal'
                self.assertEqual(self.download().read_bytes(), self.data)
                self.assertIsNone(self.requests[-1]['range'])
                native.discard_partial(self.install.cache, self.partial, self.sidecar)

    def test_resume_protocol_failures_discard_without_staging(self):
        for mode in ('wrong-range', 'wrong-total', 'wrong-length', 'etag-changed', 'gzip', 'status416'):
            with self.subTest(mode=mode):
                self.interrupt(); self.mode = mode
                with self.assertRaises(ValueError):
                    self.download()
                self.assertFalse(self.partial.exists()); self.assertFalse(self.sidecar.exists())
                self.assertFalse(self.install.version(1).exists())

    def test_initial_response_protocol_failures_are_not_kept(self):
        for mode in ('gzip', 'wrong-length', 'unsolicited-range', 'redirect'):
            with self.subTest(mode=mode):
                self.mode = mode
                with self.assertRaises(ValueError):
                    self.download()
                self.assertFalse(self.partial.exists()); self.assertFalse(self.sidecar.exists())
        self.assertFalse(any(x['path'] == '/untrusted' for x in self.requests))

    def test_certificate_rejection_preserves_tls_gate_and_discards_old_partial(self):
        self.interrupt(); self.mode = 'normal'
        untrusted = ssl.create_default_context()
        with patch.object(native, 'build_opener', side_effect=lambda *handlers:
                          build_opener(ProxyHandler({}), HTTPSHandler(context=untrusted), *handlers)):
            with self.assertRaisesRegex(ValueError, 'TLS'):
                self.download()
        self.assertFalse(self.partial.exists()); self.assertFalse(self.sidecar.exists())

    def test_write_fsync_failure_is_not_a_resumable_network_interruption(self):
        self.interrupt(); self.mode = 'normal'
        with patch.object(native.os, 'fsync', side_effect=OSError('fixture disk failure')):
            with self.assertRaisesRegex(OSError, 'disk failure'):
                self.download()
        self.assertFalse(self.partial.exists()); self.assertFalse(self.sidecar.exists())
        self.assertEqual((self.root/GAME).read_bytes(), b'baseline')

    def test_payload_write_failure_discards_resume_state(self):
        self.interrupt(); self.mode = 'normal'
        original = Path.open
        class DiskFailure:
            def __init__(inner, stream): inner.stream = stream
            def __getattr__(inner, name): return getattr(inner.stream, name)
            def write(inner, block): raise OSError('fixture payload write failed')
        def opened(path, mode='r', *args, **kwargs):
            stream = original(path, mode, *args, **kwargs)
            return DiskFailure(stream) if path == self.partial and mode == 'r+b' else stream
        with patch.object(Path, 'open', new=opened):
            with self.assertRaisesRegex(OSError, 'payload write failed'):
                self.download()
        self.assertFalse(self.partial.exists()); self.assertFalse(self.sidecar.exists())

    def test_payload_close_failure_still_discards_resume_authority(self):
        original = Path.open
        class CloseFailure:
            def __init__(inner, stream): inner.stream = stream
            def __getattr__(inner, name): return getattr(inner.stream, name)
            def close(inner):
                inner.stream.close()
                raise OSError('fixture payload close failed')
        def opened(path, mode='r', *args, **kwargs):
            stream = original(path, mode, *args, **kwargs)
            return CloseFailure(stream) if path == self.partial and mode == 'wb' else stream
        with patch.object(Path, 'open', new=opened):
            with self.assertRaisesRegex(OSError, 'payload close failed'):
                self.download()
        self.assertFalse(self.partial.exists()); self.assertFalse(self.sidecar.exists())

    def test_network_retention_fsync_error_discards_instead_of_reporting_retained(self):
        self.mode = 'disconnect'
        original = os.fsync
        def fsync(descriptor):
            if self.partial.exists() and os.fstat(descriptor).st_ino == self.partial.stat().st_ino:
                raise OSError('fixture retention fsync failed')
            return original(descriptor)
        with patch.object(native.os, 'fsync', side_effect=fsync):
            with self.assertRaisesRegex(OSError, 'retention fsync failed'):
                self.download()
        self.assertFalse(self.partial.exists()); self.assertFalse(self.sidecar.exists())

    def test_single_read_timeout_retains_only_actual_bound_bytes(self):
        self.mode = 'read-timeout'
        with patch.object(native, 'ARCHIVE_READ_SECONDS', .05):
            with self.assertRaises(native.DownloadInterrupted):
                self.download()
        length = self.partial.stat().st_size
        self.assertTrue(0 < length < len(self.data))
        self.assertEqual(self.partial.read_bytes(), self.data[:length])
        self.mode = 'normal'
        self.assertEqual(self.download().read_bytes(), self.data)
        self.assertEqual(self.requests[-1]['range'], f'bytes={length}-')

    def test_archive_can_progress_past_old_900_seconds_with_bounded_clock(self):
        clock = [0]
        def monotonic():
            clock[0] += 31
            return clock[0]
        with patch.object(native.time, 'monotonic', side_effect=monotonic):
            self.assertEqual(self.download().read_bytes(), self.data)
        self.assertGreater(clock[0], 900)

    def test_external_transfer_deadline_retains_valid_prefix_without_false_verified(self):
        offset = self.interrupt(); self.mode = 'normal'
        clock = [0]
        def monotonic():
            clock[0] += 6
            return clock[0]
        with patch.object(native, 'ARCHIVE_TOTAL_SECONDS', 5), patch.object(native.time, 'monotonic', side_effect=monotonic):
            with self.assertRaisesRegex(native.DownloadInterrupted, 'bounded transfer'):
                self.download()
        self.assertEqual(self.partial.stat().st_size, offset)
        self.assertEqual(self.partial.read_bytes(), self.data[:offset])

    def test_no_content_length_still_enforces_signed_total_and_whole_sha(self):
        self.mode = 'no-length'
        self.assertEqual(self.download().read_bytes(), self.data)

    def test_bad_signature_or_cross_origin_prevents_any_archive_request(self):
        old = self.signature
        self.signature = old[:-1] + bytes([old[-1] ^ 1])
        with self.assertRaisesRegex(ValueError, 'signature'):
            self.download()
        self.signature = old
        with self.assertRaisesRegex(ValueError, 'origin'):
            native.download_archive(self.install, 'https://untrusted.example/archive.zip', self.manifest, self.raw, self.signature)
        self.assertEqual(self.requests, [])

    def test_hardlinked_partial_is_rejected_without_modifying_alias(self):
        try:
            os.link(self.root/GAME, self.partial)
        except OSError as error:
            self.skipTest('Host cannot create test hardlink: ' + str(error))
        with self.assertRaisesRegex(ValueError, 'unaliased regular'):
            self.download()
        self.assertEqual((self.root/GAME).read_bytes(), b'baseline')
        self.assertEqual(self.requests, [])


if __name__ == '__main__': unittest.main()
