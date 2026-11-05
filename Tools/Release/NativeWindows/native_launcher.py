"""Project-owned cold native updater; delegates content verification to frozen SampleContentPlayer.

No game code is loaded here. Only explicitly trusted installed EXE/DLL paths may change.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import http.client
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import ssl
import stat
import subprocess
import sys
import time
import traceback
import uuid
from urllib.error import URLError
from urllib.parse import urljoin, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
import zipfile

MAX_MANIFEST = 65536
MAX_ARCHIVE = 1024 * 1024 * 1024
MAX_NATIVE_FILE = 1024 * 1024 * 1024
MAX_NATIVE_TOTAL = 2 * 1024 * 1024 * 1024
MAX_FILES = 32
ARCHIVE_TOTAL_SECONDS = 6 * 60 * 60
ARCHIVE_READ_SECONDS = 15
ARCHIVE_NO_PROGRESS_SECONDS = 60
ARCHIVE_BLOCK_BYTES = 64 * 1024
NATIVE_REPLACE_WAIT_SECONDS = 5.0
PROCESS_SCAN_ATTEMPTS = 3
SHA = re.compile(r"[a-f0-9]{64}\Z")
IDENTITY = ("projectId", "channel", "platform", "baseReleaseId", "engineBuildId", "compatibilityId")
CONFIG_FIELDS = {"format", *IDENTITY, "manifestUrl", "publicKeyHex", "nativeFiles", "contentLauncher", "contentConfig", "allowOffline"}
MANIFEST_FIELDS = {"format", "kind", *IDENTITY, "nativeVersion", "archive", "files"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def reject_duplicates(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def parse_json(raw, maximum=MAX_MANIFEST):
    require(0 < len(raw) <= maximum, "JSON evidence has invalid size")
    return json.loads(raw.decode("utf-8"), object_pairs_hook=reject_duplicates,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError(f"Invalid JSON constant: {value}")))


def digest(path):
    result = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def atomic_json(path, value):
    path = Path(path)
    temp = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    raw = (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8")
    with temp.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temp, path)


def relative_path(value):
    require(type(value) is str and 0 < len(value) < 240, "Native path is invalid")
    require("\\" not in value and ":" not in value and "\x00" not in value, "Native path must be an ordinary relative POSIX path")
    parts = PurePosixPath(value).parts
    require(parts and not value.startswith("/") and "/".join(parts) == value, "Noncanonical native path")
    for part in parts:
        require(part not in (".", "..") and re.fullmatch(r"[A-Za-z0-9_.-]+", part) and not part.endswith((".", " ")), "Unsafe native path component")
        require(not re.fullmatch(r"(?i)(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?", part), "Windows device path is forbidden")
    return value


def inside(root, relative):
    relative_path(relative)
    root = Path(root).resolve(strict=True)
    candidate = root
    for part in PurePosixPath(relative).parts:
        candidate = candidate / part
        if candidate.exists() or candidate.is_symlink():
            record = candidate.lstat()
            require(not stat.S_ISLNK(record.st_mode) and not (getattr(record, "st_file_attributes", 0) & 0x400), "Reparse points are not allowed inside native install/cache paths")
    require(candidate.resolve().is_relative_to(root), "Native path escapes installation")
    return candidate


def file_records(value):
    require(type(value) is list and 0 < len(value) <= MAX_FILES, "Native file inventory is invalid")
    seen = set()
    total = 0
    result = {}
    for item in value:
        require(type(item) is dict and set(item) == {"path", "size", "sha256"}, "Native inventory has unexpected fields")
        name = relative_path(item["path"])
        require(re.fullmatch(r"[A-Za-z0-9_.-]+/Binaries/Win64/[A-Za-z0-9_.-]+\.(?:exe|dll)", name, re.IGNORECASE), "Only game Win64 EXE/DLL files may be updated")
        require(name.lower() not in seen, "Case-colliding native paths")
        seen.add(name.lower())
        require(type(item["size"]) is int and 0 < item["size"] <= MAX_NATIVE_FILE and type(item["sha256"]) is str and SHA.fullmatch(item["sha256"]), "Native file size/hash is invalid")
        total += item["size"]
        result[name] = item
    require(total <= MAX_NATIVE_TOTAL, "Native inventory is too large")
    return result


def https_origin(url):
    parts = urlsplit(url)
    require(parts.scheme == "https" and parts.hostname and not parts.username and not parts.password and not parts.fragment and not parts.query, "Native endpoint must be plain HTTPS without credentials, query or fragment")
    require(not re.search(r"[\x00-\x20\\]", url), "Unsafe native URL")
    return (parts.scheme, parts.hostname.lower(), parts.port or 443)


def read_config(path):
    config = parse_json(Path(path).read_bytes())
    require(type(config) is dict and set(config) == CONFIG_FIELDS and config["format"] == 1, "Unsupported native player configuration")
    validate_identity(config)
    require(type(config["publicKeyHex"]) is str and SHA.fullmatch(config["publicKeyHex"]), "Invalid Ed25519 public key")
    https_origin(config["manifestUrl"])
    require(urlsplit(config["manifestUrl"]).path.endswith("/manifest.json"), "Native manifest URL must end in /manifest.json")
    require(config["contentLauncher"] == "SampleContent.exe" and config["contentConfig"] == "sample-player.json", "Frozen content entry/config cannot be redirected")
    require(type(config["allowOffline"]) is bool, "allowOffline must be boolean")
    file_records(config["nativeFiles"])
    return config


def validate_identity(value):
    for field in ("projectId", "channel", "engineBuildId", "compatibilityId"):
        require(type(value[field]) is str and re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", value[field]), f"Invalid native identity: {field}")
    require(value["platform"] == "Windows" and type(value["baseReleaseId"]) is int and value["baseReleaseId"] > 0, "Native platform/base identity is invalid")


def signed_manifest(raw, signature, config):
    require(len(signature) == 64, "Ed25519 signature must be 64 raw bytes")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(config["publicKeyHex"])).verify(signature, raw)
    except InvalidSignature as error:
        raise ValueError("Native manifest signature rejected") from error
    manifest = parse_json(raw)
    require(type(manifest) is dict and set(manifest) == MANIFEST_FIELDS and manifest["format"] == 1 and manifest["kind"] == "samplegame-native-windows", "Unsupported native manifest")
    validate_identity(manifest)
    for field in IDENTITY:
        require(manifest[field] == config[field], f"Native identity mismatch: {field}")
    version = manifest["nativeVersion"]
    require(type(version) is int and 0 < version <= 2**53 - 1, "Invalid native version")
    archive = manifest["archive"]
    require(type(archive) is dict and set(archive) == {"path", "size", "sha256"}, "Native archive record is invalid")
    require(archive["path"] == f"versions/{version}/native-windows.zip", "Native archive must use its immutable version path")
    require(type(archive["size"]) is int and 0 < archive["size"] <= MAX_ARCHIVE and type(archive["sha256"]) is str and SHA.fullmatch(archive["sha256"]), "Native archive size/hash is invalid")
    expected = file_records(config["nativeFiles"])
    actual = file_records(manifest["files"])
    require(expected.keys() == actual.keys(), "Native update must contain the complete preconfigured file allowlist")
    return manifest


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, file, code, message, headers, new_url):
        raise ValueError("Native download redirects are forbidden")


def fetch(url, maximum, destination=None, progress=None):
    https_origin(url)
    opener = build_opener(NoRedirect())
    request = Request(url, headers={"User-Agent": "SampleGameNativeLauncher/1", "Accept-Encoding": "identity"})
    chunks = []
    stream = None
    received = 0
    started = time.monotonic()
    try:
        if destination:
            stream = Path(destination).open("xb")
        with opener.open(request, timeout=15) as response:
            require(response.geturl() == url, "Unexpected native response URL")
            require(response.headers.get("Content-Encoding", "identity") in ("", "identity"), "Compressed HTTP native responses are unsupported")
            length = response.headers.get("Content-Length")
            if length is not None:
                require(length.isdigit() and int(length) <= maximum, "Native response exceeds declared limit")
            while True:
                require(time.monotonic() - started <= 900, "Native download exceeded total time limit")
                block = response.read(min(1024 * 1024, maximum - received + 1))
                if not block:
                    break
                received += len(block)
                require(received <= maximum, "Native download exceeded size limit")
                if stream:
                    stream.write(block)
                else:
                    chunks.append(block)
                if progress:
                    progress(received, maximum)
            if length is not None:
                require(received == int(length), "Native response was truncated")
        if stream:
            stream.flush()
            os.fsync(stream.fileno())
        return received if destination else b"".join(chunks)
    finally:
        if stream:
            stream.close()


class DownloadInterrupted(OSError):
    """Only a transient network interruption may leave a resumable archive."""


def regular_partial(path):
    if path.exists():
        value = path.stat()
        require(stat.S_ISREG(value.st_mode) and value.st_nlink == 1,
                "Native partial/sidecar must be an unaliased regular file")


def discard_partial(cache, partial, sidecar):
    for path in (partial, sidecar):
        checked = inside(cache, path.name)
        regular_partial(checked)
        if checked.exists():
            checked.unlink()


def strong_etag(value):
    return value if isinstance(value, str) and re.fullmatch(r'"[\x21\x23-\x7e]{1,512}"', value) else None


def archive_binding(url, manifest, raw, signature):
    return dict(format=1, signedMetadataSha256=hashlib.sha256(raw + signature).hexdigest(),
                url=url, size=manifest['archive']['size'], sha256=manifest['archive']['sha256'])


def archive_partial_paths(installation, number):
    return (inside(installation.cache, f'download-{number}.zip.part'),
            inside(installation.cache, f'download-{number}.zip.part.json'))


def download_archive(installation, url, manifest, raw, signature, progress=None):
    """Resume only the current signed raw archive; whole SHA remains mandatory before staging."""
    # This entry also rechecks its signed inputs so direct callers cannot bypass the policy.
    require(signed_manifest(raw, signature, installation.config) == manifest, "Archive metadata is not the verified manifest")
    expected_url = urljoin(installation.config['manifestUrl'], manifest['archive']['path'])
    require(url == expected_url and https_origin(url) == https_origin(installation.config['manifestUrl'])
            and url.startswith(installation.config['manifestUrl'].rsplit('/', 1)[0] + '/'),
            "Native payload must remain on the manifest origin and directory")
    number, total = manifest['nativeVersion'], manifest['archive']['size']
    partial, sidecar = archive_partial_paths(installation, number)
    for path in (partial, sidecar):
        regular_partial(path)
    binding = archive_binding(url, manifest, raw, signature)
    offset, etag = 0, None
    if partial.exists() and sidecar.exists():
        try:
            require(sidecar.stat().st_size <= MAX_MANIFEST, "Native resume sidecar is too large")
            saved = parse_json(sidecar.read_bytes())
            require(type(saved) is dict and set(saved) == set(binding) | {'etag'}
                    and {key: saved[key] for key in binding} == binding, "Native resume target changed")
            require(saved['etag'] is None or strong_etag(saved['etag']) == saved['etag'], "Invalid saved native ETag")
            offset, etag = partial.stat().st_size, saved['etag']
            require(0 <= offset <= total, "Native partial exceeds signed size")
        except (ValueError, KeyError, TypeError, UnicodeError):
            discard_partial(installation.cache, partial, sidecar)
            offset, etag = 0, None
    elif partial.exists() or sidecar.exists():
        discard_partial(installation.cache, partial, sidecar)
    if offset == total:
        try:
            require(digest(partial) == binding['sha256'], "Complete native partial SHA differs from signed archive")
        except BaseException:
            discard_partial(installation.cache, partial, sidecar)
            raise
        print(f'NATIVE_DOWNLOAD_VERIFIED version={number} bytes={total} recoveredCompletePartial=1', flush=True)
        return partial
    headers = {'User-Agent': 'SampleGameNativeLauncher/1', 'Accept-Encoding': 'identity'}
    if offset:
        headers['Range'] = f'bytes={offset}-'
        if etag:
            headers['If-Range'] = etag
    print(f'NATIVE_DOWNLOAD_REQUEST version={number} offset={offset} total={total}', flush=True)
    started = last_progress = time.monotonic()
    received, output = offset, None
    try:
        try:
            response = build_opener(NoRedirect()).open(Request(url, headers=headers), timeout=ARCHIVE_READ_SECONDS)
        except URLError as error:
            if isinstance(error.reason, ssl.SSLError):
                raise ValueError('Native TLS verification/handshake failed') from error
            if hasattr(error, 'code'):
                raise ValueError('Native archive HTTP response rejected: ' + str(error.code)) from error
            raise DownloadInterrupted(str(error)) from error
        except (TimeoutError, ConnectionError) as error:
            raise DownloadInterrupted(str(error)) from error
        with response:
            require(response.geturl() == url, "Unexpected native archive response URL")
            require(response.headers.get('Content-Encoding', 'identity') in ('', 'identity'),
                    "Compressed HTTP native archives are unsupported")
            status = response.status
            response_etag = strong_etag(response.headers.get('ETag'))
            if status == 206:
                require(offset > 0 and response.headers.get('Content-Range') == f'bytes {offset}-{total-1}/{total}',
                        "Native archive Content-Range differs from signed resume boundary")
                require(not etag or response_etag == etag, "Native archive resume ETag changed")
                write_offset = offset
            else:
                require(status == 200 and response.headers.get('Content-Range') is None,
                        "Native archive must be a full 200 or exact resumed 206")
                write_offset = 0
            length = response.headers.get('Content-Length')
            require(length is None or length.isdigit() and int(length) == total-write_offset,
                    "Native archive response length differs from signed remaining size")
            print(f'NATIVE_DOWNLOAD_RESPONSE version={number} code={status} offset={offset} writeOffset={write_offset} '
                  f'contentRange={response.headers.get("Content-Range", "none")}', flush=True)
            # Invalidate old resume authority before truncating on an ignored Range.
            # Interruption between these operations leaves an unbound partial, which is discarded next launch.
            if not write_offset and sidecar.exists():
                sidecar.unlink()
            partial = inside(installation.cache, partial.name)
            regular_partial(partial)
            output = partial.open('r+b' if write_offset else 'wb')
            if write_offset:
                require(os.fstat(output.fileno()).st_size == write_offset, "Native partial changed before append")
                output.seek(write_offset)
            received = write_offset
            atomic_json(sidecar, dict(binding, etag=response_etag))
            if progress:
                progress(received, total)
            while True:
                now = time.monotonic()
                if now-started > ARCHIVE_TOTAL_SECONDS or now-last_progress > ARCHIVE_NO_PROGRESS_SECONDS:
                    raise DownloadInterrupted('Native archive exceeded its bounded transfer/progress interval')
                try:
                    block = response.read1(min(ARCHIVE_BLOCK_BYTES, total-received+1))
                except ssl.SSLError as error:
                    raise ValueError('Native TLS record failed') from error
                except (OSError, http.client.IncompleteRead, http.client.RemoteDisconnected) as error:
                    raise DownloadInterrupted(str(error)) from error
                if not block:
                    if received != total:
                        raise DownloadInterrupted('Native archive ended before its signed size')
                    break
                received += len(block)
                require(received <= total, "Native archive exceeded signed total size")
                output.write(block)  # Disk errors remain fatal and never retain resume state.
                last_progress = time.monotonic()
                if progress:
                    progress(received, total)
            output.flush()
            os.fsync(output.fileno())
            output.close()
            output = None
        require(partial.stat().st_size == total and digest(partial) == binding['sha256'],
                "Native archive whole size/SHA differs from signed metadata")
        print(f'NATIVE_DOWNLOAD_VERIFIED version={number} bytes={total} recoveredCompletePartial=0', flush=True)
        return partial
    except DownloadInterrupted:
        if output:
            closing, output = output, None
            try:
                try:
                    closing.flush()
                    os.fsync(closing.fileno())
                finally:
                    closing.close()
            except BaseException:
                discard_partial(installation.cache, partial, sidecar)
                raise
        # Only keep a genuinely bound, nonempty partial. No data or state is fabricated.
        if partial.exists() and sidecar.exists() and 0 < partial.stat().st_size <= total:
            print(f'NATIVE_DOWNLOAD_RETAIN version={number} bytes={partial.stat().st_size} total={total}', flush=True)
        else:
            discard_partial(installation.cache, partial, sidecar)
        raise
    except BaseException:
        try:
            if output:
                output.close()
        finally:
            output = None
            discard_partial(installation.cache, partial, sidecar)
        raise
    finally:
        if output:
            output.close()


def verify_files(root, records):
    for name, record in records.items():
        path = inside(root, name)
        require(path.is_file() and path.stat().st_size == record["size"] and digest(path) == record["sha256"], f"Native file failed verification: {name}")


def extract_verified(archive, destination, manifest):
    records = file_records(manifest["files"])
    with zipfile.ZipFile(archive) as zipped:
        entries = zipped.infolist()
        require(len(entries) == len(records), "Native ZIP has unexpected entries")
        names = set()
        for entry in entries:
            name = relative_path(entry.filename)
            require(name in records and name.lower() not in names and not entry.is_dir(), "Native ZIP entry is unlisted or duplicated")
            names.add(name.lower())
            mode = entry.external_attr >> 16
            require(stat.S_IFMT(mode) in (0, stat.S_IFREG) and not (entry.flag_bits & 1), "Native ZIP links/encryption/special files are forbidden")
            require(entry.file_size == records[name]["size"], "Native ZIP expanded size differs from signed inventory")
            target = inside(destination, name)
            target.parent.mkdir(parents=True, exist_ok=True)
            copied = 0
            with zipped.open(entry) as source, target.open("xb") as output:
                while True:
                    block = source.read(min(1024 * 1024, entry.file_size - copied + 1))
                    if not block:
                        break
                    copied += len(block)
                    require(copied <= entry.file_size, "Native ZIP expanded beyond its signed size")
                    output.write(block)
            require(copied == entry.file_size, "Truncated native ZIP entry")
    verify_files(destination, records)


@contextmanager
def install_lock(cache):
    path = inside(cache, "install.lock")
    with path.open("a+b") as stream:
        if stream.tell() == 0:
            stream.write(b"0")
            stream.flush()
        stream.seek(0)
        if os.name == "nt":
            import msvcrt
            try:
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError as error:
                raise ValueError("Another native launcher owns this installation") from error
        else:
            import fcntl
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            yield
        finally:
            stream.seek(0)
            if os.name == "nt":
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


class ProcessInspectionError(RuntimeError):
    """A process could not be safely classified; never means it is absent."""


def _process_image_if_alive(kernel, handle, pid):
    import ctypes
    from ctypes import wintypes
    # A signalled process handle proves termination, even if its snapshot entry
    # or object remains alive while another process still holds a handle.
    wait = kernel.WaitForSingleObject(handle, 0)
    if wait == 0:
        return None
    if wait != 258:
        raise ProcessInspectionError(f"Cannot inspect game process termination pid={pid} winerror={ctypes.get_last_error()}")
    buffer = ctypes.create_unicode_buffer(32768)
    size = wintypes.DWORD(len(buffer))
    if not kernel.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)):
        error = ctypes.get_last_error()
        # The process may have exited between the zero-time wait and query.
        if kernel.WaitForSingleObject(handle, 0) == 0:
            return None
        raise ProcessInspectionError(f"Cannot verify game image path pid={pid} winerror={error}")
    return buffer.value


def _running_managed_game_once(root, names):
    """One conservative Windows snapshot. The caller may retry a stale snapshot."""
    if os.name != "nt":
        return False
    import ctypes
    from ctypes import wintypes
    class Entry(ctypes.Structure):
        _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD), ("th32ProcessID", wintypes.DWORD),
                    ("th32DefaultHeapID", ctypes.c_size_t), ("th32ModuleID", wintypes.DWORD), ("cntThreads", wintypes.DWORD),
                    ("th32ParentProcessID", wintypes.DWORD), ("pcPriClassBase", wintypes.LONG), ("dwFlags", wintypes.DWORD),
                    ("szExeFile", wintypes.WCHAR * 260)]
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(Entry)]
    kernel.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(Entry)]
    kernel.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
    kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel.WaitForSingleObject.restype = wintypes.DWORD
    snapshot = kernel.CreateToolhelp32Snapshot(2, 0)
    if not snapshot or snapshot == ctypes.c_void_p(-1).value:
        raise ProcessInspectionError(f"Cannot inventory running game processes winerror={ctypes.get_last_error()}")
    expected = {str(inside(root, name)).lower() for name in names if name.lower().endswith(".exe")}
    basenames = {Path(name).name.lower() for name in expected}
    entry = Entry()
    entry.dwSize = ctypes.sizeof(entry)
    try:
        present = kernel.Process32FirstW(snapshot, ctypes.byref(entry))
        while present:
            if entry.szExeFile.lower() in basenames and entry.th32ProcessID != os.getpid():
                # QUERY_LIMITED_INFORMATION plus SYNCHRONIZE: termination must
                # be distinguished from an inaccessible live process.
                handle = kernel.OpenProcess(0x101000, False, entry.th32ProcessID)
                if not handle:
                    raise ProcessInspectionError(f"Cannot verify a matching game process pid={entry.th32ProcessID} winerror={ctypes.get_last_error()}; refusing replacement")
                try:
                    image = _process_image_if_alive(kernel, handle, entry.th32ProcessID)
                    if image is not None and str(Path(image).resolve()).lower() in expected:
                        return True
                finally:
                    kernel.CloseHandle(handle)
            present = kernel.Process32NextW(snapshot, ctypes.byref(entry))
        if ctypes.get_last_error() != 18:  # ERROR_NO_MORE_FILES is the only complete enumeration.
            raise ProcessInspectionError(f"Game process enumeration did not complete winerror={ctypes.get_last_error()}")
        return False
    finally:
        kernel.CloseHandle(snapshot)


def running_managed_game(root, names):
    """Re-snapshot exit races; persistent unknown permissions still fail closed."""
    for attempt in range(PROCESS_SCAN_ATTEMPTS):
        try:
            return _running_managed_game_once(root, names)
        except ProcessInspectionError:
            if attempt + 1 == PROCESS_SCAN_ATTEMPTS:
                raise
            time.sleep(0.05)


def wait_for_managed_exit(root, names, deadline):
    while running_managed_game(root, names):
        remaining = deadline - time.monotonic()
        require(remaining > 0, "Game is running; native files can only change during cold start")
        time.sleep(min(0.1, remaining))


def replace_cold_native_file(source, target, root, names, deadline):
    while True:
        wait_for_managed_exit(root, names, deadline)
        try:
            os.replace(source, target)
            return
        except OSError as error:
            # Windows may briefly retain image/antivirus handles after the child
            # exits. Never ignore other errors or declare a failed replacement successful.
            remaining = deadline - time.monotonic()
            if os.name != "nt" or getattr(error, "winerror", None) not in (5, 32, 33) or remaining <= 0:
                raise
            time.sleep(min(0.1, remaining))


class NativeInstallation:
    def __init__(self, root, config):
        self.root = Path(root).resolve(strict=True)
        self.config = config
        self.base_records = file_records(config["nativeFiles"])
        self.cache = inside(self.root, ".native-update")
        self.cache.mkdir(exist_ok=True)
        self.versions = inside(self.cache, "versions")
        self.versions.mkdir(exist_ok=True)
        self.state_path = inside(self.cache, "state.json")
        self.journal_path = inside(self.cache, "transaction.json")

    def state(self):
        if not self.state_path.exists():
            return {"format": 1, "activeVersion": 0, "highestVersion": 0, "blockedVersions": [], "pendingVersion": 0}
        state = parse_json(self.state_path.read_bytes())
        require(type(state) is dict and set(state) == {"format", "activeVersion", "highestVersion", "blockedVersions", "pendingVersion"} and state["format"] == 1, "Invalid native installation state")
        for name in ("activeVersion", "highestVersion", "pendingVersion"):
            require(type(state[name]) is int and 0 <= state[name] <= 2**53 - 1, "Invalid native state version")
        require(type(state["blockedVersions"]) is list and len(state["blockedVersions"]) <= 10000 and all(type(value) is int and 0 < value <= state["highestVersion"] for value in state["blockedVersions"]), "Invalid blocked native versions")
        require(state["activeVersion"] <= state["highestVersion"] and state["pendingVersion"] <= state["highestVersion"], "Native state version order is invalid")
        return state

    def version(self, number):
        require(type(number) is int and 0 <= number <= 2**53 - 1, "Invalid cached native version")
        return inside(self.versions, str(number))

    def verify_version(self, number):
        directory = self.version(number)
        if number == 0:
            records = self.base_records
        else:
            manifest = signed_manifest(inside(directory, "manifest.json").read_bytes(), inside(directory, "manifest.json.sig").read_bytes(), self.config)
            require(manifest["nativeVersion"] == number, "Cached native version identity changed")
            records = file_records(manifest["files"])
        verify_files(directory, records)
        return directory, records

    def ensure_base(self):
        base = self.version(0)
        if base.exists():
            self.verify_version(0)
            return
        verify_files(self.root, self.base_records)
        require(shutil.disk_usage(self.cache).free > sum(record["size"] for record in self.base_records.values()) + 64 * 1024 * 1024, "Insufficient disk space for verified native base backup")
        staging = inside(self.versions, "staging-" + uuid.uuid4().hex)
        staging.mkdir()
        for name in self.base_records:
            target = inside(staging, name)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(inside(self.root, name), target)
        verify_files(staging, self.base_records)
        os.replace(staging, base)

    def apply(self, number):
        directory, records = self.verify_version(number)
        deadline = time.monotonic() + NATIVE_REPLACE_WAIT_SECONDS
        wait_for_managed_exit(self.root, records, deadline)
        for name in records:
            target = inside(self.root, name)
            require(target.is_file(), "A managed native install file disappeared")
            temp = target.with_name(target.name + ".native-" + uuid.uuid4().hex + ".tmp")
            try:
                with inside(directory, name).open("rb") as source, temp.open("xb") as output:
                    shutil.copyfileobj(source, output, 1024 * 1024)
                    output.flush()
                    os.fsync(output.fileno())
                replace_cold_native_file(temp, target, self.root, records, deadline)
            finally:
                if temp.exists():
                    temp.unlink()
        verify_files(self.root, records)

    def recover(self):
        state = self.state()
        self.ensure_base()
        if self.journal_path.exists():
            journal = parse_json(self.journal_path.read_bytes())
            require(type(journal) is dict and set(journal) == {"fromVersion", "toVersion"}, "Invalid native transaction journal")
            old, new = journal["fromVersion"], journal["toVersion"]
            require(type(old) is int and type(new) is int and 0 <= old < new <= 2**53 - 1, "Invalid native journal version order")
            self.verify_version(old)
            self.verify_version(new)
            if state["activeVersion"] == new and state["pendingVersion"] == 0:
                _, records = self.verify_version(new)
                verify_files(self.root, records)
            else:
                self.apply(old)
                state.update(activeVersion=old, highestVersion=max(state["highestVersion"], new), pendingVersion=0)
                state["blockedVersions"] = sorted(set(state["blockedVersions"]) | {new})
                atomic_json(self.state_path, state)
            self.journal_path.unlink()
        elif state["pendingVersion"]:
            raise ValueError("Pending native state has no recovery journal")
        directory, records = self.verify_version(state["activeVersion"])
        try:
            verify_files(self.root, records)
        except ValueError:
            self.apply(state["activeVersion"])
        return self.state()

    def stage(self, raw, signature, archive):
        manifest = signed_manifest(raw, signature, self.config)
        state = self.state()
        number = manifest["nativeVersion"]
        require(number > state["highestVersion"] and number not in state["blockedVersions"], "Native update is blocked, active or a downgrade")
        record = manifest["archive"]
        require(Path(archive).stat().st_size == record["size"] and digest(archive) == record["sha256"], "Native archive failed verification")
        destination = self.version(number)
        if destination.exists():
            require(inside(destination, "manifest.json").read_bytes() == raw and inside(destination, "manifest.json.sig").read_bytes() == signature, "Native version IDs are immutable")
            self.verify_version(number)
            return number
        required = sum(item["size"] for item in manifest["files"]) + max(item["size"] for item in manifest["files"]) + 64 * 1024 * 1024
        require(shutil.disk_usage(self.cache).free > required, "Insufficient disk space for complete native staging and atomic replacement")
        staging = inside(self.versions, "staging-" + uuid.uuid4().hex)
        staging.mkdir()
        extract_verified(archive, staging, manifest)
        (staging / "manifest.json").write_bytes(raw)
        (staging / "manifest.json.sig").write_bytes(signature)
        os.replace(staging, destination)
        self.verify_version(number)
        return number

    def activate(self, number):
        state = self.state()
        require(number > state["highestVersion"] and not state["pendingVersion"], "Native candidate is stale or a transaction is already pending")
        self.verify_version(number)
        _, old_records = self.verify_version(state["activeVersion"])
        verify_files(self.root, old_records)
        atomic_json(self.journal_path, {"fromVersion": state["activeVersion"], "toVersion": number})
        state.update(highestVersion=number, pendingVersion=number)
        atomic_json(self.state_path, state)
        self.apply(number)

    def finish(self, clean_exit):
        state = self.state()
        if not state["pendingVersion"]:
            return
        require(self.journal_path.exists(), "Native activation journal disappeared")
        journal = parse_json(self.journal_path.read_bytes())
        require(journal["toVersion"] == state["pendingVersion"] and journal["fromVersion"] == state["activeVersion"], "Native activation state/journal mismatch")
        if clean_exit:
            _, records = self.verify_version(state["pendingVersion"])
            verify_files(self.root, records)
            state.update(activeVersion=state["pendingVersion"], pendingVersion=0)
            atomic_json(self.state_path, state)
            self.journal_path.unlink()
        else:
            self.recover()


def check_update(installation, progress=None):
    config = installation.config
    raw = fetch(config["manifestUrl"], MAX_MANIFEST)
    signature = fetch(config["manifestUrl"] + ".sig", 64)
    manifest = signed_manifest(raw, signature, config)
    state = installation.state()
    number = manifest["nativeVersion"]
    if number <= state["highestVersion"] or number in state["blockedVersions"]:
        if number == state["activeVersion"]:
            cached = inside(installation.version(number), "manifest.json").read_bytes()
            require(cached == raw, "Active native version was republished with different bytes")
        return None
    record = manifest["archive"]
    url = urljoin(config["manifestUrl"], record["path"])
    require(https_origin(url) == https_origin(config["manifestUrl"]) and url.startswith(config["manifestUrl"].rsplit("/", 1)[0] + "/"), "Native payload must remain on the manifest origin and directory")
    cached = installation.version(number)
    if cached.exists():
        # A completed stage may survive interruption before activation. Reuse
        # only the exact current signed release, never repair an immutable ID
        # by downloading over corrupt or differently signed cached contents.
        for name, expected in (("manifest.json", raw), ("manifest.json.sig", signature)):
            with inside(cached, name).open("rb") as stream:
                require(stream.read(len(expected) + 1) == expected, "Cached staged native release differs from current signed metadata")
        _, records = installation.verify_version(number)
        require(records == file_records(manifest["files"]), "Cached native inventory differs from current signed release")
        print(f"NATIVE_STAGED_CACHE_HIT version={number}", flush=True)
        return number
    temporary = download_archive(installation, url, manifest, raw, signature, progress)
    try:
        return installation.stage(raw, signature, temporary)
    finally:
        partial, sidecar = archive_partial_paths(installation, number)
        discard_partial(installation.cache, partial, sidecar)


def run(config_path, headless=False, progress=None, starting=None):
    config_path = Path(config_path).resolve(strict=True)
    root = config_path.parent
    config = read_config(config_path)
    installation = NativeInstallation(root, config)
    content = inside(root, config["contentLauncher"])
    content_config = inside(root, config["contentConfig"])
    require(content.is_file() and content_config.is_file(), "Frozen content launcher/config is missing")
    with install_lock(installation.cache):
        installation.recover()
        candidate = None
        try:
            candidate = check_update(installation, progress)
        except (URLError, TimeoutError, ConnectionError, OSError, ValueError) as error:
            print(f"Native update unavailable/rejected: {type(error).__name__}: {error}", flush=True)
            require(config["allowOffline"], "Native update check failed and offline fallback is disabled")
        if candidate:
            try:
                installation.activate(candidate)
            except Exception:
                installation.recover()
                raise
        if starting:
            starting()
        command = [str(content), str(content_config)]
        if headless:
            command.append("--headless")
        try:
            code = subprocess.run(command, cwd=root, check=False).returncode
        except Exception:
            installation.finish(False)
            raise
        print(f"NATIVE_CHILD_EXIT code={code}", flush=True)
        installation.finish(code == 0)
        print(f"NATIVE_GAME_EXIT code={code} active={installation.state()['activeVersion']}", flush=True)
        return code


def run_with_progress(config_path):
    import queue
    import threading
    import tkinter as tk
    from tkinter import ttk
    events = queue.Queue()
    result = {"code": 1, "error": None}
    window = tk.Tk()
    window.title("正在进入游戏")
    window.geometry("380x108")
    window.resizable(False, False)
    window.protocol("WM_DELETE_WINDOW", lambda: None)
    message = ttk.Label(window, text="正在检查游戏程序更新…")
    message.pack(padx=18, pady=(18, 10), anchor="w")
    meter = ttk.Progressbar(window, mode="indeterminate", maximum=100, length=344)
    meter.pack(padx=18, pady=(0, 18))
    meter.start()
    def worker():
        try:
            result["code"] = run(config_path, progress=lambda done, total: events.put(("progress", (done, total))), starting=lambda: events.put(("starting", None)))
        except Exception as error:
            result["error"] = error
        finally:
            events.put(("done", None))
    thread = threading.Thread(target=worker)
    thread.start()
    def poll():
        while not events.empty():
            kind, value = events.get_nowait()
            if kind in ("starting", "done"):
                window.destroy()
                return
            if kind == "progress":
                done, total = value
                meter.stop()
                meter.configure(mode="determinate", value=100 * done / total)
                message.configure(text=f"正在更新游戏程序… {100 * done / total:.0f}%")
        window.after(100, poll)
    window.after(100, poll)
    window.mainloop()
    thread.join()
    if result["error"]:
        raise result["error"]
    return result["code"]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config", nargs="?", type=Path)
    parser.add_argument("--headless", action="store_true")
    options = parser.parse_args(argv)
    root = Path(sys.executable if getattr(sys, "frozen", False) else __file__).resolve().parent
    config = options.config or root / "native-player.json"
    try:
        from contextlib import redirect_stderr, redirect_stdout
        with (config.resolve(strict=True).parent / "native-update.log").open("a", encoding="utf-8", buffering=1) as log, redirect_stdout(log), redirect_stderr(log):
            print(f"NATIVE_CHECK_START time={time.time()}", flush=True)
            try:
                return run(config, True) if options.headless else run_with_progress(config)
            except Exception:
                traceback.print_exc()
                raise
    except Exception as error:
        if not options.headless and os.name == "nt":
            import ctypes
            ctypes.windll.user32.MessageBoxW(None, str(error), "游戏程序更新", 0x10)
        return 1


if __name__ == "__main__":
    sys.exit(main())
