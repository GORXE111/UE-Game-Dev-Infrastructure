"""Versioned native/content/save transactions for the V1.0.6 delivery pipeline.

This store does not launch UE, mount PAKs, download, or approve a production build.
Callers hold its OS lease until the selected game process has stopped. No existing
V1.0.5 channel or trust configuration is changed by this module.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import uuid

MAX_MANIFEST = 1024 * 1024
MAX_FILES = 8192
MAX_FILE = 8 * 1024**3
MAX_TOTAL = 32 * 1024**3
MAX_SAVES = 256 * 1024**2
MAX_NUMBER = 2**53 - 1
SHA = re.compile(r"[a-f0-9]{64}\Z")
TOKEN = re.compile(r"[A-Za-z0-9_.-]{1,128}\Z")
BINDINGS = ("projectId", "platform", "channel", "baseReleaseId", "engineBuildId", "shellCompatibilityId")
FIELDS = {"format", "kind", *BINDINGS, "releaseId", "minLoaderVersion", "sourceCommit",
          "nativeSourceHash", "buildId", "files", "save"}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("utf-8")


def parse(raw, maximum=MAX_MANIFEST):
    require(type(raw) is bytes and 0 < len(raw) <= maximum, "Invalid JSON size")
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "Duplicate JSON key")
            result[key] = value
        return result
    result = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
    require(canonical(result) == raw, "Release-set JSON must use the canonical encoding")
    return result


def number(value, minimum=0, maximum=MAX_NUMBER):
    require(type(value) is int and minimum <= value <= maximum, "Invalid integer")
    return value


def sha(value):
    require(type(value) is str and SHA.fullmatch(value), "Invalid SHA256")
    return value


def digest(path):
    result = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(256 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def relative(value):
    require(type(value) is str and 0 < len(value) <= 240, "Invalid relative path")
    parts = PurePosixPath(value).parts
    require(parts and "/".join(parts) == value and not value.startswith("/"), "Noncanonical relative path")
    for part in parts:
        require(TOKEN.fullmatch(part) and part not in (".", "..") and not part.endswith("."), "Unsafe path component")
        require(not re.fullmatch(r"(?i)(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?", part), "Device path forbidden")
    return value


def plain(path, directory=None):
    info = Path(path).lstat()
    require(not stat.S_ISLNK(info.st_mode) and not getattr(info, "st_file_attributes", 0) & 0x400,
            "Links and reparse points are forbidden")
    require(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode), "Unexpected filesystem object")


def child(root, name):
    relative(name)
    root = Path(root)
    plain(root, True)
    result = root
    for part in PurePosixPath(name).parts:
        result = result / part
        if result.exists() or result.is_symlink():
            info = result.lstat()
            require(not stat.S_ISLNK(info.st_mode) and not getattr(info, "st_file_attributes", 0) & 0x400,
                    "Aliased release-set path")
    require(result.resolve().is_relative_to(root.resolve()), "Path escaped root")
    return result


def write_new(path, raw):
    with Path(path).open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def read_bounded(path, maximum, empty=False):
    plain(path)
    require((0 if empty else 1) <= Path(path).stat().st_size <= maximum, "Metadata file size is invalid")
    with Path(path).open("rb") as stream:
        raw = stream.read(maximum + 1)
    require(len(raw) <= maximum, "Metadata grew beyond limit")
    return raw


def atomic(path, value):
    path = Path(path)
    raw = canonical(value)
    temporary = child(path.parent, "write-" + uuid.uuid4().hex + ".tmp")
    write_new(temporary, raw)
    os.replace(temporary, path)
    require(path.read_bytes() == raw, "Atomic state did not survive readback")


def save_policy(value):
    require(type(value) is dict and set(value) == {"schema", "readable", "migrations"}, "Invalid save policy")
    schema = number(value["schema"], maximum=10000)
    readable = value["readable"]
    require(type(readable) is list and 0 < len(readable) <= 64, "Invalid readable save schemas")
    for item in readable:
        number(item, maximum=schema)
    require(readable == sorted(set(readable)) and schema in readable, "Noncanonical readable schemas")
    migrations = value["migrations"]
    require(type(migrations) is list and len(migrations) <= 64, "Invalid migration registry")
    expected = sorted({version for first in readable for version in range(first, schema)})
    require(len(expected) <= 64, "Save migration path is too long")
    seen = []
    for item in migrations:
        require(type(item) is dict and set(item) == {"from", "to", "id"}, "Invalid save migration")
        first = number(item["from"], maximum=10000)
        require(number(item["to"], maximum=10000) == first + 1, "Migrations must advance one schema")
        require(type(item["id"]) is str and TOKEN.fullmatch(item["id"]), "Invalid migration identity")
        seen.append(first)
    require(seen == expected and len({item["id"] for item in migrations}) == len(migrations),
            "Every readable older schema requires a unique, contiguous migration path")
    return value


def build_id(value):
    return hashlib.sha256(canonical({key: value[key] for key in ("sourceCommit", "nativeSourceHash", "files", "save")})).hexdigest()


def windows_entry(project):
    require(type(project) is str and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", project)
            and project.lower() != "engine", "Invalid Windows project name")
    return relative(f"{project}/Binaries/Win64/{project}.exe")


def manifest(raw, trust):
    value = parse(raw)
    require(type(value) is dict and set(value) == FIELDS and type(value["format"]) is int
            and value["format"] == 1 and value["kind"] == "samplegame-release-set", "Unsupported release-set manifest")
    for key in BINDINGS:
        require(value[key] == trust[key] and type(value[key]) is type(trust[key]), "Shell identity mismatch: " + key)
    project = value["projectId"]
    require(value["platform"] == "Windows" or (value["platform"] == "Android_ARM64" and project == "SampleGame"),
            "Unsupported project/platform")
    entry = windows_entry(project) if value["platform"] == "Windows" else "libUnreal.so"
    for key in ("projectId", "channel", "engineBuildId"):
        require(type(value[key]) is str and TOKEN.fullmatch(value[key]), "Invalid identity token")
    sha(value["shellCompatibilityId"])
    number(value["baseReleaseId"], 1)
    number(value["releaseId"], value["baseReleaseId"])
    number(value["minLoaderVersion"], 1, number(trust["loaderVersion"], 1))
    require(type(value["sourceCommit"]) is str and re.fullmatch(r"[a-f0-9]{40}", value["sourceCommit"]), "Invalid source commit")
    sha(value["nativeSourceHash"])
    files = value["files"]
    require(type(files) is list and 2 <= len(files) <= MAX_FILES, "A release set requires native and cooked content")
    names, roles, total = [], set(), 0
    for item in files:
        require(type(item) is dict and set(item) == {"path", "role", "size", "sha256"}, "Invalid release file")
        name = relative(item["path"])
        role = item["role"]
        require(role in ("native", "content", "support"), "Invalid release file role")
        number(item["size"], 1, MAX_FILE)
        sha(item["sha256"])
        require(not any(part.lower() in ("saved", "savegames", ".release-sets") for part in name.split("/")), "Mutable state cannot be a release artifact")
        if value["platform"] == "Android_ARM64":
            require((role == "native" and name == "libUnreal.so") or
                    (role == "content" and re.fullmatch(r"Content/Paks/[A-Za-z0-9_.-]+\.pak", name)), "Android release payload is outside the frozen APK shell")
        else:
            require(name.startswith((project + "/", "Engine/")), "Windows artifact outside the complete game tree")
            if role == "native":
                require(name.lower().endswith((".exe", ".dll")), "Native file must be executable/library")
            if role == "content":
                require(name.startswith(project + "/Content/Paks/") and name.endswith(".pak"), "Content must be a cooked PAK")
        names.append(name)
        roles.add(role)
        total += item["size"]
    require(names == sorted(names) and len({name.lower() for name in names}) == len(names), "Duplicate, case-colliding or unsorted files")
    require({"native", "content"} <= roles and total <= MAX_TOTAL, "Incomplete or oversized release set")
    require(any(item["path"] == entry and item["role"] == "native" for item in files), "Native game entry missing")
    save_policy(value["save"])
    require(sha(value["buildId"]) == build_id(value), "Native/content/save build binding differs")
    return value


def verify_inventory(root, records, metadata=()):
    root = Path(root)
    plain(root, True)
    expected = {item["path"] for item in records}
    actual = set()
    for directory, children, names in os.walk(root, followlinks=False):
        for name in children:
            plain(Path(directory) / name, True)
        for name in names:
            path = Path(directory) / name
            plain(path)
            actual.add(path.relative_to(root).as_posix())
    require(actual == expected | set(metadata), "Release tree inventory differs from its signed manifest")


def verify_tree(root, records, metadata=()):
    verify_inventory(root, records, metadata)
    for item in records:
        path = child(root, item["path"])
        require(path.stat().st_size == item["size"] and digest(path) == item["sha256"], "Release artifact size/hash mismatch: " + item["path"])


def copy_verified_payload(source, target, item):
    """Check source bytes as they are copied into the private stage."""
    plain(source)
    expected = item["size"]
    message = "Release artifact size/hash mismatch: " + item["path"]
    require(source.stat().st_size == expected, message)
    result, size = hashlib.sha256(), 0
    with source.open("rb") as input_stream, target.open("xb") as output:
        while block := input_stream.read(256 * 1024):
            size += len(block)
            require(size <= expected, message)
            result.update(block)
            output.write(block)
        require(size == expected and result.hexdigest() == item["sha256"], message)
        output.flush()
        os.fsync(output.fileno())


def copy_saves(source, destination):
    """Opaque byte-preserving fork; UE performs declared semantic migrations later."""
    destination.mkdir()
    if source is None:
        return
    source = Path(source)
    plain(source, True)
    records, total = [], 0
    for directory, children, files in os.walk(source, followlinks=False):
        for name in children:
            plain(Path(directory) / name, True)
        for name in files:
            path = Path(directory) / name
            plain(path)
            name = relative(path.relative_to(source).as_posix())
            size = path.stat().st_size
            total += size
            require(len(records) < 4096 and total <= MAX_SAVES, "Save generation exceeds copy budget")
            records.append((name, size, digest(path)))
    require(shutil.disk_usage(destination).free >= total + 16 * 1024**2, "Insufficient disk for isolated saves")
    for name, size, expected in records:
        target = child(destination, name)
        target.parent.mkdir(parents=True, exist_ok=True)
        with child(source, name).open("rb") as input_stream, target.open("xb") as output:
            shutil.copyfileobj(input_stream, output, 256 * 1024)
            output.flush()
            os.fsync(output.fileno())
        require(target.stat().st_size == size and digest(target) == expected and digest(child(source, name)) == expected,
                "Save changed during the cold-start snapshot")


def ed25519_verifier(public_key_hex):
    sha(public_key_hex)
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
    key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
    def verify(raw, signature):
        require(type(signature) is bytes and len(signature) == 64, "Invalid Ed25519 signature")
        try:
            key.verify(signature, raw)
        except InvalidSignature as error:
            raise ValueError("Release-set signature rejected") from error
    return verify


class ReleaseSetStore:
    """Immutable payloads, one atomic active pointer, private per-release saves."""
    def __init__(self, root, trust, verify_signature):
        self.root = Path(root).absolute()
        self.root.mkdir(parents=True, exist_ok=True)
        plain(self.root, True)
        self.trust = dict(trust)
        sha(trust["baseManifestSha256"])
        self.verify_signature = verify_signature
        self.locked = False
        self.process_selected = False
        for name in ("versions", "saves"):
            child(self.root, name).mkdir(exist_ok=True)

    @contextmanager
    def lease(self):
        require(not self.locked, "Release-set lease is not reentrant")
        path = child(self.root, "lease.lock")
        with path.open("a+b") as stream:
            if path.stat().st_size == 0:
                stream.write(b"0")
                stream.flush()
            stream.seek(0)
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.locked = True
            self.process_selected = False
            try:
                yield self
            finally:
                self.locked = False
                stream.seek(0)
                if os.name == "nt":
                    msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    fcntl.flock(stream.fileno(), fcntl.LOCK_UN)

    def _held(self):
        require(self.locked, "A cold-start OS lease is required")

    def _path(self, number_value):
        number(number_value, self.trust["baseReleaseId"])
        return child(child(self.root, "versions"), str(number_value))

    def _read_version(self, release, *, verify_payload=True):
        directory = self._path(release)
        raw = read_bounded(child(directory, "manifest.json"), MAX_MANIFEST)
        signature = read_bounded(child(directory, "manifest.sig"), 8192, empty=True)
        if release == self.trust["baseReleaseId"]:
            require(hashlib.sha256(raw).hexdigest() == self.trust["baseManifestSha256"], "Installed base manifest changed")
        else:
            self.verify_signature(raw, signature)
        value = manifest(raw, self.trust)
        require(value["releaseId"] == release, "Immutable version identity differs")
        if verify_payload:
            verify_tree(directory, value["files"], ("manifest.json", "manifest.sig"))
        return value, hashlib.sha256(raw).hexdigest(), directory

    def confirmed_save_source(self, readable):
        """Read-only handover; never boot, repair or execute the old installation."""
        state = self._state()
        ref = (state["previous"] or state["base"]) if state["boot"] is not None else state["active"]
        value, expected, _ = self._read_version(ref["releaseId"], verify_payload=False)
        require(expected == ref["manifestSha256"], "Imported save manifest differs")
        require(value["save"]["schema"] in readable, "New base cannot read the confirmed save schema")
        return dict(reference=dict(ref), savesRoot=str(self._save_path(ref)), saveSchema=value["save"]["schema"],
                    pendingBootSkipped=state["boot"] is not None)

    def _ref(self, value):
        require(type(value) is dict and set(value) == {"releaseId", "manifestSha256", "saveGeneration"}, "Invalid selected release reference")
        number(value["releaseId"], self.trust["baseReleaseId"])
        sha(value["manifestSha256"])
        require(type(value["saveGeneration"]) is str and re.fullmatch(r"g-[a-f0-9]{32}", value["saveGeneration"]), "Invalid save generation")
        return value

    def _state(self):
        self._held()
        value = parse(read_bounded(child(self.root, "state.json"), 65536), 65536)
        require(type(value) is dict and set(value) == {"format", "base", "active", "previous", "highestReleaseId", "blocked", "boot"}
                and type(value["format"]) is int and value["format"] == 1, "Invalid release-set state")
        base, active = self._ref(value["base"]), self._ref(value["active"])
        require(base["releaseId"] == self.trust["baseReleaseId"] and base["manifestSha256"] == self.trust["baseManifestSha256"], "State belongs to another installed base")
        highest = number(value["highestReleaseId"], active["releaseId"])
        if value["previous"] is not None:
            previous = self._ref(value["previous"])
            require(previous["releaseId"] < active["releaseId"], "Previous release must precede selected release")
        blocked = value["blocked"]
        require(type(blocked) is list and len(blocked) <= 1024, "Invalid blocked release list")
        for release in blocked:
            number(release, self.trust["baseReleaseId"] + 1, highest)
        require(blocked == sorted(set(blocked)) and active["releaseId"] not in blocked, "Invalid blocked release order")
        if value["boot"] is not None:
            boot = value["boot"]
            require(type(boot) is dict and set(boot) == {"attemptId", "selection"} and boot["selection"] == active,
                    "Boot identity differs from the complete selected set")
            require(type(boot["attemptId"]) is str and uuid.UUID(boot["attemptId"]).hex == boot["attemptId"], "Invalid boot attempt")
        return value

    def _save_path(self, ref):
        path = child(child(self.root, "saves"), self._ref(ref)["saveGeneration"])
        plain(path, True)
        return path

    def _selection(self, ref):
        value, expected, directory = self._read_version(ref["releaseId"])
        require(expected == self._ref(ref)["manifestSha256"], "Selected manifest hash differs")
        return dict(reference=dict(ref), manifest=value, payloadRoot=str(directory), savesRoot=str(self._save_path(ref)))

    def _copy_version(self, source, raw, signature):
        value = manifest(raw, self.trust)
        destination = self._path(value["releaseId"])
        if destination.exists():
            verify_tree(source, value["files"])
            require(read_bounded(child(destination, "manifest.json"), MAX_MANIFEST) == raw
                    and read_bounded(child(destination, "manifest.sig"), 8192, empty=True) == signature,
                    "Release IDs are immutable")
            self._read_version(value["releaseId"])
            return value
        verify_inventory(source, value["files"])
        required = sum(item["size"] for item in value["files"]) + 32 * 1024**2
        require(shutil.disk_usage(self.root).free >= required, "Insufficient disk for a complete release set")
        temporary = child(child(self.root, "versions"), "stage-" + uuid.uuid4().hex)
        temporary.mkdir()
        try:
            for item in value["files"]:
                target = child(temporary, item["path"])
                target.parent.mkdir(parents=True, exist_ok=True)
                copy_verified_payload(child(source, item["path"]), target, item)
            verify_tree(temporary, value["files"])
            write_new(child(temporary, "manifest.json"), raw)
            write_new(child(temporary, "manifest.sig"), signature)
            os.replace(temporary, destination)
        except BaseException:
            if temporary.exists():
                shutil.rmtree(temporary)
            raise
        self._read_version(value["releaseId"])
        return value

    def initialize(self, source, raw, legacy_saves=None):
        self._held()
        require(not child(self.root, "state.json").exists(), "Release-set store already initialized")
        require(hashlib.sha256(raw).hexdigest() == self.trust["baseManifestSha256"], "Base manifest is not pinned by installed trust")
        value = manifest(raw, self.trust)
        require(value["releaseId"] == self.trust["baseReleaseId"], "Expected installed baseline release")
        self._copy_version(Path(source), raw, b"")
        generation = "g-" + uuid.uuid4().hex
        copy_saves(legacy_saves, child(child(self.root, "saves"), generation))
        ref = dict(releaseId=value["releaseId"], manifestSha256=self.trust["baseManifestSha256"], saveGeneration=generation)
        state = dict(format=1, base=ref, active=ref, previous=None, highestReleaseId=value["releaseId"], blocked=[], boot=None)
        atomic(child(self.root, "state.json"), state)
        return self._selection(ref)

    def stage(self, source, raw, signature):
        self._held()
        self.verify_signature(raw, signature)
        value = manifest(raw, self.trust)
        state = self._state()
        require(value["releaseId"] > state["highestReleaseId"] and value["releaseId"] not in state["blocked"], "Candidate is stale or blocked")
        self._copy_version(Path(source), raw, signature)
        return value["releaseId"]

    def activate(self, release):
        state = self._state()
        require(not self.process_selected, "A process already selected its native/content pair; restart before activation")
        require(state["boot"] is None and number(release, 1) > state["highestReleaseId"], "A boot is pending or candidate is stale")
        old = self._selection(state["active"])
        candidate, expected, _ = self._read_version(release)
        require(old["manifest"]["save"]["schema"] in candidate["save"]["readable"], "Candidate cannot migrate the selected save schema")
        generation = "g-" + uuid.uuid4().hex
        copy_saves(old["savesRoot"], child(child(self.root, "saves"), generation))
        ref = dict(releaseId=release, manifestSha256=expected, saveGeneration=generation)
        # The only visibility point. Payload verification and save fork precede it.
        state.update(previous=state["active"], active=ref, highestReleaseId=release)
        atomic(child(self.root, "state.json"), state)
        return self._selection(ref)

    def _rollback(self, state):
        failed = state["active"]["releaseId"]
        fallback = state["previous"] or state["base"]
        try:
            self._selection(fallback)
        except (OSError, ValueError):
            fallback = state["base"]
            self._selection(fallback)
        blocked = sorted(set(state["blocked"]) | ({failed} if failed != state["base"]["releaseId"] else set()))
        require(len(blocked) <= 1024, "Blocked history is full; a new baseline is required")
        state.update(active=fallback, previous=None, blocked=blocked, boot=None)
        atomic(child(self.root, "state.json"), state)
        return state

    def boot(self):
        require(not self.process_selected, "Cannot select a second native/content pair in the same process lease")
        state = self._state()
        if state["boot"] is not None:
            state = self._rollback(state)
        try:
            selected = self._selection(state["active"])
        except (OSError, ValueError):
            require(state["active"] != state["base"], "Installed base is damaged; repair installation")
            state = self._rollback(state)
            selected = self._selection(state["active"])
        attempt = uuid.uuid4().hex
        state["boot"] = dict(attemptId=attempt, selection=dict(state["active"]))
        atomic(child(self.root, "state.json"), state)
        self.process_selected = True
        selected["attemptId"] = attempt
        return selected

    def confirm(self, attempt, release, manifest_sha256, save_schema):
        state = self._state()
        boot = state["boot"]
        require(boot is not None and boot["attemptId"] == attempt and state["active"]["releaseId"] == number(release, 1)
                and state["active"]["manifestSha256"] == sha(manifest_sha256), "Health acknowledgement belongs to a different boot/set")
        selected = self._selection(state["active"])
        require(number(save_schema, maximum=10000) == selected["manifest"]["save"]["schema"], "Save migration is not ready")
        state["boot"] = None
        atomic(child(self.root, "state.json"), state)
        return selected

    def reject(self, attempt):
        state = self._state()
        require(state["boot"] is not None and state["boot"]["attemptId"] == attempt, "Failure belongs to a different boot")
        return self._selection(self._rollback(state)["active"])
