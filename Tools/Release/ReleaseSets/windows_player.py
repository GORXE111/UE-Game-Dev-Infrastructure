"""Frozen Windows player: one signed native/content/save selection per process."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import ssl
import subprocess
import sys
import time
import traceback
import uuid
from urllib.error import URLError
from urllib.parse import urljoin, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

import release_set as sets

CONFIG_FIELDS = {"format", "trust", "publicKeyHex", "manifestUrl", "allowOffline"}
TRUST_FIELDS = {*sets.BINDINGS, "loaderVersion", "baseManifestSha256"}
ACK_FIELDS = {"format", "attemptId", "releaseId", "manifestSha256", "buildId", "saveSchema", "pid", "userRoot", "luaVersion"}
PREVIOUS_BASES = {420: "0000000000000000000000000000000000000000000000000000000000000000"}


def endpoint(url):
    parts = urlsplit(url)
    sets.require(parts.scheme == "https" and parts.hostname and not parts.username and not parts.password
                 and not parts.query and not parts.fragment and parts.port in (None, 443), "Update URL must be plain HTTPS")
    sets.require("%" not in parts.path and "\\" not in parts.path and ".." not in parts.path.split("/"), "Unsafe update URL")
    return parts.scheme, parts.hostname, parts.port or 443


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, file, code, message, headers, new_url):
        raise ValueError("Update redirects are forbidden")


def fetch(url, maximum, destination=None, progress=None):
    endpoint(url)
    opener = build_opener(NoRedirect())
    request = Request(url, headers={"User-Agent": "SampleGameReleasePlayer/1", "Accept-Encoding": "identity", "Cache-Control": "no-cache"})
    received, chunks, started = 0, [], time.monotonic()
    output = None
    try:
        with opener.open(request, timeout=15) as response:
            sets.require(response.status == 200 and response.geturl() == url, "Unexpected update response")
            sets.require(response.headers.get("Content-Encoding", "identity") in ("", "identity"), "Encoded update responses are forbidden")
            length = response.headers.get("Content-Length")
            sets.require(length is None or length.isdigit() and int(length) <= maximum, "Update response exceeds signed limit")
            if destination:
                output = Path(destination).open("xb")
            while True:
                sets.require(time.monotonic() - started < 6 * 3600, "Update download exceeded time budget")
                block = response.read1(min(256 * 1024, maximum - received + 1))
                if not block:
                    break
                received += len(block)
                sets.require(received <= maximum, "Update response is oversized")
                if output:
                    output.write(block)
                else:
                    chunks.append(block)
                if progress:
                    progress(received, maximum)
            sets.require(length is None or received == int(length), "Update response is truncated")
        if output:
            output.flush()
            os.fsync(output.fileno())
        return received if destination else b"".join(chunks)
    finally:
        if output:
            output.close()


def read_config(root):
    value = sets.parse(sets.read_bounded(sets.child(root, "release-player.json"), 8192), 8192)
    sets.require(type(value) is dict and set(value) == CONFIG_FIELDS and type(value["format"]) is int and value["format"] in (1, 2), "Invalid player configuration")
    trust = value["trust"]
    sets.require(type(trust) is dict and set(trust) == TRUST_FIELDS and trust["platform"] == "Windows", "Invalid installed trust")
    sets.sha(value["publicKeyHex"])
    sets.sha(trust["baseManifestSha256"])
    sets.require(type(value["allowOffline"]) is bool, "Invalid offline policy")
    endpoint(value["manifestUrl"])
    sets.require(value["manifestUrl"].endswith("/manifest.json"), "Unexpected manifest endpoint")
    return value


def candidate(store, config, fetcher=fetch, progress=None):
    """Only transport unavailability may fall back offline; rejected bytes never do."""
    raw = fetcher(config["manifestUrl"], sets.MAX_MANIFEST)
    signature = fetcher(config["manifestUrl"] + ".sig", 64)
    store.verify_signature(raw, signature)
    value = sets.manifest(raw, store.trust)
    state = store._state()
    if value["releaseId"] <= state["highestReleaseId"]:
        if value["releaseId"] == state["active"]["releaseId"]:
            sets.require(hashlib.sha256(raw).hexdigest() == state["active"]["manifestSha256"], "Published release ID was rewritten")
        return False
    # Recovery always precedes activation; an unconfirmed previous process is never superseded.
    sets.require(state["boot"] is None, "Recover the previous boot before checking a candidate")
    incoming = sets.child(store.root, "incoming")
    incoming.mkdir(exist_ok=True)
    directory = sets.child(incoming, "r-" + str(value["releaseId"]) + "-" + hashlib.sha256(raw).hexdigest()[:16])
    directory.mkdir(exist_ok=True)
    required = sum(item["size"] for item in value["files"])
    sets.require(shutil.disk_usage(directory).free >= required * 2 + 64 * 1024**2, "Insufficient disk for download and verified staging")
    base_url = config["manifestUrl"].rsplit("/", 1)[0] + "/"
    for item in value["files"]:
        target = sets.child(directory, item["path"])
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            sets.plain(target)
            if target.stat().st_size == item["size"] and sets.digest(target) == item["sha256"]:
                continue
            target.unlink()
        url = urljoin(base_url, "versions/" + str(value["releaseId"]) + "/payload/" + item["path"])
        sets.require(endpoint(url) == endpoint(base_url) and url.startswith(base_url), "Cross-origin release file")
        downloaded = fetcher(url, item["size"], target, progress)
        sets.require(downloaded == item["size"] and sets.digest(target) == item["sha256"], "Downloaded artifact differs from signed bytes")
    store.stage(directory, raw, signature)
    store.activate(value["releaseId"])
    return True


def ticket(store, selected):
    directory = sets.child(store.root, "boots")
    directory.mkdir(exist_ok=True)
    directory = sets.child(directory, selected["attemptId"])
    directory.mkdir()
    value = dict(attemptId=selected["attemptId"], releaseId=selected["reference"]["releaseId"],
                 manifestSha256=selected["reference"]["manifestSha256"], buildId=selected["manifest"]["buildId"],
                 saveSchema=selected["manifest"]["save"]["schema"], payloadRoot=selected["payloadRoot"],
                 userRoot=selected["savesRoot"], ackPath=str(directory / "health.json"))
    path = directory / "ticket.json"
    sets.write_new(path, sets.canonical(value))
    return path, value


def acknowledgement(value, expected, pid):
    sets.require(type(value) is dict and set(value) == ACK_FIELDS and type(value["format"]) is int and value["format"] == 1, "Invalid health acknowledgement")
    for key in ("attemptId", "releaseId", "manifestSha256", "buildId", "saveSchema"):
        sets.require(type(value[key]) is type(expected[key]) and value[key] == expected[key], "Health belongs to another native/content/save selection")
    sets.require(type(value["pid"]) is int and value["pid"] == pid, "Health belongs to another process")
    sets.require(type(value["userRoot"]) is str and os.path.normcase(os.path.abspath(value["userRoot"])) == os.path.normcase(os.path.abspath(expected["userRoot"])), "Health used another save generation")
    sets.require(type(value["luaVersion"]) is str and 0 < len(value["luaVersion"]) <= 64, "Lua release is not ready")
    return value


def game_arguments(selected, ticket_path, user_args):
    # User input cannot redirect saved data, content selection, identities, binaries or config.
    flags = {"-nullrhi", "-unattended", "-nosound", "-nosplash", "-renderoffscreen", "-d3d12", "-windowed",
             "-samplegameshowreleaseversion", "-samplegamemenuprobe", "-samplegameskipboot"}
    values = {"-resx", "-resy", "-samplegamebootexitaftermenu", "-samplegamebootautostart", "-samplegamebootframes",
              "-samplegamemenuscreenshot", "-samplegameexpectedcontentversion"}
    for argument in user_args:
        sets.require(type(argument) is str and '"' not in argument and "\n" not in argument and "\r" not in argument
                     and (argument.lower() in flags or "=" in argument and argument.split("=", 1)[0].lower() in values),
                     "Game argument is not an approved display or diagnostic option")
    entry = sets.child(selected["payloadRoot"], "SampleGame/Binaries/Win64/SampleGame.exe")
    return [str(entry), "-UserDir=" + selected["savesRoot"], "-SampleGameReleaseTicket=" + str(ticket_path),
            "-abslog=" + str(ticket_path.parent / "game.log"), *user_args]


def windows_command(arguments):
    # UE FParse requires -Key="path with spaces", rather than quoting the whole -Key=value token.
    result = [subprocess.list2cmdline([arguments[0]])]
    for argument in arguments[1:]:
        if "=" in argument:
            key, value = argument.split("=", 1)
            sets.require('"' not in value and not value.endswith("\\"), "Unrepresentable UE command-line value")
            result.append(key + '="' + value + '"')
        else:
            sets.require(re.fullmatch(r"-[A-Za-z0-9]+", argument), "Invalid UE flag")
            result.append(argument)
    return " ".join(result)


def launch(store, selected, user_args=(), popen=subprocess.Popen, startup_timeout=300):
    ticket_path, expected = ticket(store, selected)
    arguments = game_arguments(selected, ticket_path, user_args)
    process = None
    ack_path = Path(expected["ackPath"])

    def read_acknowledgement():
        value = json.loads(sets.read_bounded(ack_path, 8192).decode("utf-8"))
        acknowledgement(value, expected, process.pid)
        return value

    try:
        process = popen(windows_command(arguments) if os.name == "nt" else arguments, cwd=selected["payloadRoot"], close_fds=True)
        started = time.monotonic()
        healthy = False
        while process.poll() is None:
            if not healthy:
                try:
                    read_acknowledgement()
                    healthy = True
                except (OSError, ValueError) as error:
                    if time.monotonic() - started > startup_timeout:
                        raise ValueError("Game did not provide valid startup health within its startup budget") from error
            time.sleep(.2)
        code = process.wait()
        sets.require(code == 0, "Selected game exited with status " + str(code))
        # Health AND a normal session exit are required. Exit 0 alone never commits a candidate.
        value = read_acknowledgement()
        store.confirm(selected["attemptId"], expected["releaseId"], expected["manifestSha256"], value["saveSchema"])
        sets.atomic(ticket_path.parent / "result.json", dict(status="confirmed", exitCode=code, health=value))
        return code
    except BaseException as error:
        # Never let another process acquire the lease while our game might still be alive.
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        store.reject(selected["attemptId"])
        sets.atomic(ticket_path.parent / "result.json", dict(status="rolled-back", reason=str(error)))
        raise


def legacy_snapshot(root, requested=None):
    """Only persistent saves/settings; shader caches and logs are reproducible."""
    if requested is None:
        candidates = [Path(root) / "SampleGame", Path(os.environ.get("LOCALAPPDATA", str(root))) / "SampleGame"]
        candidates = [path for path in candidates if (path / "Saved/SaveGames").is_dir()]
        sets.require(len(candidates) <= 1, "Multiple old save locations found; use --import-user-root to choose one")
        requested = candidates[0] if candidates else None
    if requested is None:
        return None
    source = Path(requested).absolute()
    sets.plain(source, True)
    total, names = 0, set()
    for name in ("SaveGames", "Config"):
        tree = sets.child(source, "Saved/" + name)
        if tree.exists():
            sets.plain(tree, True)
            for path in tree.rglob("*"):
                sets.plain(path, path.is_dir())
                if path.is_file():
                    key = path.relative_to(source).as_posix().lower()
                    sets.require(key not in names, "Ambiguous imported save filename")
                    names.add(key); total += path.stat().st_size
                    sets.require(len(names) <= 4096 and total <= sets.MAX_SAVES, "Imported saves exceed snapshot budget")
    staging = sets.child(root, ".release-import-" + uuid.uuid4().hex)
    staging.mkdir()
    for name in ("SaveGames", "Config"):
        path = sets.child(source, "Saved/" + name)
        if path.exists():
            (staging / "Saved").mkdir(exist_ok=True)
            sets.copy_saves(path, staging / "Saved" / name)
    return staging


def store_root(root, config):
    directory = sets.child(root, ".release-sets")
    if config["format"] == 2:
        trust = config["trust"]
        directory = sets.child(root, ".release-sets/b%d-%s" % (trust["baseReleaseId"], trust["baseManifestSha256"][:16]))
    return directory


def release_snapshot(root, source, config, base):
    """Import an official old cohort under its lease, leaving all old state untouched."""
    old_root = sets.child(Path(source).absolute(), ".release-sets")
    sets.plain(old_root, True)
    state = sets.parse(sets.read_bounded(sets.child(old_root, "state.json"), 65536), 65536)
    old_id = state["base"]["releaseId"]
    sets.require(type(old_id) is int and old_id in PREVIOUS_BASES and old_id < base["baseReleaseId"], "Unsupported prior installation base")
    raw = sets.read_bounded(sets.child(old_root, "versions/%d/manifest.json" % old_id), sets.MAX_MANIFEST)
    sets.require(hashlib.sha256(raw).hexdigest() == PREVIOUS_BASES[old_id], "Prior base is not an official pinned baseline")
    old_base = sets.parse(raw)
    trust = {key: old_base[key] for key in sets.BINDINGS}
    trust.update(loaderVersion=1, baseManifestSha256=PREVIOUS_BASES[old_id])
    sets.require(trust["platform"] == "Windows" and trust["projectId"] == config["trust"]["projectId"], "Prior installation belongs to another product")
    old = sets.ReleaseSetStore(old_root, trust, sets.ed25519_verifier(config["publicKeyHex"]))
    with old.lease():
        selected = old.confirmed_save_source(base["save"]["readable"])
        snapshot = legacy_snapshot(root, selected["savesRoot"])
        # Enforce the aggregate budget across both authored trees, and recheck copied bytes.
        total, count = 0, 0
        for path in snapshot.rglob("*"):
            sets.plain(path, path.is_dir())
            if path.is_file():
                total += path.stat().st_size; count += 1
        sets.require(total <= sets.MAX_SAVES and count <= 4096, "Imported saves exceed snapshot budget")
        return snapshot, dict(format=1, sourceBaseReleaseId=old_id, **selected)


def run(root, offline=False, user_args=(), import_user_root=None, fetcher=fetch, progress=None, starting=None, import_release_root=None):
    root = Path(root).absolute()
    sets.plain(root, True)
    config = read_config(root)
    sets.require(import_user_root is None or import_release_root is None, "Choose one save import source")
    store = sets.ReleaseSetStore(store_root(root, config), config["trust"], sets.ed25519_verifier(config["publicKeyHex"]))
    with store.lease():
        if not (store.root / "state.json").exists():
            raw = sets.read_bounded(sets.child(root, "base/manifest.json"), sets.MAX_MANIFEST)
            base = sets.manifest(raw, config["trust"])
            source = import_release_root
            if source is None and config["format"] == 2 and (root / ".release-sets/state.json").is_file():
                sets.require(import_user_root is None, "An old installation already exists here; import its confirmed saves")
                source = root
            if source is not None:
                legacy, receipt = release_snapshot(root, source, config, base)
                sets.atomic(sets.child(store.root, "save-import.json"), receipt)
            else:
                legacy = legacy_snapshot(root, import_user_root)
            store.initialize(sets.child(root, "base/payload"), raw, legacy)
        else:
            sets.require(import_user_root is None and import_release_root is None, "Saves can only be imported before the first launch")
        state = store._state()
        # Make an interrupted prior session/corrupt pair recover before any download or activation.
        if state["boot"] is not None:
            store._rollback(state)
        else:
            try:
                store._selection(state["active"])
            except (ValueError, OSError):
                sets.require(state["active"] != state["base"], "Installed base is damaged; repair the installation")
                store._rollback(state)
        if not offline:
            try:
                candidate(store, config, fetcher, progress)
            except URLError as error:
                sets.require(config["allowOffline"] and not isinstance(error.reason, ssl.SSLError), "Update transport failed")
                # TLS failures, invalid manifests, file corruption and disk errors never pass here.
                print("RELEASE_SET_OFFLINE " + str(error), flush=True)
        selected = store.boot()
        if starting:
            starting()
        return launch(store, selected, user_args)


def progress_window(operation, error_path):
    import queue
    import threading
    import tkinter as tk
    from tkinter import ttk
    events = queue.Queue()
    window = tk.Tk()
    window.title("SampleGame")
    window.geometry("460x170")
    window.resizable(False, False)
    window.configure(background="#292f2a")
    window.protocol("WM_DELETE_WINDOW", window.iconify)
    status = tk.StringVar(value="正在检查更新并校验游戏文件…")
    tk.Label(window, text="SAMPLEGAME / 开始游戏", bg="#292f2a", fg="#dcff32", font=("Arial", 17, "bold")).pack(pady=(22, 10))
    tk.Label(window, textvariable=status, bg="#292f2a", fg="#faf9e9").pack()
    bar = ttk.Progressbar(window, maximum=100, mode="indeterminate", length=390)
    bar.pack(pady=14); bar.start()
    result = [1]
    def worker():
        try:
            result[0] = operation(lambda count, total: events.put(("progress", count, total)), lambda: events.put(("starting",)))
        except BaseException:
            diagnostic = traceback.format_exc()
            try:
                Path(error_path).write_text(diagnostic, encoding="utf-8")
            except OSError:
                pass
            events.put(("error",))
        finally:
            events.put(("finished",))
    def poll():
        while not events.empty():
            item = events.get_nowait()
            if item[0] == "progress":
                bar.stop(); bar.configure(mode="determinate", value=item[1] * 100 / max(1, item[2]))
                status.set("正在下载更新  %.1f / %.1f MB" % (item[1] / 1024**2, item[2] / 1024**2))
            elif item[0] == "starting":
                window.withdraw()
            elif item[0] == "error":
                window.deiconify()
                from tkinter import messagebox
                messagebox.showerror("SampleGame", "游戏启动或更新失败，原有版本和存档已保留。\n请重试，或将 release-player-error.log 发给开发者。")
            elif item[0] == "finished":
                window.destroy(); return
        window.after(100, poll)
    thread = threading.Thread(target=worker)
    thread.start(); window.after(100, poll); window.mainloop(); thread.join()
    return result[0]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--headless", action="store_true")
    parser.add_argument("--import-user-root", type=Path)
    parser.add_argument("--import-release-root", type=Path, help="Old official installation directory; copy its confirmed progress")
    parser.add_argument("game_args", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    root = args.root or (Path(sys.executable).parent if getattr(sys, "frozen", False) else Path.cwd())
    user_args = args.game_args[1:] if args.game_args[:1] == ["--"] else args.game_args
    try:
        if args.headless:
            return run(root, args.offline, user_args, args.import_user_root, import_release_root=args.import_release_root)
        config = read_config(root)
        if (config["format"] == 2 and any(pin != "0" * 64 for pin in PREVIOUS_BASES.values())
                and not (store_root(root, config) / "state.json").exists()
                and not (root / ".release-sets/state.json").exists()
                and args.import_user_root is None and args.import_release_root is None):
            import tkinter as tk
            from tkinter import filedialog, messagebox
            prompt = tk.Tk(); prompt.withdraw()
            try:
                if messagebox.askyesno("接续游戏进度", "是否导入兼容旧版的游戏进度和设置？\n选择旧版 SampleGame.exe 所在文件夹。\n选择“否”将开始新进度，旧版数据仍会保留。", parent=prompt):
                    chosen = filedialog.askdirectory(title="选择旧版 SampleGame 所在文件夹", parent=prompt, mustexist=True)
                    if not chosen:
                        return 0
                    args.import_release_root = Path(chosen)
            finally:
                prompt.destroy()
        return progress_window(lambda progress, starting: run(root, args.offline, user_args, args.import_user_root, progress=progress, starting=starting, import_release_root=args.import_release_root), Path(root) / "release-player-error.log")
    except BaseException:
        diagnostic = traceback.format_exc()
        try:
            Path(root, "release-player-error.log").write_text(diagnostic, encoding="utf-8")
        except OSError:
            pass
        if not args.headless:
            import ctypes
            ctypes.windll.user32.MessageBoxW(None, "游戏启动或更新检查失败，已保留原有版本和存档。\n请查看 release-player-error.log。", "SampleGame", 0x10)
        print(diagnostic, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
