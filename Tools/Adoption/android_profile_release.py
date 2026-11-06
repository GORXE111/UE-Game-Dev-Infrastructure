"""Prepare disposable, independently signed Android ProfileSample test releases."""

import argparse
import base64
from datetime import datetime, timedelta, timezone
import hashlib
from ipaddress import ip_address
import json
import os
from pathlib import Path
import re
import secrets
import sys
from tempfile import TemporaryDirectory
import zipfile

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

import build_receipt

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "Tools" / "Release" / "ReleaseSets"))
import android_pipeline as android
import release_set as sets

PROJECT = "ProfileSample"
PACKAGE = "com.example.profilesample.adoption"
BOOTSTRAP = "com.example.samplegame.update.ReleaseBootstrapActivity"
ENDPOINT = "https://10.0.2.2/profile-sample/adoption-qa/updates/manifest.json"
ROLES = ("baseline", "candidate", "fault")
SIGN_PASSWORD = "UE_ADOPTION_ANDROID_QA_SIGN_PASSWORD"


def certificate(subject, public_key, issuer):
    now = datetime.now(timezone.utc)
    return (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(public_key)
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=7))
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False))


def name(value):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, value)])


def make_tls(output):
    authority_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    host_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    authority_name = name("ProfileSample Android adoption CA")
    authority = (certificate(authority_name, authority_key.public_key(), authority_name)
                 .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                 .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, None, None), critical=True)
                 .sign(authority_key, hashes.SHA256()))
    host = (certificate(name("10.0.2.2"), host_key.public_key(), authority_name)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ip_address("10.0.2.2"))]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(authority_key.public_key()), critical=False)
            .sign(authority_key, hashes.SHA256()))
    sets.write_new(output / "qa-ca.der", authority.public_bytes(serialization.Encoding.DER))
    sets.write_new(output / "qa-host.pem", host.public_bytes(serialization.Encoding.PEM))
    sets.write_new(output / "qa-host-key.pem", host_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return dict(status="android-qa-tls-prepared", endpoint=ENDPOINT, caDer=str(output / "qa-ca.der"),
                caSha256=sets.digest(output / "qa-ca.der"))


def apk_metadata(apk, aapt, output, ca, prefix):
    def dump(label, *arguments):
        path = output / f"{prefix}-{label}.log"
        android.execute([aapt, "dump", *arguments, apk], path)
        return path.read_text(encoding="utf-8", errors="replace")

    badging = dump("badging", "badging")
    sets.require(re.findall(r"(?m)^package: name='([^']+)'", badging) == [PACKAGE] and
                 re.findall(r"(?m)^launchable-activity: name='([^']+)'", badging) == [BOOTSTRAP] and
                 "application-debuggable" in badging, "Unexpected Android package, launcher activity or build type")
    manifest = dump("manifest", "xmltree", "--file", "AndroidManifest.xml")
    resources = dump("resources", "resources")
    resource = re.search(r"(?m)^\s*resource (0x[0-9a-f]+) (?:\S+:)?xml/profilesample_qa_network_security\b", resources, re.IGNORECASE)
    raw_ca = re.search(r"(?m)^\s*resource (0x[0-9a-f]+) (?:\S+:)?raw/profilesample_qa_ca\b", resources, re.IGNORECASE)
    sets.require(resource is not None and raw_ca is not None and
                 re.search(r"networkSecurityConfig[^\n]*=@" + re.escape(resource[1]), manifest, re.IGNORECASE) and
                 "com.epicgames.unreal.SplashActivity" in manifest and "com.epicgames.unreal.GameActivity" in manifest and
                 "android.permission.INTERNET" in manifest, "APK is missing the scoped test trust or UE startup activities")
    with zipfile.ZipFile(apk) as archive:
        inventory = android.zip_entries(archive)
        tls_xml = [item for item in inventory if item.endswith("/profilesample_qa_network_security.xml")]
        ca_entries = [item for item in inventory if re.fullmatch(r"res/raw/profilesample_qa_ca\.[A-Za-z0-9]+", item)]
        sets.require(len(tls_xml) == 1 and len(ca_entries) == 1 and inventory[ca_entries[0]].file_size <= 4096
                     and archive.read(ca_entries[0]) == ca, "APK test CA differs from the disposable fixture")
    xml = dump("network-security", "xmltree", "--file", tls_xml[0])
    anchors = re.findall(r"src=(.*)", xml)
    sets.require(re.findall(r"(?m)^\s*T: '([^']+)'$", xml) == ["10.0.2.2"]
                 and re.findall(r"cleartextTrafficPermitted=(\w+)", xml) == ["false", "false"]
                 and re.findall(r"includeSubdomains=(\w+)", xml) == ["false"]
                 and len(anchors) == 2 and re.fullmatch(r'"system"(?: \(Raw: "system"\))?', anchors[0])
                 and anchors[1] == "@" + raw_ca[1],
                 "Unexpected Android QA network security configuration")


def raw_build(report_path, role, number, aapt, output, versions, ca):
    report, report_bytes = build_receipt.read_json(report_path, build_receipt.MAX_METADATA)
    sets.require(report["status"] == "android-profile-packaged" and report["variant"] == role
                 and re.fullmatch(r"[a-f0-9]{40}", report["sourceCommit"]), "Expected the passing Android sample build report")
    apk = Path(report["apk"]).resolve(strict=True)
    sets.require(sets.digest(apk) == sets.sha(report["apkSha256"]), "Raw APK changed after the build")
    apk_metadata(apk, aapt, output, ca, role)
    payload = versions / str(number) / "payload"
    payload.mkdir(parents=True)
    files, mapping = android.payload_records(apk, number, payload, project_name=PROJECT)
    native = next(item for item in files if item["role"] == "native")
    sets.require(native["sha256"] == sets.sha(report["deliveryNativeSha256"]), "APK library differs from the verified NDK strip")
    elf = android.loader_elf(payload / native["path"])
    recorded_paks = sorted(report["stagePaks"], key=lambda item: item["path"])
    apk_paks = [dict(path=Path(item["path"]).name.removeprefix(f"r{number}_"), size=item["size"], sha256=item["sha256"])
                for item in files if item["role"] == "content"]
    sets.require(apk_paks == recorded_paks, "The APK embedded PAK set differs from the completed UAT stage")
    shell = android.apk_shell_inventory(apk, project_name=PROJECT)
    sets.require(sets.digest(apk) == report["apkSha256"], "Raw APK changed while preparing the release")
    return dict(apk=apk, manifestInput=report, reportSha256=hashlib.sha256(report_bytes).hexdigest(), files=files,
                shell=shell, mapping=mapping, nativeSha256=native["sha256"], elf=elf)


def prepare(args, output, report):
    ca = sets.read_bounded(args.tls / "qa-ca.der", 4096)
    authority = x509.load_der_x509_certificate(ca)
    sets.require(authority.extensions.get_extension_for_class(x509.BasicConstraints).value.ca, "Expected the test CA")
    java, signer, align = android.signing_tools(args.sdk, args.java_home)
    aapt = sets.child(align.parent, "aapt2.exe")
    versions = output / "Versions"
    report["phase"] = "verify-raw-apks"
    builds = [raw_build(getattr(args, role), role, number, aapt, output, versions, ca)
              for number, role in enumerate(ROLES, 100)]
    base = builds[0]
    expected_shell = {item["path"]: item for item in base["shell"]}
    for role, build in zip(ROLES[1:], builds[1:]):
        actual_shell = {item["path"]: item for item in build["shell"]}
        changes = sorted(path for path in expected_shell.keys() | actual_shell.keys()
                         if expected_shell.get(path) != actual_shell.get(path))
        sets.require(not changes, f"{role} changed the installed APK shell: {', '.join(changes[:5])}")
        sets.require(all(build["manifestInput"][field] == base["manifestInput"][field]
                         for field in ("engineBuildId", "ndkSourcePropertiesSha256")),
                     f"{role} changed the engine or NDK")
    sets.require(len({build["nativeSha256"] for build in builds}) == 3 and
                 len({sets.sha(build["manifestInput"]["nativeSourceSha256"]) for build in builds}) == 3 and
                 len({tuple(item["sha256"] for item in build["files"] if item["role"] == "content")
                      for build in builds}) == 3, "Android variants must have distinct native code and cooked PAK bytes")

    trust = dict(projectId=PROJECT, platform="Android_ARM64", channel="adoption-qa", baseReleaseId=100,
                 engineBuildId=base["manifestInput"]["engineBuildId"], loaderVersion=1,
                 shellCompatibilityId=hashlib.sha256(sets.canonical(base["shell"])).hexdigest())
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = name("ProfileSample Android disposable release signer")
    signer_certificate = (certificate(subject, private_key.public_key(), subject)
                          .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                          .sign(private_key, hashes.SHA256()))
    signer_der = signer_certificate.public_bytes(serialization.Encoding.DER)
    signer_sha256 = hashlib.sha256(signer_der).hexdigest()
    report["phase"] = "sign-release-sets"
    for number, build in enumerate(builds, 100):
        value = {field: trust[field] for field in sets.BINDINGS}
        value.update(format=1, kind="samplegame-release-set", releaseId=number, minLoaderVersion=1,
                     sourceCommit=build["manifestInput"]["sourceCommit"],
                     nativeSourceHash=build["manifestInput"]["nativeSourceSha256"], files=build["files"],
                     save=dict(schema=1, readable=[1], migrations=[]))
        value["buildId"] = sets.build_id(value)
        raw = sets.canonical(value)
        sets.manifest(raw, trust)
        directory = versions / str(number)
        sets.verify_tree(directory / "payload", build["files"])
        signature = private_key.sign(raw, padding.PKCS1v15(), hashes.SHA256())
        private_key.public_key().verify(signature, raw, padding.PKCS1v15(), hashes.SHA256())
        sets.write_new(directory / "manifest.json", raw)
        sets.write_new(directory / "manifest.json.sig", signature)
    raw = (versions / "100" / "manifest.json").read_bytes()
    trust["baseManifestSha256"] = hashlib.sha256(raw).hexdigest()
    config = dict(format=1, trust=trust, packageName=PACKAGE, manifestUrl=ENDPOINT, allowOffline=False,
                  signatureAlgorithm="SHA256withRSA", certificateBase64=base64.b64encode(signer_der).decode("ascii"),
                  certificateSha256=signer_sha256, baseArchiveEntries=base["mapping"])
    report["phase"] = "sign-apk"
    apk = output / "ProfileSample-Android-adoption-qa.apk"
    with TemporaryDirectory(prefix="signing-", dir=output) as scratch:
        scratch = Path(scratch)
        unsigned, aligned, keystore = (scratch / file for file in ("unsigned.apk", "aligned.apk", "disposable.p12"))
        android.rewrite_apk(base["apk"], unsigned, config, raw)
        android.execute([align, "-P", "16", "4", unsigned, aligned], output / "apk-zipalign.log")
        password = secrets.token_urlsafe(32)
        sets.write_new(keystore, pkcs12.serialize_key_and_certificates(
            b"adoption-qa", private_key, signer_certificate, None,
            serialization.BestAvailableEncryption(password.encode("ascii"))))
        env = dict(os.environ, **{SIGN_PASSWORD: password})
        android.execute([java, "-jar", signer, "sign", "--ks", keystore, "--ks-type", "PKCS12",
                         "--ks-key-alias", "adoption-qa", "--ks-pass", f"env:{SIGN_PASSWORD}",
                         "--key-pass", f"env:{SIGN_PASSWORD}", "--v1-signing-enabled", "true",
                         "--v2-signing-enabled", "true", "--out", apk, aligned], output / "apk-sign.log", env)
    verified = output / "apk-signature-verification.log"
    android.execute([java, "-jar", signer, "verify", "--verbose", "--print-certs", apk], verified)
    text = verified.read_text(encoding="utf-8", errors="replace")
    sets.require(re.findall(r"(?m)^Signer #\d+ certificate SHA-256 digest:\s*([a-f0-9]{64})\s*$", text) == [signer_sha256]
                 and re.search(r"Verified using v[23](?:\.1)? scheme.*:\s*true", text), "Unexpected final APK signer")
    android.execute([align, "-c", "-P", "16", "4", apk], output / "apk-alignment-verification.log")
    apk_metadata(apk, aapt, output, ca, "signed")
    with zipfile.ZipFile(apk) as final:
        sets.require(final.read(android.CONFIG_ENTRY) == sets.canonical(config) and final.read(android.MANIFEST_ENTRY) == raw,
                     "Final signed APK changed the pinned bootstrap data")
    sets.require(android.apk_shell_inventory(apk, project_name=PROJECT) == base["shell"] and
                 android.payload_records(apk, 100, project_name=PROJECT) == (base["files"], base["mapping"]),
                 "Final signed APK changed the verified runtime or shell")
    report.update(status="android-profile-prepared", phase="complete", apk=str(apk), apkSha256=sets.digest(apk),
                  versions=str(versions), packageName=PACKAGE, manifestUrl=ENDPOINT, certificateSha256=signer_sha256,
                  caSha256=hashlib.sha256(ca).hexdigest(),
                  nativeArtifacts={role: dict(sha256=build["nativeSha256"], elf=build["elf"])
                                   for role, build in zip(ROLES, builds)},
                  buildReportSha256={role: build["reportSha256"] for role, build in zip(ROLES, builds)})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    tls = commands.add_parser("tls", help="Create an off-repository disposable QA TLS identity")
    deliver = commands.add_parser("prepare", help="Wrap and sign three accepted Android sample archives")
    for command in (tls, deliver):
        command.add_argument("--output", type=Path, required=True)
    for role in ROLES:
        deliver.add_argument("--" + role, type=Path, required=True, help="Android sample package report")
    for argument in ("sdk", "java-home", "tls"):
        deliver.add_argument("--" + argument, type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    sets.require(os.name == "nt" and not output.is_relative_to(REPO), "Use Windows and an output directory outside the repository")
    output.mkdir()
    report = dict(status="blocked", phase="input")
    try:
        if args.command == "tls":
            report = make_tls(output)
        else:
            prepare(args, output, report)
    except (OSError, ValueError, KeyError, x509.ExtensionNotFound, zipfile.BadZipFile) as error:
        report["error"] = str(error)
    sets.write_new(output / "report.json", sets.canonical(report))
    print(json.dumps(report, indent=2))
    return 1 if report["status"] == "blocked" else 0


if __name__ == "__main__":
    raise SystemExit(main())
