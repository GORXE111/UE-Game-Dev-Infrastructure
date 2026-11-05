"""Prepare an insertion-only players route; apply separately with backup and rollback."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import subprocess

from deploy_players import Host
import players

MARKER = "    # SampleGame player downloads:"
ANCHOR = "    # Signed manifest and signature:"


def proposed_config(before):
    text = before.decode("utf-8")
    players.require(MARKER not in text and "/srv/ue-game-updates/players/" not in text, "Players route already exists; review rather than duplicate")
    players.require(text.count(ANCHOR) == 1 and "server_name updates.example.com;" in text, "Ambiguous nginx insertion anchor")
    fragment = Path(__file__).with_name("nginx-player.locations.conf").read_text(encoding="utf-8")
    proposed = text.replace(ANCHOR, fragment + "\n" + ANCHOR, 1)
    players.require(proposed.replace(fragment + "\n", "", 1) == text, "Existing nginx bytes changed")
    return proposed.encode("utf-8")


REMOTE_NGINX = r'''
import base64,hashlib,json,os,pathlib,re,subprocess,sys,uuid
p=json.loads(base64.b64decode(sys.argv[1]));name=p['config']
def check(ok,reason):
 if not ok:raise ValueError(reason)
check(re.fullmatch(r'/etc/nginx/(?:sites-available|conf\.d)/[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}',name)and'..'not in pathlib.PurePosixPath(name).name,'Unsafe nginx path')
config=pathlib.Path(name);check(config.is_file()and not config.is_symlink(),'nginx must be a regular file')
old=config.read_bytes();check(hashlib.sha256(old).hexdigest()==p['beforeSha256'],'nginx changed since review')
new=base64.b64decode(p['proposed'],validate=True);check(len(new)<1024*1024 and hashlib.sha256(new).hexdigest()==p['proposedSha256']and b'# SampleGame player downloads'in new,'Proposed bytes differ')
def state():
 result={}
 paths=[pathlib.Path('/srv/ue-game-updates/site/index.html')]
 for root in ['/srv/ue-game-updates/channels','/srv/ue-game-updates/native']:
  for directory in sorted(pathlib.Path(root).iterdir()):
   current=directory/'current'
   result[str(current)]={'kind':'symlink'if current.is_symlink()else'directory'if current.is_dir()else'missing','target':os.readlink(current)if current.is_symlink()else None}
   paths.extend([current/'manifest.json',current/'manifest.json.sig'])
 for path in paths:
  if path.exists():
   check(path.is_file()and path.stat().st_size<1024*1024,'Unexpected protected file');result[str(path)]=hashlib.sha256(path.read_bytes()).hexdigest()
  else:result[str(path)]=None
 return result
before=state();token=uuid.uuid4().hex;backup=config.with_name(config.name+'.players-backup-'+token)
with backup.open('xb')as stream:stream.write(old)
temporary=config.with_name(config.name+'.players-proposed-'+token)
with temporary.open('xb')as stream:stream.write(new)
os.chmod(temporary,0o644);os.replace(temporary,config)
report={'installed':False,'backup':str(backup),'checks':[]}
try:
 for command in [['nginx','-t'],['systemctl','reload','nginx']]:
  r=subprocess.run(command,capture_output=True,text=True,timeout=60);report['checks'].append({'command':command,'exitCode':r.returncode});check(r.returncode==0,r.stderr)
 check(state()==before,'Protected website/game channels changed')
 report.update(installed=True,sha256=hashlib.sha256(config.read_bytes()).hexdigest(),protectedUnchanged=True)
except Exception as error:
 report['error']=repr(error);recovery=config.with_name(config.name+'.players-recovery-'+token)
 with recovery.open('xb')as stream:stream.write(old)
 os.chmod(recovery,0o644);os.replace(recovery,config)
 report['recovery']=[]
 for command in [['nginx','-t'],['systemctl','reload','nginx']]:
  r=subprocess.run(command,capture_output=True,text=True,timeout=60);report['recovery'].append({'command':command,'exitCode':r.returncode})
 report['oldConfigRestored']=config.read_bytes()==old
print(json.dumps(report))
'''


def apply_config(before, proposed, host, nginx_config, report):
    report = Path(report).resolve()
    players.require(not report.is_relative_to(Path(__file__).resolve().parents[3]),
                    "Keep nginx deployment evidence outside repository")
    players.require(report.parent.is_dir() and not report.exists(),
                    "A fresh report in an existing external directory is required")
    payload = dict(config=nginx_config, beforeSha256=hashlib.sha256(before).hexdigest(),
                   proposedSha256=hashlib.sha256(proposed).hexdigest(), proposed=base64.b64encode(proposed).decode())
    encoded = base64.b64encode(players.canonical(payload)).decode()
    result = dict(installed=False, remoteOutcomeUnknown=True,
                  beforeSha256=payload["beforeSha256"], proposedSha256=payload["proposedSha256"])
    try:
        completed = subprocess.run(["ssh", *host.options, "-p", str(host.port), host.host, "python3", "-", encoded],
                                   input=REMOTE_NGINX.encode(), capture_output=True, timeout=240)
        players.require(completed.returncode == 0, "nginx transaction SSH failed: " + completed.stderr.decode("utf-8", "replace"))
        acknowledged = json.loads(completed.stdout)
        players.require(type(acknowledged) is dict and type(acknowledged.get("installed")) is bool,
                        "Invalid nginx transaction acknowledgement")
        result.update(acknowledged, remoteOutcomeUnknown=False)
    except Exception as error:
        result["error"] = repr(error)
    players.write_new(report, players.canonical(result))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("plan", "apply"))
    parser.add_argument("--before", type=Path, required=True)
    parser.add_argument("--proposed", type=Path, required=True)
    parser.add_argument("--nginx-config")
    parser.add_argument("--host")
    parser.add_argument("--identity", type=Path)
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    before = args.before.read_bytes()
    proposed = proposed_config(before)
    if args.action == "plan":
        players.write_new(args.proposed, proposed)
        result = dict(remoteWritesExecuted=False, beforeSha256=hashlib.sha256(before).hexdigest(),
                      proposedSha256=hashlib.sha256(proposed).hexdigest())
    else:
        players.require(args.proposed.read_bytes() == proposed, "Proposed configuration changed")
        players.require(args.host and args.identity and args.nginx_config and args.report,
                        "Apply requires explicit SSH/config and a fresh report")
        host = Host(args.host, args.identity, args.port)
        result = apply_config(before, proposed, host, args.nginx_config, args.report)
    print(json.dumps(result, indent=2))
    if result.get("installed") is False:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
