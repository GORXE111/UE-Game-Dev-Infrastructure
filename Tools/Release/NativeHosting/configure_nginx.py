"""Generate/review native locations separately; apply with backup, nginx -t and recovery."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import re

from deploy_native import Host, client

MARKER = "    # SampleGame native updates: independent of signed content channels and the website."


def proposed_config(before):
    text = before.decode("utf-8")
    client.require(MARKER not in text and "/srv/ue-game-updates/native/" not in text, "Native nginx locations are already installed; review the existing configuration")
    anchor = "    # Signed manifest and signature:"
    client.require(text.count(anchor) == 1 and "server_name updates.example.com;" in text, "Expected existing update server insertion anchor is missing or ambiguous")
    fragment = Path(__file__).with_name("nginx-native.locations.conf").read_text(encoding="utf-8")
    result = text.replace(anchor, fragment + "\n" + anchor, 1).encode("utf-8")
    client.require(text in result.decode().replace(fragment + "\n", "", 1), "Existing nginx content was changed")
    return result


REMOTE_NGINX = r'''
import base64,hashlib,json,os,pathlib,re,shutil,subprocess,sys,uuid
p=json.loads(base64.b64decode(sys.argv[1]));name=p['config']
assert re.fullmatch(r'/etc/nginx/(?:sites-available|conf\.d)/[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}',name) and '..' not in pathlib.PurePosixPath(name).name
config=pathlib.Path(name);assert config.is_file()and not config.is_symlink()
old=config.read_bytes();assert hashlib.sha256(old).hexdigest()==p['beforeSha256'],'nginx changed since reviewed snapshot'
proposed=base64.b64decode(p['proposed']);assert hashlib.sha256(proposed).hexdigest()==p['proposedSha256']
assert b'/srv/ue-game-updates/native/'in proposed and len(proposed)<1024*1024
token=uuid.uuid4().hex;backup=config.with_name(config.name+'.native-backup-'+token);backup.write_bytes(old)
temporary=config.with_name(config.name+'.native-proposed-'+token);temporary.write_bytes(proposed);os.chmod(temporary,0o644);os.replace(temporary,config)
checks=[]
try:
 test=subprocess.run(['nginx','-t'],capture_output=True,text=True);checks.append({'command':'nginx -t','code':test.returncode});assert test.returncode==0,test.stderr
 reload=subprocess.run(['systemctl','reload','nginx'],capture_output=True,text=True);checks.append({'command':'systemctl reload nginx','code':reload.returncode});assert reload.returncode==0,reload.stderr
except BaseException:
 recovery=config.with_name(config.name+'.native-recovery-'+token);recovery.write_bytes(backup.read_bytes());os.chmod(recovery,0o644);os.replace(recovery,config)
 subprocess.run(['nginx','-t'],capture_output=True);subprocess.run(['systemctl','reload','nginx'],capture_output=True)
 raise
print(json.dumps({'installed':True,'backup':str(backup),'sha256':hashlib.sha256(config.read_bytes()).hexdigest(),'checks':checks}))
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("plan", "apply"))
    parser.add_argument("--before", type=Path, required=True, help="Unmodified bytes from the reviewed current nginx file")
    parser.add_argument("--proposed", type=Path, required=True)
    parser.add_argument("--nginx-config", help="Exact /etc/nginx/sites-available/... or conf.d/... real file")
    parser.add_argument("--host")
    parser.add_argument("--identity", type=Path)
    parser.add_argument("--port", type=int, default=22)
    args = parser.parse_args()
    before = args.before.read_bytes()
    proposed = proposed_config(before)
    if args.action == "plan":
        client.require(not args.proposed.exists(), "Proposed config already exists; use a new review artifact")
        args.proposed.write_bytes(proposed)
        result = {"proposed": str(args.proposed), "beforeSha256": hashlib.sha256(before).hexdigest(), "proposedSha256": hashlib.sha256(proposed).hexdigest(), "remoteMutated": False}
    else:
        client.require(args.proposed.read_bytes() == proposed, "Proposed nginx file differs from the reviewed generator output")
        client.require(args.host and args.identity and args.nginx_config, "Apply requires explicit SSH target, identity and real nginx config path")
        client.require(re.fullmatch(r"/etc/nginx/(?:sites-available|conf\.d)/[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}", args.nginx_config) and ".." not in Path(args.nginx_config).name, "Unsafe nginx config path")
        result = Host(args.host, args.identity, args.port).run(REMOTE_NGINX, {"config": args.nginx_config, "beforeSha256": hashlib.sha256(before).hexdigest(), "proposedSha256": hashlib.sha256(proposed).hexdigest(), "proposed": base64.b64encode(proposed).decode()})
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
