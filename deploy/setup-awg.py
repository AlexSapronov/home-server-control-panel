#!/usr/bin/env python3
"""Run as root inside the panel LXC; uses root SSH once to install a bounded helper."""
import ipaddress
import json
import os
from pathlib import Path
import shlex
import subprocess

ROOT = Path(__file__).resolve().parents[1]
REMOTE_INSTALL = r'''
import base64, json
from pathlib import Path
payload = json.load(__import__('sys').stdin)
key = payload['public_key'].strip()
parts = key.split()
if len(parts) < 2 or parts[0] != 'ssh-ed25519' or '\n' in key or '\r' in key:
    raise SystemExit('Invalid public key')
base64.b64decode(parts[1], validate=True)
helper = Path('/usr/libexec/nerv-routing.py')
helper.write_text(payload['helper'])
helper.chmod(0o644)
authorized = Path('/etc/dropbear/authorized_keys')
backup = authorized.with_name('authorized_keys.before-nerv-awg')
if not backup.exists():
    backup.write_bytes(authorized.read_bytes())
    backup.chmod(0o600)
lines = [line for line in authorized.read_text().splitlines() if parts[1] not in line.split()]
options = 'command="/usr/bin/python3 /usr/libexec/nerv-routing.py",no-port-forwarding,no-agent-forwarding,no-X11-forwarding,no-pty'
lines.append(options + ' ' + key)
authorized.write_text('\n'.join(lines) + '\n')
authorized.chmod(0o600)
upgrade = Path('/etc/sysupgrade.conf')
entries = upgrade.read_text().splitlines()
for path in ('/usr/libexec/nerv-routing.py', '/etc/nerv-routing-backups/'):
    if path not in entries:
        entries.append(path)
upgrade.write_text('\n'.join(entries) + '\n')
print('Restricted AWG key installed.')
'''


def main():
    if os.geteuid() != 0:
        raise SystemExit('Run as root inside the panel container.')
    path = Path(os.environ.get('NERV_CONFIG', '/etc/nerv/config.json'))
    config = json.loads(path.read_text())
    router = config['openwrt']
    host = str(ipaddress.ip_address(router['host']))
    identity = Path(router['identity_file']).with_name('openwrt_awg_ed25519')
    if not identity.exists():
        subprocess.run(['runuser', '-u', 'nerv', '--', 'ssh-keygen', '-q', '-t', 'ed25519',
                        '-N', '', '-C', 'nerv-panel-awg', '-f', str(identity)], check=True)
    payload = {'public_key': identity.with_suffix('.pub').read_text(),
               'helper': (ROOT / 'deploy/openwrt-routing.py').read_text()}
    subprocess.run(['ssh', '-F', '/dev/null', '-T', '-o', 'StrictHostKeyChecking=yes',
                    '-o', 'UserKnownHostsFile=' + router['known_hosts_file'],
                    'root@' + host, 'python3', '-c', shlex.quote(REMOTE_INSTALL)],
                   input=json.dumps(payload), text=True, check=True)
    router.update(routing_enabled=True, routing_identity_file=str(identity))
    # Verify the restricted key as the panel user before enabling the API.
    import sys
    sys.path.insert(0, str(ROOT))
    probe = 'import json,sys;from openwrt import routing_request;print(json.dumps(routing_request(json.load(sys.stdin), {"action":"list"})))'
    subprocess.run(['runuser', '-u', 'nerv', '--', 'python3', '-c', probe], cwd=ROOT,
                   input=json.dumps(router), text=True, check=True, stdout=subprocess.DEVNULL)
    backup = path.with_name(path.name + '.before-awg')
    if not backup.exists():
        backup.write_bytes(path.read_bytes())
        backup.chmod(0o600)
    path.write_text(json.dumps(config, ensure_ascii=False, indent=2) + '\n')
    subprocess.run(['systemctl', 'restart', 'nerv-panel'], check=True)
    print('AWG site management enabled.')


if __name__ == '__main__':
    main()
