#!/usr/bin/env python3
"""Run as root inside the dashboard LXC. Requires an interactive terminal."""
import ipaddress
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from openwrt import ssh_snapshot

REMOTE_INSTALL = r'''
import base64, json, os, sys
from pathlib import Path
payload = json.load(sys.stdin)
key = payload['public_key'].strip()
parts = key.split()
if len(parts) < 2 or parts[0] != 'ssh-ed25519' or '\n' in key or '\r' in key:
    raise SystemExit('Invalid public key')
base64.b64decode(parts[1], validate=True)
collector = Path('/usr/libexec/nerv-status.py')
collector.parent.mkdir(parents=True, exist_ok=True)
collector.write_text(payload['collector'])
collector.chmod(0o644)
folder = Path('/etc/dropbear')
folder.mkdir(exist_ok=True)
authorized = folder / 'authorized_keys'
lines = authorized.read_text().splitlines() if authorized.exists() else []
# Re-running the installer replaces this key's entry, preserving other keys.
lines = [line for line in lines if parts[1] not in line.split()]
options = 'command="/usr/bin/python3 /usr/libexec/nerv-status.py",no-port-forwarding,no-agent-forwarding,no-X11-forwarding,no-pty'
lines.append(options + ' ' + key)
fd = os.open(authorized, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, 'w') as file:
    file.write('\n'.join(lines) + '\n')
authorized.chmod(0o600)
print('OpenWrt: collector and restricted key installed.')
'''


def main():
    if os.geteuid() != 0:
        raise SystemExit('Run this installer as root inside the dashboard container.')
    host = str(ipaddress.ip_address(sys.argv[1] if len(sys.argv) > 1 else '192.168.10.1'))
    config_path = Path(os.environ.get('NERV_CONFIG', '/etc/nerv/config.json'))
    config = json.loads(config_path.read_text())
    keydir = Path('/etc/nerv/ssh')
    subprocess.run(['install', '-d', '-o', 'nerv', '-g', 'nerv', '-m', '700', str(keydir)], check=True)
    identity = keydir / 'openwrt_ed25519'
    if not identity.exists():
        subprocess.run(['runuser', '-u', 'nerv', '--', 'ssh-keygen', '-q', '-t', 'ed25519',
                        '-N', '', '-C', 'nerv-panel-monitor', '-f', str(identity)], check=True)
    elif not identity.with_suffix('.pub').exists():
        raise SystemExit('Public key file is missing; existing private key was not changed.')
    payload = {'public_key': identity.with_suffix('.pub').read_text(),
               'collector': (ROOT / 'deploy/openwrt-collector.py').read_text()}
    print('Connect to OpenWrt as root for installation. Verify its host fingerprint when asked.', flush=True)
    root_known_hosts = Path('/root/.ssh/known_hosts')
    root_known_hosts.parent.mkdir(mode=0o700, exist_ok=True)
    subprocess.run(['ssh', '-F', '/dev/null', '-T', '-o', 'ConnectTimeout=10',
                    '-o', 'StrictHostKeyChecking=ask',
                    '-o', 'UserKnownHostsFile=' + str(root_known_hosts),
                    '-o', 'GlobalKnownHostsFile=/dev/null',
                    'root@' + host, 'python3', '-c', shlex.quote(REMOTE_INSTALL)],
                   input=json.dumps(payload), text=True, check=True)
    matched = subprocess.check_output(['ssh-keygen', '-F', host, '-f', str(root_known_hosts)], text=True)
    hosts_file = keydir / 'known_hosts'
    hosts_file.write_text(matched)
    subprocess.run(['chown', 'nerv:nerv', str(hosts_file)], check=True)
    hosts_file.chmod(0o600)
    router_config = {'enabled': True, 'host': host, 'identity_file': str(identity),
                     'known_hosts_file': str(hosts_file), 'adguard_port': 3001, 'telegram_port': 1443}
    # Verify the same restricted login the service will use, under the service UID.
    probe_code = 'import json,sys;from openwrt import ssh_snapshot;ssh_snapshot(json.load(sys.stdin));print("Restricted SSH: OK")'
    subprocess.run(['runuser', '-u', 'nerv', '--', 'python3', '-c', probe_code],
                   cwd=str(ROOT), input=json.dumps(router_config), text=True, check=True)
    backup = config_path.with_name(config_path.name + '.before-openwrt')
    if not backup.exists():
        backup.write_bytes(config_path.read_bytes())
        backup.chmod(0o600)
    config['openwrt'] = router_config
    services = config.setdefault('services', [])
    if not any(s.get('url') == 'http://' + host + ':3001' for s in services):
        services.append({'name': 'AdGuard Home', 'url': 'http://' + host + ':3001', 'description': 'DNS / фильтрация запросов'})
    config_path.write_text(json.dumps(config, ensure_ascii=False, indent=2) + '\n')
    subprocess.run(['systemctl', 'restart', 'nerv-panel'], check=True)
    print('OpenWrt monitoring enabled. Refresh the dashboard. Poll interval: 15 seconds.')


if __name__ == '__main__':
    main()
