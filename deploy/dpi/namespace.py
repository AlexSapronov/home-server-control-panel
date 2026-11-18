"""Set up the worker VM's test NIC and egress rules before enabling the worker."""
import argparse
from ipaddress import IPv4Address, IPv4Interface, IPv4Network
import json
from pathlib import Path
import re
import subprocess

DENIED = (
    '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16',
    '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24', '192.88.99.0/24', '192.168.0.0/16',
    '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/3',
)


def ip(*args):
    return subprocess.check_output(['ip', *args], text=True, timeout=8)


def teardown(namespace, files):
    marker = files / 'nerv-owned'
    if not marker.is_file():
        return
    if namespace in {line.split()[0] for line in ip('netns', 'list').splitlines()}:
        ip('netns', 'delete', namespace)
    for name in ('resolv.conf', 'nsswitch.conf', marker.name):
        (files / name).unlink(missing_ok=True)
    files.rmdir()


def setup(namespace, files, config):
    if files.exists() or namespace in {line.split()[0] for line in ip('netns', 'list').splitlines()}:
        raise ValueError('Test namespace or config directory already exists')
    device = config['test_device']
    if not re.fullmatch(r'[a-zA-Z0-9_.-]{1,15}', device) or device == 'lo':
        raise ValueError('A dedicated test NIC is required')
    interface = IPv4Interface(config['test_address'])
    gateway = IPv4Address(config['test_gateway'])
    dns = IPv4Address(config['test_dns'])
    route = json.loads(ip('-j', '-4', 'route', 'show', 'dev', device))
    if route or gateway not in interface.network or gateway == interface.ip or not dns.is_global:
        raise ValueError('Test NIC must be unconfigured, with a static test network and public resolver')
    files.mkdir(mode=0o755, parents=True)
    (files / 'nerv-owned').touch()
    try:
        (files / 'resolv.conf').write_text(f'nameserver {dns}\noptions timeout:2 attempts:2\n')
        (files / 'nsswitch.conf').write_text('passwd: files\ngroup: files\nhosts: dns\n')
        ip('netns', 'add', namespace)
        ip('link', 'set', device, 'netns', namespace)
        subprocess.run(['ip', 'netns', 'exec', namespace, 'sysctl', '-qw', 'net.netfilter.nf_conntrack_acct=1'],
                       check=True, timeout=8)
        ip('-n', namespace, 'link', 'set', 'lo', 'up')
        ip('-n', namespace, 'link', 'set', device, 'up')
        ip('-n', namespace, 'address', 'add', str(interface), 'dev', device)
        ip('-n', namespace, 'route', 'add', 'default', 'via', str(gateway), 'dev', device)
        denied = [str(IPv4Network(item, strict=False)) for item in config.get('test_deny', [])]
        networks = ', '.join(dict.fromkeys((*DENIED, str(interface.network), *denied)))
        policy = f'''
table inet nerv_dpi_guard {{
 set denied {{
  type ipv4_addr; flags interval; auto-merge;
  elements = {{ {networks} }}
 }}
 chain egress {{
  type filter hook output priority -10; policy drop;
  ip daddr @denied drop
  ip daddr {dns} udp dport 53 accept
  ip daddr {dns} tcp dport 53 accept
  ip protocol tcp tcp dport {{ 80, 443 }} accept
 }}
}}
'''
        subprocess.run(['ip', 'netns', 'exec', namespace, 'nft', '-f', '-'],
                       input=policy, text=True, check=True, timeout=8)
    except Exception:
        teardown(namespace, files)
        raise


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['start', 'stop'])
    parser.add_argument('config', type=Path)
    args = parser.parse_args()
    config = json.loads(args.config.read_text())
    namespace = config['namespace']
    if not re.fullmatch(r'nerv-dpi(?:-[a-z0-9]+)?', namespace):
        raise ValueError('Expected a dedicated NERV test namespace')
    files = Path('/etc/netns', namespace)
    if args.action == 'start':
        setup(namespace, files, config)
    else:
        teardown(namespace, files)


if __name__ == '__main__':
    main()
