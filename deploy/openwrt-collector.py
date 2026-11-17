#!/usr/bin/env python3
"""Forced SSH command: emits a fixed, sanitized status document; never mutates state."""
import json
import subprocess
import time
from pathlib import Path


def command(*args):
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=2, check=True)
        return result.stdout
    except (OSError, subprocess.SubprocessError):
        return None


def ubus(obj, method, args=None):
    raw = command('ubus', 'call', obj, method, json.dumps(args or {}))
    try:
        return json.loads(raw) if raw is not None else None
    except ValueError:
        return None


def service_state(data, name):
    if data is None:
        return 'unknown'
    instances = data.get(name, {}).get('instances', {})
    if any(item.get('running') is True for item in instances.values()):
        return 'running'
    return 'stopped'


def process_names():
    names = set()
    for file in Path('/proc').glob('[0-9]*/comm'):
        try:
            names.add(file.read_text().strip())
        except OSError:
            pass
    return names


def wireguard_status():
    interfaces = command('awg', 'show', 'interfaces')
    network = ubus('network.interface', 'dump')
    if interfaces is None:
        return {'state': 'unknown', 'handshake_age': None}
    if not interfaces.strip():
        configured = any(item.get('proto') == 'amneziawg' for item in (network or {}).get('interface', []))
        state = 'configured_down' if configured else ('not_configured' if network is not None else 'unknown')
        return {'state': state, 'handshake_age': None}
    raw = command('awg', 'show', 'all', 'latest-handshakes')
    times = []
    for line in (raw or '').splitlines():
        try:
            timestamp = int(line.split()[-1])
            if 0 < timestamp <= time.time():
                times.append(timestamp)
        except (ValueError, IndexError):
            pass
    return {'state': 'up', 'handshake_age': int(time.time()) - max(times) if times else None}


def collect():
    services = {}
    for name in ('adguardhome', 'zapret', 'tg-ws-proxy'):
        state = service_state(ubus('service', 'list', {'name': name}), name)
        # zapret can launch nfqws outside procd's instances.
        if name == 'zapret' and state != 'running':
            if process_names() & {'nfqws', 'nfqws2', 'tpws'}:
                state = 'running'
        services[name] = {'state': state}
    wan = ubus('network.interface.wan', 'status')
    return {'schema': 1, 'services': services,
            'wan': {'up': wan.get('up') if wan else None,
                    'addresses': [a['address'] for a in (wan or {}).get('ipv4-address', []) if 'address' in a]},
            'amneziawg': wireguard_status()}


if __name__ == '__main__':
    print(json.dumps(collect()))
