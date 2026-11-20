"""OpenWrt monitoring and AWG routing over separate forced-command SSH keys."""
import ipaddress
import json
import secrets
import socket
import struct
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor

SERVICE_NAMES = {'adguardhome': 'AdGuard Home', 'zapret': 'zapret', 'tg-ws-proxy': 'Telegram proxy'}
_LOCK = threading.Lock()
_CACHE = {}


def tcp_probe(host, port):
    try:
        with socket.create_connection((host, int(port)), timeout=2):
            return 'reachable'
    except OSError:
        return 'unreachable'


def dns_probe(host):
    """Query router DNS directly, without using the container's resolver."""
    query_id = secrets.randbits(16)
    packet = struct.pack('!6H', query_id, 0x0100, 1, 0, 0, 0)
    packet += b'\x07example\x03com\x00' + struct.pack('!2H', 1, 1)
    try:
        family = socket.AF_INET6 if ':' in host else socket.AF_INET
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.settimeout(2)
            sock.connect((host, 53))
            sock.send(packet)
            reply = sock.recv(4096)
        if len(reply) < 12:
            return 'invalid_response'
        ident, flags, questions, answers, _, _ = struct.unpack('!6H', reply[:12])
        if ident != query_id or not flags & 0x8000 or questions != 1 or flags & 0x0200:
            return 'invalid_response'
        return 'resolved' if flags & 15 == 0 and answers > 0 else 'resolution_failed'
    except OSError:
        return 'unreachable'


def ssh_snapshot(config):
    # -F prevents user/system SSH config from adding proxy commands or forwards.
    host = str(ipaddress.ip_address(config['host']))
    command = [
        'ssh', '-F', '/dev/null', '-T', '-n', '-i', config['identity_file'],
        '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
        '-o', 'StrictHostKeyChecking=yes',
        '-o', 'UserKnownHostsFile=' + config['known_hosts_file'],
        '-o', 'GlobalKnownHostsFile=/dev/null', '-o', 'ConnectTimeout=3',
        '-o', 'ConnectionAttempts=1', '-o', 'ClearAllForwardings=yes',
        '-o', 'PasswordAuthentication=no', '-o', 'KbdInteractiveAuthentication=no',
        '-o', 'LogLevel=ERROR', 'root@' + host, 'nerv-status'
    ]
    result = subprocess.run(command, capture_output=True, text=True, timeout=7, check=True)
    if len(result.stdout) > 65536:
        raise ValueError('Oversized collector response')
    data = json.loads(result.stdout)
    if data.get('schema') != 1:
        raise ValueError('Unsupported collector schema')
    # Explicit allowlist: no command lines, keys, raw ubus output or stderr.
    services = []
    for key, name in SERVICE_NAMES.items():
        item = data.get('services', {}).get(key, {})
        state = item.get('state', 'unknown')
        services.append({'id': key, 'name': name,
                         'state': state if state in ('running', 'stopped', 'unknown') else 'unknown'})
    wan = data.get('wan', {})
    addresses = []
    for value in wan.get('addresses', [])[:8]:
        try:
            addresses.append(str(ipaddress.ip_address(value)))
        except ValueError:
            pass
    wg = data.get('amneziawg', {})
    wg_state = wg.get('state', 'unknown')
    if wg_state not in ('not_configured', 'configured_down', 'up', 'unknown'):
        wg_state = 'unknown'
    age = wg.get('handshake_age')
    return {
        'services': services,
        'wan': {'up': wan.get('up') if isinstance(wan.get('up'), bool) else None, 'addresses': addresses},
        'amneziawg': {'state': wg_state, 'handshake_age': age if type(age) is int and age >= 0 else None}
    }


def router_snapshot(config):
    if not config.get('enabled'):
        return {'state': 'not_configured', 'stale': False}
    try:
        host = str(ipaddress.ip_address(config['host']))
        key = (host, config['identity_file'], config['known_hosts_file'],
               int(config.get('adguard_port', 3001)), int(config.get('telegram_port', 1443)))
    except (KeyError, ValueError, TypeError):
        return {'state': 'unavailable', 'stale': False, 'error': 'Некорректная конфигурация OpenWrt.'}
    # Serialize cache misses so simultaneous tabs do not launch repeated SSH probes.
    with _LOCK:
        previous = _CACHE.get(key)
        if previous and time.monotonic() - previous[0] < 15:
            return previous[1]
        now = int(time.time())
        with ThreadPoolExecutor(max_workers=4) as pool:
            ssh = pool.submit(ssh_snapshot, config)
            dns = pool.submit(dns_probe, host)
            adguard = pool.submit(tcp_probe, host, key[3])
            telegram = pool.submit(tcp_probe, host, key[4])
            probes = {'dns': dns.result(), 'adguard_tcp': adguard.result(), 'telegram_tcp': telegram.result()}
            try:
                result = dict(ssh.result(), state='connected', stale=False, checked_at=now)
            except (OSError, ValueError, TypeError, AttributeError, subprocess.SubprocessError):
                result = {'state': 'unavailable', 'stale': False,
                          'error': 'Нет SSH-телеметрии OpenWrt. Проверьте ключ, known_hosts и сборщик.'}
                if previous and previous[1].get('checked_at'):
                    result.update({k: previous[1][k] for k in ('services', 'wan', 'amneziawg', 'checked_at')})
                    result['stale'] = True
            result['probes'] = probes
            result['probed_at'] = now
        _CACHE[key] = (time.monotonic(), result)
        return result


def demo_router():
    return {'state': 'demo', 'stale': False, 'checked_at': int(time.time()),
            'probed_at': int(time.time()),
            'services': [{'id': key, 'name': name, 'state': 'running'} for key, name in SERVICE_NAMES.items()],
            'probes': {'dns': 'resolved', 'adguard_tcp': 'reachable', 'telegram_tcp': 'reachable'},
            'wan': {'up': True, 'addresses': ['192.168.0.145']},
            'amneziawg': {'state': 'not_configured', 'handshake_age': None}}


class RoutingError(Exception):
    def __init__(self, message, code='unavailable'):
        super().__init__(message)
        self.code = code


def routing_request(config, payload):
    if not config.get('enabled') or not config.get('routing_enabled'):
        raise RoutingError('Управление сайтами AWG не подключено.', 'disabled')
    try:
        host = str(ipaddress.ip_address(config['host']))
        command = ['ssh', '-F', '/dev/null', '-T', '-i', config['routing_identity_file'],
                   '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
                   '-o', 'StrictHostKeyChecking=yes',
                   '-o', 'UserKnownHostsFile=' + config['known_hosts_file'],
                   '-o', 'GlobalKnownHostsFile=/dev/null', '-o', 'ConnectTimeout=5',
                   '-o', 'ClearAllForwardings=yes', '-o', 'PasswordAuthentication=no',
                   '-o', 'KbdInteractiveAuthentication=no', '-o', 'LogLevel=ERROR',
                   'root@' + host, 'nerv-awg']
        response = subprocess.run(command, input=json.dumps(payload), capture_output=True,
                                  text=True, timeout=150, check=True)
        if len(response.stdout) > 65536:
            raise ValueError
        result = json.loads(response.stdout)
        if 'error' in result:
            code = result.get('code')
            if code not in ('invalid', 'conflict', 'unavailable'):
                code = 'unavailable'
            raise RoutingError(str(result['error'])[:300], code)
        if not isinstance(result.get('rules'), list) or not isinstance(result.get('revision'), str):
            raise ValueError
        return result
    except (KeyError, ValueError, TypeError, AttributeError, OSError, subprocess.SubprocessError):
        raise RoutingError('Нет ответа OpenWrt. Обновите список перед повтором: операция могла примениться.') from None
