"""Bounded, read-only public-site diagnostics on OpenWrt. No service mutations."""
import ipaddress
import json
import re
import secrets
import shlex
import socket
import struct
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit, urlunsplit


class DiagnosticError(ValueError):
    pass


def target_url(value):
    if not isinstance(value, str) or not value or len(value) > 2048 or any(ord(c) <= 32 or ord(c) == 127 for c in value):
        raise DiagnosticError('Введите домен или HTTP(S)-ссылку без пробелов.')
    try:
        parsed = urlsplit(value if '://' in value else 'https://' + value)
        host = (parsed.hostname or '').rstrip('.').encode('idna').decode().lower()
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        if (parsed.scheme not in ('http', 'https') or parsed.username is not None or parsed.password is not None
                or port not in (80, 443) or len(host) > 253 or '.' not in host
                or host.rsplit('.', 1)[-1].isdigit() or '\\' in value
                or host.endswith(('.local', '.localhost', '.lan', '.home.arpa', '.internal', '.test', '.invalid'))
                or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in host.split('.'))):
            raise ValueError
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            raise ValueError
        path = parsed.path or '/'
        # Encode Unicode paths without changing already escaped URL components.
        from urllib.parse import quote
        url = urlunsplit((parsed.scheme, host + (':' + str(port) if parsed.port else ''),
                         quote(path, safe="/%:@!$&'()*+,;=-._~"), quote(parsed.query, safe="%=&?/:@!$'()*+,;-._~"), ''))
        return url, host, port
    except (ValueError, UnicodeError):
        raise DiagnosticError('Поддерживаются публичные домены, HTTP/HTTPS и порты 80/443. Без логина и пароля в ссылке.') from None


def command(*args, timeout=4):
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=True).stdout


def skip_name(packet, offset):
    start = offset
    while True:
        if offset >= len(packet) or offset - start > 255:
            raise ValueError('Invalid DNS name')
        length = packet[offset]
        if length & 0xc0 == 0xc0:
            if offset + 1 >= len(packet):
                raise ValueError('Truncated pointer')
            return offset + 2
        if length & 0xc0 or length > 63:
            raise ValueError('Invalid label')
        offset += 1
        if length == 0:
            return offset
        offset += length


def dns_answers(packet, ident, qtype):
    if len(packet) < 12:
        raise ValueError('Short DNS response')
    received, flags, questions, answers, _, _ = struct.unpack('!6H', packet[:12])
    if received != ident or not flags & 0x8000 or flags & 0x0200 or questions != 1:
        raise ValueError('Invalid/truncated DNS response')
    if flags & 15:
        return [], 'nxdomain' if flags & 15 == 3 else 'dns_error'
    offset = skip_name(packet, 12) + 4
    addresses = []
    for _ in range(min(answers, 512)):
        offset = skip_name(packet, offset)
        kind, cls, ttl, length = struct.unpack('!HHIH', packet[offset:offset + 10])
        offset += 10
        data = packet[offset:offset + length]
        if len(data) != length:
            raise ValueError('Truncated DNS record')
        if cls == 1 and kind == qtype and (kind, length) in ((1, 4), (28, 16)):
            addresses.append(str(ipaddress.ip_address(data)))
        offset += length
    return list(dict.fromkeys(addresses))[:16], 'ok' if addresses else 'no_records'


def resolve(host, qtype):
    ident = secrets.randbits(16)
    question = b''.join(bytes([len(label)]) + label.encode('ascii') for label in host.split('.')) + b'\0'
    packet = struct.pack('!6H', ident, 0x0100, 1, 0, 0, 0) + question + struct.pack('!2H', qtype, 1)
    for _ in range(2):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(3)
                sock.connect(('127.0.0.1', 53))
                sock.send(packet)
                response = sock.recv(16384)
            return dns_answers(response, ident, qtype)
        except OSError:
            continue  # A cold upstream lookup may outlive the first attempt.
        except (ValueError, struct.error):
            return [], 'invalid_response'
    return [], 'unavailable'


def public_address(value):
    address = ipaddress.ip_address(value)
    return address.is_global and not (address.is_multicast or address.is_unspecified)


def contains(element, ip):
    try:
        if isinstance(element, str):
            return ip in ipaddress.ip_network(element, strict=False)
        if isinstance(element, dict):
            if 'prefix' in element:
                value = element['prefix']
                return ip in ipaddress.ip_network(str(value['addr']) + '/' + str(value['len']), strict=False)
            if 'range' in element:
                start, end = element['range']
                return ipaddress.ip_address(start) <= ip <= ipaddress.ip_address(end)
            if 'elem' in element:
                return contains(element['elem'].get('val'), ip)
    except (ValueError, TypeError, KeyError):
        pass
    return False


def read_policies():
    sections = {}
    for line in command('uci', '-X', 'show', 'pbr').splitlines():
        match = re.fullmatch(r'pbr\.([A-Za-z0-9_]+)(?:\.([A-Za-z0-9_]+))?=(.*)', line)
        if match:
            section, key, value = match.groups()
            sections.setdefault(section, {})[key or '_type'] = ' '.join(shlex.split(value))
    return sections


def domain_rules(host, sections):
    result = []
    for section, rule in sections.items():
        if rule.get('_type') != 'policy':
            continue
        domains = [d for d in rule.get('dest_addr', '').split() if host == d or host.endswith('.' + d)]
        if domains:
            restricted = any(rule.get(key) for key in ('src_addr', 'src_port', 'dest_port', 'proto', 'chain'))
            result.append({'id': section, 'name': rule.get('name', section)[:120],
                           'interface': rule.get('interface', ''), 'domains': domains,
                           'enabled': rule.get('enabled', '1') != '0', 'restricted': restricted})
    return result


def runtime_match(address, nftables):
    ip = ipaddress.ip_address(address)
    sets = {row['set']['name']: row['set'].get('elem', []) for row in nftables if 'set' in row}
    for row in nftables:
        rule = row.get('rule', {})
        if rule.get('chain') != 'pbr_prerouting':
            continue
        expressions = rule.get('expr', [])
        matches = [part['match'] for part in expressions if 'match' in part]
        targets = [part['goto']['target'] for part in expressions if 'goto' in part]
        # Evaluate whole-network IPv4 destination-set rules only. Never claim to
        # simulate device/port-specific policies or arbitrary nft expressions.
        if len(matches) != 1 or len(targets) != 1:
            continue
        match = matches[0]
        name = match.get('right')
        if (match.get('op') != '==' or match.get('left') != {'payload': {'protocol': 'ip', 'field': 'daddr'}}
                or not isinstance(name, str) or not name.startswith('@')):
            continue
        mark = re.fullmatch(r'pbr_mark_0x([0-9a-fA-F]+)', targets[0])
        if mark and any(contains(item, ip) for item in sets.get(name[1:], [])):
            return {'name': rule.get('comment', name[1:])[:120], 'set': name[1:], 'mark': int(mark[1], 16)}
    return None


def route_for(address, mark):
    try:
        rows = json.loads(command('ip', '-j', '-4', 'route', 'get', address, 'mark', hex(mark)))
        row = rows[0]
        if row.get('type') in ('unreachable', 'blackhole', 'prohibit'):
            return {'state': 'unreachable'}
        return {'state': 'ok', 'device': row.get('dev'), 'table': str(row.get('table', 'main')),
                'gateway': row.get('gateway')}
    except (OSError, ValueError, IndexError, subprocess.SubprocessError):
        return {'state': 'unavailable'}


def probe(url, host, port, address, device):
    base = {'device': device, 'address': address}
    if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,32}', device or ''):
        return dict(base, state='unavailable')
    args = ['curl', '-q', '-4', '--noproxy', '*', '--proto', '=http,https',
            '--interface', device, '--resolve', f'{host}:{port}:{address}',
            '--connect-timeout', '3', '--max-time', '8', '--max-filesize', '1048576',
            '--range', '0-65535', '--output', '/dev/null', '--silent', '--show-error',
            '--write-out', '%{json}', '--', url]
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=10)
        data = json.loads(result.stdout)
        code = result.returncode
        status = int(data.get('http_code', 0))
        size = int(data.get('size_download', 0))
        redirect = data.get('redirect_url', '')
        # No body, cookies, headers, stderr or signed query strings are returned.
        redirect_parts = urlsplit(redirect) if redirect else None
        redirect_host = redirect_parts.hostname if redirect_parts else None
        redirect_target = (urlunsplit((redirect_parts.scheme, redirect_host, redirect_parts.path or '/', '', ''))
                           if redirect_host and redirect_parts.scheme in ('http', 'https') else None)
        return dict(base, state='ok' if code == 0 else 'limited' if code == 63 else 'timeout' if code == 28 else
                    'tls_error' if code in (35, 60) else 'connection_error',
                    http_status=status, bytes=size, seconds=round(float(data.get('time_total', 0)), 3),
                    curl_code=code, redirect_host=redirect_host, redirect_target=redirect_target)
    except (OSError, ValueError, TypeError, subprocess.SubprocessError):
        return dict(base, state='unavailable')


def diagnose(target):
    url, host, port = target_url(target)
    with ThreadPoolExecutor(max_workers=2) as pool:
        ipv4_future = pool.submit(resolve, host, 1)
        ipv6_future = pool.submit(resolve, host, 28)
        ipv4, a_state = ipv4_future.result()
        ipv6, aaaa_state = ipv6_future.result()
    # Pin every HTTP connection to a validated DNS answer; redirects are never
    # followed. This prevents localhost/private-IP access and DNS rebinding.
    if any(not public_address(value) for value in ipv4 + ipv6):
        raise DiagnosticError('DNS вернул локальный или специальный адрес. Проверка таких адресов запрещена.')
    result = {'target': host, 'checked_at': int(time.time()), 'read_only': True,
              'dns': {'ipv4': ipv4, 'ipv6': ipv6, 'a_state': a_state, 'aaaa_state': aaaa_state},
              'rules': [], 'routes': [], 'probes': [], 'warnings': []}
    if not ipv4:
        result['warnings'].append('Нет IPv4-адреса. HTTP через IPv4 AWG не проверен.')
        return result
    try:
        sections = read_policies()
        result['rules'] = domain_rules(host, sections)
        nftables = json.loads(command('nft', '-j', 'list', 'table', 'inet', 'fw4'))['nftables']
        status = json.loads(command('ubus', 'call', 'network.interface.wan', 'status'))
        wan = status.get('l3_device') or status.get('device')
        links = json.loads(command('ip', '-j', 'link', 'show', 'awg0'))
        awg = 'awg0' if links and 'UP' in links[0].get('flags', []) else None
    except (OSError, ValueError, KeyError, subprocess.SubprocessError):
        result['warnings'].append('Не удалось прочитать часть правил или интерфейсов. Маршрут не подтверждён.')
        return result
    for address in ipv4:
        match = runtime_match(address, nftables)
        route = route_for(address, match['mark'] if match else 0)
        result['routes'].append(dict(route, address=address, matched_rule=match['name'] if match else None,
                                     mark=hex(match['mark']) if match else '0x0'))
    active = [rule for rule in result['rules'] if rule['enabled'] and not rule['restricted']]
    if active and any(not route['matched_rule'] for route in result['routes']):
        result['warnings'].append('Доменное правило есть, но часть IP не найдена в действующих наборах PBR. Возможна разница DNS-кэшей.')
    if any(route['matched_rule'] and route['matched_rule'] not in [rule['name'] for rule in active] for route in result['routes']):
        result['warnings'].append('IP совпал с другим правилом PBR: у разных сайтов могут быть общие адреса CDN.')
    if not active:
        result['warnings'].append('Активного общего доменного правила для этого имени нет.')
    if not awg:
        result['warnings'].append('Интерфейс AWG не поднят. Диагностика не пытается его запустить.')
    devices = list(dict.fromkeys(d for d in (wan, awg) if d))
    result['network'] = {'wan_device': wan, 'awg_device': awg}
    with ThreadPoolExecutor(max_workers=2) as pool:
        jobs = [pool.submit(probe, url, host, port, address, device) for address in ipv4[:2] for device in devices]
        result['probes'] = [job.result() for job in jobs]
    result['warnings'].append('Проверен путь с роутера для общих правил IPv4. Браузерный DoH, старые соединения и правила отдельных устройств могут дать другой результат.')
    if any(row.get('redirect_host') for row in result['probes']):
        result['warnings'].append('Сайт вернул перенаправление. Его адрес нужно проверить отдельно.')
    return result
