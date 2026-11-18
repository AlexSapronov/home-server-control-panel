"""Wire formats and validation shared by the panel, test VM and router."""
import hashlib
import ipaddress
import json
import re
from urllib.parse import urlsplit, urlunsplit


class DPIError(ValueError):
    pass


def digest(value):
    content = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True)
    return hashlib.sha256(content.encode()).hexdigest()


def domain(value):
    if not isinstance(value, str) or len(value) > 253:
        raise DPIError('Укажите публичное доменное имя.')
    try:
        value = value.rstrip('.').encode('idna').decode().lower()
    except UnicodeError as exc:
        raise DPIError('Некорректное доменное имя.') from exc
    labels = value.split('.')
    reserved = ('localhost', 'local', 'internal', 'lan', 'home', 'arpa', 'test', 'invalid', 'example', 'onion')
    if (len(value) > 253 or len(labels) < 2 or labels[-1] in reserved or
            not re.fullmatch(r'[a-z][a-z0-9-]*', labels[-1]) or
            any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in labels)):
        raise DPIError('Укажите публичное доменное имя.')
    return value


def public_ip(value):
    address = ipaddress.ip_address(value)
    if address.version != 4 or not address.is_global or address.is_multicast or address.is_reserved:
        raise DPIError('DNS вернул адрес вне публичного IPv4.')
    return str(address)


def target(value, *, keep_query=False):
    if not isinstance(value, str) or len(value) > 8192 or re.search(r'[\x00-\x20\x7f\\]', value):
        raise DPIError('Некорректный адрес сайта.')
    try:
        parts = urlsplit(value if '://' in value else 'https://' + value)
        host = domain(parts.hostname)
        ports = {'https': 443, 'http': 80}
        if (parts.scheme not in ports or parts.username is not None or
                parts.port not in (None, ports[parts.scheme])):
            raise ValueError
    except ValueError as exc:
        raise DPIError('Укажите HTTP(S) URL с публичным доменом и стандартным портом.') from exc
    return urlunsplit((parts.scheme, host, parts.path or '/', parts.query if keep_query else '', ''))


def within(host, suffix):
    return host == suffix or host.endswith('.' + suffix)


def profile_key(value):
    if not isinstance(value, str) or not re.fullmatch(r'[a-z0-9][a-z0-9.-]{0,252}', value) or '..' in value:
        raise DPIError('Недопустимый идентификатор профиля.')
    return value


MODE = r'(?:fake|fakedsplit|fakeddisorder|multisplit|multidisorder|split2|disorder2|syndata)'
POSITION = r'(?:-?[0-9]{1,5}|(?:method|host|endhost|sld|midsld|endsld|sniext)[+-]?[0-9]{0,5})'
OPTIONS = {
    'dpi-desync': MODE + r'(?:,' + MODE + r'){0,2}',
    'dpi-desync-split-pos': POSITION + r'(?:,' + POSITION + r'){0,7}',
    'dpi-desync-ttl': r'[1-9][0-9]?',
    'dpi-desync-autottl': r'-?[0-9](?::[0-9]{1,2}-[0-9]{1,2})?',
    'dpi-desync-fooling': r'(?:md5sig|badseq|badsum|datanoack|ts)(?:,(?:md5sig|badseq|badsum|datanoack|ts)){0,4}',
    'dpi-desync-fake-tls': r'0x(?:[0-9a-fA-F]{2}){1,256}',
    'dpi-desync-fake-tls-mod': r'(?:none|rnd|rndsni|dupsid|padencap)(?:,(?:none|rnd|rndsni|dupsid|padencap)){0,4}',
    'dpi-desync-repeats': r'[1-9]|1[0-6]',
    'dpi-desync-split-seqovl': POSITION,
    'dpi-desync-badseq-increment': r'-?[0-9]{1,9}',
    'dpi-desync-badack-increment': r'-?[0-9]{1,9}',
}


def strategy(items):
    if not isinstance(items, list) or not 1 <= len(items) <= len(OPTIONS):
        raise DPIError('Параметры профиля вне поддерживаемого набора.')
    options = {}
    for item in items:
        if not isinstance(item, str) or len(item) > 600:
            raise DPIError('Некорректный параметр nfqws.')
        key, separator, value = item.removeprefix('--').partition('=')
        if (not item.startswith('--') or not separator or key in options or key not in OPTIONS or
                not re.fullmatch(OPTIONS[key], value)):
            raise DPIError('Параметр nfqws вне списка разрешённых.')
        options[key] = value
    if 'dpi-desync' not in options:
        raise DPIError('Для профиля требуется режим nfqws.')
    return [f'--{key}={value}' for key, value in options.items()]


def rule(value):
    hosts = value['domains']
    if not isinstance(hosts, list) or not 1 <= len(hosts) <= 256:
        raise DPIError('Некорректный список доменов.')
    return {'domains': list(dict.fromkeys(domain(host) for host in hosts)),
            'args': strategy(value['args'])}


def check_spec(value):
    url = target(value['url'])
    tls = value.get('tls', 'auto')
    if tls not in ('auto', '1.2', '1.3') or (tls != 'auto' and not url.startswith('https:')):
        raise DPIError('Некорректная версия TLS.')
    minimum = value.get('min_bytes', 1)
    if type(minimum) is not int or not 1 <= minimum <= 8388608:
        raise DPIError('Некорректный минимальный размер ответа.')
    return {'name': profile_key(value['name']), 'url': url, 'tls': tls, 'min_bytes': minimum}


def report_probe(value):
    if value is None:
        return None
    error = value.get('error')
    if error not in (None, 'dns', 'connect', 'tls', 'timeout', 'body', 'http', 'redirect', 'media', 'internal'):
        raise DPIError('Неизвестный результат проверки.')
    ms, size = value['ms'], value['bytes']
    if type(ms) is not int or not 0 <= ms <= 300000 or type(size) is not int or not 0 <= size <= 16777216:
        raise DPIError('Некорректные метрики проверки.')
    raw_ips = value.get('ips', [])
    if not isinstance(raw_ips, list) or len(raw_ips) > 16:
        raise DPIError('Некорректные адреса проверки.')
    ips = [public_ip(ip) for ip in raw_ips]
    if error is None and (not ips or not size):
        raise DPIError('Успех требует IP и полученных данных.')
    when = value.get('at')
    if when is not None and (type(when) is not int or not 0 < when < 4102444800):
        raise DPIError('Некорректное время проверки.')
    return {'error': error, 'ms': ms, 'bytes': size, 'ips': ips, 'at': when}
