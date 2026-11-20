#!/usr/bin/env python3
"""Forced SSH command for whole-network AWG domain policies only."""
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit

POLICY_FILE = Path('/etc/config/pbr')
BACKUPS = Path('/etc/nerv-routing-backups')
LOCK = Path('/var/lock/nerv-routing.lock')
PRESETS = {
    'youtube.com': ('YouTube', 'youtube.com youtube-nocookie.com youtu.be googlevideo.com ytimg.com youtubei.googleapis.com youtube.googleapis.com ggpht.com'),
    'x.com': ('X', 'x.com twitter.com twimg.com t.co'),
    'chatgpt.com': ('ChatGPT', 'chatgpt.com chat.openai.com auth.openai.com auth0.openai.com oaistatic.com oaiusercontent.com oaistatsig.com cdn.openaimerge.com cdn.platform.openai.com'),
}


class RoutingError(Exception):
    def __init__(self, message, code='invalid'):
        super().__init__(message)
        self.code = code


def run(*args, timeout=10):
    return subprocess.run(args, capture_output=True, text=True, check=True, timeout=timeout).stdout


def domain_name(value):
    if not isinstance(value, str) or len(value) > 2048 or any(c.isspace() for c in value):
        raise RoutingError('Укажите доменное имя или ссылку на сайт.')
    try:
        parsed = urlsplit(value if '://' in value else 'https://' + value)
        if parsed.scheme not in ('http', 'https') or parsed.username or parsed.password or parsed.port:
            raise ValueError
        domain = (parsed.hostname or '').rstrip('.').encode('idna').decode().lower()
    except (ValueError, UnicodeError):
        raise RoutingError('Некорректный адрес сайта.') from None
    labels = domain.split('.')
    if (len(domain) > 253 or len(labels) < 2 or labels[-1].isdigit()
            or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in labels)):
        raise RoutingError('Нужно доменное имя, например example.com; IP-адреса не поддерживаются.')
    return domain


def policies():
    # shlex decodes UCI quoting without evaluating shell expressions.
    sections = {}
    for line in run('uci', '-X', 'show', 'pbr').splitlines():
        match = re.fullmatch(r'pbr\.([A-Za-z0-9_]+)(?:\.([A-Za-z0-9_]+))?=(.*)', line)
        if not match:
            continue
        section, option, raw = match.groups()
        sections.setdefault(section, {})[option or '_type'] = ' '.join(shlex.split(raw))
    result = []
    for section, item in sections.items():
        # Never expose a machine-wide or otherwise restricted policy for deletion.
        if (item.get('_type') != 'policy' or item.get('interface') != 'awg0'
                or any(value for key, value in item.items() if key not in
                       {'_type', 'name', 'interface', 'dest_addr', 'enabled'})):
            continue
        domains = item.get('dest_addr', '').split()
        try:
            if not domains or any(domain_name(d) != d for d in domains):
                continue
        except RoutingError:
            continue
        result.append({'id': section, 'name': item.get('name', section)[:120],
                       'domains': domains, 'enabled': item.get('enabled', '1') != '0'})
    return result


def revision():
    return hashlib.sha256(POLICY_FILE.read_bytes()).hexdigest()


def state():
    return {'rules': policies(), 'revision': revision(), 'scope': 'all-lan'}


def ipsets():
    data = json.loads(run('nft', '-j', 'list', 'table', 'inet', 'fw4'))
    return {item['set']['name']: item['set'].get('elem', []) for item in data['nftables']
            if 'set' in item and item['set']['name'].startswith('pbr_')}


def restore_ipsets(saved):
    existing = ipsets()
    operations = [{'add': {'element': {'family': 'inet', 'table': 'fw4', 'name': name, 'elem': elements}}}
                  for name, elements in saved.items() if name in existing and elements]
    if operations:
        subprocess.run(['nft', '-j', '-f', '-'], input=json.dumps({'nftables': operations}),
                       capture_output=True, text=True, timeout=10, check=True)


def warm_domains(domains):
    try:
        port = int(run('uci', '-q', 'get', 'dhcp.@dnsmasq[0].port').strip())
        if not 1 <= port <= 65535:
            return
    except (ValueError, OSError, subprocess.SubprocessError):
        port = 53
    def query(domain):
        try:
            # OpenWrt's local dnsmasq owns the PBR nftset integration. Resolve past
            # any AdGuard frontend cache so the new domain works immediately.
            run('nslookup', domain, '127.0.0.1:' + str(port), timeout=3)
        except (OSError, subprocess.SubprocessError):
            pass  # NXDOMAIN/offline hosts still have a valid persisted policy.
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(query, domains))


def apply(request):
    action = request.get('action')
    if action == 'list':
        return state()
    if action not in ('add', 'remove'):
        raise RoutingError('Неизвестная операция.')
    if request.get('revision') != revision():
        raise RoutingError('Список изменён. Обновите его и повторите действие.', 'conflict')
    current = policies()
    if action == 'add':
        domain = domain_name(request.get('domain'))
        if any(domain == d or domain.endswith('.' + d) for r in current if r['enabled'] for d in r['domains']):
            raise RoutingError('Этот сайт уже направлен через AWG.', 'conflict')
        name, domains = PRESETS.get(domain, (domain, domain))
        section = 'nerv_' + hashlib.sha256(domain.encode()).hexdigest()[:16]
        # A pre-existing disabled rule or manually created section must not be overwritten.
        if subprocess.run(['uci', '-q', 'get', 'pbr.' + section], capture_output=True).returncode == 0:
            raise RoutingError('Правило уже существует. Удалите его перед добавлением.', 'conflict')
        commands = [('set', f'pbr.{section}=policy'), ('set', f'pbr.{section}.name={name}'),
                    ('set', f'pbr.{section}.interface=awg0'), ('set', f'pbr.{section}.dest_addr={domains}'),
                    ('set', f'pbr.{section}.enabled=1'), ('reorder', f'pbr.{section}=2')]
    else:
        section = request.get('id')
        if not any(r['id'] == section for r in current):
            raise RoutingError('Правило недоступно для удаления.', 'conflict')
        commands = [('delete', 'pbr.' + section)]
    # Refuse to commit someone else's pending LuCI/UCI edits.
    if run('uci', 'changes', 'pbr').strip():
        raise RoutingError('На роутере есть несохранённые изменения PBR. Сначала примените их в LuCI.', 'conflict')
    original = POLICY_FILE.read_bytes()
    saved_ipsets = ipsets()
    BACKUPS.mkdir(mode=0o700, exist_ok=True)
    backup = BACKUPS / (str(time.time_ns()) + '.pbr')
    backup.write_bytes(original)
    backup.chmod(0o600)
    try:
        for command in commands:
            run('uci', *command)
        run('uci', 'commit', 'pbr')
        run('/etc/init.d/pbr', 'restart', timeout=60)
        run('/etc/init.d/pbr', 'running')
        run('nft', 'list', 'chain', 'inet', 'fw4', 'pbr_prerouting')
        # PBR can return success even after failing to generate its nft rules.
        for rule in policies():
            if rule['enabled']:
                run('nft', 'list', 'set', 'inet', 'fw4', 'pbr_awg0_4_dst_ip_' + rule['id'])
        restore_ipsets(saved_ipsets)
        if action == 'add':
            warm_domains(domains.split())
    except (OSError, subprocess.SubprocessError):
        run('uci', 'revert', 'pbr')
        POLICY_FILE.write_bytes(original)
        try:
            run('/etc/init.d/pbr', 'restart', timeout=60)
            restore_ipsets(saved_ipsets)
        except (OSError, subprocess.SubprocessError):
            raise RoutingError('Применение и восстановление завершились ошибкой. Проверьте PBR на роутере.', 'unavailable') from None
        raise RoutingError('Не удалось применить правило. Предыдущие настройки восстановлены.', 'unavailable') from None
    for old in sorted(BACKUPS.glob('*.pbr'))[:-10]:
        old.unlink()
    return state()


def main():
    if os.environ.get('SSH_ORIGINAL_COMMAND') != 'nerv-awg':
        raise SystemExit(1)
    import fcntl
    try:
        with LOCK.open('w') as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise RoutingError('Другая операция ещё выполняется. Обновите список через несколько секунд.', 'conflict')
            raw = sys.stdin.buffer.read(8193)
            if len(raw) > 8192:
                raise RoutingError('Запрос слишком большой.')
            request = json.loads(raw)
            if not isinstance(request, dict):
                raise RoutingError('Некорректный запрос.')
            result = apply(request)
        print(json.dumps(result, ensure_ascii=False))
    except RoutingError as error:
        print(json.dumps({'error': str(error), 'code': error.code}, ensure_ascii=False))
    except (ValueError, OSError, subprocess.SubprocessError):
        print(json.dumps({'error': 'Не удалось прочитать настройки PBR на роутере.', 'code': 'unavailable'}, ensure_ascii=False))


if __name__ == '__main__':
    main()
