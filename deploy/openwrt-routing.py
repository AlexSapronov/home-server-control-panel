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
    'chatgpt.com': ('ChatGPT', 'chatgpt.com openai.com oaistatic.com oaiusercontent.com oaistatsig.com cdn.openaimerge.com challenges.cloudflare.com cdn.workos.com forwarder.workos.com frontend-apps-multi-region.workos.com images.workoscdn.com setup.workos.com workos.imgix.net'),
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
        # Never expose a machine-wide or otherwise restricted policy for changes.
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
    return {'rules': policies(), 'revision': revision(), 'scope': 'all-lan',
            'presets': [{'domain': domain, 'name': name, 'domains': domains.split()}
                        for domain, (name, domains) in PRESETS.items()]}


def domain_group(primary, extra=None):
    domain = domain_name(primary)
    canonical = domain.removeprefix('www.')
    canonical = {'youtu.be': 'youtube.com', 'twitter.com': 'x.com',
                 'chat.openai.com': 'chatgpt.com'}.get(canonical, canonical)
    name, defaults = PRESETS.get(canonical, (domain, domain))
    if extra is None:
        extra = []
    if not isinstance(extra, list) or len(extra) > 32:
        raise RoutingError('Можно указать не более 32 дополнительных доменов.')
    domains = list(dict.fromkeys(defaults.split() + [domain_name(value) for value in extra]))
    return domain, name, domains


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
    if action == 'diagnose':
        from nerv_diagnostics import diagnose, DiagnosticError
        try:
            return diagnose(request.get('target'))
        except DiagnosticError as error:
            raise RoutingError(str(error)) from None
    if action == 'list':
        return state()
    if action not in ('add', 'set_enabled', 'update_domains'):
        raise RoutingError('Неизвестная операция.')
    if request.get('revision') != revision():
        raise RoutingError('Список изменён. Обновите его и повторите действие.', 'conflict')
    current = policies()
    removed_domains = set()
    if action == 'add':
        domain, name, domains = domain_group(request.get('domain'), request.get('extra_domains'))
        if any(domain == d or domain.endswith('.' + d) for r in current for d in r['domains']):
            raise RoutingError('Этот сайт уже сохранён. Используйте его переключатель.', 'conflict')
        section = 'nerv_' + hashlib.sha256(domain.encode()).hexdigest()[:16]
        # A pre-existing disabled rule or manually created section must not be overwritten.
        if subprocess.run(['uci', '-q', 'get', 'pbr.' + section], capture_output=True).returncode == 0:
            raise RoutingError('Правило уже существует. Обновите список сайтов.', 'conflict')
        commands = [('set', f'pbr.{section}=policy'), ('set', f'pbr.{section}.name={name}'),
                    ('set', f'pbr.{section}.interface=awg0'), ('set', f'pbr.{section}.dest_addr={" ".join(domains)}'),
                    ('set', f'pbr.{section}.enabled=1'), ('reorder', f'pbr.{section}=2')]
    else:
        section = request.get('id')
        rule = next((r for r in current if r['id'] == section), None)
        if rule is None:
            raise RoutingError('Правило недоступно для изменения.', 'conflict')
        if action == 'set_enabled':
            enabled = request.get('enabled')
            if type(enabled) is not bool:
                raise RoutingError('Укажите состояние переключателя.')
            if rule['enabled'] == enabled:
                return state()
            commands = [('set', f'pbr.{section}.enabled={int(enabled)}')]
            domains = rule['domains'] if enabled else []
        else:
            values = request.get('domains')
            if not isinstance(values, list) or not 1 <= len(values) <= 40:
                raise RoutingError('Укажите от 1 до 40 доменов.')
            domains = list(dict.fromkeys(domain_name(value) for value in values))
            removed_domains = set(rule['domains']) - set(domains)
            commands = [('set', f'pbr.{section}.dest_addr={" ".join(domains)}')]
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
        # Additive edits must preserve cached client addresses, which may differ
        # from a fresh router lookup. Drop this set only when names were removed;
        # keep the full snapshot separately for rollback.
        retained = {name: values for name, values in saved_ipsets.items()
                    if not removed_domains or name != 'pbr_awg0_4_dst_ip_' + section}
        restore_ipsets(retained)
        if action in ('add', 'update_domains') or request.get('enabled') is True:
            warm_domains(domains)
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
