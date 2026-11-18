"""Durable queue, verification and router delivery for NERV."""
from contextlib import contextmanager
import json
from pathlib import Path
import re
import secrets
import sqlite3
from statistics import median
import time
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo
from datetime import datetime

from dpi_policy import DPIError, check_spec, digest, domain, profile_key, report_probe, rule, target, within


class DPIStore:
    def __init__(self, filename, config, clock=time.time):
        self.filename = filename
        self.clock = clock
        self.check_interval = int(config.get('check_interval', 21600))
        self.revision_interval = int(config.get('revision_interval', 604800))
        self.lease = int(config.get('job_timeout', 3600))
        self.freshness = int(config.get('freshness', 172800))
        self.series_gap = int(config.get('series_gap', 120))
        self.backup_window = config.get('backup_window', ['02:45', '04:00'])
        self.tz = ZoneInfo(config.get('timezone', 'Europe/Moscow'))
        self.control = check_spec({'name': 'control', 'url': config.get('control_url', 'https://example.com/')})
        if min(self.check_interval, self.revision_interval, self.freshness) < 60 or not 1 <= self.series_gap < self.lease:
            raise DPIError('Некорректные интервалы DPI.')
        if len(self.backup_window) != 2:
            raise DPIError('Окно резервирования требует двух значений HH:MM.')
        for stamp in self.backup_window:
            datetime.strptime(stamp, '%H:%M')
        self.defaults = {}
        for key, settings in config.get('profiles', {}).items():
            checks = [check_spec(item) for item in settings['checks']]
            if not 1 <= len(checks) <= 5 or len({item['name'] for item in checks} | {'submitted'}) != len(checks) + 1:
                raise DPIError('Проверки профиля должны иметь уникальные имена.')
            video = settings.get('video_id')
            if video is not None and (key != 'youtube' or not re.fullmatch(r'[A-Za-z0-9_-]{11}', video) or
                                      any(item['name'] == 'video' for item in checks)):
                raise DPIError('Некорректная настройка видео YouTube.')
            if key == 'youtube' and not video:
                raise DPIError('Для профиля YouTube укажите контрольное видео.')
            self.defaults[profile_key(key)] = {'checks': checks, 'video_id': video,
                                               'automatic': settings.get('automatic') is True}
        Path(filename).parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.filename) as conn:
            conn.execute('PRAGMA journal_mode=WAL')
            conn.execute('CREATE TABLE IF NOT EXISTS dpi_state (id INTEGER PRIMARY KEY CHECK(id=1), body TEXT)')
            conn.execute('INSERT OR IGNORE INTO dpi_state VALUES (1, ?)', (json.dumps({
                'router': None, 'profiles': {}, 'jobs': [], 'versions': [], 'operation': None, 'last_operation': None,
                'lan_seen': 0,
            }),))

    @contextmanager
    def edit(self):
        conn = sqlite3.connect(self.filename, timeout=10)
        try:
            conn.execute('BEGIN IMMEDIATE')
            original = conn.execute('SELECT body FROM dpi_state WHERE id=1').fetchone()[0]
            data = json.loads(original)
            now = int(self.clock())
            self.maintain(data, now)
            yield data, now
            body = json.dumps(data, separators=(',', ':'), allow_nan=False)
            if body != original:
                conn.execute('UPDATE dpi_state SET body=? WHERE id=1', (body,))
            conn.commit()
        finally:
            conn.close()

    def maintain(self, data, now):
        deferred = []
        for job in data['jobs']:
            if job['state'] == 'running' and job['deadline'] <= now:
                job.update(state='timeout', finished=now)
                if job.get('followup'):
                    deferred.append(job)
        for job in deferred:
            self.queue(data, now, job['profile'], job['followup'], job.get('followup_extra'))
        operation = data['operation']
        if operation and operation['deadline'] <= now and operation['phase'] == 'queued':
            data['last_operation'] = dict(operation, phase='expired')
            data['operation'] = None

    def queue(self, data, now, key, kind, extra=None):
        waiting = [job for job in data['jobs'] if job['profile'] == key and job['state'] in ('queued', 'running')]
        if waiting:
            job = waiting[-1]
            if job['state'] == 'queued':
                if kind != 'check' and job['kind'] in ('check', 'revision'):
                    job['kind'] = kind
                if extra:
                    job['extra'] = extra
            elif kind != 'check' and (job['kind'] == 'check' or extra):
                job['followup'] = kind
                job['followup_extra'] = extra
            return job['id']
        if sum(job['state'] == 'queued' for job in data['jobs']) >= 32:
            raise DPIError('Очередь проверок заполнена.')
        job = {'id': secrets.token_hex(12), 'profile': key, 'kind': kind, 'state': 'queued', 'created': now}
        if extra:
            job['extra'] = extra
        data['jobs'] = [old for old in data['jobs'] if old['state'] in ('queued', 'running')] + [
            old for old in data['jobs'] if old['state'] not in ('queued', 'running')][-59:] + [job]
        return job['id']

    def tick(self):
        with self.edit() as (data, now):
            self.schedule(data, now)

    def in_backup_window(self, now):
        stamp = datetime.fromtimestamp(now, self.tz).strftime('%H:%M')
        start, end = self.backup_window
        return start <= stamp < end if start <= end else stamp >= start or stamp < end

    def schedule(self, data, now):
        in_backup = self.in_backup_window(now)
        if data['operation']:
            return
        for key, profile in data['profiles'].items():
            if not profile.get('active') or not self.router_current(data, now):
                continue
            if not in_backup and now >= profile['next_revision']:
                self.queue(data, now, key, 'revision')
            elif now >= profile['next_check']:
                self.queue(data, now, key, 'check')

    def router_current(self, data, now):
        return data['router'] and now - data['router']['seen'] <= 75

    def admin(self, action, body):
        with self.edit() as (data, now):
            if action == 'add':
                url = target(body['url'])
                key = urlsplit(url).hostname
                for managed, profile in data['profiles'].items():
                    hosts = profile.get('active', {}).get('domains', []) if profile.get('active') else []
                    if key == managed or within(key, managed) or any(within(key, host) for host in hosts):
                        extra = check_spec({'name': 'submitted', 'url': url})
                        return {'id': self.queue(data, now, managed, 'manual', extra)}
                if len(data['profiles']) >= 32:
                    raise DPIError('Достигнут предел управляемых профилей.')
                data['profiles'][key] = {'checks': [check_spec({'name': 'page', 'url': url})], 'active': None,
                                         'video_id': None, 'next_check': now, 'next_revision': now,
                                         'failures': 0, 'automatic': False, 'drift': False}
                return {'id': self.queue(data, now, key, 'search')}
            if action == 'revision':
                key = profile_key(body['profile'])
                if key not in data['profiles']:
                    raise DPIError('Профиль не найден.')
                return {'id': self.queue(data, now, key, 'manual')}
            if action == 'auto':
                key = profile_key(body['profile'])
                if key not in data['profiles'] or type(body.get('enabled')) is not bool:
                    raise DPIError('Не указана настройка автоматического переключения.')
                data['profiles'][key]['automatic'] = body['enabled']
                return {}
            if action == 'cancel':
                job = next((j for j in data['jobs'] if j['id'] == body['id']), None)
                if not job or job['state'] not in ('queued', 'running'):
                    raise DPIError('Задание уже завершено.')
                if job['state'] == 'running':
                    job['cancel_requested'] = True
                else:
                    job.update(state='cancelled', finished=now)
                return {}
            if action in ('apply', 'rollback'):
                return self.request_operation(data, now, action, body.get('id'))
            raise DPIError('Неизвестная операция DPI.')

    @staticmethod
    def eligible(data, version, now):
        return bool(version['expires'] > now and data['router'] and
                version['base'] == data['router']['snapshot']['base'])

    def request_operation(self, data, now, action, version_id=None):
        if data['operation']:
            raise DPIError('Дождитесь завершения текущей операции на роутере.')
        if not self.router_current(data, now):
            raise DPIError('Роутер не на связи.')
        if now - data['lan_seen'] > 45 and action == 'apply':
            raise DPIError('LAN-зонд недоступен.')
        router = data['router']
        snapshot = router['snapshot']
        if action == 'apply':
            version = next((v for v in data['versions'] if v['id'] == version_id), None)
            if not version or not version.get('delivered') or not self.eligible(data, version, now):
                raise DPIError('Сначала дождитесь доставки свежего подтверждённого профиля.')
            key = version['profile']
        else:
            key = router.get('previous')
            if not key:
                raise DPIError('Роутер не подтвердил наличие резервной версии.')
        op = {'id': secrets.token_hex(12), 'action': action, 'version': version_id, 'base': snapshot['base'],
              'profile': key, 'phase': 'queued', 'deadline': now + 120}
        data['operation'] = op
        return {'id': op['id']}

    def claim(self):
        with self.edit() as (data, now):
            self.schedule(data, now)
            if data['operation'] or not self.router_current(data, now) or any(
                    job['state'] == 'running' for job in data['jobs']):
                return None
            in_backup = self.in_backup_window(now)
            job = next((job for job in data['jobs'] if job['state'] == 'queued' and
                        (job['kind'] != 'revision' or not in_backup)), None)
            if not job:
                return None
            profile = data['profiles'][job['profile']]
            snapshot = data['router']['snapshot']
            backups = [v['rule'] for v in data['versions'] if v['profile'] == job['profile']][-3:]
            job.update(state='running', started=now, deadline=now + self.lease, snapshot=snapshot)
            if job['kind'] != 'check':
                profile['next_revision'] = now + self.revision_interval
            profile['next_check'] = now + self.check_interval
            specs = {key: {'checks': item['checks'], 'video_id': item['video_id']}
                     for key, item in data['profiles'].items() if item.get('active') or key == job['profile']}
            if job.get('extra'):
                specs[job['profile']]['checks'] = specs[job['profile']]['checks'] + [job['extra']]
            job['specs'] = specs
            return dict(job, backups=backups, control=self.control, series_gap=self.series_gap)

    def worker_heartbeat(self, job_id):
        with self.edit() as (data, now):
            job = next((job for job in data['jobs'] if job['id'] == job_id), None)
            return {'stop': not job or job['state'] != 'running' or bool(job.get('cancel_requested'))}

    @staticmethod
    def clean_attempt(attempt, requirements):
        if not isinstance(attempt, dict) or not set(attempt).issubset(requirements):
            raise DPIError('Неизвестная проверка в отчёте.')
        results = {}
        for name, minimum in requirements.items():
            row = report_probe(attempt.get(name))
            if row and row['error'] is None and row['bytes'] < minimum:
                row['error'] = 'body'
            results[name] = row
        return results

    @staticmethod
    def test_requirements(spec):
        checks = {check['name']: check['min_bytes'] for check in spec['checks']}
        if spec['video_id']:
            checks['video'] = 1048576
        return checks

    @staticmethod
    def passing(attempts, names):
        return sum(all(row.get(name) and row[name]['error'] is None for name in names) for row in attempts)

    def report(self, body):
        with self.edit() as (data, now):
            job = next((item for item in data['jobs'] if item['id'] == body['id']), None)
            if not job or job['state'] == 'queued':
                raise DPIError('Задание не найдено.')
            if job['state'] != 'running':
                return {}
            state = body['state']
            if job.get('cancel_requested'):
                state = 'cancelled'
            if state not in ('done', 'infrastructure', 'failed', 'cancelled', 'incompatible'):
                raise DPIError('Некорректный статус отчёта.')
            if state == 'done':
                self.validate_report(data, job, body, now)
            elif state == 'infrastructure' and body.get('control'):
                job['report'] = {'control': [report_probe(body['control'])]}
            job.update(state=state, finished=now)
            if job.get('followup'):
                self.queue(data, now, job['profile'], job['followup'], job.get('followup_extra'))
            profile = data['profiles'][job['profile']]
            if state == 'done' and profile['failures'] == 2 and job['kind'] == 'check':
                self.queue(data, now, job['profile'], 'revision')
            return {}

    def validate_report(self, data, job, body, now):
        key = job['profile']
        profile = data['profiles'][key]
        snapshot = job['snapshot']
        spec = job['specs'][key]
        names = self.test_requirements(spec)
        if body['zapret'] != snapshot['zapret']:
            raise DPIError('Версия zapret стенда отличается от версии роутера.')
        baseline = [self.clean_attempt(row, names) for row in body['baseline']]
        active = [self.clean_attempt(row, names) for row in body['active']]
        control_rows = [report_probe(row) for row in body['control']]
        series = body['series']
        count = 3 if job['kind'] == 'check' else 6
        if (len(series) != count // 3 or any(type(at) is not int or not job['started'] <= at <= now for at in series)
                or (count == 6 and series[1] - series[0] < self.series_gap)
                or not len(baseline) == len(active) == len(control_rows) == count
                or not all(row and row['error'] is None for row in control_rows)):
            raise DPIError('Неполная серия либо сбой контрольного сайта.')
        selection = body.get('selection', 'not_requested')
        if selection not in ('not_requested', 'completed', 'timeout', 'failed'):
            raise DPIError('Неизвестный результат подбора.')
        job['report'] = {'selection': selection, 'baseline': baseline, 'active': active, 'control': control_rows,
                         'series': series, 'candidates': [], 'quic': 'not_checked', 'ipv6': 'not_checked'}
        active_score = self.passing(active, (set(names) - {'submitted'}))
        if job['kind'] in ('check', 'revision', 'manual') and profile.get('active'):
            profile['failures'] = profile['failures'] + 1 if active_score < count else 0
            profile['last_check'] = now
            if not profile['failures']:
                profile.pop('automatic_attempts', None)
            profile['active_score'] = [active_score, count]
        candidates = body['candidates']
        if not isinstance(candidates, list) or len(candidates) > 6 or (job['kind'] == 'check' and candidates):
            raise DPIError('Некорректный список кандидатов.')
        current_snapshot = data['router']['snapshot'] if data['router'] else None
        neighbors = {f'{other}:{name}': minimum
                     for other in snapshot['profiles'] if other != key
                     for name, minimum in self.test_requirements(job['specs'][other]).items()}
        for candidate in candidates:
            parsed = rule(candidate['rule'])
            expected_domains = snapshot['profiles'][key]['domains'] if key in snapshot['profiles'] else [key]
            if parsed['domains'] != expected_domains:
                raise DPIError('Кандидат изменяет список доменов профиля.')
            attempts = [self.clean_attempt(row, names) for row in candidate['attempts']]
            adjacent = [self.clean_attempt(row, neighbors) for row in candidate['neighbors']]
            if len(attempts) != count or len(adjacent) != count:
                raise DPIError('В отчёте отсутствуют обязательные попытки.')
            score = self.passing(attempts, names)
            accepted = (score == count and self.passing(adjacent, neighbors) == count and
                        candidate.get('syntax') is True and current_snapshot == snapshot and
                        parsed != profile.get('active') and self.passing(baseline, names) < count)
            latency = int(median(sum(row[name]['ms'] for name in names) for row in attempts)) if score == count else None
            job['report']['candidates'].append({'rule': parsed, 'attempts': attempts, 'neighbors': adjacent,
                                                'score': [score, count], 'median_ms': latency,
                                                'syntax': candidate.get('syntax') is True, 'accepted': accepted})
            if accepted:
                self.promote(data, now, job, parsed, latency)
        if self.passing(baseline, names) == count:
            job['report']['outcome'] = 'direct'
        elif current_snapshot != snapshot:
            job['report']['outcome'] = 'stale'
            job['followup'] = 'revision'
        elif any(item['accepted'] for item in job['report']['candidates']):
            job['report']['outcome'] = 'verified'
        else:
            job['report']['outcome'] = 'no_candidate' if job['kind'] != 'check' else 'checked'

    def promote(self, data, now, job, parsed, latency):
        snapshot = job['snapshot']
        package = {'profile': job['profile'], 'base': snapshot['base'], 'zapret': snapshot['zapret'],
                   'openwrt': snapshot['openwrt'], 'rule': parsed, 'report': job['id'],
                   'expires': now + self.freshness, 'median_ms': latency}
        package['id'] = digest(package)
        version = dict(package)
        matching = [v for v in data['versions'] if v['profile'] == job['profile'] and v['rule'] != parsed]
        others = [v for v in data['versions'] if v['profile'] != job['profile']]
        pool = matching + [version]
        pool.sort(key=lambda item: (not self.eligible(data, item, now), item.get('median_ms', float('inf')),
                                    -item['expires']))
        data['versions'] = others + pool[:3]

    def router(self, body):
        with self.edit() as (data, now):
            snapshot = body['snapshot']
            if (not re.fullmatch(r'[0-9a-f]{64}', snapshot['base']) or
                    not isinstance(snapshot['zapret'], str) or not 1 <= len(snapshot['zapret']) <= 200 or
                    not isinstance(snapshot['openwrt'], str) or not 1 <= len(snapshot['openwrt']) <= 100 or
                    set(snapshot['profiles']) - (set(self.defaults) | set(data['profiles'])) or
                    any(type(snapshot['packets'][key]) is not int or not 0 <= snapshot['packets'][key] <= 64
                        for key in ('out', 'in')) or snapshot['packets']['out'] < 1):
                raise DPIError('Некорректный снимок конфигурации роутера.')
            snapshot = {'base': snapshot['base'], 'zapret': snapshot['zapret'], 'openwrt': snapshot['openwrt'],
                        'packets': snapshot['packets'], 'profiles': {
                            profile_key(key): rule(value) for key, value in snapshot['profiles'].items()}}
            previous = body.get('previous')
            if previous is not None and previous not in snapshot['profiles'] and previous not in data['profiles']:
                raise DPIError('Неизвестная резервная версия роутера.')
            data['router'] = {'snapshot': snapshot, 'seen': now, 'previous': previous}
            operation = data['operation']
            result = body.get('operation')
            completed = None
            if operation and result and result.get('id') == operation['id']:
                phase = result['phase']
                if phase == 'checking':
                    operation['phase'] = phase
                elif phase in ('applied', 'rolled_back', 'failed'):
                    operation['phase'] = phase
                    operation['reason'] = result.get('reason') if result.get('reason') in (
                        'drift', 'syntax', 'service', 'probe', 'timeout', 'storage') else None
                    data['last_operation'] = completed = operation
                    data['operation'] = None
            managed = snapshot['profiles']
            if not data['operation']:
                for key in set(managed) | set(data['profiles']):
                    if key not in data['profiles']:
                        data['profiles'][key] = dict(self.defaults[key], failures=0, next_check=now,
                                                      next_revision=now + self.revision_interval, drift=False)
                    profile = data['profiles'][key]
                    old_active = profile.get('active')
                    old_base = profile.get('active_base')
                    profile['active'] = managed.get(key)
                    profile['active_base'] = snapshot['base'] if profile['active'] else None
                    approved = completed and completed['phase'] in ('applied', 'rolled_back')
                    if approved and key == completed['profile']:
                        profile['drift'] = False
                    if old_active != profile['active'] or (old_base and old_base != snapshot['base']):
                        if not approved and (old_active or old_base):
                            profile['drift'] = True
                        profile.update(next_check=now, failures=0, active_score=None)
            delivered = body.get('delivered', [])
            if not isinstance(delivered, list) or len(delivered) > 96:
                raise DPIError('Некорректное подтверждение доставки.')
            for version in data['versions']:
                if version['base'] == snapshot['base']:
                    if version['id'] in delivered and version['expires'] > now:
                        version.setdefault('delivered', now)
                    else:
                        version.pop('delivered', None)
            if not data['operation'] and now - data['lan_seen'] <= 45:
                for version in data['versions']:
                    profile = data['profiles'][version['profile']]
                    fingerprint = digest(version['rule'])
                    attempts = profile.get('automatic_attempts', [])
                    if (profile['automatic'] and profile['failures'] >= 2 and version.get('delivered') and
                            fingerprint not in attempts and self.eligible(data, version, now)):
                        self.request_operation(data, now, 'apply', version['id'])
                        profile['automatic_attempts'] = (attempts + [fingerprint])[-12:]
                        break
            operation = data['operation']
            command = None
            if operation and operation['phase'] == 'queued':
                version = next((v for v in data['versions'] if v['id'] == operation['version']), None)
                if operation['action'] == 'rollback' or (version and self.eligible(data, version, now)):
                    command = operation
                else:
                    data['last_operation'] = dict(operation, phase='expired')
                    data['operation'] = None
            decision = None if not operation or operation['phase'] != 'checking' else operation.get('decision')
            return {'packages': [
                {key: val for key, val in v.items() if key != 'delivered'}
                for v in data['versions'] if self.eligible(data, v, now) and v['id'] not in delivered
            ], 'command': command, 'decision': decision}

    def lan(self, body):
        with self.edit() as (data, now):
            data['lan_seen'] = now
            operation = data['operation']
            if not operation or operation['phase'] != 'checking':
                return None
            if body.get('id') == operation['id'] and type(body.get('ok')) is bool:
                operation.setdefault('decision', {'id': operation['id'], 'ok': body['ok']})
                return None
            if not operation.get('decision'):
                selected = [data['profiles'][operation['profile']]]
                neighbor = next((profile for key, profile in data['profiles'].items()
                                 if profile.get('active') and key != operation['profile']), None)
                if neighbor:
                    selected.append(neighbor)
                return {'id': operation['id'],
                        'checks': [self.control] + [check for profile in selected for check in profile['checks']],
                        'videos': [profile['video_id'] for profile in selected if profile['video_id']]}
            return None

    def status(self):
        with self.edit() as (data, now):
            return {'enabled': True, 'router_online': bool(self.router_current(data, now)),
                    'lan_online': now - data['lan_seen'] <= 45, 'router': data['router'],
                    'profiles': data['profiles'], 'jobs': [
                        {key: val for key, val in job.items() if key not in ('snapshot', 'specs', 'extra', 'followup_extra')} for job in data['jobs'][-30:]
                    ], 'versions': [dict(version, eligible=self.eligible(data, version, now)) for version in data['versions']],
                    'operation': data['operation'], 'last_operation': data['last_operation']}
