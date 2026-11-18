"""Stand-alone Linux test worker. Packet processing is confined to the test namespace."""
import argparse
from contextlib import contextmanager
import json
import logging
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
from urllib.parse import quote, urljoin, urlsplit

from dpi_agent import Cancelled, Panel, Runner, binary_version
from dpi_policy import DPIError, public_ip, strategy, target, within
from openwrt import dns_probe


QUEUE = 59781
MARK = '0x20000000'
TABLE = 'nerv_dpi'
MEDIA_SIZE = 1048576
LOG = logging.getLogger('nerv-dpi')


class Probes:
    def __init__(self, runner, yt_dlp='yt-dlp'):
        self.runner = runner
        self.yt_dlp = yt_dlp

    def resolve(self, host, port, book, sample):
        key = (host, port)
        if key not in book:
            code, result = self.runner.run(['getent', 'ahostsv4', host], timeout=5)
            if code:
                raise DPIError('dns')
            addresses = sorted({public_ip(line.split()[0]) for line in result.decode().splitlines() if line.split()})
            if not addresses:
                raise DPIError('dns')
            book[key] = addresses[sample % len(addresses)]
        return book[key]

    def fetch(self, url, tls, book, sample, *, media=False, minimum=1):
        start = time.monotonic()
        started_at = int(time.time())
        ips, size, error = [], 0, 'redirect'
        with tempfile.TemporaryDirectory() as temp:
            headers = Path(temp, 'headers')
            body = Path(temp, 'body')
            for _ in range(6):
                try:
                    parsed = urlsplit(target(url, keep_query=True))
                    if (tls != 'auto' and parsed.scheme != 'https') or (
                            media and not within(parsed.hostname, 'googlevideo.com')):
                        break
                    port = 443 if parsed.scheme == 'https' else 80
                    try:
                        ip = self.resolve(parsed.hostname, port, book, sample)
                    except (ValueError, subprocess.TimeoutExpired):
                        error = 'dns'
                        break
                    ips.append(ip)
                    headers.touch()
                    body.touch()
                    headers.write_bytes(b'')
                    body.write_bytes(b'')
                    flags = ['--tlsv' + tls, '--tls-max', tls] if tls != 'auto' else []
                    if media:
                        flags += ['--range', f'0-{MEDIA_SIZE - 1}']
                    addr = parsed._replace(path=quote(parsed.path, safe="/%:@!$&'()*+,;=-._~")).geturl()
                    code, _ = self.runner.run([
                        'curl', '-q', '--silent', '--globoff', '--noproxy', '*', '--ipv4', '--http1.1',
                        '--proto', '=http,https', '--connect-timeout', '5', '--max-time', '12',
                        '--max-filesize', '8388608', '--resolve', f'{parsed.hostname}:{port}:{ip}',
                        '--dump-header', str(headers), '--output', str(body), *flags, '--', addr,
                    ], timeout=14)
                    size = min(body.stat().st_size, 16777216)
                    if code:
                        error = {7: 'connect', 18: 'body', 28: 'timeout', 35: 'tls',
                                 60: 'tls', 63: 'body'}.get(code, 'internal')
                        break
                    blocks = re.split(r'\r?\n\r?\n', headers.read_text(errors='replace'))
                    responses = [block for block in blocks if block.startswith('HTTP/')]
                    match = re.match(r'HTTP/\S+ (\d{3})', responses[-1]) if responses else None
                    status = int(match[1]) if match else 0
                    if status in (301, 302, 303, 307, 308):
                        location = re.search(r'^location:\s*(\S+)\s*$', responses[-1], re.I | re.M)
                        if not location:
                            break
                        url = urljoin(addr, location[1])
                        continue
                    if media:
                        error = None if status == 206 and size == MEDIA_SIZE else 'body'
                    elif 200 <= status < 300:
                        error = None if size >= minimum else 'body'
                    else:
                        error = 'http'
                    break
                except (ValueError, OSError):
                    error = 'redirect'
                    break
                except subprocess.TimeoutExpired:
                    error = 'timeout'
                    break
        return {'error': error, 'ms': min(int((time.monotonic() - start) * 1000), 300000),
                'bytes': size, 'ips': ips, 'at': started_at}

    def video(self, video_id, book, sample):
        try:
            code, output = self.runner.run([self.yt_dlp, '--ignore-config', '--proxy', '', '--no-playlist', '--force-ipv4',
                                            '--socket-timeout', '6', '--retries', '0', '--extractor-retries', '0',
                                            '--no-cache-dir', '--no-warnings', '--get-url',
                                            '-f', 'best[protocol=https]/bestvideo[protocol=https]',
                                            'https://www.youtube.com/watch?v=' + video_id], timeout=25)
            urls = output.decode().strip().splitlines()
            if code or len(urls) != 1:
                raise DPIError('media')
            return self.fetch(urls[0], 'auto', book, sample, media=True)
        except (ValueError, OSError, subprocess.TimeoutExpired):
            return {'error': 'media', 'ms': 0, 'bytes': 0, 'ips': []}

    def check(self, spec, book, sample):
        return self.fetch(spec['url'], spec['tls'], book, sample, minimum=spec.get('min_bytes', 1))

    def group(self, spec, book, sample):
        rows = {check['name']: self.check(check, book, sample) for check in spec['checks']}
        if spec.get('video_id'):
            rows['video'] = self.video(spec['video_id'], book, sample)
        return rows


class Engine:
    def __init__(self, config, runner):
        self.config = config
        self.runner = runner
        self.cleanup_runner = Runner(config['namespace'])
        self.binary = config.get('nfqws', '/opt/zapret/nfq/nfqws')

    def cleanup(self):
        for table in (TABLE, 'blockcheck'):
            self.cleanup_runner.run(['nft', 'delete', 'table', 'inet', table], timeout=5)

    @contextmanager
    def enable(self, profiles, packets):
        if not profiles:
            yield True
            return
        with tempfile.TemporaryDirectory() as temp:
            switches = []
            for index, rule in enumerate(profiles.values()):
                hosts = Path(temp, f'hosts-{index}.txt')
                hosts.write_text('\n'.join(rule['domains']) + '\n')
                switches.extend(['--new', '--filter-l3=ipv4', '--filter-tcp=443', '--hostlist=' + str(hosts),
                                 *rule['args']])
            args = [self.binary, f'--qnum={QUEUE}', f'--dpi-desync-fwmark={MARK}', *switches[1:]]
            code, _ = self.runner.run(args + ['--dry-run'], timeout=5)
            if code:
                yield False
                return
            config = Path(temp, 'nft.conf')
            inbound = (f'ip protocol tcp tcp sport 443 ct reply packets 1-{packets["in"]} queue num {QUEUE} bypass'
                       if packets['in'] else '')
            config.write_text(f'''
table inet {TABLE} {{
 chain outgoing {{
  type filter hook postrouting priority 105; policy accept;
  ip protocol tcp tcp dport 443 meta mark & {MARK} == 0 ct original packets 1-{packets["out"]} queue num {QUEUE} bypass
 }}
 chain incoming {{
  type filter hook prerouting priority -110; policy accept;
  {inbound}
 }}
}}
''')
            proc = self.runner.open(args, stdout=subprocess.DEVNULL)
            try:
                time.sleep(0.2)
                if proc.poll() is not None or self.runner.run(['nft', '-f', str(config)], timeout=5)[0]:
                    raise DPIError('nfqws laboratory startup failed')
                yield True
                if proc.poll() is not None:
                    raise DPIError('nfqws exited during measurement')
            finally:
                Runner.stop(proc)
                self.cleanup()

    def search(self, host, *, force=False):
        # The input is a canonical domain, passed as data to the upstream batch interface.
        try:
            env = {'PATH': os.defpath + ':/usr/local/bin:/usr/sbin:/sbin', 'LC_ALL': 'C',
                   'ZAPRET_CONFIG': '/dev/null', 'NFQWS': self.binary, 'DOMAINS': host,
                   'BATCH': '1', 'IPVS': '4', 'ENABLE_HTTP': '0', 'ENABLE_HTTPS_TLS12': '1',
                   'ENABLE_HTTPS_TLS13': '1', 'ENABLE_HTTP3': '0', 'SCANLEVEL': 'force' if force else 'standard',
                   'SKIP_TPWS': '1', 'SKIP_DNSCHECK': '1', 'PARALLEL': '0', 'REPEATS': '1',
                   'CURL_MAX_TIME': '3', 'SKIP_IPBLOCK': '1'}
            self.runner.run(['getent', 'ahostsv4', host], timeout=5)
            code, output = self.runner.run([self.config.get('blockcheck', '/opt/zapret/blockcheck.sh')],
                                           timeout=int(self.config.get('search_timeout', 180)), env=env)
            return ('failed', []) if code else ('completed', search_results(output, host))
        except subprocess.TimeoutExpired:
            return 'timeout', []
        finally:
            self.cleanup()


def search_results(output, host):
    lines = output.decode(errors='replace').partition('* SUMMARY\n')[2].splitlines()
    prefix = re.compile(r'^curl_test_https_tls1[23] ipv4 ' + re.escape(host) + r' : nfqws (.+)$')
    results = []
    for line in lines:
        match = prefix.fullmatch(line)
        if not match:
            continue
        try:
            args = strategy(match[1].split())
        except DPIError:
            continue
        if args not in results:
            results.append(args)
    return results[:3]


def wait_until(moment, pulse):
    while (remaining := moment - time.monotonic()) > 0:
        pulse()
        time.sleep(min(1, remaining))


def run_job(config, panel, job):
    job_id = job['id']
    last_pulse = time.monotonic() - 10

    def pulse():
        nonlocal last_pulse
        if time.monotonic() - last_pulse >= 5:
            last_pulse = time.monotonic()
            if panel.post('heartbeat', {'id': job_id})['stop']:
                raise Cancelled

    namespace = config['namespace']
    if not re.fullmatch(r'nerv-dpi(?:-[a-z0-9]+)?', namespace):
        raise DPIError('A dedicated test network namespace is required')
    runner = Runner(namespace, pulse)
    engine = Engine(config, runner)
    probes = Probes(runner, config.get('yt_dlp', 'yt-dlp'))
    snapshot = job['snapshot']
    result = {'id': job_id, 'state': 'done', 'candidates': [], 'baseline': [], 'active': [], 'control': [],
              'series': [], 'selection': 'not_requested'}
    try:
        pulse()
        engine.cleanup()
        result['zapret'] = binary_version(engine.binary, runner)
        if result['zapret'] != snapshot['zapret']:
            return {'id': job_id, 'state': 'incompatible'}
        active = snapshot['profiles']
        key = job['profile']
        spec = job['specs'][key]
        search_host = urlsplit(spec['checks'][0]['url']).hostname
        domains = active[key]['domains'] if key in active else [key]
        candidates = [dict(rule=rule, attempts=[], neighbors=[], syntax=True) for rule in job['backups']
                      if rule != active.get(key)]
        if job['kind'] != 'check':
            control = job['control']
            initial = probes.check(control, {}, 0)
            if initial['error']:
                return {'id': job_id, 'state': 'infrastructure', 'control': initial}
            direct = all(not record['error'] for attempt in range(1 if key in active else 3)
                         for record in probes.group(spec, {}, attempt).values())
            if key in active or not direct:
                try:
                    probes.resolve(search_host, 443, {}, 0)
                except (ValueError, subprocess.TimeoutExpired):
                    return {'id': job_id, 'state': 'infrastructure',
                            'control': {'error': 'dns', 'ms': 0, 'bytes': 0, 'ips': []}}
                result['selection'], options = engine.search(search_host, force=direct)
                for args in options:
                    rule = {'domains': domains, 'args': args}
                    if rule != active.get(key) and not any(rule == item['rule'] for item in candidates):
                        candidates.append(dict(rule=rule, attempts=[], neighbors=[], syntax=True))
        for series in range(1 if job['kind'] == 'check' else 2):
            if series:
                wait_until(time.monotonic() + job['series_gap'] + 1, pulse)
            result['series'].append(int(time.time()))
            for attempt in range(3):
                sample = series * 3 + attempt
                book = {}
                control = job['control']
                control_probe = probes.check(control, book, sample)
                result['control'].append(control_probe)
                if control_probe['error']:
                    return {'id': job_id, 'state': 'infrastructure', 'control': control_probe}
                result['baseline'].append(probes.group(spec, book, sample))
                with engine.enable(active, snapshot['packets']) as syntax:
                    if not syntax:
                        return {'id': job_id, 'state': 'incompatible'}
                    result['active'].append(probes.group(spec, book, sample) if key in active else {})
                if job['kind'] != 'check':
                    for item in candidates:
                        combined = dict(active)
                        combined[key] = item['rule']
                        neighbors = {}
                        with engine.enable(combined, snapshot['packets']) as syntax:
                            item['syntax'] &= syntax
                            item['attempts'].append(probes.group(spec, book, sample) if syntax else {})
                            if syntax:
                                for other in active:
                                    if other == key:
                                        continue
                                    neighbors.update({f'{other}:{name}': record for name, record in
                                                      probes.group(job['specs'][other], book, sample).items()})
                        item['neighbors'].append(neighbors)
        result['candidates'] = candidates if job['kind'] != 'check' else []
        return result
    except Cancelled:
        return {'id': job_id, 'state': 'cancelled'}
    except (DPIError, OSError, subprocess.TimeoutExpired):
        return {'id': job_id, 'state': 'infrastructure'}
    finally:
        engine.cleanup()


def lan_cycle(panel, probes, dns_host):
    job = panel.post('probe')
    if not job:
        return
    book = {}
    ok = (dns_probe(dns_host) == 'resolved' and
          all(probes.check(item, book, 0)['error'] is None for item in job['checks']) and
          all(probes.video(video, book, 0)['error'] is None for video in job['videos']))
    panel.post('probe', {'id': job['id'], 'ok': ok})


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('role', choices=['worker', 'lan'])
    parser.add_argument('config', type=Path)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO)
    config = json.loads(args.config.read_text())
    panel = Panel(config, args.role)
    probes = Probes(Runner(), config.get('yt_dlp', 'yt-dlp'))
    while True:
        try:
            if args.role == 'worker':
                job = panel.post('claim')
                if job:
                    result = run_job(config, panel, job)
                    for _ in range(3):
                        try:
                            panel.post('report', result)
                            break
                        except OSError:
                            time.sleep(2)
                    else:
                        LOG.warning('Worker could not submit the job result')
            else:
                lan_cycle(panel, probes, config['dns_host'])
        except (OSError, DPIError, ValueError):
            LOG.warning('Cycle interrupted, retrying')
        time.sleep(5)


if __name__ == '__main__':
    main()
