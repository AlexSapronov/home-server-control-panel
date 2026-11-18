import base64
from contextlib import contextmanager
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
import json
from pathlib import Path
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch

from dpi_agent import Runner
from dpi_policy import DPIError, target
from dpi_router import Router, Zapret
from dpi_store import DPIStore
from dpi_worker import Probes, run_job, search_results
from server import Handler


OLD = '\n'.join([
    'NFQWS_ENABLE=1',
    'MODE_FILTER=none',
    'DISABLE_IPV6=1',
    'AUTOHOSTLIST_RETRANS_THRESHOLD=3',
    'NFQWS_TCP_PKT_OUT=$((6+$AUTOHOSTLIST_RETRANS_THRESHOLD))',
    'NFQWS_TCP_PKT_IN=3',
])
A = ['--dpi-desync=multidisorder', '--dpi-desync-split-pos=midsld']
B = ['--dpi-desync=fake', '--dpi-desync-ttl=8', '--dpi-desync-fake-tls=0x00000000']
C = ['--dpi-desync=fake,multidisorder', '--dpi-desync-ttl=9']
VERSION = 'github version v72.13 (87e0586)'
PASS = {'error': None, 'ms': 80, 'bytes': 32768, 'ips': ['1.1.1.1']}
FAIL = dict(PASS, error='timeout', bytes=15360)


class Clock:
    now = 1800000100

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


class LocalTransport:
    def __init__(self, store):
        self.store = store
        self.failed = False

    def post(self, action, data=None):
        if self.failed:
            raise ConnectionError()
        if action == 'sync':
            return self.store.router(data)
        return self.store.lan(data or {})


class RouterWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.clock = Clock()
        self.settings = {
            'series_gap': 5, 'job_timeout': 150, 'check_interval': 60, 'revision_interval': 600,
            'backup_window': ['00:00', '00:00'],
            'profiles': {
                'youtube': {'checks': [{'name': 'web', 'url': 'https://www.youtube.com/'}],
                            'video_id': '_YOUR_VIDEO'},
                'discord': {'checks': [{'name': 'page', 'url': 'https://discord.com/'}]},
            },
        }
        self.store = self.open_store()
        self.panel = LocalTransport(self.store)
        self.zapret_root = self.root / 'zapret'
        (self.zapret_root / 'ipset').mkdir(parents=True)
        (self.zapret_root / 'nfq').mkdir()
        self.write_script(self.zapret_root / 'nfq/nfqws', f'printf "%s\\n" "{VERSION}"\n')
        self.write_script(self.root / 'init', 'exit 0\n')
        (self.root / 'release').write_text("DISTRIB_RELEASE='25.12.6'\n")
        self.hosts = {'youtube': 'youtube.txt', 'discord': 'discord.txt'}
        self.router_settings = {'state_dir': str(self.root / 'state'), 'zapret_root': str(self.zapret_root),
                                'zapret_init': str(self.root / 'init'), 'openwrt_release': str(self.root / 'release'),
                                'hostlists': self.hosts}
        self.zapret = Zapret(self.router_settings, Runner())
        self.restart = patch.object(self.zapret, 'restart', return_value=True).start()
        self.addCleanup(patch.stopall)
        opts = []
        for key, args in [('youtube', A), ('discord', B)]:
            hostlist = self.zapret_root / 'ipset' / self.hosts[key]
            hostlist.write_text('# retained on rollback\n' + key + '.com\n')
            opts.append(' '.join(['--filter-tcp=443', '--hostlist=' + str(hostlist), *args]))
        self.original = OLD + '\nNFQWS_OPT="\n' + ' --new\n'.join(opts) + '\n"\n'
        self.zapret.config.write_text(self.original)
        self.router = Router(self.router_settings, self.panel, self.zapret, self.clock, self.clock)
        self.router.cycle()

    def open_store(self):
        return DPIStore(self.root / 'queue.sqlite3', self.settings, self.clock)

    def write_script(self, path, body):
        path.write_text('#!/bin/sh\n' + body)
        path.chmod(0o755)

    def claim(self):
        self.router.cycle()
        return self.store.claim()

    def baseline_report(self, job, good=False, direct=False):
        youtube = job['profile'] == 'youtube'
        names = ['web', 'video'] if youtube else ['page']
        if job.get('extra'):
            names.append('submitted')
        count = 3 if job['kind'] == 'check' else 6
        stamps = [self.clock()]
        if count == 6:
            self.clock.advance(6)
            stamps.append(self.clock())
        sample = dict(PASS, bytes=1048576) if youtube else PASS
        body = {
            'id': job['id'], 'state': 'done', 'zapret': VERSION, 'series': stamps, 'control': [PASS] * count,
            'baseline': [{name: sample if direct else FAIL for name in names} for _ in range(count)],
            'active': [{name: sample for name in names} for _ in range(count)], 'candidates': [],
        }
        if count == 6:
            domains = [job['profile'] + '.com'] if job['profile'] in ('youtube', 'discord') else [job['profile']]
            neighbors = {k + ':' + check['name']: PASS for k, spec in job['specs'].items()
                         if k != job['profile'] for check in spec['checks']}
            neighbors.update({k + ':video': dict(PASS, bytes=1048576) for k, spec in job['specs'].items()
                              if k != job['profile'] and spec['video_id']})
            body['candidates'] = [{
                'rule': {'domains': domains, 'args': C}, 'syntax': True,
                'attempts': [{name: sample if good or index != 2 else FAIL for name in names}
                             for index in range(count)],
                'neighbors': [neighbors] * count,
            }]
        return body

    def clear_initial_checks(self):
        for _ in range(2):
            job = self.claim()
            self.assertEqual(job['kind'], 'check')
            self.store.report(self.baseline_report(job))

    def prepared_version(self, name='youtube'):
        self.store.admin('revision', {'profile': name})
        job = self.claim()
        self.store.report(self.baseline_report(job, good=True))
        self.router.cycle()  # stage
        self.router.cycle()  # acknowledge delivery
        version, = self.store.status()['versions']
        self.assertTrue(version['eligible'])
        self.assertTrue(version['delivered'])
        self.assertEqual(self.zapret.config.read_text(), self.original)
        return version

    def start_application(self, version):
        self.store.lan({})
        self.store.admin('apply', {'id': version['id']})
        self.router.cycle()
        self.assertNotEqual(self.zapret.config.read_text(), self.original)
        self.router.cycle()
        return self.store.lan({})

    def test_revision_delivery_activation_manual_rollback_and_drift(self):
        self.clear_initial_checks()
        self.clock.advance(601)
        rev = self.claim()
        self.assertEqual(rev['kind'], 'revision')
        self.store.report(self.baseline_report(rev, good=True))
        self.router.cycle()
        self.router.cycle()
        version, = self.store.status()['versions']
        self.assertTrue(version['delivered'])
        probe = self.start_application(version)
        self.assertEqual({check['name'] for check in probe['checks']}, {'control', 'page', 'web'})
        self.assertEqual(probe['videos'], ['_YOUR_VIDEO'])
        self.store.lan({'id': probe['id'], 'ok': True})
        self.router.cycle()
        self.router.cycle()
        state = self.store.status()
        self.assertEqual(state['last_operation']['phase'], 'applied')
        self.assertEqual(state['profiles'][version['profile']]['active']['args'], C)
        self.assertFalse(state['profiles'][version['profile']]['drift'])
        self.store.admin('rollback', {})
        self.router.cycle()
        self.router.cycle()
        self.assertEqual(self.store.status()['last_operation']['phase'], 'rolled_back')
        self.assertEqual(self.zapret.config.read_text(), self.original)
        self.assertTrue((self.zapret.hosts / self.hosts['youtube']).read_text().startswith('# retained'))
        self.zapret.config.write_text(self.original + '# a manually edited router\n')
        self.router.cycle()
        state = self.store.status()
        self.assertTrue(state['profiles']['youtube']['drift'])
        self.assertFalse(state['versions'][0]['eligible'])

    def test_failure_then_local_recovery_on_panel_loss(self):
        self.clear_initial_checks()
        version = self.prepared_version('discord')
        probe = self.start_application(version)
        self.assertTrue(probe)
        self.panel.failed = True
        self.clock.advance(105)
        with self.assertRaises(ConnectionError):
            self.router.cycle()
        self.assertEqual(self.zapret.config.read_text(), self.original)
        self.assertFalse(self.router.pending.exists())
        self.panel.failed = False
        self.router.cycle()
        result = self.store.status()['last_operation']
        self.assertEqual((result['phase'], result['reason']), ('rolled_back', 'timeout'))

    def test_recovery_after_agent_restart_before_lan_approval(self):
        self.clear_initial_checks()
        version = self.prepared_version()
        self.start_application(version)
        new_router = Router(self.router_settings, self.panel, self.zapret, self.clock, self.clock)
        new_router.recover()
        new_router.cycle()
        self.assertEqual(self.store.status()['last_operation']['phase'], 'rolled_back')
        self.assertEqual(self.zapret.config.read_text(), self.original)

    def test_partial_candidate_and_already_accessible_site_never_delivered(self):
        self.clear_initial_checks()
        for good, direct in [(False, False), (True, True)]:
            self.store.admin('revision', {'profile': 'youtube'})
            job = self.claim()
            self.store.report(self.baseline_report(job, good, direct))
            self.assertEqual(self.store.status()['versions'], [])
            self.assertEqual(list(self.router.packages.iterdir()), [])

    def test_candidate_against_old_snapshot_needs_retest(self):
        self.clear_initial_checks()
        self.store.admin('revision', {'profile': 'discord'})
        job = self.claim()
        self.zapret.config.write_text(self.original + '# manual edit\n')
        self.router.cycle()
        self.store.report(self.baseline_report(job, good=True))
        self.assertEqual(self.store.status()['versions'], [])
        self.assertEqual(self.claim()['kind'], 'revision')

    def test_durable_queue_duplicate_input_and_worker_timeout(self):
        self.clear_initial_checks()
        address = 'https://somepublicsite.com/projects?token=secret'
        result = self.store.admin('add', {'url': address})
        self.assertEqual(self.store.admin('add', {'url': address}), result)
        self.store = self.open_store()
        self.panel.store = self.store
        job = self.claim()
        self.assertEqual(job['specs'][job['profile']]['checks'][0]['url'], address.split('?')[0])
        self.assertEqual(job['id'], result['id'])
        self.assertIsNone(self.store.claim())
        self.clock.advance(151)
        self.assertEqual(self.store.status()['jobs'][-1]['state'], 'timeout')
        self.assertNotIn('secret', json.dumps(self.store.status()))
        self.assertEqual(self.zapret.config.read_text(), self.original)

    def test_two_active_failures_queue_revision(self):
        self.clear_initial_checks()
        for _ in range(2):
            self.clock.advance(61)
            for _ in range(2):
                job = self.claim()
                report = self.baseline_report(job)
                if job['profile'] == 'discord':
                    report['active'] = [{'page': FAIL}] * 3
                self.store.report(report)
        self.assertEqual(self.claim()['kind'], 'revision')

    def test_manual_url_for_active_profile_keeps_target_path(self):
        self.clear_initial_checks()
        self.store.admin('add', {'url': 'https://discord.com/custom/page?token=secret'})
        job = self.claim()
        self.assertEqual(job['profile'], 'discord')
        self.assertEqual(job['specs']['discord']['checks'][-1]['url'], 'https://discord.com/custom/page')

    def test_new_profile_uses_independent_hostlist_and_can_roll_back(self):
        self.clear_initial_checks()
        key = 'somepublicsite.com'
        self.store.admin('add', {'url': key})
        job = self.claim()
        self.store.report(self.baseline_report(job, good=True))
        self.router.cycle()
        self.router.cycle()
        version, = self.store.status()['versions']
        probe = self.start_application(version)
        self.store.lan({'id': probe['id'], 'ok': False})
        self.router.cycle()
        self.router.cycle()
        self.assertEqual(self.zapret.config.read_text(), self.original)
        self.assertFalse(self.zapret.new_hostlist(key).exists())

    def test_machine_api_auth_and_browser_cross_origin_rejection(self):
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        server.config = {'mode': 'demo'}
        server.dpi = self.store
        server.dpi_tokens = {role: role * 32 for role in ('router', 'lan', 'worker')}
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)

        def send(path, auth, extra=None):
            conn = HTTPConnection('127.0.0.1', server.server_port)
            try:
                conn.request('POST', '/api/dpi/' + path, '{}',
                             {'Authorization': auth, 'Content-Type': 'application/json', **(extra or {})})
                response = conn.getresponse()
                response.read()
                return response.status
            finally:
                conn.close()

        self.clear_initial_checks()
        with patch.dict('os.environ', {'NERV_PASSWORD': 'test'}):
            credentials = 'Basic ' + base64.b64encode(b'admin:test').decode()
            self.assertEqual(send('admin/rollback', credentials), 403)
            self.assertEqual(send('admin/rollback', 'Bearer ' + 'worker' * 32, {'X-NERV-Request': 'dpi'}), 401)
            self.assertEqual(send('worker/claim', 'Bearer ' + 'router' * 32), 403)
            self.assertEqual(send('worker/claim', 'Bearer ' + 'worker' * 32), 200)


class WorkerTests(unittest.TestCase):
    def test_periodic_revision_performs_new_search_even_if_active_and_baseline_are_healthy(self):
        class PanelStub:
            def post(self, action, data):
                return {'stop': False}

        job = {'id': 'job', 'kind': 'revision', 'profile': 'discord', 'series_gap': 1, 'backups': [],
               'snapshot': {'zapret': VERSION, 'packets': {'out': 9, 'in': 3}, 'profiles': {
                   'discord': {'domains': ['discord.com'], 'args': B},
               }}, 'control': {'name': 'control', 'url': 'https://example.com/', 'tls': 'auto'},
               'specs': {'discord': {'checks': [{'name': 'page', 'url': 'https://discord.com/', 'tls': 'auto'}]}}}

        @contextmanager
        def enabled(*_):
            yield True

        with (patch('dpi_worker.binary_version', return_value=VERSION),
              patch('dpi_worker.Engine.cleanup'), patch('dpi_worker.Engine.enable', enabled),
              patch('dpi_worker.Engine.search', return_value=('completed', [C])) as search,
              patch('dpi_worker.Probes.fetch', return_value=PASS),
              patch('dpi_worker.Probes.resolve', return_value='1.1.1.1'),
              patch('dpi_worker.wait_until')):
            report = run_job({'namespace': 'nerv-dpi'}, PanelStub(), job)
        search.assert_called_once_with('discord.com', force=True)
        self.assertEqual(len(report['baseline']), 6)
        self.assertEqual(len(report['candidates'][0]['attempts']), 6)

    def test_public_ip_pinning_on_each_redirect_and_body_timeout(self):
        class MockRunner:
            def __init__(self, redirect, addresses, code=0):
                self.redirect = redirect
                self.addresses = addresses
                self.code = code
                self.calls = []

            def run(self, args, **_):
                self.calls.append(args)
                if args[0] == 'getent':
                    return 0, self.addresses[args[-1]].encode()
                self.assert_tls(args)
                Path(args[args.index('--dump-header') + 1]).write_bytes(
                    b'HTTP/1.1 302 Found\r\nLocation: ' + self.redirect.encode() + b'\r\n\r\n'
                    if self.redirect else b'HTTP/1.1 200 OK\r\nContent-Length: 32768\r\n\r\n')
                Path(args[args.index('--output') + 1]).write_bytes(bytes(15360))
                return self.code, b''

            @staticmethod
            def assert_tls(args):
                assert '--tlsv1.2' in args and args[args.index('--tls-max') + 1] == '1.2'

        runner = MockRunner('https://router.example.com/', {'example.com': '1.1.1.1 STREAM',
                                                            'router.example.com': '192.168.10.1 STREAM'})
        result = Probes(runner).fetch('https://example.com/', '1.2', {}, 0)
        self.assertEqual(result['error'], 'dns')
        curl, = [call for call in runner.calls if call[0] == 'curl']
        self.assertIn('example.com:443:1.1.1.1', curl)
        runner = MockRunner(None, {'example.com': '1.1.1.1 STREAM'}, code=28)
        result = Probes(runner).fetch('https://example.com/', '1.2', {}, 0)
        self.assertEqual((result['error'], result['bytes']), ('timeout', 15360))

    def test_blockcheck_parser_drops_unknown_and_unscoped_options(self):
        data = f'''
* SUMMARY
curl_test_https_tls12 ipv4 example.com : nfqws {' '.join(A)}
curl_test_https_tls13 ipv4 example.com : nfqws --dpi-desync=fake --hostlist=/etc/shadow
curl_test_https_tls13 ipv6 example.com : nfqws --dpi-desync=fake
'''.encode()
        self.assertEqual(search_results(data, 'example.com'), [A])

    def test_url_policy(self):
        for url in ('http://192.168.10.1/', 'https://localhost/', 'ftp://example.com/',
                    'https://example.com:4443/', 'https://user@example.com/', 'http://example.com/\n'):
            with self.subTest(url=url), self.assertRaises(DPIError):
                target(url)
        self.assertEqual(target('https://example.com/path?a=secret#fragment'), 'https://example.com/path')

    def test_runner_cancels_timed_out_subprocess(self):
        with self.assertRaises(subprocess.TimeoutExpired):
            Runner().run(['sh', '-c', 'sleep 300'], timeout=0.05)


if __name__ == '__main__':
    unittest.main()
