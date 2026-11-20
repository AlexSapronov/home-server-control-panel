import importlib.util
import json
from pathlib import Path
import socket
import struct
import unittest
from unittest.mock import patch, MagicMock

spec = importlib.util.spec_from_file_location('diagnostics', 'deploy/nerv_diagnostics.py')
diag = importlib.util.module_from_spec(spec)
spec.loader.exec_module(diag)


def runtime_rule(name, set_name, mark, source=False):
    return {'rule': {'chain': 'pbr_prerouting', 'comment': name, 'expr': [
        {'match': {'op': '==', 'left': {'payload': {'protocol': 'ip', 'field': 'saddr' if source else 'daddr'}},
                   'right': '@' + set_name}}, {'goto': {'target': 'pbr_mark_0x' + mark}}]}}


class DiagnosticTests(unittest.TestCase):
    def test_url_validation_and_private_targets(self):
        self.assertEqual(diag.target_url('rutracker.org')[0], 'https://rutracker.org/')
        self.assertEqual(diag.target_url('https://EXAMPLE.com/a?b=1#fragment'), ('https://example.com/a?b=1', 'example.com', 443))
        for value in ('file:///etc/passwd', 'https://user:pass@example.com', 'http://127.0.0.1/',
                      'http://[::1]/', 'http://router.home.arpa/', 'http://localhost/',
                      'https://example.com:22/', 'https://example.com\nX:1', 'https://example.com\\@127.0.0.1',
                      '-x.com', 'http://2130706433/', 'ftp://example.com', None):
            with self.subTest(value=value), self.assertRaises(diag.DiagnosticError):
                diag.target_url(value)
        with patch.object(diag, 'resolve', return_value=(['192.168.10.1'], 'ok')), patch.object(diag, 'command') as command:
            with self.assertRaises(diag.DiagnosticError):
                diag.diagnose('example.com')
            command.assert_not_called()
        for address in ('10.0.0.1', '169.254.169.254', '127.0.0.1', '224.0.0.1', '::1', 'fc00::1'):
            self.assertFalse(diag.public_address(address))

    def test_dns_packet_parsing_and_rejection(self):
        question = b'\x07example\x03com\0' + struct.pack('!HH', 1, 1)
        answer = b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 60, 4) + socket.inet_aton('1.1.1.1')
        packet = struct.pack('!6H', 42, 0x8180, 1, 1, 0, 0) + question + answer
        self.assertEqual(diag.dns_answers(packet, 42, 1), (['1.1.1.1'], 'ok'))
        with self.assertRaises(ValueError):
            diag.dns_answers(packet, 43, 1)
        with self.assertRaises(ValueError):
            diag.dns_answers(packet[:-2], 42, 1)
        nx = struct.pack('!6H', 42, 0x8183, 1, 0, 0, 0) + question
        self.assertEqual(diag.dns_answers(nx, 42, 1), ([], 'nxdomain'))

    def test_first_actual_ip_rule_wins_over_domain_intent(self):
        rows = [{'set': {'name': 'wan', 'elem': [{'prefix': {'addr': '1.1.1.0', 'len': 24}}]}},
                {'set': {'name': 'awg', 'elem': ['1.1.1.1']}},
                runtime_rule('Device-only', 'awg', '020000', source=True),
                runtime_rule('Direct exception', 'wan', '010000'),
                runtime_rule('Requested AWG', 'awg', '020000')]
        self.assertEqual(diag.runtime_match('1.1.1.1', rows)['name'], 'Direct exception')
        self.assertEqual(diag.runtime_match('1.1.1.1', rows)['mark'], 65536)
        self.assertIsNone(diag.runtime_match('8.8.8.8', rows))
        import ipaddress
        self.assertTrue(diag.contains({'range': ['1.1.1.1', '1.1.1.9']}, ipaddress.ip_address('1.1.1.5')))

    def test_domain_matching_respects_subdomain_boundary_and_disabled_state(self):
        sections = {'site': {'_type': 'policy', 'dest_addr': 'example.com', 'enabled': '0', 'interface': 'awg0'}}
        self.assertFalse(diag.domain_rules('cdn.example.com', sections)[0]['enabled'])
        self.assertEqual(diag.domain_rules('notexample.com', sections), [])

    def test_http_is_pinned_bounded_no_proxy_no_redirects_and_no_secrets(self):
        response = MagicMock(returncode=28, stdout=json.dumps({'http_code': 200, 'size_download': 17327,
                            'time_total': 8.0, 'redirect_url': 'http://127.0.0.1/private?token=SECRET'}))
        with patch.object(diag.subprocess, 'run', return_value=response) as run:
            result = diag.probe('https://example.com/resource', 'example.com', 443, '1.1.1.1', 'awg0')
        args = run.call_args.args[0]
        self.assertIn('example.com:443:1.1.1.1', args)
        self.assertNotIn('--location', args)
        self.assertNotIn('-L', args)
        self.assertIn('--noproxy', args)
        self.assertIn('--max-filesize', args)
        self.assertEqual(result['state'], 'timeout')
        self.assertEqual(result['bytes'], 17327)
        self.assertNotIn('SECRET', json.dumps(result))

    def test_dns_failure_does_not_attempt_any_http_or_rules(self):
        with patch.object(diag, 'resolve', return_value=([], 'nxdomain')), patch.object(diag, 'command') as command, \
                patch.object(diag, 'probe') as probe:
            result = diag.diagnose('example.com')
        self.assertEqual(result['dns']['a_state'], 'nxdomain')
        self.assertTrue(result['read_only'])
        command.assert_not_called()
        probe.assert_not_called()

    def test_diagnosis_uses_only_read_commands_and_marks_missing_runtime_ips(self):
        calls = []
        def command(*args, **kwargs):
            calls.append(args)
            if args[0] == 'uci':
                return "pbr.site=policy\npbr.site.interface='awg0'\npbr.site.dest_addr='example.com'\npbr.site.name='Example'"
            if args[0] == 'nft':
                return '{"nftables":[]}'
            if args[0] == 'ubus':
                return '{"l3_device":"eth1"}'
            if 'link' in args:
                return '[{"flags":["UP"]}]'
            if 'route' in args:
                return '[{"dev":"eth1"}]'
            raise AssertionError(args)
        with patch.object(diag, 'resolve', side_effect=lambda host, typ: (['1.1.1.1'], 'ok') if typ == 1 else ([], 'no_records')), \
                patch.object(diag, 'command', side_effect=command), patch.object(diag, 'probe', return_value={'state':'ok'}):
            result = diag.diagnose('example.com')
        self.assertIsNone(result['routes'][0]['matched_rule'])
        self.assertTrue(any('часть IP' in warning for warning in result['warnings']))
        self.assertFalse(any(arg in ('set','add','delete','restart','reload','commit') for call in calls for arg in call))

    def test_helper_diagnosis_never_runs_the_mutation_path(self):
        import sys
        routing_spec = importlib.util.spec_from_file_location('routing_diag', 'deploy/openwrt-routing.py')
        routing = importlib.util.module_from_spec(routing_spec)
        routing_spec.loader.exec_module(routing)
        with patch.dict(sys.modules, {'nerv_diagnostics': diag}), patch.object(diag, 'diagnose', return_value={'read_only':True}) as check, \
                patch.object(routing, 'run') as command:
            routing.apply({'action':'diagnose', 'target':'rutracker.org'})
        check.assert_called_once_with('rutracker.org')
        command.assert_not_called()
