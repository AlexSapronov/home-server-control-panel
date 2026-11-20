import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch, MagicMock

import openwrt

spec = importlib.util.spec_from_file_location('routing', 'deploy/openwrt-routing.py')
routing = importlib.util.module_from_spec(spec)
spec.loader.exec_module(routing)

UCI = """pbr.config=pbr
pbr.discord=policy
pbr.discord.interface='wan'
pbr.discord.dest_addr='discord.com'
pbr.youtube=policy
pbr.youtube.name='YouTube All LAN'
pbr.youtube.interface='awg0'
pbr.youtube.dest_addr='youtube.com googlevideo.com'
pbr.hermes=policy
pbr.hermes.interface='awg0'
pbr.hermes.src_addr='192.168.10.183'
pbr.custom=policy
pbr.custom.interface='awg0'
pbr.custom.dest_addr='example.org'
pbr.custom.proto='tcp'
"""


class RoutingTests(unittest.TestCase):
    def test_domains_urls_idn_and_injection(self):
        self.assertEqual(routing.domain_name('https://Example.COM/path?q=1'), 'example.com')
        self.assertEqual(routing.domain_name('пример.рф'), 'xn--e1afmkfd.xn--p1ai')
        for value in ('1.2.3.4', 'localhost', 'a.com;reboot', 'https://user:pass@a.com',
                      'https://a.com:443', '-foo.com', 'a.com\nreboot', '$(id).com', None):
            with self.subTest(value=value), self.assertRaises(routing.RoutingError):
                routing.domain_name(value)

    def test_only_unrestricted_awg_domain_policies_are_manageable(self):
        with patch.object(routing, 'run', return_value=UCI):
            rules = routing.policies()
        self.assertEqual([r['id'] for r in rules], ['youtube'])
        self.assertEqual(rules[0]['domains'], ['youtube.com', 'googlevideo.com'])

    def test_conflict_and_protected_removal_never_mutate(self):
        with patch.object(routing, 'revision', return_value='current'), \
                patch.object(routing, 'policies', return_value=[]), patch.object(routing, 'run') as run:
            for request in ({'action': 'add', 'domain': 'a.com', 'revision': 'old'},
                            {'action': 'set_enabled', 'id': 'discord', 'enabled': False, 'revision': 'current'},
                            {'action': 'set_enabled', 'id': 'hermes', 'enabled': False, 'revision': 'current'}):
                with self.assertRaises(routing.RoutingError):
                    routing.apply(request)
            run.assert_not_called()

    def test_duplicate_subdomain_does_not_change_router(self):
        with patch.object(routing, 'revision', return_value='r'), patch.object(routing, 'policies', return_value=[
                {'id': 'youtube', 'enabled': True, 'domains': ['youtube.com']}]), patch.object(routing, 'run') as run:
            with self.assertRaises(routing.RoutingError):
                routing.apply({'action': 'add', 'domain': 'www.youtube.com', 'revision': 'r'})
            run.assert_not_called()

    def test_failed_restart_restores_original_config(self):
        with tempfile.TemporaryDirectory() as temp:
            config = Path(temp) / 'pbr'
            config.write_bytes(b'original config')
            calls = []
            def command(*args, **kwargs):
                calls.append(args)
                if args == ('uci', 'commit', 'pbr'):
                    config.write_bytes(b'changed config')
                if args == ('/etc/init.d/pbr', 'restart') and calls.count(args) == 1:
                    raise subprocess.CalledProcessError(1, args)
                return ''
            with patch.object(routing, 'POLICY_FILE', config), patch.object(routing, 'BACKUPS', Path(temp)/'backups'), \
                    patch.object(routing, 'policies', return_value=[{'id': 'youtube', 'enabled': True, 'domains': ['youtube.com']}]), patch.object(routing, 'ipsets', return_value={}), \
                    patch.object(routing, 'run', side_effect=command):
                with self.assertRaisesRegex(routing.RoutingError, 'восстановлены'):
                    routing.apply({'action': 'set_enabled', 'id': 'youtube', 'enabled': False, 'revision': routing.revision()})
            self.assertEqual(config.read_bytes(), b'original config')
            self.assertEqual(calls.count(('/etc/init.d/pbr', 'restart')), 2)
            self.assertEqual(next((Path(temp)/'backups').glob('*.pbr')).read_bytes(), b'original config')

    def test_retains_cached_ips_only_for_sets_still_present(self):
        saved = {'pbr_old': ['1.1.1.1'], 'pbr_removed': ['2.2.2.2']}
        with patch.object(routing, 'ipsets', return_value={'pbr_old': []}), patch.object(routing.subprocess, 'run') as run:
            routing.restore_ipsets(saved)
        operations = json.loads(run.call_args.kwargs['input'])['nftables']
        self.assertEqual(operations, [{'add': {'element': {'family': 'inet', 'table': 'fw4', 'name': 'pbr_old', 'elem': ['1.1.1.1']}}}])

    def test_presets_aliases_custom_domains_and_validation(self):
        domain, name, domains = routing.domain_group('https://www.youtube.com/watch?v=test', ['img.example.org', 'youtube.com'])
        self.assertEqual(name, 'YouTube')
        self.assertIn('googlevideo.com', domains)
        self.assertIn('img.example.org', domains)
        self.assertEqual(domains.count('youtube.com'), 1)
        self.assertEqual(routing.domain_group('example.com', ['cdn.example.org'])[2], ['example.com', 'cdn.example.org'])
        with self.assertRaises(routing.RoutingError):
            routing.domain_group('example.com', 'not-a-list')

    def test_toggle_preserves_rule_and_only_changes_enabled(self):
        for enabled in (True, False):
            with self.subTest(enabled=enabled), tempfile.TemporaryDirectory() as temp:
                config = Path(temp)/'pbr'
                config.write_text('original')
                rule = {'id': 'youtube', 'enabled': not enabled, 'domains': ['youtube.com']}
                with patch.object(routing, 'POLICY_FILE', config), patch.object(routing, 'BACKUPS', Path(temp)/'backups'), \
                        patch.object(routing, 'policies', return_value=[rule]), patch.object(routing, 'ipsets', return_value={}), \
                        patch.object(routing, 'run', return_value='') as run, patch.object(routing, 'warm_domains') as warm:
                    routing.apply({'action': 'set_enabled', 'id': 'youtube', 'enabled': enabled, 'revision': routing.revision()})
                mutations = [call.args for call in run.call_args_list if call.args[:2] in [('uci','set'),('uci','delete')]]
                self.assertEqual(mutations, [('uci', 'set', f'pbr.youtube.enabled={int(enabled)}')])
                if enabled:
                    warm.assert_called_once_with(['youtube.com'])
                else:
                    warm.assert_not_called()

    def test_domain_edits_keep_cached_addresses_unless_a_name_is_removed(self):
        saved = {'pbr_awg0_4_dst_ip_site': ['1.1.1.1'], 'pbr_wan_4_dst_ip_discord': ['2.2.2.2']}
        for domains, keep in ((['example.com', 'cdn.example.org'], True),
                              (['example.com'], True), (['new.example.org'], False)):
            with self.subTest(domains=domains), tempfile.TemporaryDirectory() as temp:
                config = Path(temp)/'pbr'
                config.write_text('original')
                rule = {'id': 'site', 'enabled': True, 'domains': ['example.com']}
                with patch.object(routing, 'POLICY_FILE', config), patch.object(routing, 'BACKUPS', Path(temp)/'backups'), \
                        patch.object(routing, 'policies', return_value=[rule]), patch.object(routing, 'ipsets', return_value=saved), \
                        patch.object(routing, 'run', return_value=''), patch.object(routing, 'warm_domains'), \
                        patch.object(routing, 'restore_ipsets') as restore:
                    routing.apply({'action': 'update_domains', 'id': 'site', 'domains': domains, 'revision': routing.revision()})
                expected = saved if keep else {'pbr_wan_4_dst_ip_discord': ['2.2.2.2']}
                restore.assert_called_once_with(expected)

    def test_panel_key_has_no_shell_and_payload_uses_stdin(self):
        config = {'enabled': True, 'routing_enabled': True, 'host': '192.168.10.1',
                  'routing_identity_file': '/routing-key', 'known_hosts_file': '/hosts'}
        payload = {'action': 'add', 'domain': 'a.com;reboot', 'revision': 'r'}
        with patch('openwrt.subprocess.run', return_value=MagicMock(stdout='{"rules":[],"revision":"r"}')) as run:
            openwrt.routing_request(config, payload)
        args = run.call_args.args[0]
        self.assertEqual(args[-1], 'nerv-awg')
        self.assertIn('StrictHostKeyChecking=yes', args)
        self.assertNotIn(payload['domain'], args)
        self.assertEqual(json.loads(run.call_args.kwargs['input']), payload)

    def test_transport_errors_do_not_expose_secrets(self):
        config = {'enabled': True, 'routing_enabled': True, 'host': '192.168.10.1',
                  'routing_identity_file': '/key', 'known_hosts_file': '/hosts'}
        with patch('openwrt.subprocess.run', side_effect=OSError('SECRET')):
            with self.assertRaises(openwrt.RoutingError) as error:
                openwrt.routing_request(config, {'action': 'list'})
        self.assertNotIn('SECRET', str(error.exception))
