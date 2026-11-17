import importlib.util
import json
import socket
import struct
import subprocess
import unittest
from unittest.mock import patch, MagicMock
import openwrt
from server import snapshot

spec = importlib.util.spec_from_file_location('collector', 'deploy/openwrt-collector.py')
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)

CONFIG = {'enabled': True, 'host': '192.168.10.1', 'identity_file': '/key', 'known_hosts_file': '/hosts'}

class OpenWrtTests(unittest.TestCase):
    def setUp(self):
        openwrt._CACHE.clear()

    def test_disabled_never_runs_ssh(self):
        with patch('openwrt.subprocess.run') as run:
            self.assertEqual(openwrt.router_snapshot({})['state'], 'not_configured')
            run.assert_not_called()

    def test_allowlist_and_host_verification(self):
        payload = {'schema':1, 'secret':'must-not-leak',
                   'services':{'adguardhome':{'state':'running','command':['secret']}},
                   'wan':{'up':True,'addresses':['192.168.0.145','not-an-ip']},
                   'amneziawg':{'state':'up','handshake_age':10,'privatekey':'secret'}}
        with patch('openwrt.subprocess.run', return_value=MagicMock(stdout=json.dumps(payload))) as run:
            result = openwrt.ssh_snapshot(CONFIG)
        self.assertNotIn('secret', json.dumps(result))
        self.assertEqual(result['wan']['addresses'], ['192.168.0.145'])
        args = run.call_args.args[0]
        self.assertIn('StrictHostKeyChecking=yes', args)
        self.assertIn('PasswordAuthentication=no', args)
        self.assertEqual(args[-1], 'nerv-status')

    def test_cache_and_stale_services_with_fresh_probes(self):
        data = {'services':[], 'wan':{'up':True,'addresses':[]},'amneziawg':{'state':'not_configured'}}
        with patch('openwrt.ssh_snapshot', return_value=data) as ssh, patch('openwrt.dns_probe', return_value='resolved'), patch('openwrt.tcp_probe', return_value='reachable'), patch('openwrt.time.monotonic', return_value=100):
            self.assertEqual(openwrt.router_snapshot(CONFIG)['state'], 'connected')
            openwrt.router_snapshot(CONFIG)
            self.assertEqual(ssh.call_count,1)
        with patch('openwrt.ssh_snapshot', side_effect=subprocess.TimeoutExpired('ssh SECRET',7)), patch('openwrt.dns_probe', return_value='unreachable'), patch('openwrt.tcp_probe', return_value='unreachable'), patch('openwrt.time.monotonic', return_value=120):
            result = openwrt.router_snapshot(CONFIG)
        self.assertTrue(result['stale'])
        self.assertEqual(result['probes']['dns'], 'unreachable')
        self.assertNotIn('SECRET', json.dumps(result))

    def test_initial_failure_not_healthy(self):
        with patch('openwrt.ssh_snapshot', side_effect=OSError()), patch('openwrt.dns_probe', return_value='resolved'), patch('openwrt.tcp_probe', return_value='reachable'):
            result = openwrt.router_snapshot(CONFIG)
        self.assertEqual(result['state'],'unavailable')
        self.assertNotIn('services', result)
        self.assertEqual(result['probes']['dns'],'resolved')

    def test_dns_rejects_unrelated_or_error_response(self):
        sock = MagicMock()
        sock.__enter__.return_value = sock
        with patch('openwrt.secrets.randbits',return_value=42), patch('openwrt.socket.socket',return_value=sock):
            sock.recv.return_value = struct.pack('!6H',42,0x8180,1,1,0,0)
            self.assertEqual(openwrt.dns_probe('192.168.10.1'),'resolved')
            sock.recv.return_value = struct.pack('!6H',43,0x8180,1,1,0,0)
            self.assertEqual(openwrt.dns_probe('192.168.10.1'),'invalid_response')
            sock.recv.return_value = struct.pack('!6H',42,0x8183,1,0,0,0)
            self.assertEqual(openwrt.dns_probe('192.168.10.1'),'resolution_failed')

    def test_missing_openwrt_does_not_break_proxmox(self):
        data={'nodes':[],'guests':[],'storage':[],'tasks':[],'warnings':[]}
        with patch('server.Proxmox') as pve:
            pve.return_value.snapshot.return_value=data
            result=snapshot({'mode':'live','proxmox':{}})
        self.assertEqual(result['router']['state'],'not_configured')

    def test_demo_makes_no_router_connections(self):
        with patch('openwrt.subprocess.run') as run:
            result=snapshot({'mode':'demo','openwrt':CONFIG})
        self.assertEqual(result['router']['state'],'demo')
        run.assert_not_called()

class CollectorTests(unittest.TestCase):
    def test_service_state_excludes_command_secrets(self):
        raw={'tg-ws-proxy':{'instances':{'main':{'running':True,'command':['--secret','SECRET']}}}}
        self.assertEqual(collector.service_state(raw,'tg-ws-proxy'),'running')
        self.assertEqual(collector.service_state(None,'tg-ws-proxy'),'unknown')
        self.assertEqual(collector.service_state({},'tg-ws-proxy'),'stopped')

    def test_unconfigured_vs_configured_down(self):
        with patch.object(collector,'command',return_value=''), patch.object(collector,'ubus',return_value={'interface':[]}):
            self.assertEqual(collector.wireguard_status()['state'],'not_configured')
        with patch.object(collector,'command',return_value=''), patch.object(collector,'ubus',return_value={'interface':[{'proto':'amneziawg'}]}):
            self.assertEqual(collector.wireguard_status()['state'],'configured_down')

    def test_interface_without_handshake_not_reported_connected(self):
        with patch.object(collector,'command',side_effect=['awg0','awg0 PUBLICKEY 0']), patch.object(collector,'ubus',return_value={}):
            data=collector.wireguard_status()
        self.assertEqual(data['state'],'up')
        self.assertIsNone(data['handshake_age'])

    def test_non_procd_zapret_process_fallback(self):
        with patch.object(collector,'ubus',return_value={}), patch.object(collector,'process_names',return_value={'nfqws'}), patch.object(collector,'wireguard_status',return_value={'state':'unknown'}):
            data=collector.collect()
        self.assertEqual(data['services']['zapret']['state'],'running')
        self.assertNotIn('command',json.dumps(data))

class InstallerTests(unittest.TestCase):
    def test_remote_install_preserves_other_keys_and_restricts_monitor_key(self):
        import base64
        import contextlib
        import io
        import tempfile
        from pathlib import Path
        setup_spec=importlib.util.spec_from_file_location('setup_openwrt','deploy/setup-openwrt.py')
        setup=importlib.util.module_from_spec(setup_spec)
        setup_spec.loader.exec_module(setup)
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            folder=root/'dropbear'
            folder.mkdir()
            authorized=folder/'authorized_keys'
            authorized.write_text('ssh-ed25519 OTHERKEY existing-admin\n')
            key='ssh-ed25519 '+base64.b64encode(b'public-test-key').decode()+' nerv-panel-monitor'
            payload=json.dumps({'public_key':key,'collector':'# sanitized collector'})
            source=setup.REMOTE_INSTALL.replace('/usr/libexec/nerv-status.py',str(root/'nerv-status.py')).replace('/etc/dropbear',str(folder))
            for _ in range(2):
                with patch('sys.stdin',io.StringIO(payload)), contextlib.redirect_stdout(io.StringIO()):
                    exec(compile(source,'remote-install','exec'),{})
            lines=authorized.read_text().splitlines()
            self.assertEqual(len(lines),2)
            self.assertEqual(lines[0],'ssh-ed25519 OTHERKEY existing-admin')
            for option in ['command="','no-port-forwarding','no-agent-forwarding','no-X11-forwarding','no-pty']:
                self.assertIn(option,lines[1])
            self.assertEqual(authorized.stat().st_mode&0o777,0o600)
            self.assertNotIn('SSH_ORIGINAL_COMMAND',(root/'nerv-status.py').read_text())
