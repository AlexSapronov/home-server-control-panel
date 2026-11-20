import base64
import json
import os
import threading
import unittest
from http.server import ThreadingHTTPServer
from unittest.mock import Mock, patch
from server import Handler, Proxmox, snapshot

class SnapshotTests(unittest.TestCase):
    def test_partial_failure(self):
        client = object.__new__(Proxmox)
        def get(path):
            if path == '/cluster/resources':
                return [{'type': 'node', 'node': 'home'}, {'type': 'qemu', 'vmid': 100}]
            raise TimeoutError()
        client.get = get
        data = client.snapshot()
        self.assertEqual(data['guests'][0]['vmid'], 100)
        self.assertEqual(len(data['warnings']), 1)
        self.assertEqual(data['tasks'], [])

    def test_api_failure_not_empty_healthy_dashboard(self):
        client = object.__new__(Proxmox)
        client.get = lambda _: (_ for _ in ()).throw(TimeoutError())
        with self.assertRaises(ConnectionError):
            client.snapshot()

    def test_power_uses_inventory_node_and_graceful_shutdown_for_both_types(self):
        for kind in ('qemu', 'lxc'):
            with self.subTest(kind=kind):
                client = object.__new__(Proxmox)
                guest = {'type': kind, 'vmid': 103, 'node': 'home', 'status': 'running'}
                client.get = Mock(return_value=[guest])
                client.request = Mock(return_value='UPID:home:task')
                self.assertEqual(client.power(103, 'shutdown'), {'upid': 'UPID:home:task'})
                client.request.assert_called_once_with(f'/nodes/home/{kind}/103/status/shutdown', 'POST')
                with self.assertRaises(RuntimeError):
                    client.power(103, 'start')
                client.request.assert_called_once()

    def test_explicit_demo_without_secret(self):
        with patch.dict(os.environ, {'PROXMOX_TOKEN': 'secret-token'}):
            data = snapshot({'mode': 'demo'})
        self.assertEqual(data['mode'], 'demo')
        self.assertNotIn('secret-token', json.dumps(data))

class HTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        cls.server.config = {'mode': 'demo'}
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def request(self, path, headers=None, method='GET', body=None):
        import http.client
        conn = http.client.HTTPConnection('127.0.0.1', self.server.server_port)
        conn.request(method, path, body=body, headers=headers or {})
        response = conn.getresponse()
        result = response.status, response.read()
        conn.close()
        return result

    def test_password_protects_ui_and_api(self):
        with patch.dict(os.environ, {'NERV_PASSWORD': 'test-password'}):
            for path in ['/', '/app.js', '/api/status']:
                self.assertEqual(self.request(path)[0], 401)
            auth = base64.b64encode(b'admin:test-password').decode()
            status, body = self.request('/api/status', {'Authorization': 'Basic '+auth})
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(body)['mode'], 'demo')

    def test_power_requires_authentication_same_origin_and_allowlist(self):
        config = {'mode': 'live', 'proxmox': {'managed_vmids': [103]}}
        auth = base64.b64encode(b'admin:test-password').decode()
        headers = {'Authorization': 'Basic ' + auth, 'X-NERV-Action': 'guest-power'}
        path = '/api/guests/103/reboot'
        upid = 'UPID:home:00000000:00000000:00000000:qmreboot:103:nerv@pve!panel:'
        with patch.dict(os.environ, {'NERV_PASSWORD': 'test-password'}), \
                patch.object(self.server, 'config', config), patch('server.Proxmox') as client:
            client.return_value.power.return_value = {'upid': upid}
            self.assertEqual(self.request(path, method='POST')[0], 401)
            self.assertEqual(self.request(path, {'Authorization': headers['Authorization']}, 'POST')[0], 403)
            self.assertEqual(self.request(path, dict(headers, **{'Sec-Fetch-Site': 'cross-site'}), 'POST')[0], 403)
            self.assertEqual(self.request('/api/guests/100/reboot', headers, 'POST')[0], 403)
            client.assert_not_called()
            status, body = self.request(path, headers, 'POST')
            self.assertEqual(status, 202)
            self.assertEqual(json.loads(body)['upid'], upid)
            client.return_value.power.assert_called_once_with(103, 'reboot')
            from urllib.parse import quote
            client.return_value.get.return_value = {'status': 'stopped', 'exitstatus': 'OK'}
            status, body = self.request('/api/power-tasks/' + quote(upid, safe=''), headers)
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(body), {'status': 'stopped', 'exitstatus': 'OK'})
            client.return_value.get.assert_called_once_with('/nodes/home/tasks/' + quote(upid, safe='') + '/status')

    def test_no_configuration_or_traversal(self):
        for path in ['/config.json', '/server.py', '/../config.example.json']:
            self.assertEqual(self.request(path)[0], 404)

    def test_awg_requires_password_live_config_and_same_origin(self):
        config = {'mode': 'live', 'openwrt': {'routing_enabled': True}}
        auth = base64.b64encode(b'admin:test-password').decode()
        headers = {'Authorization': 'Basic ' + auth, 'X-NERV-Action': 'awg-routing',
                   'Content-Type': 'application/json'}
        path = '/api/router/awg-sites'
        body = json.dumps({'action': 'add', 'domain': 'example.com', 'revision': 'r'})
        with patch.object(self.server, 'config', config), patch('server.routing_request') as routing:
            with patch.dict(os.environ, {'NERV_PASSWORD': ''}):
                self.assertEqual(self.request(path)[0], 403)
                self.assertEqual(self.request(path, headers, 'POST', body)[0], 403)
            with patch.dict(os.environ, {'NERV_PASSWORD': 'test-password'}):
                self.assertEqual(self.request(path)[0], 401)
                self.assertEqual(self.request(path, {'Authorization': headers['Authorization']}, 'POST', body)[0], 403)
                self.assertEqual(self.request(path, dict(headers, **{'Sec-Fetch-Site': 'cross-site'}), 'POST', body)[0], 403)
                self.assertEqual(self.request(path, headers, 'POST', 'not-json')[0], 400)
                routing.assert_not_called()
                routing.return_value = {'rules': [], 'revision': 'new'}
                self.assertEqual(self.request(path, headers, 'POST', body)[0], 200)
                routing.assert_called_once_with(config['openwrt'], json.loads(body))
                self.assertEqual(self.request(path, headers)[0], 200)
            with patch.object(self.server, 'config', dict(config, mode='demo')):
                self.assertEqual(self.request(path)[0], 403)

    def test_sanitized_errors(self):
        with patch('server.snapshot', side_effect=ValueError('secret-value')):
            status, body = self.request('/api/status')
        self.assertEqual(status, 502)
        self.assertNotIn(b'secret-value', body)

    def test_site_diagnostics_auth_same_origin_and_fixed_action(self):
        config = {'mode':'live', 'openwrt':{'routing_enabled':True}}
        auth = base64.b64encode(b'admin:test-password').decode()
        headers = {'Authorization':'Basic '+auth, 'Content-Type':'application/json', 'X-NERV-Action':'site-diagnostics'}
        path = '/api/router/diagnose'
        body = json.dumps({'target':'rutracker.org', 'action':'set_enabled', 'enabled':False})
        with patch.dict(os.environ, {'NERV_PASSWORD':'test-password'}), patch.object(self.server, 'config', config), \
                patch('server.routing_request', return_value={'read_only':True,'dns':{}}) as request:
            self.assertEqual(self.request(path, method='POST', body=body)[0], 401)
            self.assertEqual(self.request(path, dict(headers, **{'Sec-Fetch-Site':'cross-site'}), 'POST', body)[0], 403)
            self.assertEqual(self.request(path, headers, 'POST', 'not-json')[0], 400)
            request.assert_not_called()
            self.assertEqual(self.request(path, headers, 'POST', body)[0], 200)
            request.assert_called_once_with(config['openwrt'], {'action':'diagnose', 'target':'rutracker.org'})

if __name__ == '__main__':
    unittest.main()
