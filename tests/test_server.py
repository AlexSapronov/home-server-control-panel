import base64
import json
import os
import threading
import unittest
from http.server import ThreadingHTTPServer
from unittest.mock import patch
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

    def request(self, path, headers=None):
        import http.client
        conn = http.client.HTTPConnection('127.0.0.1', self.server.server_port)
        conn.request('GET', path, headers=headers or {})
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

    def test_no_configuration_or_traversal(self):
        for path in ['/config.json', '/server.py', '/../config.example.json']:
            self.assertEqual(self.request(path)[0], 404)

    def test_sanitized_errors(self):
        with patch('server.snapshot', side_effect=ValueError('secret-value')):
            status, body = self.request('/api/status')
        self.assertEqual(status, 502)
        self.assertNotIn(b'secret-value', body)

if __name__ == '__main__':
    unittest.main()
