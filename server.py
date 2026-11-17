"""NERV server dashboard. Python 3.11+, standard library only."""
import argparse
import base64
import hmac
import json
import os
import ssl
import time
from concurrent.futures import ThreadPoolExecutor
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parent


def load_config():
    path = Path(os.environ.get('NERV_CONFIG', ROOT / 'config.json'))
    config = json.loads(path.read_text()) if path.exists() else {'mode': 'demo'}
    if config.get('mode', 'demo') not in ('demo', 'live'):
        raise ValueError('mode must be demo or live')
    for service in config.get('services', []):
        if urlsplit(service['url']).scheme not in ('http', 'https'):
            raise ValueError('Service URLs must use HTTP or HTTPS')
    return config


class Proxmox:
    def __init__(self, config):
        self.url = config['url'].rstrip('/')
        if urlsplit(self.url).scheme != 'https':
            raise ValueError('Proxmox API requires HTTPS')
        self.context = ssl.create_default_context(cafile=config.get('ca_file'))
        self.token = os.environ.get('PROXMOX_TOKEN', '')
        if not self.token:
            raise ValueError('PROXMOX_TOKEN is not configured')

    def get(self, path):
        req = Request(self.url + '/api2/json' + path,
                      headers={'Authorization': 'PVEAPIToken=' + self.token})
        with urlopen(req, context=self.context, timeout=5) as response:
            return json.load(response)['data']

    def snapshot(self):
        errors = []
        def read(path):
            try:
                return self.get(path)
            except (HTTPError, URLError, TimeoutError, ValueError, OSError):
                errors.append('Недоступен API: ' + path)
                return None
        resources = read('/cluster/resources')
        if resources is None:
            raise ConnectionError('Proxmox недоступен. Проверьте адрес, сертификат и права API-токена.')
        nodes = [r for r in resources if r['type'] == 'node']
        tasks = []
        with ThreadPoolExecutor(max_workers=4) as pool:
            paths = ['/nodes/' + quote(n['node'], safe='') + '/tasks?limit=20' for n in nodes]
            for result in pool.map(read, paths):
                tasks.extend(result or [])
        return {'nodes': nodes, 'guests': [r for r in resources if r['type'] in ('qemu', 'lxc')],
                'storage': [r for r in resources if r['type'] == 'storage'],
                'tasks': sorted(tasks, key=lambda t: t.get('starttime', 0), reverse=True)[:20], 'warnings': errors}


def demo_snapshot():
    gib = 1024 ** 3
    return {
        'nodes': [{'node': 'homeserver', 'status': 'online', 'cpu': .12, 'maxcpu': 16,
                   'mem': 6.4*gib, 'maxmem': 32*gib, 'uptime': 172440}],
        'guests': [{'vmid': 100, 'name': 'OpenWrt-Router', 'type': 'qemu', 'node': 'homeserver',
                    'status': 'running', 'cpu': .035, 'mem': .38*gib, 'maxmem': 2*gib},
                   {'vmid': 101, 'name': 'Media · пример', 'type': 'lxc', 'node': 'homeserver',
                    'status': 'stopped', 'cpu': 0, 'mem': 0, 'maxmem': 4*gib}],
        'storage': [{'storage': 'local-lvm', 'node': 'homeserver', 'status': 'available', 'disk': 24*gib, 'maxdisk': 80*gib},
                    {'storage': 'backup-hdd', 'node': 'homeserver', 'status': 'available', 'disk': 340*gib, 'maxdisk': 7.28*1024*gib}],
        'tasks': [{'type': 'vzdump', 'id': '100', 'status': 'OK', 'starttime': int(time.time())-3600, 'endtime': int(time.time())-3500},
                  {'type': 'qmstart', 'id': '100', 'status': 'OK', 'starttime': int(time.time())-86400, 'endtime': int(time.time())-86399}],
        'warnings': []}


def snapshot(config):
    data = demo_snapshot() if config.get('mode', 'demo') == 'demo' else Proxmox(config['proxmox']).snapshot()
    return dict(data, mode=config.get('mode', 'demo'), updated_at=int(time.time()),
                services=config.get('services', []), title=config.get('title', 'HOME SERVER'))


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT / 'static'), **kwargs)

    def end_headers(self):
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Content-Security-Policy', "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
        super().end_headers()

    def do_GET(self):
        password = os.environ.get('NERV_PASSWORD')
        if password:
            expected = 'Basic ' + base64.b64encode(('admin:' + password).encode()).decode()
            if not hmac.compare_digest(self.headers.get('Authorization', ''), expected):
                self.send_response(401)
                self.send_header('WWW-Authenticate', 'Basic realm="NERV"')
                self.end_headers()
                return
        if self.path == '/api/status':
            try:
                data, code = snapshot(self.server.config), 200
            except (KeyError, ValueError, ConnectionError, OSError):
                data, code = {'error': 'Нет данных Proxmox. Проверьте конфигурацию, TLS-сертификат и API-токен.'}, 502
            body = json.dumps(data, ensure_ascii=False).encode()
            self.send_response(code)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif urlsplit(self.path).path in ('/', '/index.html', '/app.js', '/style.css'):
            super().do_GET()
        else:
            self.send_error(404)

    def do_HEAD(self):
        self.send_error(405)

    def log_message(self, fmt, *args):
        # Never log Authorization headers or configuration.
        super().log_message(fmt, *args)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=8080)
    args = parser.parse_args()
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    server.config = load_config()
    print(f'NERV / {server.config.get("mode", "demo")} / http://{args.host}:{args.port}', flush=True)
    server.serve_forever()


if __name__ == '__main__':
    main()
