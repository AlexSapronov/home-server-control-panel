"""NERV server dashboard. Python 3.11+, standard library only."""
import argparse
import base64
import hmac
import json
import os
import ssl
import time
import threading
from concurrent.futures import ThreadPoolExecutor
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from dpi_policy import DPIError
from dpi_store import DPIStore
from openwrt import router_snapshot, demo_router
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
                services=config.get('services', []), title=config.get('title', 'HOME SERVER'),
                router=demo_router() if config.get('mode', 'demo') == 'demo'
                else router_snapshot(config.get('openwrt', {})))


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT / 'static'), **kwargs)

    def end_headers(self):
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Content-Security-Policy', "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
        super().end_headers()

    def authorized(self):
        password = os.environ.get('NERV_PASSWORD')
        expected = 'Basic ' + base64.b64encode(('admin:' + (password or '')).encode()).decode()
        if not password or self.has_token(expected):
            return True
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm="NERV"')
        self.end_headers()
        return False

    def has_token(self, expected):
        return hmac.compare_digest(self.headers.get('Authorization', '').encode(), expected.encode())

    def respond(self, code, data):
        body = json.dumps(data, ensure_ascii=False, allow_nan=False).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if not self.authorized():
            return
        store = getattr(self.server, 'dpi', None)
        if self.path == '/api/dpi':
            self.respond(200, store.status() if store else {'enabled': False})
        elif self.path == '/api/status':
            try:
                data, code = snapshot(self.server.config), 200
            except (KeyError, ValueError, ConnectionError, OSError):
                data, code = {'error': 'Нет данных Proxmox. Проверьте конфигурацию, TLS-сертификат и API-токен.'}, 502
            self.respond(code, data)
        elif urlsplit(self.path).path in ('/', '/index.html', '/app.js', '/style.css', '/dpi.js'):
            super().do_GET()
        else:
            self.send_error(404)

    def do_POST(self):
        store = getattr(self.server, 'dpi', None)
        path = self.path.split('/')
        if not store or len(path) != 5 or path[1:3] != ['api', 'dpi']:
            self.respond(404, {'error': 'Операция недоступна.'})
            return
        role, action = path[3:]
        handlers = {'worker': {'claim': lambda _: store.claim(), 'report': store.report,
                               'heartbeat': lambda body: store.worker_heartbeat(body['id'])},
                    'router': {'sync': store.router}, 'lan': {'probe': store.lan}}
        if role == 'admin':
            if not self.authorized():
                return
            if self.headers.get('X-NERV-Request') != 'dpi':
                self.respond(403, {'error': 'Требуется запрос из панели.'})
                return
            handle = lambda body: store.admin(action, body)
        else:
            handle = handlers.get(role, {}).get(action)
            token = getattr(self.server, 'dpi_tokens', {}).get(role)
            if not handle or not token or not self.has_token('Bearer ' + token):
                self.respond(403, {'error': 'Нет доступа.'})
                return
        try:
            length = int(self.headers.get('Content-Length', '0'))
            if not 1 <= length <= 2 * 1024 * 1024 or self.headers.get_content_type() != 'application/json':
                raise DPIError('Требуется JSON допустимого размера.')
            self.connection.settimeout(10)
            body = json.loads(self.rfile.read(length))
            if not isinstance(body, dict):
                raise DPIError('Ожидается объект JSON.')
            result = handle(body)
        except DPIError as exc:
            self.respond(409, {'error': str(exc)})
        except (ValueError, TypeError, KeyError, AttributeError, OSError):
            self.respond(400, {'error': 'Некорректный запрос DPI.'})
        else:
            self.respond(200, result)

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
    dpi_config = server.config.get('dpi', {})
    if dpi_config.get('enabled'):
        tokens = {role: os.environ.get('NERV_DPI_' + role.upper() + '_TOKEN', '')
                  for role in ('worker', 'router', 'lan')}
        if (not os.environ.get('NERV_PASSWORD') or len(set(tokens.values())) != len(tokens) or
                any(len(token) < 32 for token in tokens.values())):
            raise SystemExit('DPI requires NERV_PASSWORD and three distinct machine tokens of at least 32 characters')
        server.dpi = DPIStore(dpi_config.get('db', '/var/lib/nerv-panel/dpi.sqlite3'), dpi_config)
        server.dpi_tokens = tokens

        def schedule():
            while True:
                try:
                    server.dpi.tick()
                except Exception:
                    print('NERV DPI: scheduler could not update the queue', flush=True)
                time.sleep(15)

        threading.Thread(target=schedule, daemon=True).start()
    print(f'NERV / {server.config.get("mode", "demo")} / http://{args.host}:{args.port}', flush=True)
    server.serve_forever()


if __name__ == '__main__':
    main()
