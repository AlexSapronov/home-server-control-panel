"""NERV server dashboard. Python 3.11+, standard library only."""
import argparse
import base64
import hmac
import json
import os
import re
import ssl
import time
from concurrent.futures import ThreadPoolExecutor
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from openwrt import router_snapshot, demo_router
from urllib.error import HTTPError, URLError
from urllib.parse import quote, unquote, urlsplit
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parent


def load_config():
    path = Path(os.environ.get('NERV_CONFIG', ROOT / 'config.json'))
    config = json.loads(path.read_text()) if path.exists() else {'mode': 'demo'}
    if config.get('mode', 'demo') not in ('demo', 'live'):
        raise ValueError('mode must be demo or live')
    vmids = config.get('proxmox', {}).get('managed_vmids', [])
    if not isinstance(vmids, list) or any(type(vmid) is not int or not 100 <= vmid <= 999999999 for vmid in vmids):
        raise ValueError('managed_vmids must be a list of valid Proxmox IDs')
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
        return self.request(path)

    def request(self, path, method='GET'):
        req = Request(self.url + '/api2/json' + path,
                      headers={'Authorization': 'PVEAPIToken=' + self.token},
                      method=method, data=b'' if method == 'POST' else None)
        with urlopen(req, context=self.context, timeout=5) as response:
            return json.load(response)['data']

    def power(self, vmid, action):
        guests = self.get('/cluster/resources?type=vm')
        guest = next((g for g in guests if g.get('vmid') == vmid
                      and g.get('type') in ('qemu', 'lxc')), None)
        if guest is None:
            raise LookupError
        expected = 'stopped' if action == 'start' else 'running'
        if guest.get('status') != expected or guest.get('template') or guest.get('lock'):
            raise RuntimeError
        node = guest['node']
        path = f"/nodes/{quote(node, safe='')}/{guest['type']}/{vmid}/status/{action}"
        return {'upid': self.request(path, 'POST')}

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


def managed_guests(config):
    if config.get('mode') != 'live' or not os.environ.get('NERV_PASSWORD'):
        return []
    return config['proxmox'].get('managed_vmids', [])


def snapshot(config):
    data = demo_snapshot() if config.get('mode', 'demo') == 'demo' else Proxmox(config['proxmox']).snapshot()
    return dict(data, mode=config.get('mode', 'demo'), updated_at=int(time.time()),
                managed_vmids=managed_guests(config), services=config.get('services', []), title=config.get('title', 'HOME SERVER'),
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
        if password:
            expected = 'Basic ' + base64.b64encode(('admin:' + password).encode()).decode()
            if not hmac.compare_digest(self.headers.get('Authorization', ''), expected):
                self.send_response(401)
                self.send_header('WWW-Authenticate', 'Basic realm="NERV"')
                self.end_headers()
                return False
        return True

    def send_json(self, code, data):
        body = json.dumps(data, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if not self.authorized():
            return
        match = re.fullmatch(r'/api/guests/([1-9][0-9]{2,8})/(start|shutdown|reboot)', self.path)
        if not match:
            return self.send_json(404, {'error': 'Неизвестная операция.'})
        vmid, action = match.groups()
        config = self.server.config
        # A browser cannot attach this header cross-origin without a CORS preflight.
        if (int(vmid) not in managed_guests(config)
                or self.headers.get('X-NERV-Action') != 'guest-power'
                or self.headers.get('Sec-Fetch-Site', 'same-origin') != 'same-origin'):
            return self.send_json(403, {'error': 'Управление этой машиной недоступно.'})
        try:
            task = Proxmox(config['proxmox']).power(int(vmid), action)
        except LookupError:
            return self.send_json(404, {'error': 'Машина недоступна в Proxmox.'})
        except RuntimeError:
            return self.send_json(409, {'error': 'Текущее состояние машины не допускает эту операцию.'})
        except HTTPError as error:
            if error.code in (401, 403):
                return self.send_json(403, {'error': 'Проверьте право VM.PowerMgmt для API-токена.'})
            return self.send_json(502, {'error': 'Proxmox отклонил команду. Проверьте журнал задач.'})
        except (OSError, ValueError):
            return self.send_json(502, {'error': 'Ответ Proxmox не получен. Проверьте статус и журнал перед повтором.'})
        self.send_json(202, task)

    def do_GET(self):
        if not self.authorized():
            return
        if self.path == '/api/status':
            try:
                data, code = snapshot(self.server.config), 200
            except (KeyError, ValueError, ConnectionError, OSError):
                data, code = {'error': 'Нет данных Proxmox. Проверьте конфигурацию, TLS-сертификат и API-токен.'}, 502
            self.send_json(code, data)
        elif match := re.fullmatch(r'/api/power-tasks/(UPID:([a-zA-Z0-9_-]+):[a-zA-Z0-9_.:@!+-]{1,512})', unquote(self.path)):
            if not managed_guests(self.server.config):
                return self.send_json(403, {'error': 'Управление машинами недоступно.'})
            upid, node = match.groups()
            try:
                task = Proxmox(self.server.config['proxmox']).get(
                    f"/nodes/{node}/tasks/{quote(upid, safe='')}/status")
                self.send_json(200, {'status': task.get('status'), 'exitstatus': task.get('exitstatus')})
            except (OSError, ValueError):
                self.send_json(502, {'error': 'Не удалось получить результат задачи Proxmox.'})
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
