"""HTTPS client and subprocess lifecycle shared by the DPI agents."""
import json
import os
from pathlib import Path
import signal
import ssl
import subprocess
import time
from urllib.parse import urlsplit
from urllib.request import HTTPSHandler, HTTPRedirectHandler, ProxyHandler, Request, build_opener

from dpi_policy import DPIError


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


class Panel:
    def __init__(self, config, role):
        self.url = config['panel_url'].rstrip('/')
        parsed = urlsplit(self.url)
        if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.query or parsed.fragment:
            raise DPIError('panel_url requires HTTPS without authentication in the URL')
        self.role = role
        self.token = (Path(config['token_file']).read_text().strip() if config.get('token_file')
                      else os.environ.get('NERV_DPI_TOKEN', ''))
        if len(self.token) < 32:
            raise DPIError('NERV_DPI_TOKEN must contain at least 32 characters')
        tls = ssl.create_default_context(cafile=config.get('ca_file'))
        self.opener = build_opener(ProxyHandler({}), HTTPSHandler(context=tls), NoRedirect())

    def post(self, action, data=None):
        req = Request(f'{self.url}/api/dpi/{self.role}/{action}',
                      data=json.dumps(data or {}, allow_nan=False).encode(),
                      headers={'Authorization': 'Bearer ' + self.token, 'Content-Type': 'application/json'})
        with self.opener.open(req, timeout=8) as response:
            return json.loads(response.read(4 * 1024 * 1024))


class Cancelled(Exception):
    pass


class Runner:
    def __init__(self, namespace=None, pulse=lambda: None):
        self.prefix = ['ip', 'netns', 'exec', namespace] if namespace else []
        self.pulse = pulse

    def open(self, args, **kwargs):
        return subprocess.Popen(self.prefix + args, stdin=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                start_new_session=True, **kwargs)

    @staticmethod
    def stop(proc):
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            return
        try:
            proc.wait(timeout=1)
        except subprocess.TimeoutExpired:
            pass
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait(timeout=2)

    def run(self, args, *, timeout, env=None):
        end = time.monotonic() + timeout
        with self.open(args, stdout=subprocess.PIPE, env=env) as proc:
            try:
                while True:
                    self.pulse()
                    remaining = end - time.monotonic()
                    if remaining <= 0:
                        raise subprocess.TimeoutExpired(args[0], timeout)
                    try:
                        output, _ = proc.communicate(timeout=min(1, remaining))
                    except subprocess.TimeoutExpired:
                        continue
                    return proc.returncode, output
            finally:
                self.stop(proc)


def binary_version(binary, runner):
    code, content = runner.run([binary, '--version'], timeout=5)
    lines = content.decode(errors='replace').splitlines()
    if code or not lines or not lines[0].strip():
        raise DPIError('Cannot read nfqws version')
    return lines[0].strip()
