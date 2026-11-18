"""OpenWrt receiver with local recovery, independent of the panel connection."""
import argparse
import base64
import fcntl
import hashlib
import json
import logging
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import time

from dpi_agent import Panel, Runner, binary_version
from dpi_policy import DPIError, digest, domain, profile_key, rule, within


LOG = logging.getLogger('nerv-dpi-router')
BLOCK = re.compile(r'^NFQWS_OPT="([^"]*)"[ \t]*$', re.M)
HOSTLIST = '--hostlist='


def sha(data):
    return hashlib.sha256(data).hexdigest()


def regular(path):
    if not stat.S_ISREG(path.lstat().st_mode):
        raise DPIError('Expected a regular file: ' + path.name)


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def replace(path, content, mode=0o600):
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name + '.', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        sync_dir(path.parent)
    finally:
        Path(temporary).unlink(missing_ok=True)


def remove(path):
    path.unlink(missing_ok=True)
    sync_dir(path.parent)


def record(path):
    if not path.exists() and not path.is_symlink():
        return None
    regular(path)
    return {'mode': stat.S_IMODE(path.stat().st_mode), 'data': base64.b64encode(path.read_bytes()).decode()}


def restore(files):
    for name, entry in reversed(list(files.items())):
        path = Path(name)
        if entry is None:
            remove(path)
        else:
            replace(path, base64.b64decode(entry['data']), entry['mode'])


class Zapret:
    def __init__(self, config, runner):
        self.runner = runner
        self.root = Path(config.get('zapret_root', '/opt/zapret')).resolve()
        self.config = self.root / 'config'
        self.hosts = self.root / 'ipset'
        self.binary = str(self.root / 'nfq/nfqws')
        self.service = Path(config.get('zapret_init', '/etc/init.d/zapret'))
        self.release = Path(config.get('openwrt_release', '/etc/openwrt_release'))
        self.managed = {profile_key(key): self.hosts / name for key, name in config['hostlists'].items()}
        if (len(set(self.managed.values())) != len(self.managed) or
                any(path.parent != self.hosts or not path.name.endswith('.txt') for path in self.managed.values())):
            raise DPIError('Hostlists must be distinct .txt files under zapret ipset')

    def value(self, text, name, default=None):
        options = re.findall(r'^' + name + r'=(.+?)[ \t]*$', text, re.M)
        if len(options) > 1:
            raise DPIError('Ambiguous zapret setting: ' + name)
        return options[0].strip('"\'') if options else default

    def new_hostlist(self, key):
        return self.hosts / f'nerv-dpi-{digest(key)[:24]}.txt'

    def read(self):
        regular(self.config)
        text = self.config.read_text()
        if (self.value(text, 'NFQWS_ENABLE') != '1' or self.value(text, 'DISABLE_IPV4', '0') != '0' or
                self.value(text, 'MODE_FILTER', 'none') != 'none' or
                self.value(text, 'TPWS_ENABLE', '0') != '0' or self.value(text, 'TPWS_SOCKS_ENABLE', '0') != '0'):
            raise DPIError('Unsupported active zapret configuration')
        matches = list(BLOCK.finditer(text))
        if len(matches) != 1:
            raise DPIError('Expected a single quoted NFQWS_OPT assignment')
        block = matches[0]
        content = block[1]
        if not re.fullmatch(r'[a-zA-Z0-9_./=,+: \t\r\n-]*', content):
            raise DPIError('Unexpected shell syntax in NFQWS_OPT')
        groups = [group.strip() for group in re.split(r'(?:^|\s+)--new(?=\s|$)', content)]
        if any(not group for group in groups):
            raise DPIError('Empty or ambiguous nfqws rule')
        maps = {path: key for key, path in self.managed.items()}
        entries, file_hashes = {}, {}
        disabled6 = self.value(text, 'DISABLE_IPV6', '0') == '1'
        for group in groups:
            tokens = group.split()
            host_paths = [self.hosts / Path(token.removeprefix(HOSTLIST)).name
                          for token in tokens if token.startswith(HOSTLIST)]
            if len(host_paths) != 1:
                raise DPIError('Each managed nfqws rule requires exactly one hostlist')
            path = host_paths[0]
            if HOSTLIST + str(path) not in tokens:
                raise DPIError('Expected an absolute hostlist under zapret ipset')
            regular(path)
            lists = path.read_bytes()
            hosts = [domain(line.strip()) for line in lists.decode().splitlines()
                     if line.strip() and not line.lstrip().startswith('#')]
            if not hosts:
                raise DPIError('Empty nfqws hostlist')
            key = maps.get(path)
            if key is None and self.new_hostlist(hosts[0]) == path:
                key = hosts[0]
            if not key or key in entries:
                raise DPIError('Unmanaged or repeated nfqws rule')
            filters = [token for token in tokens if token.startswith('--filter-')]
            if (filters.count('--filter-tcp=443') != 1 or
                    set(filters) - {'--filter-tcp=443', '--filter-l3=ipv4'} or
                    ('--filter-l3=ipv4' not in filters and not disabled6)):
                raise DPIError('Only effective IPv4 TCP/443 rules can be managed')
            args = [token for token in tokens if token not in filters and not token.startswith(HOSTLIST)]
            entries[key] = {'rule': rule({'domains': hosts, 'args': args}), 'path': path, 'line': group}
            file_hashes[str(path)] = sha(lists)
        if self.managed.keys() - entries.keys():
            raise DPIError('An imported profile hostlist is missing from NFQWS_OPT')
        raw_out = self.value(text, 'NFQWS_TCP_PKT_OUT')
        raw_in = self.value(text, 'NFQWS_TCP_PKT_IN')
        if raw_out == '$((6+$AUTOHOSTLIST_RETRANS_THRESHOLD))':
            raw_out = str(6 + int(self.value(text, 'AUTOHOSTLIST_RETRANS_THRESHOLD', '3')))
        packets = {'out': int(raw_out), 'in': int(raw_in)}
        release = self.value(self.release.read_text(), 'DISTRIB_RELEASE')
        if not release or not 1 <= packets['out'] <= 64 or not 0 <= packets['in'] <= 64:
            raise DPIError('Cannot determine packet limits or OpenWrt release')
        ver = binary_version(self.binary, self.runner)
        snapshot = {'zapret': ver, 'openwrt': release, 'packets': packets,
                    'profiles': {key: value['rule'] for key, value in entries.items()}}
        snapshot['base'] = digest({'config': sha(text.encode()), 'hostlists': file_hashes, 'snapshot': snapshot,
                                   'binary': sha(Path(self.binary).read_bytes()),
                                   'init': sha(self.service.read_bytes())})
        return snapshot, text, block, entries

    def validate_and_stage(self, package, loaded):
        snapshot, text, block, entries = loaded
        key = profile_key(package['profile'])
        candidate = rule(package['rule'])
        existing = entries.get(key)
        if candidate['domains'] != (existing['rule']['domains'] if existing else [domain(key)]):
            raise DPIError('Candidate hostlist differs from managed profile')
        if not existing and any(within(key, host) or within(host, key)
                                for entry in entries.values() for host in entry['rule']['domains']):
            raise DPIError('Candidate domains overlap another profile')
        path = existing['path'] if existing else self.new_hostlist(key)
        if not existing and (path.exists() or path.is_symlink()):
            raise DPIError('Unexpected file at the new hostlist path')
        line = ' '.join(['--filter-l3=ipv4', '--filter-tcp=443', HOSTLIST + str(path), *candidate['args']])
        content = block[1]
        position = block.start(1)
        if existing:
            if content.count(existing['line']) != 1:
                raise DPIError('Cannot locate profile in NFQWS_OPT')
            content = content.replace(existing['line'], line, 1)
        else:
            content = content.rstrip() + ' --new\n' + line + '\n'
        changed = text[:position] + content + text[block.end(1):]
        new_hosts = path.read_bytes() if existing else ('\n'.join(candidate['domains']) + '\n').encode()
        with tempfile.TemporaryDirectory() as folder:
            temporary_hosts = Path(folder, 'hosts.txt')
            temporary_hosts.write_bytes(new_hosts)
            temporary_config = Path(folder, 'config')
            temporary_config.write_text(changed)
            if self.runner.run(['sh', '-n', str(temporary_config)], timeout=5)[0]:
                raise DPIError('zapret shell syntax validation failed')
            args = content.replace(HOSTLIST + str(path), HOSTLIST + str(temporary_hosts)).split()
            if self.runner.run([self.binary, '--dry-run', '--qnum=200', *args], timeout=8)[0]:
                raise DPIError('nfqws rejected the combined configuration')
        return path, changed.encode(), new_hosts

    def restart(self):
        if self.runner.run([str(self.service), 'restart'], timeout=20)[0]:
            return False
        for _ in range(5):
            if (self.runner.run([str(self.service), 'status'], timeout=4)[0] == 0 and
                    self.runner.run(['pidof', 'nfqws'], timeout=4)[0] == 0):
                return True
            time.sleep(0.5)
        return False


class Router:
    def __init__(self, config, panel, zapret, clock=time.time, monotonic=time.monotonic):
        self.panel = panel
        self.zapret = zapret
        self.clock = clock
        self.monotonic = monotonic
        state = Path(config.get('state_dir', '/etc/nerv-dpi/state'))
        state.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.state = state
        self.packages = state / 'packages'
        self.packages.mkdir(exist_ok=True, mode=0o700)
        self.previous = state / 'previous.json'
        self.pending = state / 'pending.json'
        self.last = state / 'last.json'
        self.working = None
        self.watchdog = 0

    def read_json(self, path):
        return json.loads(path.read_text()) if path.exists() else None

    def save(self, path, data):
        replace(path, json.dumps(data, separators=(',', ':'), allow_nan=False).encode())

    def finish(self, operation, phase, reason=None):
        result = {'id': operation['id'], 'phase': phase, 'reason': reason}
        self.save(self.last, result)
        remove(self.pending)
        self.working = None
        return result

    def recover(self, reason='timeout'):
        operation = self.working or self.read_json(self.pending)
        if not operation:
            return None
        # A terminal result is durable before its journal is removed.
        last = self.read_json(self.last)
        if last and last['id'] == operation['id']:
            remove(self.pending)
            self.working = None
            return last
        self.working = operation
        restore(operation['files'])
        if operation.get('previous') is not None:
            self.save(self.previous, operation['previous'])
        else:
            remove(self.previous)
        if not self.zapret.restart():
            raise DPIError('Could not restart zapret with the restored configuration')
        return self.finish(operation, 'failed' if operation.get('manual_rollback') else 'rolled_back', reason)

    def valid_package(self, package, snapshot):
        checksum = package['id']
        if not re.fullmatch(r'[0-9a-f]{64}', checksum):
            return False
        profile_key(package['profile'])
        return (checksum == digest({key: value for key, value in package.items() if key != 'id'}) and
                self.clock() < package['expires'] and
                all(package[key] == snapshot[key] for key in ('base', 'openwrt', 'zapret')) and
                rule(package['rule']) == package['rule'])

    def saved_packages(self, snapshot):
        usable = []
        for path in self.packages.glob('*.json'):
            try:
                package = self.read_json(path)
                if package and path.stem == package['id'] and self.valid_package(package, snapshot):
                    usable.append(path.stem)
                    continue
            except (ValueError, KeyError, TypeError, OSError):
                pass
            remove(path)
        return usable

    def begin(self, command, loaded):
        snapshot = loaded[0]
        if command['deadline'] <= self.clock() or command['base'] != snapshot['base']:
            return self.finish(command, 'failed', 'drift')
        if command['action'] == 'rollback':
            previous = self.read_json(self.previous)
            if not previous or previous['after'] != snapshot['base']:
                return self.finish(command, 'failed', 'drift')
            changes = previous['files']
            operation = dict(command, files={name: record(Path(name)) for name in changes},
                             manual_rollback=True, previous=previous)
            self.save(self.pending, operation)
            self.working = operation
            try:
                restore(changes)
                if not self.zapret.restart():
                    return self.recover('service')
                remove(self.previous)
                return self.finish(operation, 'rolled_back')
            except (ValueError, OSError, subprocess.TimeoutExpired):
                return self.recover('service')
        version = command['version']
        if not isinstance(version, str) or not re.fullmatch(r'[0-9a-f]{64}', version):
            return self.finish(command, 'failed', 'syntax')
        package = self.read_json(self.packages / (version + '.json'))
        if not package or not self.valid_package(package, snapshot) or package['profile'] != command['profile']:
            return self.finish(command, 'failed', 'drift')
        try:
            hosts, config, domains = self.zapret.validate_and_stage(package, loaded)
        except (ValueError, OSError, subprocess.TimeoutExpired):
            return self.finish(command, 'failed', 'syntax')
        if self.zapret.read()[0]['base'] != snapshot['base'] or not self.valid_package(package, snapshot):
            return self.finish(command, 'failed', 'drift')
        config_path = self.zapret.config
        files = {str(config_path): record(config_path), str(hosts): record(hosts)}
        operation = dict(command, files=files, previous=self.read_json(self.previous))
        self.save(self.pending, operation)
        self.working = operation
        self.watchdog = self.monotonic() + min(100, max(0, command['deadline'] - self.clock()))
        try:
            replace(hosts, domains, files[str(hosts)]['mode'] if files[str(hosts)] else 0o644)
            replace(config_path, config, files[str(config_path)]['mode'])
            operation['after'] = self.zapret.read()[0]['base']
            self.save(self.pending, operation)
            if not self.zapret.restart():
                return self.recover('service')
        except (ValueError, OSError, subprocess.TimeoutExpired):
            return self.recover('service')
        return None

    def cycle(self):
        if self.working and self.monotonic() >= self.watchdog:
            self.recover()
        loaded = self.zapret.read()
        snapshot = loaded[0]
        if self.working and self.working.get('after') != snapshot['base']:
            self.recover('drift')
            return
        previous = self.read_json(self.previous)
        result = ({'id': self.working['id'], 'phase': 'checking'} if self.working else self.read_json(self.last))
        response = self.panel.post('sync', {'snapshot': snapshot, 'operation': result,
                                            'previous': previous['profile'] if previous and
                                            previous['after'] == snapshot['base'] else None,
                                            'delivered': self.saved_packages(snapshot)})
        if self.working:
            if self.monotonic() >= self.watchdog:
                self.recover()
                return
            decision = response.get('decision')
            if decision and decision['id'] == self.working['id']:
                if decision['ok'] is True:
                    self.save(self.previous, {'files': self.working['files'], 'after': snapshot['base'],
                                              'profile': self.working['profile']})
                    self.finish(self.working, 'applied')
                else:
                    self.recover('probe')
            return
        for package in response['packages']:
            if self.valid_package(package, snapshot):
                self.save(self.packages / (package['id'] + '.json'), package)
        command = response.get('command')
        if command and (not result or result['id'] != command['id']):
            self.begin(command, loaded)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('config', type=Path)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--recover', action='store_true')
    mode.add_argument('--inspect', action='store_true')
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO)
    config = json.loads(args.config.read_text())
    zapret = Zapret(config, Runner())
    if args.inspect:
        print(json.dumps(zapret.read()[0], ensure_ascii=False, indent=2))
        return
    router = Router(config, None if args.recover else Panel(config, 'router'), zapret)
    with (router.state / 'lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        router.recover()
        if args.recover:
            return
        while True:
            try:
                router.cycle()
            except (DPIError, ValueError, TypeError, KeyError, OSError, subprocess.TimeoutExpired):
                LOG.warning('Router synchronization incomplete, retrying')
            time.sleep(4)


if __name__ == '__main__':
    main()
