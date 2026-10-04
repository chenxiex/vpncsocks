#!/usr/bin/env python3
"""Run from the repository: python3 tests/integration.py.

Requires a built localhost/vpncsocks image, rootless Podman, pasta, curl and ssh.
Builds a test-only image and creates disposable containers without real VPN credentials.
"""

import json
import os
import shlex
import shutil
import socket
import struct
import subprocess
import tempfile
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IMAGE = 'localhost/vpncsocks-integration'
TEST_DIRECTORY_ROOT = None
CONFIG_FIELDS = {
    'IPSec gateway': '192.0.2.1', 'IPSec ID': 'fixture-group',
    'IPSec secret': 'fixture-secret', 'Xauth username': 'fixture-user',
    'Xauth password': 'fixture-password', 'Interface MTU': '1412',
    'Enable weak encryption': '0',
}


def configuration(updates=None):
    fields = dict(CONFIG_FIELDS)
    fields.update(updates or {})
    return ''.join(f'{key} {value}\n' for key, value in fields.items())


def guarded_test_path(path):
    resolved = Path(path).resolve()
    root = TEST_DIRECTORY_ROOT
    if (root is None or root.parent != (ROOT / 'tests').resolve()
            or not root.name.startswith('vpncsocks-integration-')
            or not resolved.is_relative_to(root)):
        raise ValueError('Test configuration paths must stay inside the integration temporary directory.')
    return resolved


def configuration_mount(path):
    return str(guarded_test_path(path)) + ':/run/secrets/vpnc.conf:ro'


def write_configuration(directory, updates=None):
    directory = guarded_test_path(directory)
    path = directory / ('fixture-' + uuid.uuid4().hex + '.conf')
    path.write_text(configuration(updates))
    path.chmod(0o600)
    return path


def run(*args, input=None, check=True, timeout=60, environment=None, cwd=None):
    result = subprocess.run(args, input=input, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=timeout, env=environment, cwd=cwd)
    if check and result.returncode:
        raise AssertionError(f'{shlex.join(args)} failed: {result.stderr.decode(errors="replace")}')
    return result


def port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def assert_removed(name):
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        if run('podman', 'container', 'exists', name, check=False).returncode == 1:
            return
        time.sleep(0.1)
    raise AssertionError(f'--rm did not remove attached container {name}')


class AttachedContainer:
    """The same foreground Podman run used directly by SSH ProxyCommand."""

    def __init__(self, directory, *mode_arguments, settings=None, **environment):
        self.name = 'vpncsocks-stdio-test-' + uuid.uuid4().hex[:10]
        self.arguments = ['podman', 'run', '--rm', '-i', '--name', self.name,
                          '--userns=host', '--user', '0', '--device=/dev/net/tun',
                          '--cap-add=NET_ADMIN', '--sysctl=net.ipv4.conf.all.rp_filter=2',
                          '--network=pasta:-I,eth0,--ipv4-only,--mtu,1500', '--http-proxy=false',
                          '-v', configuration_mount(write_configuration(directory, settings))]
        for key, value in environment.items():
            self.arguments.extend(['-e', key + '=' + value])
        self.arguments.extend([IMAGE, 'stdio', *mode_arguments])
        self.process = None

    def exec(self, *args, check=True):
        return run('podman', 'exec', self.name, *args, check=check, timeout=10)

    def start(self):
        self.process = subprocess.Popen(self.arguments, stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return self.process

    def finish(self, timeout=20):
        if self.process.stdin is not None:
            self.process.stdin.close()
            self.process.stdin = None
        output, diagnostics = self.process.communicate(timeout=timeout)
        assert_removed(self.name)
        return self.process.returncode, output, diagnostics

    def close(self):
        run('podman', 'rm', '-f', self.name, check=False, timeout=20)
        if self.process is not None:
            if self.process.poll() is None:
                self.process.terminate()
            try:
                self.process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.communicate(timeout=5)


def await_state(name, predicate, seconds=25):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.2)
    logs = run('podman', 'logs', name, check=False).stdout.decode(errors='replace')
    errors = run('podman', 'logs', name, check=False).stderr.decode(errors='replace')
    raise AssertionError('container did not reach expected state:\n' + logs + errors)


class Container:
    def __init__(self, directory, settings=None, **environment):
        self.name = 'vpncsocks-test-' + uuid.uuid4().hex[:10]
        self.socks, self.http = port(), port()
        arguments = ['podman', 'run', '-d', '--name', self.name, '--userns=host', '--user', '0',
                     '--device=/dev/net/tun', '--cap-add=NET_ADMIN',
                     '--sysctl=net.ipv4.conf.all.rp_filter=2',
                     '--network=pasta:-I,eth0,--ipv4-only,--mtu,1500', '--http-proxy=false',
                     '--health-cmd=vpncsocks-healthcheck', '--health-interval=15s',
                     '--health-timeout=5s', '--health-start-period=60s', '--health-retries=3',
                     '-p', f'127.0.0.1:{self.socks}:1080/tcp',
                     '-p', f'127.0.0.1:{self.http}:8888/tcp',
                     '-v', configuration_mount(write_configuration(directory, settings))]
        for key, value in environment.items():
            arguments.extend(['-e', key + '=' + value])
        try:
            run(*arguments, IMAGE)
        except BaseException:
            self.close()
            raise

    def exec(self, *args, user=None, input=None, check=True):
        arguments = ['podman', 'exec', '-i']
        if user:
            arguments.extend(['--user', user])
        return run(*arguments, self.name, *args, input=input, check=check, timeout=15)

    def ready(self):
        await_state(self.name, lambda: self.exec('vpncsocks-healthcheck', check=False).returncode == 0)

    def rejected_packets(self):
        rules = json.loads(self.exec('nft', '-j', 'list', 'chain', 'inet', 'vpncsocks', 'output').stdout)
        return sum(expression['counter']['packets']
                   for item in rules['nftables'] if 'rule' in item
                   for expression in item['rule']['expr'] if 'counter' in expression)

    def curl(self, url, socks=False, check=True):
        proxy = (f'socks5h://127.0.0.1:{self.socks}' if socks
                 else f'http://127.0.0.1:{self.http}')
        return run('curl', '-ksS', '--max-time', '6', '--noproxy', '', '--proxy', proxy,
                   url, check=check, timeout=10)

    def close(self):
        run('podman', 'rm', '-f', self.name, check=False, timeout=20)


def suite(directory):
    container = Container(directory)
    try:
        container.ready()
        assert json.loads(container.exec('cat', '/run/vpncsocks/private/vpnc-options.json').stdout) == {'weak_encryption': False}
        assert container.exec('/usr/local/lib/vpncsocks/entrypoint.sh', 'unexpected', check=False).returncode == 64
        assert container.exec('/usr/local/lib/vpncsocks/entrypoint.sh', user='vpnproxy', check=False).returncode == 78
        run('podman', 'healthcheck', 'run', container.name)
        configuration = json.loads(run('podman', 'inspect', container.name).stdout)[0]
        assert configuration['State']['Health']['Status'] == 'healthy'
        for bindings in configuration['NetworkSettings']['Ports'].values():
            assert all(binding['HostIp'] == '127.0.0.1' for binding in bindings)
        bootstrap = container.exec('cat', '/run/vpncsocks/private/bootstrap-resolv.conf').stdout
        for url, socks in [('http://internal.test:8080/', True),
                           ('http://internal.test:8080/', False),
                           ('https://internal.test:8443/', False)]:
            assert container.curl(url, socks).stdout == b'fixture-vpn-only\n'
        print('PASS SOCKS5h, HTTP and HTTPS CONNECT through VPN fixture', flush=True)
        with socket.create_connection(('127.0.0.1', container.http), timeout=5) as tunnel:
            tunnel.sendall(b'CONNECT internal.test:2222 HTTP/1.1\r\nHost: internal.test:2222\r\n\r\n')
            response = b''
            while b'SSH-2.0-' not in response:
                part = tunnel.recv(4096)
                assert part
                response += part
            assert b' 200 ' in response.split(b'\r\n', 1)[0]
        print('PASS HTTP CONNECT permits SSH custom port 2222', flush=True)
        assert b'internal.test' in container.exec('cat', '/run/vpncsocks/private/dns-queries').stdout
        payload = bytes(range(256)) * 257
        result = container.exec('proxy-stdio', 'internal.test', '9000',
                                user='vpnproxy', input=payload)
        assert result.stdout == payload[::-1]
        print('PASS stdio binary integrity and stdin EOF half-close', flush=True)
        key = directory / 'client'
        key.write_bytes(container.exec('cat', '/test/client').stdout)
        key.chmod(0o600)
        proxy_command = shlex.join(['podman', 'exec', '-i', '--user', 'vpnproxy',
                                    container.name, 'proxy-stdio', '%h', '%p'])
        result = run('ssh', '-F', '/dev/null', '-i', str(key), '-p', '2222',
                     '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null',
                     '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes', '-o', 'ConnectTimeout=10',
                     '-o', 'ProxyCommand=' + proxy_command,
                     'root@internal.test', 'printf fixture-ssh', timeout=20, check=False)
        assert result.returncode == 0 and result.stdout == b'fixture-ssh', (
            result.stderr.decode(errors='replace') + '\n' +
            container.exec('cat', '/run/vpncsocks/private/vpnc.log').stdout.decode(errors='replace'))
        print('PASS real SSH via stdio on custom port 2222', flush=True)
        underlay = container.exec('sh', '-c', "ip -o -4 addr show eth0 | awk '{split($4,a,\"/\");print a[1]}'").stdout.decode().strip()
        rejected_before = container.rejected_packets()
        forbidden = container.exec('ncat', '-4', '-s', underlay, '--wait', '2',
                                   '198.18.0.2', '8080', user='vpnproxy',
                                   input=b'GET / HTTP/1.0\r\n\r\n', check=False)
        assert forbidden.returncode != 0 and b'fixture-vpn-only' not in forbidden.stdout
        assert container.rejected_packets() > rejected_before
        print('PASS explicitly bound underlay source cannot bypass firewall', flush=True)
        rejected_before = container.rejected_packets()
        labels = b''.join(bytes([len(label)]) + label for label in (b'forbidden', b'test')) + b'\x00'
        query = struct.pack('!HHHHHH', 42, 0x0100, 1, 0, 0, 0) + labels + struct.pack('!HH', 1, 1)
        container.exec('ncat', '-u', '-4', '-s', underlay, '--send-only', '--wait', '2',
                       '198.18.0.2', '53', user='vpnproxy', input=query, check=False)
        assert container.rejected_packets() > rejected_before
        assert b'forbidden.test' not in container.exec('cat', '/run/vpncsocks/private/dns-queries').stdout
        print('PASS DNS datagram bound to underlay source is rejected by firewall', flush=True)
        container.exec('rm', '-f', '/run/vpncsocks/private/echo-open')
        session = subprocess.Popen(['podman', 'exec', '-i', '--user', 'vpnproxy',
                                    container.name, 'proxy-stdio', '198.18.0.2', '9000'],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            session.stdin.write(b'established-session')
            session.stdin.flush()
            await_state(container.name, lambda: container.exec(
                'test', '-f', '/run/vpncsocks/private/echo-open', check=False).returncode == 0)
            assert session.poll() is None
            container.exec('touch', '/run/vpncsocks/private/hold')
            container.exec('sh', '-c', 'kill -TERM "$(cat /run/vpncsocks/vpnc.pid)"')
            session.wait(timeout=8)
            assert session.returncode != 0
        finally:
            if session.poll() is None:
                session.terminate()
                session.wait(timeout=5)
            session.stdin.close()
            session.stdout.close()
            session.stderr.close()
        await_state(container.name, lambda: container.exec('vpncsocks-healthcheck', check=False).returncode != 0)
        assert container.exec('proxy-stdio', '198.18.0.2', '9000', user='vpnproxy', input=b'x', check=False).returncode != 0
        assert container.curl('http://198.18.0.2:8080/', check=False).returncode != 0
        container.exec('rm', '/run/vpncsocks/private/hold')
        container.ready()
        assert container.exec('cat', '/run/vpncsocks/private/bootstrap-resolv.conf').stdout == bootstrap
        assert container.curl('http://internal.test:8080/', socks=True).stdout == b'fixture-vpn-only\n'
        print('PASS VPN disconnect closes established stdio, blocks new connections and reconnects', flush=True)
        run('podman', 'stop', '--time', '5', container.name, timeout=15)
        run('podman', 'start', container.name)
        container.ready()
        assert container.exec('cat', '/run/vpncsocks/private/bootstrap-resolv.conf').stdout == bootstrap
        assert container.curl('http://internal.test:8080/', socks=True).stdout == b'fixture-vpn-only\n'
        print('PASS container stop/start retains bootstrap configuration', flush=True)
    finally:
        container.close()
    container = Container(directory, FIXTURE_DNS='0')
    try:
        container.ready()
        assert container.curl('http://198.18.0.2:8080/', socks=True).stdout == b'fixture-vpn-only\n'
        assert container.curl('http://internal.test:8080/', socks=True, check=False).returncode != 0
        print('PASS no-DNS mode allows IP targets and rejects hostname targets', flush=True)
    finally:
        container.close()
    container = Container(directory, FIXTURE_MODE='auth')
    try:
        def exited():
            state = json.loads(run('podman', 'inspect', container.name).stdout)[0]['State']
            return not state['Running']
        await_state(container.name, exited)
        state = json.loads(run('podman', 'inspect', container.name).stdout)[0]['State']
        result = run('podman', 'logs', container.name)
        logs = result.stdout + result.stderr
        assert state['ExitCode'] == 78, f'exit {state["ExitCode"]}: {logs.decode(errors="replace")}'
        for secret in (b'fixture-secret', b'fixture-user', b'fixture-password', b'192.0.2.1', b'fixture-group'):
            assert secret not in logs
        assert b'[redacted]' in logs
        assert logs.count(b'Connecting ') == 1
        print('PASS authentication failure exits 78 and redacts credentials', flush=True)
    finally:
        container.close()
    container = Container(directory, settings={'Interface MTU': '0576'})
    try:
        container.ready()
        interface = json.loads(container.exec('ip', '-j', 'link', 'show', 'tun0').stdout)[0]
        assert interface['mtu'] == 576
        assert container.curl('http://198.18.0.2:8080/', socks=True).stdout == b'fixture-vpn-only\n'
        print('PASS leading-zero Interface MTU is normalized to decimal 576', flush=True)
    finally:
        container.close()
    container = Container(directory, FIXTURE_MODE='3des')
    try:
        await_state(container.name, lambda: not json.loads(
            run('podman', 'inspect', container.name).stdout)[0]['State']['Running'])
        state = json.loads(run('podman', 'inspect', container.name).stdout)[0]['State']
        assert state['ExitCode'] == 78
        result = run('podman', 'logs', container.name)
        logs = result.stdout + result.stderr
        assert b'3DES' in logs and b'considered too weak' in logs
        assert logs.count(b'Connecting ') == 1
        print('PASS weak 3DES rejection is terminal with encryption opt-in disabled', flush=True)
    finally:
        container.close()
    container = Container(directory, settings={'Enable weak encryption': '1'}, FIXTURE_MODE='3des')
    try:
        container.ready()
        assert json.loads(container.exec('cat', '/run/vpncsocks/private/vpnc-options.json').stdout) == {'weak_encryption': True}
        assert container.curl('http://internal.test:8080/', socks=True).stdout == b'fixture-vpn-only\n'
        assert container.curl('http://198.18.0.2:8080/').stdout == b'fixture-vpn-only\n'
        print('PASS explicit weak-encryption opt-in reaches vpnc argv and restores proxy connectivity', flush=True)
    finally:
        container.close()
    container = Container(directory, settings={'VPN DNS': '198.18.0.2'}, FIXTURE_DNS='0')
    try:
        container.ready()
        assert container.curl('http://internal.test:8080/', socks=True).stdout == b'fixture-vpn-only\n'
        print('PASS configured VPN DNS supplies hostname resolution without server-provided DNS', flush=True)
    finally:
        container.close()


def stdio_suite(directory):
    attached = AttachedContainer(directory, 'internal.test', '9000', FIXTURE_CONNECT_DELAY='5',
                                 FIXTURE_FAIL_FIRST_ATTEMPT='1')
    try:
        process = attached.start()
        await_state(attached.name, lambda: attached.exec(
            'test', '-f', '/run/vpncsocks/private/vpnc-options.json', check=False).returncode == 0)
        assert attached.exec('test', '-f', '/run/vpncsocks/tunnel-ready', check=False).returncode != 0
        payload = bytes(range(256)) * 17
        process.stdin.write(payload)
        process.stdin.flush()
        process.stdin.close()
        process.stdin = None
        assert attached.exec('test', '-f', '/run/vpncsocks/tunnel-ready', check=False).returncode != 0
        status, output, diagnostics = attached.finish(timeout=25)
        assert status == 0, diagnostics.decode(errors='replace')
        assert output == payload[::-1]
        assert b'VPN' in diagnostics
        assert diagnostics.count(b'Connecting ') == 2 and b'retrying' in diagnostics
        print('PASS attached run buffers pre-VPN binary stdin across initial retry, preserves half-close and removes container', flush=True)
    finally:
        attached.close()

    attached = AttachedContainer(directory, '%h', '%p')
    try:
        proxy_command = shlex.join(attached.arguments)
        result = run('ssh', '-F', '/dev/null', '-i', str(directory / 'client'), '-p', '2222',
                     '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null',
                     '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes', '-o', 'ConnectTimeout=20',
                     '-o', 'ProxyCommand=' + proxy_command,
                     'root@internal.test', 'printf attached-ssh', timeout=30, check=False)
        assert result.returncode == 0, result.stderr.decode(errors='replace')
        assert result.stdout == b'attached-ssh'
        assert_removed(attached.name)
        print('PASS SSH ProxyCommand starts its own attached --rm container on custom port 2222', flush=True)
    finally:
        attached.close()

    for arguments in (('-option', '22'), ('internal.test', '0'), ('internal.test', '65536'),
                      ('internal.test',), ('internal.test', '22', 'extra')):
        attached = AttachedContainer(directory, *arguments)
        try:
            result = run(*attached.arguments, input=b'not-a-stream', check=False, timeout=15)
            assert result.returncode == 64, result.stderr.decode(errors='replace')
            assert result.stdout == b''
            assert_removed(attached.name)
        finally:
            attached.close()
    print('PASS attached stdio invalid targets exit 64 before VPN setup', flush=True)

    attached = AttachedContainer(directory, 'internal.test', '9000', FIXTURE_MODE='auth')
    try:
        result = run(*attached.arguments, input=b'queued-not-connected', check=False, timeout=15)
        assert result.returncode == 78, result.stderr.decode(errors='replace')
        assert result.stdout == b''
        assert result.stderr.count(b'Connecting ') == 1
        for secret in (b'fixture-secret', b'fixture-user', b'fixture-password', b'queued-not-connected',
                       b'192.0.2.1', b'fixture-group'):
            assert secret not in result.stderr
        assert_removed(attached.name)
        print('PASS attached authentication failure exits 78 with clean stdout and redacted stderr', flush=True)
    finally:
        attached.close()

    attached = AttachedContainer(directory, 'internal.test', '9000')
    try:
        process = attached.start()
        process.stdin.write(b'open-stdio-session')
        process.stdin.flush()
        await_state(attached.name, lambda: attached.exec(
            'test', '-f', '/run/vpncsocks/private/echo-open', check=False).returncode == 0)
        assert attached.exec('test', '-f', '/run/vpncsocks/socks.pid', check=False).returncode != 0
        assert attached.exec('test', '-f', '/run/vpncsocks/http.pid', check=False).returncode != 0
        attached.exec('sh', '-c', 'kill -TERM "$(cat /run/vpncsocks/vpnc.pid)"')
        process.wait(timeout=10)
        status, output, diagnostics = attached.finish()
        assert status == 69, diagnostics.decode(errors='replace')
        assert output == b''
        assert diagnostics.count(b'Connecting ') == 1
        print('PASS attached VPN disconnect ends active stdio with exit 69 and no reconnect', flush=True)
    finally:
        attached.close()

    attached = AttachedContainer(directory, 'internal.test', '9000')
    try:
        process = attached.start()
        process.stdin.write(b'cancelled-session')
        process.stdin.flush()
        await_state(attached.name, lambda: attached.exec(
            'test', '-f', '/run/vpncsocks/private/echo-open', check=False).returncode == 0)
        process.terminate()
        process.wait(timeout=10)
        attached.finish()
        print('PASS cancelling attached Podman run removes container and its VPN session', flush=True)
    finally:
        attached.close()


def fixture_container_ids():
    return set(run('podman', 'ps', '-aq', '--filter', 'ancestor=' + IMAGE).stdout.decode().split())


def assert_no_new_containers(previous):
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        extra = fixture_container_ids() - previous
        if not extra:
            return
        time.sleep(0.1)
    raise AssertionError(f'wrapper left test containers behind: {sorted(extra)}')


def wrapper_environment(**settings):
    environment = os.environ.copy()
    for name in ('VPNCS_IMAGE', 'VPNCS_NAME', 'VPNCS_CONFIG', 'VPNCS_SOCKS_PORT', 'VPNCS_HTTP_PORT',
                 'VPN_GATEWAY', 'VPN_IPSEC_ID', 'VPN_DNS', 'VPN_MTU', 'VPN_ENABLE_WEAK_ENCRYPTION'):
        environment.pop(name, None)
    environment.update(VPNCS_IMAGE=IMAGE)
    environment.update(settings)
    return environment


def wrapper_suite(directory):
    wrapper = ROOT / 'vpncsocks.sh'
    helpers = guarded_test_path(directory / '帮助 tools with spaces')
    helpers.mkdir()
    copied_wrapper = helpers / 'vpncsocks.sh'
    shutil.copy2(wrapper, copied_wrapper)
    helper_config = guarded_test_path(helpers / 'vpnc.conf')
    helper_config.write_text(configuration())
    helper_config.chmod(0o600)
    foreign_cwd = directory / 'unrelated cwd'
    foreign_cwd.mkdir()
    previous = fixture_container_ids()
    try:
        payload = bytes(range(256)) * 17
        result = run(str(copied_wrapper), 'stdio', 'internal.test', '9000', input=payload,
                     environment=wrapper_environment(), cwd=foreign_cwd, timeout=30)
        assert result.stdout == payload[::-1]
        assert b'VPN' in result.stderr
        assert_no_new_containers(previous)
        print('PASS helper stdio uses script-local config from another cwd with UTF-8/space paths and clean binary stdout', flush=True)

        credentials = guarded_test_path(directory / '凭据 settings with spaces')
        credentials.mkdir()
        config = guarded_test_path(credentials / 'vpnc.conf')
        config.write_text(configuration())
        config.chmod(0o600)
        environment = wrapper_environment(VPNCS_CONFIG=str(config.relative_to(directory)),
                                          VPN_GATEWAY='203.0.113.1', VPN_IPSEC_ID='ignored-group',
                                          VPN_MTU='1490', VPN_DNS='203.0.113.53',
                                          VPN_ENABLE_WEAK_ENCRYPTION='1')
        result = run('ssh', '-F', '/dev/null', '-i', str(directory / 'client'), '-p', '2222',
                     '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null',
                     '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes', '-o', 'ConnectTimeout=20',
                     '-o', 'ProxyCommand=' + shlex.join([str(wrapper), 'stdio', '%h', '%p']),
                     'root@internal.test',
                     'printf wrapper-ssh; cat /run/vpncsocks/private/vpnc-options.json',
                     environment=environment, cwd=directory, timeout=30)
        assert result.stdout.startswith(b'wrapper-ssh')
        assert json.loads(result.stdout.removeprefix(b'wrapper-ssh')) == {'weak_encryption': False}
        assert_no_new_containers(previous)
        print('PASS helper SSH ProxyCommand resolves relative spaced config and ignores old VPN environment overrides', flush=True)

        name = 'vpncsocks-wrapper-test-' + uuid.uuid4().hex[:10]
        socks_port, http_port = port(), port()
        legacy_config = write_configuration(credentials, {'Enable weak encryption': '1'})
        environment = wrapper_environment(VPNCS_CONFIG=str(legacy_config), VPNCS_NAME=name,
                                          VPNCS_SOCKS_PORT=str(socks_port), VPNCS_HTTP_PORT=str(http_port))
        try:
            run(str(wrapper), 'start', '-e', 'FIXTURE_MODE=3des', '--label', 'vpncsocks.test=wrapper',
                environment=environment, cwd=foreign_cwd)
            await_state(name, lambda: run('podman', 'exec', name, 'vpncsocks-healthcheck', check=False).returncode == 0)
            inspection = json.loads(run('podman', 'inspect', name).stdout)[0]
            assert inspection['Config']['Labels']['vpncsocks.test'] == 'wrapper'
            for container_port, host_port in (('1080/tcp', socks_port), ('8888/tcp', http_port)):
                binding = inspection['NetworkSettings']['Ports'][container_port][0]
                assert binding['HostIp'] == '127.0.0.1' and int(binding['HostPort']) == host_port
            assert json.loads(run('podman', 'exec', name, 'cat', '/run/vpncsocks/private/vpnc-options.json').stdout) == {'weak_encryption': True}
            result = run(str(wrapper), 'exec-stdio', 'internal.test', '9000', input=payload,
                         environment=environment, cwd=foreign_cwd, timeout=20)
            assert result.stdout == payload[::-1]
            result = run(str(wrapper), 'status', '--format', '{{.Names}}', environment=environment)
            assert name in result.stdout.decode().splitlines()
            run(str(wrapper), 'logs', '--tail', '2', environment=environment)
            run(str(wrapper), 'stop', '--time', '5', environment=environment, timeout=15)
            assert not json.loads(run('podman', 'inspect', name).stdout)[0]['State']['Running']
            run(str(wrapper), 'restart', '--time', '5', environment=environment, timeout=15)
            await_state(name, lambda: run('podman', 'exec', name, 'vpncsocks-healthcheck', check=False).returncode == 0)
            run(str(wrapper), 'rm', '--force', environment=environment, timeout=15)
            assert_removed(name)
            print('PASS helper daemon lifecycle/custom ports and explicit configured 3DES opt-in', flush=True)
        finally:
            run('podman', 'rm', '-f', name, check=False, timeout=20)
    finally:
        extra = fixture_container_ids() - previous
        if extra:
            run('podman', 'rm', '-f', *sorted(extra), check=False, timeout=20)


if __name__ == '__main__':
    run('podman', 'build', '--http-proxy=false', '-f', str(ROOT / 'tests/Dockerfile'),
        '-t', IMAGE, str(ROOT / 'tests'), timeout=300)
    # Static checks only: no device, credentials mount or network access.
    run('podman', 'run', '--rm', '--pull=never', '--network=none', '--entrypoint', '/bin/sh', IMAGE, '-ec',
        'test "$(readlink -f /usr/local/bin/vpnc)" = /test/fixture.py; '
        'test "$(readlink -f /usr/sbin/vpnc)" = /test/fixture.py; test -x /test/fixture.py')
    with tempfile.TemporaryDirectory(prefix='vpncsocks-integration-', dir=ROOT / 'tests') as temporary:
        TEST_DIRECTORY_ROOT = Path(temporary).resolve()
        directory = TEST_DIRECTORY_ROOT
        suite(directory)
        stdio_suite(directory)
        wrapper_suite(directory)
