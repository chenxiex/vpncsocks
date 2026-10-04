#!/usr/bin/python3
"""Isolated fake vpnc and services; never connects to a real VPN gateway."""

import http.server
import json
import os
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path

STATE = Path('/run/vpncsocks/private')
ADDRESS = '198.18.0.2'
STOP = threading.Event()


def command(*args):
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL)


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'fixture-vpn-only\n'
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def dns():
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind((ADDRESS, 53))
    while not STOP.is_set():
        query, client = server.recvfrom(4096)
        cursor = 12
        labels = []
        while query[cursor]:
            size = query[cursor]
            labels.append(query[cursor + 1:cursor + 1 + size])
            cursor += size + 1
        cursor += 1
        kind, family = struct.unpack('!HH', query[cursor:cursor + 4])
        question = query[12:cursor + 4]
        name = b'.'.join(labels).decode()
        with (STATE / 'dns-queries').open('a') as output:
            output.write(name + '\n')
        answer = b''
        if name == 'internal.test' and kind == 1 and family == 1:
            answer = b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 30, 4) + socket.inet_aton(ADDRESS)
        flags = 0x8180 if name == 'internal.test' else 0x8183
        header = query[:2] + struct.pack('!HHHHH', flags, 1, bool(answer), 0, 0)
        server.sendto(header + question + answer, client)


def echo_connection(client):
    (STATE / 'echo-open').touch()
    with client:
        data = bytearray()
        while True:
            part = client.recv(65536)
            if not part:
                break
            data.extend(part)
        # Respond only after client half-close, testing stdin EOF handling.
        client.sendall(bytes(data)[::-1])


def echo():
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((ADDRESS, 9000))
    server.listen()
    while not STOP.is_set():
        client, _ = server.accept()
        threading.Thread(target=echo_connection, args=(client,), daemon=True).start()


def peer():
    (STATE / 'peer-started').write_text(str(os.getpid()))
    deadline = time.monotonic() + 15
    while subprocess.run(['ip', 'link', 'show', 'vpnpeer'], stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL).returncode:
        if time.monotonic() > deadline:
            raise RuntimeError('peer interface did not arrive')
        time.sleep(0.05)
    command('ip', 'link', 'set', 'lo', 'up')
    command('ip', 'addr', 'add', ADDRESS + '/24', 'dev', 'vpnpeer')
    command('ip', 'link', 'set', 'vpnpeer', 'up')
    plain_http = http.server.ThreadingHTTPServer((ADDRESS, 8080), Handler)
    https = http.server.ThreadingHTTPServer((ADDRESS, 8443), Handler)
    import ssl
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain('/test/tls.crt', '/test/tls.key')
    https.socket = context.wrap_socket(https.socket, server_side=True)
    for task in (plain_http.serve_forever, https.serve_forever, dns, echo):
        threading.Thread(target=task, daemon=True).start()
    sshd = subprocess.Popen([
        '/usr/sbin/sshd', '-D', '-e', '-p', '2222', '-h', '/test/ssh_host_ed25519_key',
        '-o', 'AuthorizedKeysFile=/test/client.pub', '-o', 'StrictModes=no',
        '-o', 'PermitRootLogin=yes', '-o', 'PasswordAuthentication=no',
        '-o', 'UsePAM=no', '-o', 'PidFile=/run/sshd/fixture.pid'])
    (STATE / 'peer-ready').touch()
    try:
        while not STOP.wait(0.1):
            if sshd.poll() is not None:
                raise RuntimeError('fixture sshd exited')
    finally:
        sshd.terminate()
        sshd.wait(timeout=3)


def fake_vpnc():
    supplied = {'Interface MTU': '1412', 'Enable weak encryption': '0'}
    for line in Path('/run/secrets/vpnc.conf').read_text().splitlines():
        for key in ('IPSec gateway', 'IPSec ID', 'Interface MTU', 'Enable weak encryption'):
            if line.startswith(key + ' '):
                supplied[key] = line[len(key) + 1:]
    weak_encryption = supplied['Enable weak encryption'] == '1'
    if sys.argv.count('--enable-weak-encryption') != int(weak_encryption):
        raise RuntimeError('actual vpnc weak-encryption flag does not match its opt-in setting')
    for flag, expected in (('--gateway', supplied['IPSec gateway']), ('--id', supplied['IPSec ID']),
                           ('--ifmtu', str(int(supplied['Interface MTU'], 10)))):
        if sys.argv[sys.argv.index(flag) + 1] != expected:
            raise RuntimeError(f'actual vpnc {flag} does not match the mounted configuration')
    if any(argument.startswith(('--enable-weak-authentication', '--enable-no-encryption'))
           for argument in sys.argv[1:]):
        raise RuntimeError('weak authentication and no-encryption must not be enabled')
    (STATE / 'vpnc-options.json').write_text(json.dumps({'weak_encryption': weak_encryption}))
    if os.environ.get('FIXTURE_MODE') == '3des' and not weak_encryption:
        print('Peer has selected 3DES as encryption method.\n'
              'This algorithm is considered too weak today.\n'
              'Use the "--enable-weak-encryption" option.')
        return 1
    if os.environ.get('FIXTURE_MODE') == 'auth':
        print('authentication unsuccessful')
        print('Gateway ' + supplied['IPSec gateway'] + '; group ' + supplied['IPSec ID'])
        print(Path(sys.argv[-1]).read_text())
        return 2
    retry_marker = STATE / 'fixture-retried'
    if os.environ.get('FIXTURE_FAIL_FIRST_ATTEMPT') == '1' and not retry_marker.exists():
        retry_marker.touch()
        print('fixture: transient negotiation failure')
        return 1
    if STOP.wait(float(os.environ.get('FIXTURE_CONNECT_DELAY', '0'))):
        return 0
    while (STATE / 'hold').exists() and not STOP.wait(0.1):
        pass
    if STOP.is_set():
        return 0
    for name in ('peer-ready', 'peer-started', 'peer-unshared', 'peer-mapped'):
        (STATE / name).unlink(missing_ok=True)
    command('ip', 'link', 'add', 'tun0', 'type', 'veth', 'peer', 'name', 'vpnpeer')
    child = subprocess.Popen(['/test/fixture.py', 'isolated-peer'])
    try:
        deadline = time.monotonic() + 15
        while not (STATE / 'peer-unshared').exists():
            if child.poll() is not None or time.monotonic() > deadline:
                raise RuntimeError('nested fixture namespace failed')
            time.sleep(0.05)
        # Parent has SETUID/SETGID in its own user namespace. Mapping its
        # existing IDs permits sshd's privilege separation and setgroups.
        for mapping in ('uid_map', 'gid_map'):
            try:
                # Rootless Podman maps ID 0 separately from the subuid block;
                # kernel mapping ranges must not cross that extent boundary.
                Path(f'/proc/{child.pid}/{mapping}').write_text('0 0 1\n1 1 65535\n')
            except OSError as error:
                raise RuntimeError(f'{mapping}: {error}; parent mapping: ' +
                                   Path('/proc/self/' + mapping).read_text() +
                                   '; setgroups: ' + Path('/proc/self/setgroups').read_text()) from error
        (STATE / 'peer-mapped').touch()
        while not (STATE / 'peer-started').exists():
            if child.poll() is not None or time.monotonic() > deadline:
                raise RuntimeError('nested fixture namespace failed')
            time.sleep(0.05)
        command('ip', 'link', 'set', 'vpnpeer', 'netns', str(child.pid))
        while not (STATE / 'peer-ready').exists():
            if child.poll() is not None or time.monotonic() > deadline:
                raise RuntimeError('fixture services failed')
            time.sleep(0.05)
        environment = dict(os.environ, reason='connect', TUNDEV='tun0',
                           INTERNAL_IP4_ADDRESS='198.18.0.1',
                           INTERNAL_IP4_DNS=ADDRESS if os.environ.get('FIXTURE_DNS', '1') == '1' else '')
        subprocess.run(['/usr/local/lib/vpncsocks/vpnc-hook.sh'], env=environment, check=True)
        while not STOP.wait(0.1):
            if child.poll() is not None:
                raise RuntimeError('fixture peer exited')
    finally:
        environment = dict(os.environ, reason='disconnect')
        subprocess.run(['/usr/local/lib/vpncsocks/vpnc-hook.sh'], env=environment)
        child.terminate()
        try:
            child.wait(timeout=3)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait()
        subprocess.run(['ip', 'link', 'del', 'tun0'], stderr=subprocess.DEVNULL)
    return 0


def isolated_peer():
    import ctypes
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.unshare(0x10000000 | 0x40000000):
        raise OSError(ctypes.get_errno(), 'unshare user/network namespace')
    (STATE / 'peer-unshared').touch()
    deadline = time.monotonic() + 10
    while not (STATE / 'peer-mapped').exists():
        if time.monotonic() > deadline:
            raise RuntimeError('peer UID/GID mappings did not arrive')
        time.sleep(0.05)
    os.setresgid(0, 0, 0)
    os.setresuid(0, 0, 0)
    os.execl('/test/fixture.py', '/test/fixture.py', 'peer')


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, lambda *_: STOP.set())
    signal.signal(signal.SIGINT, lambda *_: STOP.set())
    try:
        if len(sys.argv) == 2 and sys.argv[1] == 'isolated-peer':
            isolated_peer()
        if len(sys.argv) == 2 and sys.argv[1] == 'peer':
            peer()
            sys.exit(0)
        sys.exit(fake_vpnc())
    except Exception as error:
        print('fixture failed: ' + str(error), file=sys.stderr)
        sys.exit(1)
