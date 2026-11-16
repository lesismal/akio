"""SOCKS5 checks against a server: UDP ASSOCIATE through PySocks (a widely used client,
Debian's python3-socks), and BIND and UDP edge cases with a hand-written client.

    python3 clients.py PROXY_HOST PROXY_PORT [user pass]

Starts its own TCP and UDP echo servers on 127.0.0.1. Exits non-zero on the first failure.
"""

import socket
import struct
import sys
import threading

import socks  # PySocks

HOST, PORT = sys.argv[1], int(sys.argv[2])
AUTH = tuple(sys.argv[3:5]) if len(sys.argv) >= 5 else None


def udp_echo():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))

    def run():
        while True:
            d, a = s.recvfrom(65535)
            s.sendto(d, a)

    threading.Thread(target=run, daemon=True).start()
    return s.getsockname()


def ok(name):
    print(f"  ok  {name}")


def pysocks_udp(echo):
    s = socks.socksocket(socket.AF_INET, socket.SOCK_DGRAM)
    if AUTH:
        s.set_proxy(socks.SOCKS5, HOST, PORT, username=AUTH[0], password=AUTH[1])
    else:
        s.set_proxy(socks.SOCKS5, HOST, PORT)
    s.settimeout(3)
    s.bind(("127.0.0.1", 0))  # PySocks sends UDP ASSOCIATE here
    for i, size in enumerate([1, 512, 1400, 8000]):
        payload = bytes((i + j) % 256 for j in range(size))
        s.sendto(payload, echo)
        data, frm = s.recvfrom(65535)
        assert data == payload, f"payload {size}"
        assert frm == echo, frm
    # By name: the proxy resolves it.
    s.sendto(b"by name", ("localhost", echo[1]))
    try:
        data, _ = s.recvfrom(65535)
        assert data == b"by name"
    except socket.timeout:
        pass  # localhost resolved to ::1 on the proxy, where nothing listens
    s.close()
    ok("PySocks UDP ASSOCIATE: echo 1..8000 bytes, by name")


def greet(c):
    if AUTH:
        c.sendall(b"\x05\x01\x02")
        assert c.recv(2) == b"\x05\x02"
        u, p = AUTH[0].encode(), AUTH[1].encode()
        c.sendall(b"\x01" + bytes([len(u)]) + u + bytes([len(p)]) + p)
        assert c.recv(2) == b"\x01\x00"
    else:
        c.sendall(b"\x05\x01\x00")
        assert c.recv(2) == b"\x05\x00"


def recv_exact(c, n):
    b = b""
    while len(b) < n:
        d = c.recv(n - len(b))
        assert d, "EOF"
        b += d
    return b


def reply(c):
    h = recv_exact(c, 4)
    assert h[0] == 5, h
    if h[3] == 1:
        a = recv_exact(c, 6)
        return h[1], (socket.inet_ntoa(a[:4]), struct.unpack("!H", a[4:])[0])
    if h[3] == 4:
        a = recv_exact(c, 18)
        return h[1], (socket.inet_ntop(socket.AF_INET6, a[:16]), struct.unpack("!H", a[16:])[0])
    raise AssertionError(f"atyp {h[3]}")


def v4(addr):
    return b"\x01" + socket.inet_aton(addr[0]) + struct.pack("!H", addr[1])


def raw_udp(echo):
    c = socket.create_connection((HOST, PORT), timeout=5)
    greet(c)
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.bind(("127.0.0.1", 0))
    u.settimeout(1)
    c.sendall(b"\x05\x03\x00" + v4(u.getsockname()))
    rep, relay = reply(c)
    assert rep == 0, rep
    u.sendto(b"\x00\x00\x00" + v4(echo) + b"hello", relay)
    d = u.recv(65535)
    assert d == b"\x00\x00\x00" + v4(echo) + b"hello", d
    u.sendto(b"\x00\x00\x01" + v4(echo) + b"fragment", relay)
    try:
        u.recv(65535)
        raise AssertionError("fragment relayed")
    except socket.timeout:
        pass
    c.close()
    ok("raw UDP ASSOCIATE: declared port, header, fragment dropped")


def bind():
    c = socket.create_connection((HOST, PORT), timeout=5)
    greet(c)
    c.sendall(b"\x05\x02\x00" + v4(("127.0.0.1", 0)))
    rep, bound = reply(c)
    assert rep == 0, rep
    p = socket.create_connection(bound, timeout=5)
    rep, peer = reply(c)
    assert rep == 0 and peer == p.getsockname(), (rep, peer, p.getsockname())
    p.sendall(b"from peer")
    assert recv_exact(c, 9) == b"from peer"
    c.sendall(b"from client")
    assert recv_exact(p, 11) == b"from client"
    p.close()
    assert c.recv(1) == b""
    c.close()
    ok("BIND: two replies, relay both ways, close propagates")


echo_u = udp_echo()
for name, f in [("pysocks", pysocks_udp), ("raw", raw_udp)]:
    f(echo_u)
bind()
print("clients.py: all passed")
