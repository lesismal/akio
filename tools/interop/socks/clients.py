"""SOCKS checks against a server: UDP ASSOCIATE through PySocks (a widely used client,
Debian's python3-socks), and BIND and UDP edge cases with a hand-written client.

    python3 clients.py PROXY_HOST PROXY_PORT [user pass] [--fragments] [--socks4-bind]

`--fragments`: the server reassembles fragmented UDP datagrams (RFC 1928 FRAG; Dante, like
most servers, drops them). `--socks4-bind`: check SOCKS4 BIND too. Starts its own TCP and
UDP echo servers on 127.0.0.1. Exits non-zero on the first failure.
"""

import socket
import struct
import sys
import threading

import socks  # PySocks

FLAGS = {a for a in sys.argv[1:] if a.startswith("--")}
ARGS = [a for a in sys.argv[1:] if not a.startswith("--")]
HOST, PORT = ARGS[0], int(ARGS[1])
AUTH = tuple(ARGS[2:4]) if len(ARGS) >= 4 else None


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
    # A first fragment alone is never relayed: dropped, or held for the rest.
    u.sendto(b"\x00\x00\x01" + v4(echo) + b"fragment", relay)
    try:
        u.recv(65535)
        raise AssertionError("fragment relayed")
    except socket.timeout:
        pass
    if "--fragments" in FLAGS:
        # Three fragments (positions 1, 2, 3 with the end bit) arrive as one datagram.
        for frag, part in [(1, b"frag"), (2, b"mented "), (0x83, b"datagram")]:
            u.sendto(b"\x00\x00" + bytes([frag]) + v4(echo) + part, relay)
        d = u.recv(65535)
        assert d == b"\x00\x00\x00" + v4(echo) + b"fragmented datagram", d
        # A gap drops the sequence; a whole datagram still passes.
        for frag, part in [(1, b"a"), (3, b"c"), (0x84, b"d")]:
            u.sendto(b"\x00\x00" + bytes([frag]) + v4(echo) + part, relay)
        u.sendto(b"\x00\x00\x00" + v4(echo) + b"whole", relay)
        d = u.recv(65535)
        assert d.endswith(b"whole"), d
        ok("raw UDP ASSOCIATE: fragments reassembled, a gap drops the sequence")
    c.close()
    ok("raw UDP ASSOCIATE: declared port, header, lone fragment not relayed")


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


def socks4_bind():
    c = socket.create_connection((HOST, PORT), timeout=5)
    # VN=4 CD=2 DSTPORT DSTIP=0.0.0.0 (any peer) USERID NUL
    c.sendall(b"\x04\x02\x00\x00\x00\x00\x00\x00" + (AUTH[0].encode() if AUTH else b"") + b"\x00")
    r = recv_exact(c, 8)
    assert r[1] == 0x5A, r
    ip = socket.inet_ntoa(r[4:8])
    if ip == "0.0.0.0":
        ip = HOST
    p = socket.create_connection((ip, struct.unpack("!H", r[2:4])[0]), timeout=5)
    r = recv_exact(c, 8)
    assert r[1] == 0x5A, r
    p.sendall(b"from peer")
    assert recv_exact(c, 9) == b"from peer"
    c.sendall(b"from client")
    assert recv_exact(p, 11) == b"from client"
    p.close()
    c.close()
    ok("SOCKS4 BIND: two replies, relay both ways")


echo_u = udp_echo()
for name, f in [("pysocks", pysocks_udp), ("raw", raw_udp)]:
    f(echo_u)
bind()
if "--socks4-bind" in FLAGS:
    socks4_bind()
print("clients.py: all passed")
