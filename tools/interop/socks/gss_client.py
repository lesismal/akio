#!/usr/bin/env python3
"""An independent RFC 1961 SOCKS5 GSS-API client (python3-gssapi, MIT Kerberos), for
tools/interop/socks/gssapi.sh: run against Dante first (so the client is right), then against
only-socks' server. CONNECTs to an echo server through the proxy at the given protection level
and checks a 300 KiB echo; with `udp`, makes a UDP ASSOCIATE instead and checks datagrams
through the relay, each one an RFC 1961 encapsulated message (VER 1, MTYP 3, LEN, TOKEN) at
levels 1 and 2.

    gss_client.py PROXY_PORT SERVICE@HOST LEVEL(0|1|2) [EXPECT_LEVEL] [udp]
"""
import os
import socket
import struct
import sys
import threading

import gssapi

args = sys.argv[1:]
udp = args[-1] == "udp"
if udp:
    args = args[:-1]
port, service, level = int(args[0]), args[1], int(args[2])
expect = int(args[3]) if len(args) > 3 else level


def recv_exact(s, n):
    b = b""
    while len(b) < n:
        c = s.recv(n - len(b))
        if not c:
            raise SystemExit("proxy closed the connection")
        b += c
    return b


def recv_msg(s):
    ver, mtyp = recv_exact(s, 2)
    assert ver == 1, ver
    if mtyp == 0xFF:
        raise SystemExit("proxy aborted the GSS-API exchange")
    (n,) = struct.unpack(">H", recv_exact(s, 2))
    return mtyp, recv_exact(s, n)


def send_msg(s, mtyp, token):
    s.sendall(bytes([1, mtyp]) + struct.pack(">H", len(token)) + token)


# An echo server.
echo = socket.socket()
echo.bind(("127.0.0.1", 0))
echo.listen()


def serve():
    c, _ = echo.accept()
    while True:
        d = c.recv(65536)
        if not d:
            return
        c.sendall(d)


threading.Thread(target=serve, daemon=True).start()

s = socket.create_connection(("127.0.0.1", port))
s.sendall(b"\x05\x01\x01")
assert recv_exact(s, 2) == b"\x05\x01", "proxy did not choose GSS-API"
flags = (gssapi.RequirementFlag.mutual_authentication | gssapi.RequirementFlag.integrity
         | gssapi.RequirementFlag.confidentiality)
ctx = gssapi.SecurityContext(name=gssapi.Name(service, gssapi.NameType.hostbased_service),
                             usage="initiate", flags=flags)
token = ctx.step()
while True:
    send_msg(s, 1, token)
    mtyp, t = recv_msg(s)
    assert mtyp == 1, mtyp
    token = ctx.step(t)
    if ctx.complete:
        if token:
            send_msg(s, 1, token)
        break
send_msg(s, 2, ctx.wrap(bytes([level]), False).message)
mtyp, t = recv_msg(s)
assert mtyp == 2, mtyp
granted = ctx.unwrap(t).message[0]
assert granted == expect, f"granted {granted}, expected {expect}"

rx = b""


def send(data):
    if granted == 0:
        s.sendall(data)
    else:
        for i in range(0, len(data), 32768):
            send_msg(s, 3, ctx.wrap(data[i:i + 32768], granted == 2).message)


def recv(n):
    global rx
    while len(rx) < n:
        if granted == 0:
            c = s.recv(65536)
            if not c:
                raise SystemExit("tunnel closed")
            rx += c
        else:
            mtyp, t = recv_msg(s)
            assert mtyp == 3, mtyp
            rx += ctx.unwrap(t).message
    out, rx = rx[:n], rx[n:]
    return out


def udp_associate():
    """RFC 1961 section 5: with protection, every datagram is one encapsulated message."""
    uecho = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    uecho.bind(("127.0.0.1", 0))

    def userve():
        while True:
            d, a = uecho.recvfrom(65536)
            uecho.sendto(d, a)

    threading.Thread(target=userve, daemon=True).start()
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.bind(("127.0.0.1", 0))
    u.settimeout(5)
    send(b"\x05\x03\x00\x01" + socket.inet_aton("127.0.0.1")
         + struct.pack(">H", u.getsockname()[1]))
    rep = recv(10)
    assert rep[:2] == b"\x05\x00", rep
    rhost = socket.inet_ntoa(rep[4:8])
    relay = ("127.0.0.1" if rhost == "0.0.0.0" else rhost, struct.unpack(">H", rep[8:10])[0])
    eh, ep = uecho.getsockname()
    header = b"\x00\x00\x00\x01" + socket.inet_aton(eh) + struct.pack(">H", ep)
    for n in (1, 500, 1400):
        payload = os.urandom(n)
        d = header + payload
        if granted:
            w = ctx.wrap(d, granted == 2).message
            d = bytes([1, 3]) + struct.pack(">H", len(w)) + w
        u.sendto(d, relay)
        r, _ = u.recvfrom(65536)
        if granted:
            assert r[:2] == b"\x01\x03", r[:4]
            (ln,) = struct.unpack(">H", r[2:4])
            assert len(r) == 4 + ln, "trailing bytes after the encapsulated message"
            r = ctx.unwrap(r[4:]).message
        assert r[:10] == header, r[:10]
        assert r[10:] == payload, f"{n}-byte datagram differs"
    print(f"ok: level {granted}, UDP datagrams of 1, 500 and 1400 bytes")
    sys.exit(0)


if udp:
    udp_associate()

host, eport = echo.getsockname()
send(b"\x05\x01\x00\x01" + socket.inet_aton(host) + struct.pack(">H", eport))
rep = recv(10)
assert rep[:2] == b"\x05\x00", rep
data = os.urandom(300 << 10)
threading.Thread(target=send, args=(data,), daemon=True).start()
assert recv(len(data)) == data, "echo differs"
print(f"ok: level {granted}, {len(data)} bytes")
