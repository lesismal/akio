#!/usr/bin/env python3
"""Test-only GSS-API shim for tools/interop/socks/gssapi.sh: one security context of MIT
Kerberos (python3-gssapi), driven over stdin/stdout by akio-socks' `socks-gss-interop`
example, which adapts it to the `akio_socks::gssapi::GssContext` trait (ADR-071).

    gss_shim.py initiate SERVICE@HOST   # the client side (credentials from the ccache)
    gss_shim.py accept                  # the server side (keys from $KRB5_KTNAME)

Requests: op (1 byte) + length (4 bytes, big-endian) + payload. Ops: S step (the peer's
token), W wrap (1 byte confidential flag + message), U unwrap (token), N peer name.
Replies: status (1 byte) + length + payload. Status: C continue (token), D done (token),
K ok (payload), E error (message).
"""
import struct
import sys

import gssapi

rd, wr = sys.stdin.buffer, sys.stdout.buffer


def read_exact(n):
    b = b""
    while len(b) < n:
        c = rd.read(n - len(b))
        if not c:
            sys.exit(0)
        b += c
    return b


def reply(status, payload=b""):
    wr.write(status + struct.pack(">I", len(payload)) + payload)
    wr.flush()


if sys.argv[1] == "initiate":
    name = gssapi.Name(sys.argv[2], gssapi.NameType.hostbased_service)
    flags = (gssapi.RequirementFlag.mutual_authentication
             | gssapi.RequirementFlag.integrity
             | gssapi.RequirementFlag.confidentiality)
    ctx = gssapi.SecurityContext(name=name, usage="initiate", flags=flags)
else:
    ctx = gssapi.SecurityContext(creds=gssapi.Credentials(usage="accept"), usage="accept")

while True:
    op = read_exact(1)
    (n,) = struct.unpack(">I", read_exact(4))
    data = read_exact(n)
    try:
        if op == b"S":
            out = ctx.step(data if data else None) or b""
            reply(b"D" if ctx.complete else b"C", out)
        elif op == b"W":
            reply(b"K", ctx.wrap(data[1:], data[0] == 1).message)
        elif op == b"U":
            reply(b"K", ctx.unwrap(data).message)
        elif op == b"N":
            peer = ctx.initiator_name if ctx.usage == "accept" else ctx.target_name
            reply(b"K", str(peer).encode())
        else:
            reply(b"E", b"unknown op")
    except gssapi.exceptions.GSSError as e:
        reply(b"E", str(e).encode())
