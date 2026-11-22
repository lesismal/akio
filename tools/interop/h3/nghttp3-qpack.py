#!/usr/bin/env python3
"""akio-h3's QPACK encoder checked by libnghttp3's QPACK decoder (RFC 9204).

    nghttp3-qpack.py LIBNGHTTP3 QPACK_PIPE [ROUNDS]

QPACK_PIPE is `target/.../examples/qpack-pipe` (akio-h3 with feature `fuzzing`); LIBNGHTTP3 is
`libnghttp3.so.9` (Debian's, which curl's HTTP/3 uses). Plain ctypes: no build, no download.

Over-the-wire HTTP/3 peers (curl, quic-go) advertise a decoder table of 0, so our encoder's
table would never be used against them; here nghttp3's decoder gets everything our encoder
writes: inserts (static, dynamic and literal names), Duplicate, field lines with dynamic and
post-base references, sections that block until the encoder stream arrives (the encoder stream
is delivered late and in pieces), stream cancellations, and its decoder stream (section
acknowledgements, insert count increments) goes back to our encoder. Every section must
decode to the fields encoded, in several configurations (tables, blocked streams).
"""
import ctypes
import random
import subprocess
import sys

FLAG_EMIT, FLAG_FINAL, FLAG_BLOCKED = 1, 2, 4


class Buf(ctypes.Structure):
    _fields_ = [("begin", ctypes.c_void_p), ("end", ctypes.c_void_p),
                ("pos", ctypes.c_void_p), ("last", ctypes.c_void_p)]


class QpackNv(ctypes.Structure):
    _fields_ = [("name", ctypes.c_void_p), ("value", ctypes.c_void_p),
                ("token", ctypes.c_int32), ("flags", ctypes.c_uint8)]


class Vec(ctypes.Structure):
    _fields_ = [("base", ctypes.c_void_p), ("len", ctypes.c_size_t)]


def fail(msg):
    print("FAIL: " + msg)
    sys.exit(1)


class Nghttp3:
    def __init__(self, path):
        lib = ctypes.CDLL(path)
        lib.nghttp3_mem_default.restype = ctypes.c_void_p
        lib.nghttp3_qpack_decoder_new.argtypes = [ctypes.POINTER(ctypes.c_void_p), ctypes.c_size_t,
                                                  ctypes.c_size_t, ctypes.c_void_p]
        lib.nghttp3_qpack_decoder_set_max_dtable_capacity.argtypes = [ctypes.c_void_p,
                                                                      ctypes.c_size_t]
        lib.nghttp3_qpack_decoder_read_encoder.argtypes = [ctypes.c_void_p, ctypes.c_char_p,
                                                           ctypes.c_size_t]
        lib.nghttp3_qpack_decoder_read_encoder.restype = ctypes.c_ssize_t
        lib.nghttp3_qpack_stream_context_new.argtypes = [ctypes.POINTER(ctypes.c_void_p),
                                                         ctypes.c_int64, ctypes.c_void_p]
        lib.nghttp3_qpack_stream_context_reset.argtypes = [ctypes.c_void_p]
        lib.nghttp3_qpack_decoder_read_request.argtypes = [
            ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(QpackNv),
            ctypes.POINTER(ctypes.c_uint8), ctypes.c_char_p, ctypes.c_size_t, ctypes.c_int]
        lib.nghttp3_qpack_decoder_read_request.restype = ctypes.c_ssize_t
        lib.nghttp3_qpack_decoder_get_decoder_streamlen.argtypes = [ctypes.c_void_p]
        lib.nghttp3_qpack_decoder_get_decoder_streamlen.restype = ctypes.c_size_t
        lib.nghttp3_qpack_decoder_write_decoder.argtypes = [ctypes.c_void_p, ctypes.POINTER(Buf)]
        lib.nghttp3_qpack_decoder_cancel_stream.argtypes = [ctypes.c_void_p, ctypes.c_int64]
        lib.nghttp3_rcbuf_get_buf.argtypes = [ctypes.c_void_p]
        lib.nghttp3_rcbuf_get_buf.restype = Vec
        lib.nghttp3_rcbuf_decref.argtypes = [ctypes.c_void_p]
        self.lib = lib
        self.mem = lib.nghttp3_mem_default()

    def decoder(self, capacity, blocked):
        d = ctypes.c_void_p()
        if self.lib.nghttp3_qpack_decoder_new(ctypes.byref(d), capacity, blocked, self.mem) != 0:
            fail("nghttp3_qpack_decoder_new")
        self.lib.nghttp3_qpack_decoder_set_max_dtable_capacity(d, capacity)
        return d

    def stream(self, sid):
        s = ctypes.c_void_p()
        if self.lib.nghttp3_qpack_stream_context_new(ctypes.byref(s), sid, self.mem) != 0:
            fail("nghttp3_qpack_stream_context_new")
        return s

    def rcbuf(self, p):
        v = self.lib.nghttp3_rcbuf_get_buf(p)
        return ctypes.string_at(v.base, v.len) if v.len else b""


class Pipe:
    def __init__(self, exe, cap, peer_cap, blocked):
        self.p = subprocess.Popen([exe, str(cap), str(peer_cap), str(blocked)],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)

    def call(self, line):
        self.p.stdin.write(line + "\n")
        self.p.stdin.flush()
        r = self.p.stdout.readline().split()
        if not r or r[0] != "ok":
            fail("qpack-pipe: %s -> %s" % (line[:80], " ".join(r)))
        return r[1:]

    def close(self):
        self.p.stdin.close()
        self.p.wait()


def unhex(s):
    return b"" if s == "-" else bytes.fromhex(s)


def tohex(b):
    return b.hex() if b else "-"


NAMES = [b"x-a", b"x-b", b"server", b"content-type", b"x-a-much-longer-header-name", b"date",
         b":authority", b"accept-language", b"x-trace-id-for-this-request", b"user-agent"]
VALUES = [b"1", b"2", b"akio", b"text/html", b"application/x-a-rather-long-media-type-value",
          b"Mon, 16 Nov 2026 00:00:00 GMT", b"example.com", b"", b"en-US,en;q=0.9",
          b"curl/8 (x86_64) libcurl nghttp3 ngtcp2"]


def run(ng, exe, cap, peer_cap, blocked, rounds, seed):
    rnd = random.Random(seed)
    dec = ng.decoder(peer_cap, blocked)
    pipe = Pipe(exe, cap, peer_cap, blocked)
    enc_wire = bytearray()      # encoder stream not delivered yet
    dec_wire = bytearray()      # decoder stream not delivered yet
    pending = []                # [stream id, context, remaining bytes, fields so far, expected]
    next_stream = 0
    decoded = 0

    def feed(entry):
        nonlocal decoded
        sid, ctx, rest, got, want = entry
        while True:
            nv = QpackNv()
            flags = ctypes.c_uint8(0)
            n = ng.lib.nghttp3_qpack_decoder_read_request(
                dec, ctx, ctypes.byref(nv), ctypes.byref(flags), bytes(rest), len(rest), 1)
            if n < 0:
                fail("nghttp3 read_request on stream %d: %d" % (sid, n))
            del rest[:n]
            if flags.value & FLAG_EMIT:
                got.append((ng.rcbuf(nv.name), ng.rcbuf(nv.value)))
                ng.lib.nghttp3_rcbuf_decref(nv.name)
                ng.lib.nghttp3_rcbuf_decref(nv.value)
            if flags.value & FLAG_FINAL:
                # The stream's next section (trailers) starts afresh.
                ng.lib.nghttp3_qpack_stream_context_reset(ctx)
                if got != want:
                    fail("stream %d decoded %r, want %r" % (sid, got, want))
                decoded += 1
                return True
            if flags.value & FLAG_BLOCKED:
                return False
            if n == 0 and not rest:
                fail("stream %d: section ended early" % sid)

    def decode_ready():
        # In order per stream: a later section of a stream waits for its earlier one.
        waiting = set()
        for e in list(pending):
            if e[0] in waiting:
                continue
            if feed(e):
                pending.remove(e)
            else:
                waiting.add(e[0])
        if len(waiting) > blocked:
            fail("%d streams blocked, %d allowed" % (len(waiting), blocked))

    def deliver_encoder(n):
        n = min(n, len(enc_wire))
        if n:
            got = ng.lib.nghttp3_qpack_decoder_read_encoder(dec, bytes(enc_wire[:n]), n)
            if got != n:
                fail("nghttp3 read_encoder: %d" % got)
            del enc_wire[:n]

    def take_decoder():
        n = ng.lib.nghttp3_qpack_decoder_get_decoder_streamlen(dec)
        if n:
            raw = ctypes.create_string_buffer(n)
            addr = ctypes.addressof(raw)
            b = Buf(addr, addr + n, addr, addr)
            ng.lib.nghttp3_qpack_decoder_write_decoder(dec, ctypes.byref(b))
            dec_wire.extend(raw.raw[:b.last - addr])

    def deliver_decoder(n):
        n = min(n, len(dec_wire))
        if n:
            taken = int(pipe.call("dec " + tohex(bytes(dec_wire[:n])))[0])
            del dec_wire[:taken]

    for _ in range(rounds):
        op = rnd.random()
        if op < 0.45:
            if pending and rnd.random() < 0.2:
                sid = rnd.choice(pending)[0]       # trailers on a stream still decoding
            else:
                sid = next_stream
                next_stream += 4
            fields = []
            for _ in range(rnd.randint(1, 7)):
                fields.append((rnd.choice(NAMES), rnd.choice(VALUES)))
            line = "enc %d %s" % (sid, " ".join(tohex(n) + "=" + tohex(v) for n, v in fields))
            ins, sec = pipe.call(line)
            enc_wire.extend(unhex(ins))
            ctx = None
            for e in pending:
                if e[0] == sid:
                    ctx = e[1]
            # Sections of one stream share its context (reset between sections).
            pending.append([sid, ctx or ng.stream(sid), bytearray(unhex(sec)), [], fields])
        elif op < 0.65:
            deliver_encoder(rnd.randint(1, 64) if rnd.random() < 0.7 else len(enc_wire))
        elif op < 0.80:
            decode_ready()
        elif op < 0.95:
            take_decoder()
            deliver_decoder(rnd.randint(1, 16) if rnd.random() < 0.5 else len(dec_wire))
        elif pending:
            sid = rnd.choice(pending)[0]
            pending[:] = [e for e in pending if e[0] != sid]
            if ng.lib.nghttp3_qpack_decoder_cancel_stream(dec, sid) != 0:
                fail("nghttp3 cancel_stream")
    deliver_encoder(len(enc_wire))
    decode_ready()
    if pending:
        fail("%d sections never decoded" % len(pending))
    take_decoder()
    deliver_decoder(len(dec_wire))
    st = [int(x) for x in pipe.call("stats")]
    pipe.close()
    return decoded, st


def main():
    ng = Nghttp3(sys.argv[1])
    exe = sys.argv[2]
    rounds = int(sys.argv[3]) if len(sys.argv) > 3 else 4000
    total = [0] * 6
    for cap, peer_cap, blocked in ((4096, 4096, 16), (4096, 4096, 0), (512, 512, 4),
                                   (256, 1024, 1), (16384, 16384, 100)):
        for seed in range(3):
            decoded, st = run(ng, exe, cap, peer_cap, blocked, rounds, seed)
            total = [a + b for a, b in zip(total, st[:6])]
            print("ok: table %d/%d, %d blocked: %d sections decoded; inserts %d, duplicates %d, "
                  "dynamic-name inserts %d, dynamic-name lines %d, post-base lines %d, "
                  "blocking sections %d" % ((cap, peer_cap, blocked, decoded) + tuple(st[:6])))
    names = ["inserts", "duplicates", "dynamic-name inserts", "dynamic-name lines",
             "post-base lines", "blocking sections"]
    for n, v in zip(names, total):
        if v == 0:
            fail("no " + n + " exercised")
    print("nghttp3 QPACK decoder vs akio-h3 encoder: all passed")


if __name__ == "__main__":
    main()
