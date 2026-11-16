#!/usr/bin/env python3
"""HTTP/3 client checks through libcurl, against an only-h3 server (h3-interop example).

    libcurl-h3.py LIB https://127.0.0.1:9401

LIB is a libcurl built with HTTP/3: `libcurl-gnutls.so.4` (ngtcp2 + GnuTLS on Debian) or
`libcurl.so.4` (OpenSSL 3.5's own QUIC stack + nghttp3). Plain ctypes: no build, no download.
One easy handle for every request, so they share a connection, with repeated header fields:
nghttp3's QPACK encoder fills the dynamic table the server allows, and the server's (with
`h3-interop server ... qpack`) is exercised against nghttp3's decoder.
"""
import ctypes
import sys

CURLOPT_URL = 10002
CURLOPT_WRITEFUNCTION = 20011
CURLOPT_POSTFIELDS = 10015
CURLOPT_POSTFIELDSIZE_LARGE = 30120
CURLOPT_HTTP_VERSION = 84
CURLOPT_SSL_VERIFYPEER = 64
CURLOPT_SSL_VERIFYHOST = 81
CURLOPT_TIMEOUT = 13
CURLOPT_HTTPGET = 80
CURLOPT_HTTPHEADER = 10023
CURL_HTTP_VERSION_3ONLY = 31
CURLINFO_RESPONSE_CODE = 0x200002
CURLINFO_HTTP_VERSION = 0x200000 + 46
CURL_HTTP_VERSION_3 = 30

WRITE = ctypes.CFUNCTYPE(ctypes.c_size_t, ctypes.POINTER(ctypes.c_char), ctypes.c_size_t,
                         ctypes.c_size_t, ctypes.c_void_p)


def fail(msg):
    print("FAIL: " + msg)
    sys.exit(1)


def main():
    lib = ctypes.CDLL(sys.argv[1])
    base = sys.argv[2]
    lib.curl_version.restype = ctypes.c_char_p
    lib.curl_easy_init.restype = ctypes.c_void_p
    lib.curl_easy_setopt.argtypes = [ctypes.c_void_p, ctypes.c_int]
    lib.curl_easy_perform.argtypes = [ctypes.c_void_p]
    lib.curl_easy_getinfo.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p]
    lib.curl_easy_strerror.restype = ctypes.c_char_p
    lib.curl_easy_cleanup.argtypes = [ctypes.c_void_p]
    lib.curl_slist_append.restype = ctypes.c_void_p
    lib.curl_slist_append.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    print(lib.curl_version().decode())
    h = lib.curl_easy_init()
    hdrs = None
    for line in (b"x-application-id: only-h3-interop", b"x-tenant: a-tenant-with-a-long-name",
                 b"accept-language: en-US,en;q=0.9"):
        hdrs = lib.curl_slist_append(hdrs, line)
    lib.curl_easy_setopt(h, CURLOPT_HTTPHEADER, ctypes.c_void_p(hdrs))

    def request(path, body=None):
        out = bytearray()

        def on_write(ptr, size, n, _ud):
            out.extend(ctypes.string_at(ptr, size * n))
            return size * n

        cb = WRITE(on_write)
        lib.curl_easy_setopt(h, CURLOPT_URL, ctypes.c_char_p((base + path).encode()))
        lib.curl_easy_setopt(h, CURLOPT_HTTP_VERSION, ctypes.c_long(CURL_HTTP_VERSION_3ONLY))
        lib.curl_easy_setopt(h, CURLOPT_SSL_VERIFYPEER, ctypes.c_long(0))
        lib.curl_easy_setopt(h, CURLOPT_SSL_VERIFYHOST, ctypes.c_long(0))
        lib.curl_easy_setopt(h, CURLOPT_TIMEOUT, ctypes.c_long(20))
        lib.curl_easy_setopt(h, CURLOPT_WRITEFUNCTION, cb)
        keep = None
        lib.curl_easy_setopt(h, CURLOPT_HTTPGET, ctypes.c_long(1))
        if body is not None:
            keep = ctypes.create_string_buffer(body, len(body))
            lib.curl_easy_setopt(h, CURLOPT_POSTFIELDSIZE_LARGE, ctypes.c_longlong(len(body)))
            lib.curl_easy_setopt(h, CURLOPT_POSTFIELDS, keep)
        rc = lib.curl_easy_perform(h)
        if rc != 0:
            fail(f"{path}: {lib.curl_easy_strerror(rc).decode()}")
        code, ver = ctypes.c_long(), ctypes.c_long()
        lib.curl_easy_getinfo(h, CURLINFO_RESPONSE_CODE, ctypes.byref(code))
        lib.curl_easy_getinfo(h, CURLINFO_HTTP_VERSION, ctypes.byref(ver))
        del keep
        if ver.value != CURL_HTTP_VERSION_3:
            fail(f"{path}: not HTTP/3 (version {ver.value})")
        return code.value, bytes(out)

    code, b = request("/")
    if code != 200 or b != b"hello h3":
        fail(f"/: {code} {b[:40]!r}")
    code, b = request("/user/42")
    if code != 200 or not b.startswith(b"user 42"):
        fail(f"/user/42: {code} {b[:40]!r}")
    body = bytes((i * 7 + (i >> 9)) & 0xff for i in range(300_000))
    code, b = request("/echo", body)
    if code != 200 or b != body:
        fail(f"/echo: {code}, {len(b)} bytes back")
    code, b = request("/stream")
    if code != 200 or b.count(b"line ") != 50:
        fail(f"/stream: {code} {len(b)} bytes")
    code, b = request("/count", body)
    if code != 200 or b != str(len(body)).encode():
        fail(f"/count: {code} {b[:40]!r}")
    for i in range(30):
        code, b = request(f"/user/{i % 3}")
        if code != 200 or not b.startswith(f"user {i % 3}".encode()):
            fail(f"/user/{i % 3}: {code} {b[:40]!r}")
    lib.curl_easy_cleanup(h)
    print("ok: GET /, GET /user/42, POST /echo (300 KB), GET /stream, POST /count (streamed), "
          "30 more requests on one connection over HTTP/3")


main()
