#!/usr/bin/env python3
"""Independent SRTP/SRTCP for the AES-f8 (RFC 3711 §4.1.2) and SEED (RFC 5669) profiles.

Writes f8_seed.txt next to this file: the packets of libsrtp.txt (the inputs of its
Aes128CmHmacSha1_80 cases: plain, mki, hdrext, cryptex, cryptex+mki) protected under AesF8HmacSha1_80,
AesF8HmacSha1_32, SeedCtrHmacSha1_80, SeedCcm80 and SeedGcm96, same keys, MKIs, re-keying points,
RFC 6904 IDs and cryptex, in the same line format; and SEED-CTR PRF outputs ("kdf" lines).

Written from the RFCs alone, sharing no code with the Rust crate: the block ciphers come from
pyca/cryptography (OpenSSL's AES and SEED, ECB only); CTR, f8, CCM, GCM/GHASH, key derivation,
RFC 6904, cryptex and the packet layouts are implemented here. Before writing anything it checks
itself against RFC 3711 Appendix B.1 (f8) and B.3 (key derivation), RFC 4269 Appendix B and
RFC 5669 Appendix A (A.1 keystream; A.2 CCM; A.3 GCM).

    python3 f8_seed.py          # needs `cryptography` (with SEED, e.g. 41.x)
"""

import hashlib
import hmac
import os
import warnings

warnings.filterwarnings("ignore")  # SEED is a "decrepit" algorithm in newer cryptography
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))


def ecb(alg, key):
    enc = Cipher(alg(key), modes.ECB()).encryptor()
    return lambda block: enc.update(block)


def aes(key):
    return ecb(algorithms.AES, key)


def seed(key):
    return ecb(algorithms.SEED, key)


def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def ctr(E, iv, n):
    """CTR keystream with a 128-bit big-endian increment."""
    out, c = b"", int.from_bytes(iv, "big")
    while len(out) < n:
        out += E(c.to_bytes(16, "big"))
        c = (c + 1) % (1 << 128)
    return out[:n]


def f8(key, salt, iv, n):
    """RFC 3711 §4.1.2.1: IV' = E(k_e XOR m, IV), S(j) = E(k_e, IV' XOR j XOR S(j-1))."""
    m = salt + b"\x55" * (len(key) - len(salt))
    ivp = int.from_bytes(aes(xor(key, m))(iv), "big")
    E, s, out, j = aes(key), 0, b"", 0
    while len(out) < n:
        blk = E((ivp ^ j ^ s).to_bytes(16, "big"))
        s, out, j = int.from_bytes(blk, "big"), out + blk, j + 1
    return out[:n]


def gf128(x, y):
    """GHASH multiplication (SP 800-38D §6.3), bit-reflected convention."""
    r, z, v = 0xE1 << 120, 0, x
    for i in range(127, -1, -1):
        if (y >> i) & 1:
            z ^= v
        v = (v >> 1) ^ r if v & 1 else v >> 1
    return z


def ghash(h, data):
    y = 0
    for i in range(0, len(data), 16):
        y = gf128(y ^ int.from_bytes(data[i : i + 16], "big"), h)
    return y


def pad16(b):
    return b + bytes(-len(b) % 16)


def gcm_seal(E, nonce, aad, pt, tlen):
    h = int.from_bytes(E(bytes(16)), "big")
    j0 = nonce + b"\x00\x00\x00\x01"
    ks, c = b"", 2
    while len(ks) < len(pt):
        ks += E(nonce + c.to_bytes(4, "big"))
        c = (c + 1) % (1 << 32)
    ct = xor(pt, ks)
    lens = (len(aad) * 8).to_bytes(8, "big") + (len(ct) * 8).to_bytes(8, "big")
    s = ghash(h, pad16(aad) + pad16(ct) + lens)
    return ct + xor(s.to_bytes(16, "big"), E(j0))[:tlen]


def ccm_seal(E, nonce, aad, pt, m):
    """RFC 3610 with L = 15 - len(nonce)."""
    L = 15 - len(nonce)
    b0 = bytes([(64 if aad else 0) | ((m - 2) // 2) << 3 | (L - 1)]) + nonce + len(pt).to_bytes(L, "big")
    blocks = b0
    if aad:
        assert len(aad) < 0xFF00
        blocks += pad16(len(aad).to_bytes(2, "big") + aad)
    blocks += pad16(pt)
    x = bytes(16)
    for i in range(0, len(blocks), 16):
        x = E(xor(x, blocks[i : i + 16]))
    a0 = bytes([L - 1]) + nonce + bytes(L)
    ks = ctr(E, a0, 16 + len(pt))
    return xor(pt, ks[16:]) + xor(x[:m], ks[:m])


def prf(E, master_salt, label, r, n):
    """RFC 3711 §4.3.1/4.3.3 (AES-CM PRF), RFC 5669 §4 (SEED-CTR PRF)."""
    x = bytearray(master_salt + bytes(14 - len(master_salt)))
    x[7] ^= label
    for i, b in enumerate(r.to_bytes(6, "big")):
        x[8 + i] ^= b
    return ctr(E, bytes(x) + b"\x00\x00", n)


def cm_iv(salt, ssrc, idx):
    iv = bytearray(salt + bytes(16 - len(salt)))
    for i, b in enumerate(ssrc.to_bytes(4, "big")):
        iv[4 + i] ^= b
    for i, b in enumerate(idx.to_bytes(6, "big")):
        iv[8 + i] ^= b
    return bytes(iv)


PROFILES = {
    # name: (transform, SRTP tag, SRTCP tag, session salt length)
    "AesF8HmacSha1_80": ("f8", 10, 10, 14),
    "AesF8HmacSha1_32": ("f8", 4, 10, 14),
    "SeedCtrHmacSha1_80": ("seedctr", 10, 10, 14),
    "SeedGcm96": ("gcm", 12, 12, 12),
    "SeedCcm80": ("ccm", 10, 10, 12),
}


class Keys:
    def __init__(self, profile, mki, key, salt):
        t, _, _, sl = PROFILES[profile]
        E = seed(key) if t != "f8" else aes(key)
        self.mki = mki
        d = lambda label, n: prf(E, salt, label, 0, n)  # noqa: E731
        self.rtp = (d(0, 16), d(2, sl), d(1, 20))
        self.rtcp = (d(3, 16), d(5, sl), d(4, 20))
        self.hdr = (d(6, 16), d(7, sl))


class Sender:
    def __init__(self, profile, keys, hdr_ids=(), cryptex=False):
        self.p, self.keys, self.hdr_ids, self.cryptex = profile, keys, set(hdr_ids), cryptex
        self.t, self.tag, self.rtcp_tag, _ = PROFILES[profile]
        self.highest, self.rtcp_idx = {}, {}

    def aead(self):
        return self.t in ("gcm", "ccm")

    def keystream(self, key, salt, head, roc, n):
        ssrc, seq = int.from_bytes(head[8:12], "big"), int.from_bytes(head[2:4], "big")
        if self.t == "f8":
            iv = b"\x00" + head[1:12] + roc.to_bytes(4, "big")
            return f8(key, salt, iv, n)
        E = seed(key)
        return ctr(E, cm_iv(salt, ssrc, (roc << 16) | seq), n)

    def seal(self, keys, aad, body, nonce):
        E = seed(keys[0])
        if self.t == "gcm":
            return gcm_seal(E, nonce, aad, body, self.tag)
        return ccm_seal(E, nonce, aad, body, self.tag)

    def roc_for(self, ssrc, seq):
        if ssrc not in self.highest:
            return 0
        h = self.highest[ssrc]
        roc, s_l = h >> 16, h & 0xFFFF
        if s_l < 32768:
            return roc - 1 if seq - s_l > 32768 else roc
        return roc + 1 if s_l - 32768 > seq else roc

    def protect_rtp(self, pkt, ki):
        k = self.keys[ki]
        b0 = pkt[0]
        cc = b0 & 15
        hlen, ext = 12 + 4 * cc, None
        if b0 & 0x10:
            ext = hlen
            hlen += 4 + 4 * int.from_bytes(pkt[hlen + 2 : hlen + 4], "big")
        ssrc, seq = int.from_bytes(pkt[8:12], "big"), int.from_bytes(pkt[2:4], "big")
        roc = self.roc_for(ssrc, seq)
        self.highest[ssrc] = max(self.highest.get(ssrc, 0), (roc << 16) | seq)
        enc_key, salt, auth = k.rtp
        out = bytearray(pkt)
        crx = self.cryptex and (cc or ext is not None)
        if crx:
            if ext is not None:
                marker = {0xBEDE: 0xC0DE, 0x1000: 0xC2DE}[int.from_bytes(pkt[ext : ext + 2], "big")]
                out[ext : ext + 2] = marker.to_bytes(2, "big")
            else:
                end = 12 + 4 * cc
                out = bytearray(pkt[:end] + b"\xc0\xde\x00\x00" + pkt[end:])
                out[0] |= 0x10
            # RFC 9335 §6.2: fixed header || extension header is the AAD, the rest contiguous.
            region = out[12 : 12 + 4 * cc + 4]
            out[12 : 12 + 4 * cc + 4] = region[-4:] + region[:-4]
            aad_len = 16
        else:
            if ext is not None and self.hdr_ids:
                hk, hs = k.hdr
                data = out[ext + 4 : hlen]
                ks = self.keystream(hk, hs, pkt, roc, len(data))
                two = int.from_bytes(pkt[ext : ext + 2], "big") & 0xFFF0 == 0x1000
                i = 0
                while i < len(data):
                    b = data[i]
                    if b == 0:
                        i += 1
                        continue
                    if two:
                        eid, ln, at = b, data[i + 1], i + 2
                    else:
                        if b >> 4 == 15:
                            break
                        eid, ln, at = b >> 4, (b & 15) + 1, i + 1
                    if eid in self.hdr_ids:
                        for j in range(at, at + ln):
                            data[j] ^= ks[j]
                    i = at + ln
                out[ext + 4 : hlen] = data
            aad_len = hlen
        if self.aead():
            nonce = xor(bytes(2) + ssrc.to_bytes(4, "big") + roc.to_bytes(4, "big") + seq.to_bytes(2, "big"), salt)
            sealed = self.seal(k.rtp, bytes(out[:aad_len]), bytes(out[aad_len:]), nonce)
            out = out[:aad_len] + sealed
        else:
            body = out[aad_len:]
            out[aad_len:] = xor(body, self.keystream(enc_key, salt, bytes(out[:12]), roc, len(body)))
        if crx:
            n = 4 * cc + 4
            region = out[12 : 12 + n]
            out[12 : 12 + n] = region[4:] + region[:4]
        if self.aead():
            return bytes(out) + k.mki
        tag = hmac.new(auth, bytes(out) + roc.to_bytes(4, "big"), hashlib.sha1).digest()[: self.tag]
        return bytes(out) + k.mki + tag

    def protect_rtcp(self, pkt, ki):
        k = self.keys[ki]
        enc_key, salt, auth = k.rtcp
        ssrc = int.from_bytes(pkt[4:8], "big")
        idx = self.rtcp_idx.get(ssrc, 0)
        self.rtcp_idx[ssrc] = idx + 1
        word = (0x80000000 | idx).to_bytes(4, "big")
        if self.aead():
            nonce = xor(bytes(2) + ssrc.to_bytes(4, "big") + bytes(2) + idx.to_bytes(4, "big"), salt)
            sealed = self.seal(k.rtcp, pkt[:8] + word, pkt[8:], nonce)
            return pkt[:8] + sealed + word + k.mki
        if self.t == "f8":
            ks = f8(enc_key, salt, bytes(4) + word + pkt[:8], len(pkt) - 8)
        else:
            ks = ctr(seed(enc_key), cm_iv(salt, ssrc, idx), len(pkt) - 8)
        out = pkt[:8] + xor(pkt[8:], ks) + word
        tag = hmac.new(auth, out, hashlib.sha1).digest()[: self.rtcp_tag]
        return out + k.mki + tag


def h(s):
    return bytes.fromhex("".join(s.split()))


def self_check():
    # RFC 3711 B.1 (f8, 4-byte salt as in the RFC).
    ks = f8(h("234829008467be186c3de14aae72d62c"), h("32f2870d"), h("006e5cba50681de55c621599d462564a"), 39)
    pt = h("70736575646f72616e646f6d6e65737320697320746865206e6578742062657374207468696e67")
    assert xor(pt, ks) == h(
        "019ce7a26e7854014a6366aa95d4eefd1ad4172a14f9faf455b7f1d4b62bd08f562c0eef7c4802"
    )
    # RFC 3711 B.3.
    E = aes(h("E1F97A0D3E018BE0D64FA32C06DE4139"))
    ms = h("0EC675AD498AFEEBB6960B3AABE6")
    assert prf(E, ms, 0, 0, 16) == h("C61E7A93744F39EE10734AFE3FF7A087")
    assert prf(E, ms, 2, 0, 14) == h("30CBBC08863D8C85D49DB34A9AE1")
    # RFC 4269 B.4.
    assert seed(h("28DBC3BC49FFD87DCFA509B11D422BE7"))(h("B41E6BE2EBA84A148E2EED84593C5EC7")) == h(
        "9B9B7BFCD1813CB95D0B3618F40F5122"
    )
    payload = h(
        """f57af5fd4ae19562976ec57a5a7ad55a5af5c5e5c5fdf5c55ad57a4a7272d572
        62e9729566ed66e97ac54a4a5a7ad5e15ae5fdd5fd5ac5d56ae56ad5c572d54a
        e54ac55a956afd6aed5a4ac562957a9516991691d572fd14e97ae962ed7a9f4a
        955af572e162f57a956666e17ae1f54a95f566d54a66e16e4afd6a9f7ae1c5c5
        5ae5d56afde916c5e94a6ec56695e14afde1148416e94ad57ac5146ed59d1cc5"""
    )
    # RFC 5669 A.1 (the keystream; its tag is not over the ciphertext and ROC).
    iv = cm_iv(h("cd3a7c42c671e0067a2a2639b43a"), 0x20E8F5EB, 0x315E)
    assert iv == h("cd3a7c42e69915ed7a2a263985640000")
    assert xor(payload, ctr(seed(h("0c5ffd37a11edc42c325287fc0604f2e")), iv, 160))[:16] == h(
        "df5a89291e7e383e9beff765e691a737"
    )
    nonce, aad = h("000020e8f5eb00000000315e"), h("8008315ebf2e6fe020e8f5eb")
    # RFC 5669 A.2, A.3.
    assert ccm_seal(seed(h("974bee725d44fc3992267b284c3c6750")), nonce, aad, payload, 10)[-18:] == h(
        "7a57e3919c5dab82 b0a8274cf6a8bb6cc466"
    )
    assert gcm_seal(seed(h("e91e5e75da65554a48181f3846349562")), nonce, aad, payload, 12)[-20:] == h(
        "4acb0087eefbac99 36cd9ae602be3ee2cd8d5d9d"
    )


def main():
    self_check()
    inputs = {}
    for line in open(os.path.join(HERE, "libsrtp.txt")):
        if line.startswith("#") or not line.strip():
            continue
        case, kind, inp, _ = line.split()
        k, prof = case.split(":")
        if prof == "Aes128CmHmacSha1_80":
            inputs.setdefault(k, []).append((kind, h(inp)))
    key0, salt0 = bytes(range(1, 17)), bytes(0xA0 + i for i in range(14))
    key1, salt1 = bytes(0x40 + i for i in range(16)), bytes(0xC0 + i for i in range(14))
    mki0, mki1 = h("01020304"), h("0a0b0c0d")
    out = [
        "# SRTP/SRTCP packets protected by testdata/f8_seed.py (an independent Python implementation on",
        "# pyca/cryptography 41 AES and SEED): the inputs of the libsrtp.txt Aes128CmHmacSha1_80 cases under",
        "# the AES-f8 and SEED profiles. <case> <rtp|rtcp> <input> <protected>; same keys, MKIs, re-keying",
        "# points, RFC 6904 IDs (1, 3, 14) and cryptex as libsrtp.txt. `kdf <profile> <label> <r> <out>`:",
        "# PRF outputs for the RFC 3711 B.3 master key and salt.",
    ]
    for kind in ("plain", "mki", "hdrext", "cryptex", "cryptex+mki"):
        for prof in PROFILES:
            keys = [Keys(prof, b"", key0, salt0)]
            if "mki" in kind:
                keys = [Keys(prof, mki0, key0, salt0), Keys(prof, mki1, key1, salt1)]
            tx = Sender(prof, keys, (1, 3, 14) if kind == "hdrext" else (), kind.startswith("cryptex"))
            nrtp = nrtcp = 0
            for what, pkt in inputs[kind]:
                if what == "rtp":
                    ki = 1 if kind == "mki" and nrtp >= 2 else 0
                    nrtp += 1
                    prot = tx.protect_rtp(pkt, ki)
                else:
                    ki = 1 if kind == "mki" and nrtcp >= 1 else 0
                    nrtcp += 1
                    prot = tx.protect_rtcp(pkt, ki)
                out.append(f"{kind}:{prof} {what} {pkt.hex()} {prot.hex()}")
    E = seed(h("E1F97A0D3E018BE0D64FA32C06DE4139"))
    ms = h("0EC675AD498AFEEBB6960B3AABE6")
    for label, r, n in ((0, 0, 16), (1, 0, 20), (2, 0, 14), (2, 0, 12), (3, 0x0102_0304_0506, 16), (6, 7, 16), (7, 7, 12)):
        out.append(f"kdf SeedCtrHmacSha1_80 {label} {r:x} {prf(E, ms, label, r, n).hex()}")
    with open(os.path.join(HERE, "f8_seed.txt"), "w") as f:
        f.write("\n".join(out) + "\n")


if __name__ == "__main__":
    main()
