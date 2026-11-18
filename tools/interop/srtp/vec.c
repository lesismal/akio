// libsrtp cross-check vector generator for only-srtp (a test tool, not a dependency; run.sh
// builds it against libsrtp and compares with crates/only-srtp/testdata/libsrtp.txt).
// Prints: <case> <kind> <hex in> <hex out>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include "srtp.h"

static size_t unhex(const char *s, uint8_t *out) {
    size_t n = 0;
    while (*s) {
        if (*s == ' ') { s++; continue; }
        unsigned v; sscanf(s, "%2x", &v); out[n++] = (uint8_t)v; s += 2;
    }
    return n;
}
static void phex(const uint8_t *b, size_t n) { for (size_t i = 0; i < n; i++) printf("%02x", b[i]); }

typedef struct { const char *name; srtp_profile_t prof; size_t klen, slen; } prof_t;
static const prof_t P[] = {
    {"Aes128CmHmacSha1_80", srtp_profile_aes128_cm_sha1_80, 16, 14},
    {"Aes128CmHmacSha1_32", srtp_profile_aes128_cm_sha1_32, 16, 14},
    {"Aes192CmHmacSha1_80", srtp_profile_aes192_cm_sha1_80, 24, 14},
    {"Aes192CmHmacSha1_32", srtp_profile_aes192_cm_sha1_32, 24, 14},
    {"Aes256CmHmacSha1_80", srtp_profile_aes256_cm_sha1_80, 32, 14},
    {"Aes256CmHmacSha1_32", srtp_profile_aes256_cm_sha1_32, 32, 14},
    {"NullHmacSha1_80", srtp_profile_null_sha1_80, 16, 14},
    {"NullHmacSha1_32", srtp_profile_null_sha1_32, 16, 14},
    {"AeadAes128Gcm", srtp_profile_aead_aes_128_gcm, 16, 12},
    {"AeadAes256Gcm", srtp_profile_aead_aes_256_gcm, 32, 12},
};

static const char *RTP[] = {
    "9160fffe11223344cafebabe01020304bede000110aa000068656c6c6f207372747020776f726c64",
    "a0e0ffff11223345cafebabe0102030405000003",
    "8060000011223346cafebabe000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    "8060000111223347cafebabe090909",
};
static const char *RTCP[] = {
    "80c80006cafebabe0102030405060708112233440000000a000003e8",
    "81c90007cafebabe000000010500000200010003000000040000000500000006",
};

#define CHECK(x) do { srtp_err_status_t e_ = (x); if (e_) { fprintf(stderr, "%s:%d %s -> %d\n", __FILE__, __LINE__, #x, e_); exit(1); } } while (0)

static void key_of(int which, const prof_t *p, uint8_t *k, uint8_t *s) {
    for (size_t i = 0; i < p->klen; i++) k[i] = which ? 0x40 + i : 1 + i;
    for (size_t i = 0; i < p->slen; i++) s[i] = which ? 0xc0 + i : 0xa0 + i;
}

static srtp_t make(const prof_t *p, size_t mki_len, bool cryptex, const uint8_t *ids, size_t nids) {
    srtp_policy_t pol;
    CHECK(srtp_policy_create(&pol));
    CHECK(srtp_policy_set_profile(pol, p->prof));
    srtp_ssrc_t ssrc = {ssrc_any_outbound, 0};
    CHECK(srtp_policy_set_ssrc(pol, ssrc));
    uint8_t k[32], s[14];
    if (mki_len) {
        CHECK(srtp_policy_use_mki(pol, mki_len));
        uint8_t m0[4] = {1, 2, 3, 4}, m1[4] = {0x0a, 0x0b, 0x0c, 0x0d};
        key_of(0, p, k, s);
        CHECK(srtp_policy_add_key(pol, k, p->klen, s, p->slen, m0, 4));
        key_of(1, p, k, s);
        CHECK(srtp_policy_add_key(pol, k, p->klen, s, p->slen, m1, 4));
    } else {
        key_of(0, p, k, s);
        CHECK(srtp_policy_add_key(pol, k, p->klen, s, p->slen, NULL, 0));
    }
    if (cryptex) CHECK(srtp_policy_set_cryptex(pol, true));
    for (size_t i = 0; i < nids; i++) CHECK(srtp_policy_add_enc_hdr_xtnd_id(pol, ids[i]));
    srtp_t sess;
    CHECK(srtp_create(&sess, pol));
    srtp_policy_destroy(pol);
    return sess;
}

static void rtp(srtp_t s, const char *c, const char *in, size_t mki_index) {
    uint8_t a[2048], b[2048];
    size_t n = unhex(in, a), m = sizeof b;
    memcpy(b, a, n); // in place: libsrtp needs it for AEAD cryptex with CSRCs
    CHECK(srtp_protect(s, b, n, b, &m, mki_index));
    printf("%s rtp ", c); phex(a, n); printf(" "); phex(b, m); printf("\n");
}
static void rtcp(srtp_t s, const char *c, const char *in, size_t mki_index) {
    uint8_t a[2048], b[2048];
    size_t n = unhex(in, a), m = sizeof b;
    CHECK(srtp_protect_rtcp(s, a, n, b, &m, mki_index));
    printf("%s rtcp ", c); phex(a, n); printf(" "); phex(b, m); printf("\n");
}

int main(void) {
    CHECK(srtp_init());
    char c[128];
    const char *one = "9160100011223344cafebabe01020304bede000410aa21bbcc3311223344e0550000000068656c6c6f";
    const char *two = "9060100111223345cafebabe100000040103aabbccc8000304112233440e0155776f726c64";
    const char *plain = "8060100311223347cafebabe090909";
    // 1. Every profile: plain RTP (across the rollover) and SRTCP.
    for (size_t i = 0; i < sizeof P / sizeof *P; i++) {
        snprintf(c, sizeof c, "plain:%s", P[i].name);
        srtp_t s = make(&P[i], 0, false, NULL, 0);
        for (int j = 0; j < 4; j++) rtp(s, c, RTP[j], 0);
        for (int j = 0; j < 2; j++) rtcp(s, c, RTCP[j], 0);
        srtp_dealloc(s);
    }
    // 2. MKI: packets 0, 1 under key 0 (01020304), 2, 3 under key 1 (0a0b0c0d).
    for (size_t i = 0; i < sizeof P / sizeof *P; i++) {
        snprintf(c, sizeof c, "mki:%s", P[i].name);
        srtp_t s = make(&P[i], 4, false, NULL, 0);
        for (int j = 0; j < 4; j++) rtp(s, c, RTP[j], j / 2);
        for (int j = 0; j < 2; j++) rtcp(s, c, RTCP[j], j);
        srtp_dealloc(s);
    }
    // 3. RFC 6904: IDs 1, 3, 14 encrypted.
    uint8_t ids[] = {1, 3, 14};
    for (size_t i = 0; i < sizeof P / sizeof *P; i++) {
        snprintf(c, sizeof c, "hdrext:%s", P[i].name);
        srtp_t s = make(&P[i], 0, false, ids, 3);
        rtp(s, c, one, 0);
        rtp(s, c, two, 0);
        rtp(s, c, plain, 0);
        srtp_dealloc(s);
    }
    // 4. Cryptex (with an MKI on the second run).
    for (size_t i = 0; i < sizeof P / sizeof *P; i++) {
        for (int mki = 0; mki < 2; mki++) {
            snprintf(c, sizeof c, "cryptex%s:%s", mki ? "+mki" : "", P[i].name);
            srtp_t s = make(&P[i], mki ? 4 : 0, true, NULL, 0);
            rtp(s, c, one, 0);
            rtp(s, c, two, 0);
            // CSRCs with an empty extension (libsrtp wants it spelt out).
            rtp(s, c, "9260100211223346cafebabe0001e2400000b26ebede0000616263", 0);
            rtp(s, c, plain, 0);
            srtp_dealloc(s);
        }
    }
    return 0;
}
