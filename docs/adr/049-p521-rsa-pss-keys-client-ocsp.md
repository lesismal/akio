# ADR-049: P-521, RSA-PSS keys and the client's OCSP response in TLS 1.3

English | [简体中文](049-p521-rsa-pss-keys-client-ocsp.zh-CN.md)

Status: accepted (2026-11-19)

## Context

akio-tls's README listed, among what it did not implement: RSA-PSS keys, P-521, a client's OCSP
response in TLS 1.3 client authentication and `status_request_v2`. akio-crypto had ECDH and
ECDSA on P-256 and P-384 only, and RSA keys only as `rsaEncryption` (RSASSA-PSS signatures with
such keys, the TLS 1.3 `rsa_pss_rsae_*` schemes, were supported). Certificates whose key is an
`id-RSASSA-PSS` key (RFC 4055, OpenSSL's `genpkey -algorithm RSA-PSS`) and P-521 certificates
did not parse, and peers offering only secp521r1 or the `rsa_pss_pss_*` schemes could not
connect. RFC 8446 section 4.4.2.1 also lets a server ask a TLS 1.3 client to send an OCSP
response with its certificate; akio-tls's server never asked and its client never sent one,
although the server-side machinery of ADR-038 (the stapled response, validated under a
`RevocationPolicy`) was there.

## Decision

1. **akio-crypto, P-521** (internal tier): a new `p521` module with the API of `p256` / `p384`
   (`SecretKey`, `PublicKey`, `Signature`, `SCALAR_LEN = 66`; SHA-512 by default, any `Hash`
   for prehashing, RFC 6979 nonces with `bits2int` over the leftmost 521 bits, DER and 132-byte
   fixed-width signatures, compressed and uncompressed SEC1 points, validated). It is its own
   code, not the generic `ec` module, which assumes a scalar of `8·L` bytes and proves the
   absence of exceptional cases from `n` being close to `2^(64L)`; P-521 sits in nine 64-bit
   limbs with 55 bits to spare. Instead:
   - the base field `GF(2⁵²¹ - 1)` in nine unsaturated limbs (eight of 58 bits, one of 57):
     the product's high half folds onto the low half doubled (`2⁵²² ≡ 2`), one carry chain whose
     top carry re-enters at limb 0; additions and subtractions (with a `2p` offset) end in one
     carry step done for every limb at once; inversion `a^(p-2)` and square roots `a^(2⁵¹⁹)`
     by fixed chains. The limb bounds are written down in the module and asserted by tests;
   - points in projective coordinates with the complete formulas of Renes, Costello and Batina
     (`a = -3`), so no exceptional case needs an argument: ECDH by signed 5-bit Booth windows
     over `0·P … 16·P` with full-table masked scans, the doublings in Jacobian coordinates
     (dbl-2001-b, which maps the identity `(1:1:0)` to itself; no point of order two exists),
     key generation and signing by a signed 4-bit comb of 131 rows of affine multiples of `G`
     (complete mixed additions, the whole row read for every digit); verification by
     interleaved wNAF, variable time on public data;
   - the scalar field on the generic Montgomery code of `field.rs` (nine limbs). Portable Rust
     only: P-521 is rare enough that assembly is not worth it. `tools/ct-dudect` gains
     `p521-ecdh`, `p521-keygen` and `p521-sign`.
   - `pkey::PublicKey::P521`, `pkey::PrivateKey::P521` (SPKI, PKCS#8, SEC1), `der::oid::SECP521R1`.
2. **akio-crypto, RSA-PSS keys**: `pkey::PublicKey::RsaPss(rsa::PublicKey, Option<PssParams>)`
   and `pkey::PrivateKey::RsaPss(Box<rsa::PrivateKey>, Option<PssParams>)` for the
   `id-RSASSA-PSS` algorithm in SubjectPublicKeyInfo and PKCS#8, with or without
   `RSASSA-PSS-params`. `PssParams { hash, salt_len }` (`new`, `from_der`, `to_der`, `allows`):
   only SHA-256/384/512 with MGF1 over the same hash and trailer 1 are supported (absent
   fields default to SHA-1 per RFC 4055, which fails as `Unsupported`). Such a key signs and
   verifies RSASSA-PSS only (never PKCS#1 v1.5), and with parameters only with their hash and a
   salt (the hash length, as TLS 1.3 and X.509 use) at least their minimum. Its default
   certificate signature algorithm is RSA-PSS with its hash (SHA-256 without parameters). The
   encodings equal OpenSSL's byte for byte.
3. **akio-x509**: no API change. Certificates with P-521 and `id-RSASSA-PSS` keys parse, verify
   and are issued (`CertificateParams::signed_by` with such a key); a certificate signature is
   checked against the issuer key's restrictions.
4. **akio-tls**:
   - group secp521r1 (0x0019), offered last in the default list (after x448: a ClientHello
     lists it, its key share goes for X25519); signature scheme `ecdsa_secp521r1_sha512`
     (0x0603) for P-521 keys (TLS 1.2: any ECDSA scheme fits any curve, as before for P-256 and
     P-384); `rsa_pss_pss_sha256/384/512` (0x0809–0x080b) for `id-RSASSA-PSS` keys, server and
     client certificates, TLS 1.3 and 1.2 (ECDHE-RSA suites), within the key's parameters. The
     `rsae` and `pss` schemes are never crossed between the two key kinds (RFC 8446 4.2.3).
   - **The client's OCSP response** (RFC 8446 4.4.2.1): `ServerConfigBuilder::client_ocsp_policy(
     RevocationPolicy)` sends an empty `status_request` in the TLS 1.3 CertificateRequest and
     validates what the client staples to its leaf's CertificateEntry exactly as
     `ClientConfigBuilder::ocsp_policy` validates a server's (ADR-038: issuer or delegated
     responder, about this certificate, current within 5 minutes; soft fail refuses only a
     valid "revoked", hard fail requires a valid "good"). `ClientConfigBuilder::
     client_cert_ocsp_response(der)` is the client's response, sent only when asked.
     `TlsInfo::ocsp_response` on the server is the client's response. TLS 1.2 has no way for a
     client to send one: under hard fail, TLS 1.2 client certificates are refused (servers that
     want this pair it with `tls13_only`). A response the server did not ask for is ignored, as
     the client ignores a server's unasked one. Resumed sessions are not checked again.
5. **Validation**: Wycheproof ECDSA P-521/SHA-512 (DER and P1363) and ECDH P-521 vectors
   (vendored), RFC 6979 A.2.7 (SHA-512 and SHA-256, also what OpenSSL's deterministic ECDSA
   gives), OpenSSL-made RSA-PSS keys (with and without parameters) and signatures, OpenSSL-made
   P-521 and RSA-PSS-key certificate chains in akio-x509; in-memory TLS matrices with P-521 and
   RSA-PSS-key certificates (server and client, both versions), secp521r1, and the client OCSP
   response under every policy; `tools/interop/tls/run.sh` against OpenSSL (secp521r1, P-521
   and RSA-PSS-key certificates both ways in TLS 1.3 and 1.2, such client certificates, and
   OpenSSL's client and server around the client OCSP request, which OpenSSL neither sends nor
   asks for) and Go (P-521 certificates and curve). Fuzzing: `x509_parse` (SPKI and PKCS#8
   parsing, now with PSS parameters and P-521 points), `tls_server` (the client's
   CertificateEntry extensions).

Not done, on purpose:

- **`status_request_v2`** (RFC 6961, OCSP for intermediates): TLS 1.2 only, never adopted
  widely (OpenSSL, Go, BoringSSL and rustls never implemented it), and obsoleted by TLS 1.3,
  where every CertificateEntry can carry a status_request response (RFC 8446 4.4.2.1).
- **Signing with a PSS salt other than the hash length**, and PSS keys restricted to SHA-1 or
  to a different MGF1 hash: TLS 1.3 and the Web PKI use only the hash-length salt with
  same-hash MGF1.
- **P-521 assembly**: the portable code is on par with OpenSSL's (see Consequences), and P-521
  is rarely negotiated.

## Consequences

- `pkey::PublicKey`, `pkey::PrivateKey` gain variants (non-exhaustive enums); `pkey::PssParams`,
  `p521`, `der::oid::SECP521R1`, `ServerConfigBuilder::client_ocsp_policy` and
  `ClientConfigBuilder::client_cert_ocsp_response` are new. Code matching `PublicKey::Rsa` to
  mean "an RSA key" should also match `RsaPss`.
- Default ClientHellos list one more group (2 bytes); servers with only secp521r1 or only the
  `rsa_pss_pss_*` schemes now connect. Nothing else in a default handshake changes: the first
  key share stays X25519, the scheme preferred for each existing key type is unchanged.
- P-521 performance (`pk_bench 521`, portable Rust; docs/BENCHMARKS.md): on the x86_64 benchmark
  host against OpenSSL 3.0.13, signing 1.09×, verification 1.05×, ECDH 0.84×; on an Apple
  M-series core against OpenSSL 4.1, signing about 1.07×, ECDH about 0.54×. Default handshakes
  measured unchanged.
