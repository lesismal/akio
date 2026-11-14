# only-x509

[中文](README.zh-CN.md)

X.509 certificates for [`only`](https://github.com/lesismal/only), on
[`only-crypto`](../only-crypto), in safe Rust (`#![forbid(unsafe_code)]`) with no other
dependencies. It is the certificate layer of the in-house TLS 1.2/1.3, DTLS and QUIC stacks
planned in DEV-PLAN waves C and D (and will replace `rcgen` for test certificates). An internal
crate (docs/api-stability.md): its API follows those stacks and may change in any release.

- `Certificate`: strict DER parsing of v1/v3 certificates (trailing data, BER lengths, explicit
  v1, duplicate extensions and mismatched signature algorithms are rejected); subjectAltName
  (DNS, IP, e-mail, URI, directoryName), basicConstraints, keyUsage, extKeyUsage,
  nameConstraints, subject/authority key identifiers; unknown critical extensions are recorded
  and fail verification; PEM in and out; `verify_signed_by`.
- `Verifier` over a `RootStore`: path building through unordered intermediates (depth limit,
  loop detection, a budget of signature checks), validity times, CA bit and pathLenConstraint,
  keyCertSign, extKeyUsage on the leaf and intermediates (server or client auth),
  CA-as-end-entity rejection, name constraints (DNS, IP and directoryName; other forms fail
  closed), and RFC 6125 server names: DNS names match dNSName SANs case-insensitively, a
  wildcard only as the whole leftmost label and never over a public-suffix-like single label
  (`*.com`), IP addresses match iPAddress SANs only; the common name is not used. Trust anchors
  are subject name plus key (their own validity is not checked, as in rustls-webpki).
- `CertificateParams` and `generate_simple_self_signed`: self-signed and CA-signed certificates
  signed with ECDSA P-256 (default for generated keys) or P-384, Ed25519 or RSA keys; SANs,
  validity, serial, CA/pathLen, key usage, EKU, name constraints, custom extensions, key
  identifiers.

Supported signature algorithms: ECDSA with SHA-256/384/512 (P-256, P-384 keys), Ed25519, RSA
PKCS#1 v1.5 with SHA-256/384/512 (SHA-1 for verifying legacy certificates) and RSA-PSS with
SHA-256/384/512. Not implemented: revocation (CRL, OCSP), certificate policies, Ed448, DSA.

```rust
use only_crypto::pkey::PrivateKey;
use only_x509::{CertificateParams, RootStore, Verifier};

let ca_key = PrivateKey::P256(only_crypto::p256::SecretKey::generate().unwrap());
let ca = CertificateParams::ca("Dev CA").self_signed(&ca_key).unwrap();
let key = PrivateKey::P256(only_crypto::p256::SecretKey::generate().unwrap());
let cert = CertificateParams::new(["localhost", "127.0.0.1"])
    .signed_by(&key.public_key(), &ca, &ca_key)
    .unwrap();
let (cert_pem, key_pem) = (cert.to_pem(), key.to_pkcs8_pem());

let mut roots = RootStore::new();
roots.add(ca);
Verifier::new(&roots).verify_server(&cert, &[], "localhost").unwrap();
# let _ = (cert_pem, key_pem);
```

## Testing

- Real-world chains (vendored public certificates, `tests/data/real`): Google Trust Services
  (ECDSA, root cross-signed by GlobalSign's SHA-1 RSA root), Let's Encrypt ECDSA (ISRG Root X2,
  also reachable through X1) and RSA (ISRG Root X1), each verified at a time inside the
  validity windows, plus wrong-name, expired, not-yet-valid, missing-intermediate, wrong-usage
  and corrupted-signature negatives.
- OpenSSL-made chains and keys (`tests/data/openssl`, generated in Docker): an RSA-3072 root, a
  P-384 intermediate signed with RSA-PSS, Ed25519 and RSA leaves with wildcard and IPv4/IPv6
  SANs; PKCS#8, SEC1 and PKCS#1 key files; OpenSSL's ECDSA, Ed25519, RSA PKCS#1 and PSS
  signatures verified, and ours equal OpenSSL's where deterministic. These keys are test-only.
- Interop: rcgen (ring) certificates verify here and rcgen loads our PKCS#8 keys; our CA and
  leaf certificates verify with rustls-webpki (dev-dependencies only).
- Constructed negatives in the spirit of BetterTLS / x509-limbo: pathLen exceeded, non-CA
  issuer, CA as end entity, missing keyCertSign, intermediate EKU without serverAuth, expired
  intermediate, unknown critical extension, wrong signing key, name-constraint violations
  (DNS, excluded subtrees, IP ranges, look-alike suffixes), wildcard edge cases, every
  truncation and many corruptions of a certificate.
- Fuzzing: target `x509_parse` (certificate/PEM/SPKI/PKCS#8 parsing, round trips,
  self-verification) in `fuzz/`; `fuzzing::tests` replays `fuzz/corpus/x509_parse` on stable.
