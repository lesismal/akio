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
  nameConstraints, subject/authority key identifiers, certificatePolicies, policyMappings,
  policyConstraints, inhibitAnyPolicy; unknown critical extensions are recorded and fail
  verification; PEM in and out; `verify_signed_by`.
- `Verifier` over a `RootStore`: path building through unordered intermediates (depth limit,
  loop detection, a budget of signature checks), validity times, CA bit and pathLenConstraint,
  keyCertSign, extKeyUsage on the leaf and intermediates (server or client auth),
  CA-as-end-entity rejection (`allow_ca_end_entity` to validate a CA certificate), name
  constraints (DNS, IP, directoryName, rfc822Name including the subject's emailAddress, and
  URI; other forms fail closed; self-issued intermediates exempt, and not counted against
  pathLen), certificate policies (ADR-046: RFC 5280 §6.1 on the policy graph of RFC 9618,
  `Verifier::policies(PolicyOptions)` for the initial policy set, explicit policy and the
  inhibit flags; `verify_path` returns the user-constrained policy set), and RFC 6125 server
  names: DNS names match dNSName SANs case-insensitively, a
  wildcard only as the whole leftmost label and never over a public-suffix-like single label
  (`*.com`), IP addresses match iPAddress SANs only; the common name is not used. Trust anchors
  are subject name plus key (their own validity is not checked, as in rustls-webpki).
- `CertificateParams` and `generate_simple_self_signed`: self-signed and CA-signed certificates
  signed with ECDSA P-256 (default for generated keys) or P-384, Ed25519, Ed448 or RSA keys; SANs,
  validity, serial, CA/pathLen, key usage, EKU, name constraints, custom extensions, key
  identifiers.
- Revocation (ADR-038), without network access (the application fetches;
  `Certificate::crl_distribution_points`, `ocsp_urls` and `ca_issuer_urls` say where):
  `Crl` (RFC 5280 section 5: strict DER/PEM, cRLNumber, delta CRLs, reason codes,
  invalidityDate, issuingDistributionPoint scopes; signature checked against the issuer once and
  remembered) and `CrlSet::status` (good / revoked / unknown with clock skew, deltas and
  removeFromCRL, reason coverage), applied to whole paths by `Verifier::crls` with
  `RevocationMode::{SoftFail, HardFail}`, checked once a candidate path reaches a root; indirect
  CRLs (certificateIssuer entries, a distribution point's cRLIssuer) and CRLs signed by another
  key of the CA, whose signer certificate (among the intermediates, `Verifier::crl_signers` and
  the roots) must validate to the same root (ADR-046, RFC 5280 §6.3.3); `OcspResponse::verify` (RFC 6960: the issuer or a
  delegated responder with id-kp-OCSPSigning, CertID with SHA-1/256/384/512, nonce compared in
  constant time, thisUpdate / nextUpdate with clock skew) and `OcspRequest`; `CrlParams` and
  `OcspResponseParams` build signed CRLs and responses for tests and development CAs.

Supported signature algorithms: ECDSA with SHA-256/384/512 (P-256, P-384 keys), Ed25519, Ed448,
RSA PKCS#1 v1.5 with SHA-256/384/512 (SHA-1 for verifying legacy certificates), RSA-PSS with
SHA-256/384/512, and DSA with SHA-1/224/256 (verification only; FIPS 186-4 sizes; parameters
inherited from the issuer are not supported). Not implemented, on purpose (ADR-046): signed OCSP
requests (responders do not require them; only the application's client key could sign) and
fetching anything over the network (the crate is sans-io; fetching would stall handshakes on
third parties, tell the CA which sites a client visits, and follow attacker-supplied URLs). Names
are chained by their DER bytes (RFC 5280 §7.1 allows it), not with RFC 4518 case and whitespace
folding.

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
- Revocation (`tests/revocation.rs`): OpenSSL-made CRLs (complete, delta, IDP, root) and OCSP
  responses (`tests/data/revocation/gen.sh`: delegated, by the CA, byKey, SHA-256, no
  nextUpdate, nonce, revoked, hold, unknown, multiple; negatives: no OCSPSigning EKU, a responder
  of another CA, signer not included, wrong certificate, expired and not yet valid around the
  skew, corrupted signatures, every truncation); requests byte-identical to `openssl ocsp`'s;
  generated CRLs and responses for deltas lifting holds, scopes, partial reasons, revoked
  intermediates and expired responders.
- NIST PKITS (`tests/pkits.rs`, the suite downloaded by `tools/pkits/prepare.sh`, not vendored):
  every test of section 4 with the policy settings the PKITS document lists and revocation in
  hard-fail mode; 242 of 248 runs as expected, the 6 others listed with the reason (DSA
  parameter inheritance, RFC 4518 name folding).
- Policies, indirect CRLs and separate CRL keys on generated chains (`tests/policy.rs`:
  explicit policy, requireExplicitPolicy, mappings and inhibitPolicyMapping, anyPolicy and
  inhibitAnyPolicy, malformed extensions, indirect CRLs with certificateIssuer, revoked and
  expired CRL signers, negative serial numbers, rfc822Name and URI constraints).
- Ed448 and DSA from OpenSSL (`tests/data/ed448-dsa/gen.sh`): an Ed448 chain, key and
  signature (ours equals OpenSSL's), a DSA 2048/256 root signing P-256 leaves and a CRL.
- Fuzzing: targets `x509_parse` (certificate/PEM/SPKI/PKCS#8 parsing, round trips,
  self-verification, policy accessors), `x509_crl` and `x509_ocsp` (parsing, round trips,
  status lookups including indirect-CRL entries, validation) and `x509_policy` (arbitrary
  paths through policy processing) in `fuzz/`; `fuzzing::tests` replays their corpora on
  stable.
