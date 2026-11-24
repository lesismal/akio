# ADR-107: Certificate signing requests in akio-x509

English | [简体中文](107-x509-certificate-requests.zh-CN.md)

Status: accepted (2026-11-23)

## Context

akit, the gateway built on akio, issues certificates over ACME (RFC 8555) with a client of its
own, as fit does over Go's `x/crypto/acme`. Finalizing an order sends a PKCS#10 certificate
signing request (RFC 2986) for the order's names, signed by the certificate's key (akit's
request A6). `akio-x509` generated certificates, CRLs and OCSP responses but not requests, and a
gateway should not carry its own ASN.1 for one. JWS signatures, the other half of A6, need nothing
new: `PrivateKey::sign` with `SignatureAlgorithm` already gives ES256/384/512, EdDSA and RS256 in
the raw forms JWS uses.

## Decision

- **`CsrParams`** (subject, subjectAltNames, extKeyUsage, further extensions) with
  `CsrParams::new(names)` (the first DNS name as the common name, as `CertificateParams::new`
  does) and `sign(&PrivateKey) -> CertificateRequest`, signed with the key's default algorithm.
  Requested extensions go in one `extensionRequest` attribute; subjectAltName is critical when the
  subject is empty (RFC 5280 §4.2.1.6).
- **`CertificateRequest`**, parsed strictly from DER or PEM (`CERTIFICATE REQUEST`, and the legacy
  `NEW CERTIFICATE REQUEST` label), with the subject, public key, signature algorithm, requested
  extensions and subjectAltNames, other attributes left unparsed, and `verify_signature` for the
  proof of possession. Version must be v1 (0); an empty attribute list may be omitted and an
  empty `extensionRequest` (as OpenSSL writes) is accepted.
- **Limits**: `MAX_REQUEST_LEN` (64 KiB) and `MAX_ATTRIBUTES` (32); a duplicate attribute or
  extension is an error.
- Fuzz target `x509_csr` with OpenSSL- and akio-made seeds, replayed by the unit tests on stable.

## Consequences

ACME clients (akit's, or an application's) and test CAs can make and check requests with no new
dependency. Additive API; no change to certificate parsing or verification.

## Verification

Unit tests (P-256, P-384, Ed25519, names and IP addresses, EKU and custom extensions, tampered
requests, bad versions, truncation, size limit, PEM blocks); interop: requests made by rcgen (P-256,
P-384, Ed25519) and by OpenSSL 4.1 (RSA with SANs and EKU; Ed25519 with challengePassword and an
empty extensionRequest) parse and verify here, and a request made here passes
`openssl req -verify`.
