# ADR-038: Certificate revocation: CRLs, OCSP and stapled-response validation

English | [简体中文](038-x509-revocation.zh-CN.md)

Status: accepted (2026-11-18)

## Context

`akio-x509` built and validated chains but had no revocation at all, and `akio-tls` stapled OCSP
responses on servers and handed the client the raw bytes with "not verified" in the docs. A
client could not tell a revoked certificate from a good one without bringing its own ASN.1 and
signature code, and a server could not refuse revoked client certificates.

Revocation information has to be fetched (CRLs from distribution points, OCSP from responders),
but the library runs handshakes on I/O threads that must never block, and has no HTTP client of
its own below `akio-http`. Fetching therefore stays with the application; the library parses,
authenticates and applies what it is given.

## Decision

1. **`akio-x509` CRLs** (RFC 5280 section 5): `Crl` parses v1/v2 CRLs strictly (signature
   algorithm match, `critical` DEFAULT FALSE omitted, no duplicate extensions, at most one
   "akio" flag in an issuingDistributionPoint), with cRLNumber, deltaCRLIndicator,
   issuingDistributionPoint (fullName, onlyUser/onlyCA/onlySomeReasons/indirect/attribute),
   authorityKeyIdentifier, and per entry reasonCode, invalidityDate and holdInstructionCode.
   Entries are sorted by serial for a binary search. An unknown critical CRL or entry extension
   (certificateIssuer of indirect CRLs included) makes the CRL unusable for lookups rather than
   unparsable. `verify_signed_by(issuer)` checks the name, cRLSign (when keyUsage is present)
   and the signature, and remembers the issuer key after the first success, so a large CRL is
   hashed and verified once, not per handshake.
2. **`CrlSet::status(cert, issuer, now, skew)`** answers `Good`, `Revoked { time, reason }` or
   `Unknown` (RFC 5280 section 6.3 without indirect CRLs): a CRL is used if it is from the
   issuer (name and signature), current (thisUpdate ≤ now + skew, nextUpdate required and
   ≥ now − skew), in scope (IDP user/CA restriction; its fullName must match one of the
   certificate's distribution points, or the issuer as a directoryName when the certificate
   has none) and free of unsupported critical extensions. A listing in a used complete CRL
   revokes (removeFromCRL entries ignored there); `Good` needs the used complete CRLs to cover
   every reason (an onlySomeReasons partition counts); the newest current delta whose base is
   at most the newest used complete CRL's number then adds revocations, and its removeFromCRL
   lifts a certificateHold.
3. **`Verifier::crls(&set)`** checks every certificate below the root during path building
   (after each signature check), so a revoked intermediate fails that path and an alternative
   path may still succeed. `RevocationMode::{SoftFail (default), HardFail}` decides about
   certificates no CRL covers (`Error::RevocationUnknown`); revoked ones fail with
   `Error::Revoked(reason)`. `Verifier::clock_skew` (default `DEFAULT_CLOCK_SKEW`, 300 s).
4. **`akio-x509` OCSP** (RFC 6960): `OcspResponse` (status, `BasicOcspResponse` with responder
   ID by name or key, producedAt, single responses with CertID, good / revoked (time, reason) /
   unknown, thisUpdate, nextUpdate, nonce, included certificates). `verify(cert, issuer,
   &OcspValidation)` requires: a successful response; a signer that is the issuer itself or an
   included certificate matching the responder ID, issued and signed by the issuer, with
   id-kp-OCSPSigning, digitalSignature if keyUsage is present, valid at now ± skew; a valid
   signature over ResponseData; no unsupported critical extension; the expected nonce if one
   is set (compared in constant time; RFC 8954 OCTET STRING form, raw form accepted); a
   single response whose CertID (SHA-1/256/384/512) names the certificate; thisUpdate ≤ now +
   skew and nextUpdate (or thisUpdate + `max_age`, default one day, when absent) ≥ now − skew.
   Errors (`UnauthorizedResponder`, `BadSignature`, `NonceMismatch`, `NoMatchingResponse`,
   `RevocationInfoNotYetValid`, `RevocationInfoExpired`, `OcspStatus`) mean "not trustworthy";
   `Ok(Unknown)` is the responder's own answer. `OcspRequest` encodes requests (SHA-1 CertID,
   optional nonce) byte-identical to `openssl ocsp`'s.
5. **Hooks for fetching.** `Certificate::crl_distribution_points()` (fullName, reasons,
   cRLIssuer), `ocsp_urls()` and `ca_issuer_urls()` (authorityInfoAccess) tell an application
   where to fetch; these two extensions are parsed leniently (a malformed one only loses the
   pointer, the certificate still parses). `CrlParams` and `OcspResponseParams` build signed
   CRLs and responses for tests, development CAs and servers that sign their own staples.
6. **`akio-tls`** (additive public API): `RevocationPolicy::{Off (default), SoftFail,
   HardFail}`; `ClientConfigBuilder::ocsp_policy(policy)` validates the stapled response for the
   leaf (TLS 1.3: the status_request of the leaf's CertificateEntry, checked when the
   Certificate arrives; TLS 1.2: CertificateStatus, checked when ServerKeyExchange arrives) and
   asks for stapling whenever it is not off. Soft fail rejects only an authentic, current
   "revoked" (`certificate_revoked`); hard fail requires an authentic, current "good"
   (otherwise `bad_certificate_status_response`, or `certificate_revoked`). `Crls` (DER or PEM)
   with `ClientConfigBuilder::crls(crls, policy)` and `ServerConfigBuilder::client_crls(crls,
   policy)` run the chain check of item 3 for the server's chain and for client certificates
   (revoked: `certificate_revoked`; uncovered under hard fail: `certificate_unknown`).
   Resumed sessions are not re-checked (no certificate is sent); `insecure_skip_verify` skips
   OCSP; refreshing CRLs means building a new configuration.
7. **Not done**: indirect CRLs and CRLs signed by a separate CRL-signing key of the CA; delta
   CRLs pointed to by freshestCRL are not fetched (nothing is); signed OCSP requests; the OCSP
   check of intermediates (stapling covers the leaf; `status_request_v2` is not implemented);
   OCSP responses in TLS 1.3 client authentication; an OCSP must-staple (TLS feature)
   extension check.

## Consequences

- Clients can refuse revoked servers with nothing but configuration, and servers can refuse
  revoked client certificates. Tests: OpenSSL-made CRLs (complete, delta on base 1, IDP
  onlyUser with a fullName, a root CRL) and OCSP responses (delegated responder, by the CA,
  byKey, SHA-256 CertID, no nextUpdate, nonce, revoked, certificateHold, unknown, two single
  responses, no OCSPSigning EKU, a responder certified by another CA, signer not included),
  with expiry and skew on both edges, corrupted signatures and every truncation
  (`akio-x509/tests/revocation.rs`, fixtures from `tests/data/revocation/gen.sh`); generated
  CRLs and responses for holds lifted by deltas, onlyCA scopes, partial reason coverage, a
  revoked intermediate and expired responder certificates; in-memory TLS 1.3 and 1.2
  handshakes for each policy and response kind and for CRLs on both sides
  (`akio-tls/src/proto/revocation_tests.rs`); interop: akio's client against `openssl
  s_server -status_file` (good, revoked, missing staple under soft and hard fail) and against
  OpenSSL-made CRLs (`tools/interop/tls/run.sh`).
- With every policy off (the default) the handshake does the same work as before: the
  verified path, which the verifier already built, is returned instead of dropped, and the
  checks are one comparison each. `tls-bench handshakes` on gpu51 (`quiet.sh`, same-run A/B,
  5 alternating pairs, medians, full handshakes/s): X25519 5460 before, 5436 after; secp256r1
  5514 / 5509; X25519 with an RSA-2048 certificate 3300 / 3295 (1.00x, noise; rustls in the
  same runs moved as much).
- Fuzz targets `x509_crl` and `x509_ocsp` (seeded with the OpenSSL fixtures) ran 661 s each on
  gpu51 (25.6M and 12.9M inputs) without a failure; `fuzzing::tests` replay their corpora on
  stable.
- Soft fail is weak by design (an attacker who can block or strip the staple makes it pass);
  it is there for deployments that cannot afford an outage when a responder is down. Hard
  fail breaks with servers that do not staple.
- A `CrlSet` lives inside an immutable configuration: an application that refreshes CRLs
  builds a new configuration (cheap compared to a CRL download) and swaps it in.
