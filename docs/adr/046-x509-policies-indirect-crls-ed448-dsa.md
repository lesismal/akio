# ADR-046: Certificate policies, indirect CRLs, Ed448, X448 and DSA verification

English | [简体中文](046-x509-policies-indirect-crls-ed448-dsa.zh-CN.md)

Status: accepted (2026-11-19)

## Context

akio-x509's README listed what RFC 5280 path validation it did not do: certificate policies,
indirect CRLs and CRLs signed by another key of the CA, signed OCSP requests, fetching anything
over the network, Ed448 and DSA. Policies matter to government and enterprise PKIs (and to
anyone validating against NIST PKITS); indirect CRLs and separate CRL-signing keys are how such
PKIs publish revocation; Ed448 is the other EdDSA curve of RFC 8032 / RFC 8410 and TLS 1.3
(`ed448`, group `x448`); DSA certificates still exist in legacy PKIs and in PKITS.

The verifier built paths depth-first from the leaf and checked revocation of each certificate
while extending the path, against CRLs signed by that certificate's issuer only. Policies were
parsed as "understood" and ignored, so a critical certificatePolicies passed and a critical
policyConstraints failed as unknown.

## Decision

1. **akio-crypto** (internal tier; enums are `#[non_exhaustive]`):
   - `hash::{Shake128, Shake256}` (FIPS 202): a Keccak-f[1600] sponge with `update` and
     `squeeze` (extendable output, not the `Hash` trait).
   - `ed448` (RFC 8032 §5.2, pure Ed448, empty context): `SigningKey::{from_seed, generate,
     seed, verifying_key, sign}`, `VerifyingKey::{from_bytes, as_bytes, is_weak, verify}`.
     Verification is strict like `ed25519` (canonical `S`, unused key bits zero, cofactorless
     equation compared on the encoding of `R`).
   - `x448` (RFC 7748): `x448()`, `PrivateKey::{generate, from_bytes, to_bytes, public_key,
     diffie_hellman}` (rejects the all-zero result), `BASEPOINT`, `KEY_LEN`.
   - Both on a private `curve448` module: GF(2⁴⁴⁸ − 2²²⁴ − 1) and the scalar field on the
     generic Montgomery code of `field.rs` (seven limbs, masked corrections, Fermat inversion),
     edwards448 in projective coordinates with RFC 8032's complete formulas; secret scalars use
     fixed 4-bit windows with masked full-table scans, the ladder masked swaps. No assembly:
     these curves are rare enough that portable constant-time code is the right trade.
     `tools/ct-dudect` gains `x448`, `ed448-keygen` and `ed448-sign`.
   - `dsa` (FIPS 186-4 §4.7), verification only: `PublicKey::{from_components, from_der,
     params_der, key_der, p_bits, q_bits, verify, verify_prehash}`. Only the FIPS sizes
     (1024/160, 2048/224, 2048/256, 3072/256) are accepted, and keys are checked once
     (`1 < g, y < p`, `g^q = y^q = 1 mod p`). On the existing bignum code, variable time (public
     data).
   - `rsa::HashAlg::Sha224` (DSA with SHA-224; not offered for RSA signing),
     `pkey::SignatureAlgorithm::{Ed448, DsaSha1, DsaSha224, DsaSha256}`,
     `pkey::PublicKey::{Ed448, Dsa}`, `pkey::PrivateKey::Ed448` (PKCS#8), and the OIDs in
     `der::oid` (`ED448`, `X448`, `DSA`, `DSA_WITH_SHA*`). DSA parameters inherited from the
     issuer (absent in the SubjectPublicKeyInfo, RFC 3279 §2.3.2) are not supported.
2. **akio-x509, certificate policies** (RFC 5280 §6.1): certificatePolicies, policyMappings,
   policyConstraints and inhibitAnyPolicy are parsed strictly (a repeated policy OID, an empty
   policyConstraints or mappings list is an encoding error) and exposed
   (`Certificate::{certificate_policies, policy_mappings, policy_constraints,
   inhibit_any_policy, is_self_issued}`, `PolicyConstraints`, `ext::{ANY_POLICY,
   POLICY_MAPPINGS, POLICY_CONSTRAINTS, INHIBIT_ANY_POLICY}`). Processing runs on every
   validated path, with the inputs of `Verifier::policies(PolicyOptions)`
   (`initial_policy_set`, empty for any-policy; `explicit_policy`; `inhibit_policy_mapping`;
   `inhibit_any_policy`). It uses the **policy graph of RFC 9618** instead of the tree: at most
   one node per policy OID per depth, so crafted mappings cannot make it exponential
   (CVE-2023-0464). `Verifier::verify_path` returns a `VerifiedPath { chain, policies }` where
   `policies` is the user-constrained policy set (`ValidPolicies::{Any, Set}`); `verify` keeps
   returning the chain. A failure is `Error::PolicyViolation`. With the default options a path
   fails only when a certificate's policyConstraints require an explicit policy and none is
   valid, which RFC 5280 requires of any validator.
3. **akio-x509, the rest of §6.1 the tests exposed**: self-issued intermediates do not count
   against pathLenConstraint (§6.1.4 (l)) and are exempt from name constraints (§6.1.3 (b));
   rfc822Name and URI name constraints are evaluated (mailbox, host and `.domain` forms; a URI
   without an authority, or with an IP literal, fails closed) and the legacy `emailAddress`
   attribute of the leaf's subject is checked against rfc822Name constraints (before, an
   address there escaped them); `Verifier::allow_ca_end_entity(bool)` validates a CA
   certificate as the end entity (PKITS does, the Web PKI default stays "no").
4. **akio-x509, revocation (§6.3.3)**: the verifier now checks revocation once a candidate path
   reaches a root, from the top down, so it knows the trust anchor. A CRL is used when its
   scope fits the certificate: for each distribution point, the CRL issuer must be the
   certificate's issuer or, for an **indirect CRL** (`indirectCRL` in the IDP), the point's
   cRLIssuer; the IDP name must match the point's name (`nameRelativeToCRLIssuer` included:
   `DistributionPoint::relative_name`, `IssuingDistributionPoint::relative_name`) or its
   cRLIssuer; the reasons are the IDP's onlySomeReasons intersected with the point's reasons.
   Entries of an indirect CRL belong to the issuer their certificateIssuer extension names,
   carried forward to later entries (`RevokedCertificate::certificate_issuer`,
   `Crl::find_for(serial, issuer)`). The CRL's signature is checked against the certificate's
   issuer first; otherwise against a certificate with the CRL issuer's name and cRLSign — a
   **separate CRL-signing key** of the CA or the indirect CRL issuer — found among the
   intermediates, the new `Verifier::crl_signers(&[Certificate])` and the roots, whose own path
   must validate to the **same trust anchor**, including its revocation (signer paths of
   signer paths are validated without further revocation checks; everything counts against
   `MAX_SIGNATURE_CHECKS`). `CrlSet::status` keeps its contract (only the issuer's own key) and
   gains the distribution point matching. Delta CRLs must have the same issuer and IDP as the
   complete CRL they extend. Serial numbers are compared as signed INTEGER contents (a CRL
   entry for −1 no longer matches certificate 255).
5. **akio-tls**: group `x448` (0x001e, last in the default list, so ClientHellos list it but
   send their key share for X25519) and signature scheme `ed448` (0x0808) in TLS 1.3 and 1.2
   (ECDSA suites), certificates included (`Group::X448` in the hidden `__proto` module).
6. **Validation**: NIST PKITS through `crates/akio-x509/tests/pkits.rs` (`tools/pkits/prepare.sh`
   downloads the suite; not vendored). Every test of section 4 runs with the settings the PKITS
   document lists, revocation in hard-fail mode: 242 of 248 runs as expected; the 6 others are
   listed with reasons (DSA parameter inheritance; name chaining by DER bytes rather than with
   RFC 4518 folding, a deliberate choice since the first version). FIPS 186-4 SigVer vectors
   for DSA, RFC 8032 and 7748 vectors for Ed448 and X448, OpenSSL-made Ed448 and DSA
   certificates and CRL, and akio-tls against `openssl s_server` / `s_client` with X448 and
   Ed448.

Not done, on purpose:

- **Signed OCSP requests** (RFC 6960 §4.1.2 optional signature): public responders do not
  require them (the RFC 5019 profile that CAs follow sends unsigned requests, and most
  responders ignore a signature), and only a client certificate and key the application holds
  could sign them. `OcspRequest` stays unsigned.
- **Fetching CRLs, OCSP responses or issuer certificates over the network**: akio-x509 and
  akio-tls are sans-io; fetching needs an HTTP client above them in the dependency graph, would
  block or stall a handshake on a third party (rules.md, rule 1), leaks to the CA which sites a
  client visits, and follows URLs from attacker-supplied certificates (SSRF). The application
  fetches; `crl_distribution_points`, `ocsp_urls` and `ca_issuer_urls` say where.

## Consequences

- The default verifier rejects paths whose policyConstraints require an explicit policy that
  is absent (RFC behaviour; Web PKI chains do not carry such constraints). Certificates with a
  malformed policy extension no longer parse.
- With CRLs configured, revocation is checked after a path is found instead of during the
  search: a revoked intermediate still makes the search try another path. Errors on a path
  rank as before.
- `RevokedCertificate`, `DistributionPoint` and `IssuingDistributionPoint` gain a public field
  each (struct literals need it); `pkey`/`rsa` enums gain variants (they are non-exhaustive).
- Ed448 and X448 are an order of magnitude slower than Ed25519 and X25519, which have assembly
  and precomputed tables (`pk_bench 448` on an Apple M-series core: Ed448 sign 5.5k/s, verify
  4.1k/s, X448 5.6k/s, DSA-2048 verify 1.2k/s); neither is on a default fast path (X448 is
  offered last, never sent as the first key share).
