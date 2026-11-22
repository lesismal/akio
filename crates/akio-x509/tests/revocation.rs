//! CRLs and OCSP responses made by OpenSSL (tests/data/revocation, see gen.sh there) and by
//! this crate's builders.
#![allow(clippy::unwrap_used)]

use akio_crypto::pkey::PrivateKey;
use akio_x509::{
    Certificate, CertificateParams, Crl, CrlParams, CrlSet, Error, GeneralName,
    IssuingDistributionPoint, OcspRequest, OcspResponse, OcspResponseParams, OcspResponseStatus,
    OcspValidation, ReasonFlags, RevocationMode, RevocationReason, RevocationStatus, RootStore,
    Verifier, ext,
};

fn data(name: &str) -> Vec<u8> {
    let p = format!(
        "{}/tests/data/revocation/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(&p).unwrap_or_else(|e| panic!("{p}: {e}"))
}

fn cert(name: &str) -> Certificate {
    Certificate::from_pem(&data(&format!("{name}.pem")))
        .unwrap()
        .remove(0)
}

fn crl(name: &str) -> Crl {
    Crl::from_der(data(name)).unwrap()
}

fn ocsp(name: &str) -> OcspResponse {
    OcspResponse::from_der(data(name)).unwrap()
}

fn set(names: &[&str]) -> CrlSet {
    let mut s = CrlSet::new();
    for n in names {
        s.add(crl(n));
    }
    s
}

const SKEW: u32 = 300;

#[test]
fn openssl_crl_parses() {
    let c = crl("ca.crl");
    let ca = cert("ca");
    assert_eq!(c.version(), 2);
    assert_eq!(c.issuer(), ca.subject());
    assert_eq!(c.crl_number(), Some(&[2][..]));
    assert!(!c.is_delta());
    assert_eq!(c.authority_key_id(), ca.subject_key_id());
    assert_eq!(c.revoked().len(), 2);
    let revoked = cert("revoked");
    let hold = cert("hold");
    let e = c.find(revoked.serial()).unwrap();
    assert_eq!(e.reason, Some(RevocationReason::KeyCompromise));
    assert_eq!(e.revocation_date, c.this_update());
    assert_eq!(
        c.find(hold.serial()).unwrap().reason,
        Some(RevocationReason::CertificateHold)
    );
    assert!(c.find(cert("good").serial()).is_none());
    assert_eq!(c.next_update(), Some(c.this_update() + 30 * 86_400));
    assert!(c.unsupported_critical_extension().is_none());
    c.verify_signed_by(&ca).unwrap();
    // Twice: the second check is remembered.
    c.verify_signed_by(&ca).unwrap();
    assert_eq!(c.verify_signed_by(&cert("root")), Err(Error::UnknownIssuer));
    // PEM round trip.
    let again = Crl::from_pem(c.to_pem().as_bytes()).unwrap();
    assert_eq!(again, vec![c.clone()]);
    assert_eq!(Crl::from_der(c.as_der()).unwrap(), c);
    // The delta and IDP variants.
    let d = crl("ca_delta.crl");
    assert!(d.is_delta());
    assert_eq!(d.delta_base(), Some(&[1][..]));
    assert_eq!(d.crl_number(), Some(&[3][..]));
    let i = crl("ca_idp.crl");
    let idp = i.issuing_distribution_point().unwrap();
    assert!(idp.only_user_certs && !idp.only_ca_certs && !idp.indirect_crl);
    assert_eq!(
        idp.full_name,
        vec![GeneralName::Uri("http://crl.only.test/ca.crl".into())]
    );
    assert_eq!(
        cert("root").subject(),
        crl("root.crl").issuer(),
        "the root's own CRL"
    );
}

#[test]
fn certificate_revocation_pointers() {
    let g = cert("good");
    let dps = g.crl_distribution_points();
    assert_eq!(dps.len(), 1);
    assert_eq!(
        dps[0].full_name,
        vec![GeneralName::Uri("http://crl.only.test/ca.crl".into())]
    );
    assert_eq!(g.ocsp_urls(), ["http://ocsp.only.test/"]);
    assert_eq!(g.ca_issuer_urls(), ["http://ca.only.test/ca.der"]);
    assert!(cert("unlisted").crl_distribution_points().is_empty());
    assert!(cert("unlisted").ocsp_urls().is_empty());
}

#[test]
fn crl_status() {
    let (ca, good, revoked, hold) = (cert("ca"), cert("good"), cert("revoked"), cert("hold"));
    let s = set(&["ca.crl"]);
    let t = s.crls()[0].this_update() + 60;
    assert_eq!(s.status(&good, &ca, t, SKEW), RevocationStatus::Good);
    assert!(matches!(
        s.status(&revoked, &ca, t, SKEW),
        RevocationStatus::Revoked {
            reason: Some(RevocationReason::KeyCompromise),
            ..
        }
    ));
    assert!(matches!(
        s.status(&hold, &ca, t, SKEW),
        RevocationStatus::Revoked {
            reason: Some(RevocationReason::CertificateHold),
            ..
        }
    ));
    // Expired, and not yet valid (beyond the skew), the CRL says nothing.
    let next = s.crls()[0].next_update().unwrap();
    assert_eq!(
        s.status(&revoked, &ca, next + 299, SKEW),
        RevocationStatus::Revoked {
            time: s.crls()[0].this_update(),
            reason: Some(RevocationReason::KeyCompromise)
        }
    );
    assert_eq!(
        s.status(&revoked, &ca, next + 301, SKEW),
        RevocationStatus::Unknown
    );
    assert_eq!(
        s.status(&good, &ca, t - 60 - 301, SKEW),
        RevocationStatus::Unknown
    );
    assert_eq!(
        s.status(&good, &ca, t - 60 - 299, SKEW),
        RevocationStatus::Good
    );
    // The wrong issuer, an empty set.
    assert_eq!(
        s.status(&good, &cert("root"), t, SKEW),
        RevocationStatus::Unknown
    );
    assert_eq!(
        CrlSet::new().status(&good, &ca, t, SKEW),
        RevocationStatus::Unknown
    );
}

#[test]
fn delta_crls() {
    let (ca, good, revoked) = (cert("ca"), cert("good"), cert("revoked"));
    let t = crl("ca_empty.crl").this_update() + 60;
    // CRL 1 predates the revocations.
    let s = set(&["ca_empty.crl"]);
    assert_eq!(s.status(&revoked, &ca, t, SKEW), RevocationStatus::Good);
    // Delta 3 on base 1 adds them.
    let s = set(&["ca_empty.crl", "ca_delta.crl"]);
    assert!(matches!(
        s.status(&revoked, &ca, t, SKEW),
        RevocationStatus::Revoked {
            reason: Some(RevocationReason::KeyCompromise),
            ..
        }
    ));
    assert_eq!(s.status(&good, &ca, t, SKEW), RevocationStatus::Good);
    // A delta alone is not complete information.
    let s = set(&["ca_delta.crl"]);
    assert_eq!(s.status(&good, &ca, t, SKEW), RevocationStatus::Unknown);
    assert!(matches!(
        s.status(&revoked, &ca, t, SKEW),
        RevocationStatus::Unknown
    ));
}

#[test]
fn issuing_distribution_point_scope() {
    let (ca, good, revoked) = (cert("ca"), cert("good"), cert("revoked"));
    let s = set(&["ca_idp.crl"]);
    let t = s.crls()[0].this_update() + 60;
    assert_eq!(s.status(&good, &ca, t, SKEW), RevocationStatus::Good);
    assert!(matches!(
        s.status(&revoked, &ca, t, SKEW),
        RevocationStatus::Revoked { .. }
    ));
    // No cRLDistributionPoints: the IDP's URI name does not match the issuer's name.
    assert_eq!(
        s.status(&cert("unlisted"), &ca, t, SKEW),
        RevocationStatus::Unknown
    );
}

#[test]
fn corrupted_crls_are_ignored() {
    let (ca, revoked) = (cert("ca"), cert("revoked"));
    let mut der = data("ca.crl");
    let n = der.len();
    der[n - 5] ^= 0x01; // inside the signature
    let bad = Crl::from_der(der).unwrap();
    assert_eq!(bad.verify_signed_by(&ca), Err(Error::BadSignature));
    let t = bad.this_update() + 60;
    let mut s = CrlSet::new();
    s.add(bad);
    assert_eq!(s.status(&revoked, &ca, t, SKEW), RevocationStatus::Unknown);
    // Every truncation fails to parse.
    let der = data("ca.crl");
    for cut in 0..der.len() {
        assert!(Crl::from_der(&der[..cut]).is_err(), "cut {cut}");
    }
    assert!(Crl::from_der(data("good.pem")).is_err());
}

#[test]
fn verifier_checks_crls() {
    let mut roots = RootStore::new();
    roots.add(cert("root"));
    let ca = cert("ca");
    let inter = [ca];
    let crls = set(&["ca.crl", "root.crl"]);
    let t = crls.crls()[0].this_update() + 60;
    let v = Verifier::new(&roots).at_time(t).crls(&crls);
    v.verify_server(&cert("good"), &inter, "localhost").unwrap();
    assert_eq!(
        v.verify_server(&cert("revoked"), &inter, "localhost"),
        Err(Error::Revoked(Some(RevocationReason::KeyCompromise)))
    );
    // Hard fail: every certificate below the root needs a CRL.
    let hard = v.clone().revocation_mode(RevocationMode::HardFail);
    hard.verify_server(&cert("good"), &inter, "localhost")
        .unwrap();
    let leaf_only = set(&["ca.crl"]);
    let hard = Verifier::new(&roots)
        .at_time(t)
        .crls(&leaf_only)
        .revocation_mode(RevocationMode::HardFail);
    assert_eq!(
        hard.verify_server(&cert("good"), &inter, "localhost"),
        Err(Error::RevocationUnknown)
    );
    // Soft fail with the same set passes.
    Verifier::new(&roots)
        .at_time(t)
        .crls(&leaf_only)
        .verify_server(&cert("good"), &inter, "localhost")
        .unwrap();
}

/// A generated root -> intermediate -> leaf chain, with keys.
struct Pki {
    root: Certificate,
    root_key: PrivateKey,
    ca: Certificate,
    ca_key: PrivateKey,
    leaf: Certificate,
    leaf2: Certificate,
}

fn p256() -> PrivateKey {
    PrivateKey::P256(akio_crypto::p256::SecretKey::generate().unwrap())
}

fn pki() -> Pki {
    let root_key = p256();
    let root = CertificateParams::ca("Gen Root")
        .self_signed(&root_key)
        .unwrap();
    let ca_key = p256();
    let ca = CertificateParams::ca("Gen CA")
        .signed_by(&ca_key.public_key(), &root, &root_key)
        .unwrap();
    let leaf = CertificateParams::new(["a.test"])
        .signed_by(&p256().public_key(), &ca, &ca_key)
        .unwrap();
    let leaf2 = CertificateParams::new(["b.test"])
        .signed_by(&p256().public_key(), &ca, &ca_key)
        .unwrap();
    Pki {
        root,
        root_key,
        ca,
        ca_key,
        leaf,
        leaf2,
    }
}

#[test]
fn generated_crls() {
    let p = pki();
    let now = Crl::from_der(CrlParams::new().sign(&p.ca, &p.ca_key).unwrap().as_der())
        .unwrap()
        .this_update()
        + 3600;
    // A hold, then a delta that lifts it.
    let base = CrlParams::new()
        .revoke(&p.leaf, Some(RevocationReason::CertificateHold))
        .revoke(&p.leaf2, None);
    let base_crl = base.sign(&p.ca, &p.ca_key).unwrap();
    assert_eq!(base_crl.revoked().len(), 2);
    let mut delta = CrlParams::new();
    delta.crl_number = 2;
    delta.delta_base = Some(1);
    let delta = delta.revoke(&p.leaf, Some(RevocationReason::RemoveFromCrl));
    let delta_crl = delta.sign(&p.ca, &p.ca_key).unwrap();
    assert!(delta_crl.is_delta());
    let mut s = CrlSet::new();
    s.add(base_crl.clone());
    assert!(matches!(
        s.status(&p.leaf, &p.ca, now, SKEW),
        RevocationStatus::Revoked {
            reason: Some(RevocationReason::CertificateHold),
            ..
        }
    ));
    assert!(matches!(
        s.status(&p.leaf2, &p.ca, now, SKEW),
        RevocationStatus::Revoked { reason: None, .. }
    ));
    s.add(delta_crl);
    assert_eq!(s.status(&p.leaf, &p.ca, now, SKEW), RevocationStatus::Good);
    assert!(matches!(
        s.status(&p.leaf2, &p.ca, now, SKEW),
        RevocationStatus::Revoked { .. }
    ));

    // onlyCACerts: does not cover leaves; onlySomeReasons: partial coverage.
    let mut ca_only = CrlParams::new();
    ca_only.issuing_distribution_point = Some(IssuingDistributionPoint {
        only_ca_certs: true,
        ..Default::default()
    });
    let mut s = CrlSet::new();
    s.add(ca_only.sign(&p.ca, &p.ca_key).unwrap());
    assert_eq!(
        s.status(&p.leaf, &p.ca, now, SKEW),
        RevocationStatus::Unknown
    );
    let mut some = CrlParams::new();
    some.issuing_distribution_point = Some(IssuingDistributionPoint {
        only_some_reasons: Some(RevocationReason::KeyCompromise.flag().unwrap()),
        ..Default::default()
    });
    let some_crl = some.sign(&p.ca, &p.ca_key).unwrap();
    assert_eq!(
        some_crl
            .issuing_distribution_point()
            .unwrap()
            .only_some_reasons,
        Some(ReasonFlags(1 << 1))
    );
    let mut s = CrlSet::new();
    s.add(some_crl);
    assert_eq!(
        s.status(&p.leaf, &p.ca, now, SKEW),
        RevocationStatus::Unknown
    );
    let mut rest = CrlParams::new();
    rest.issuing_distribution_point = Some(IssuingDistributionPoint {
        only_some_reasons: Some(ReasonFlags(ReasonFlags::ALL.0 & !(1 << 1))),
        ..Default::default()
    });
    s.add(rest.sign(&p.ca, &p.ca_key).unwrap());
    assert_eq!(s.status(&p.leaf, &p.ca, now, SKEW), RevocationStatus::Good);

    // A revoked intermediate fails the path, through the root's CRL.
    let mut roots = RootStore::new();
    roots.add(p.root.clone());
    let mut s = CrlSet::new();
    s.add(
        CrlParams::new()
            .revoke(&p.ca, Some(RevocationReason::CaCompromise))
            .sign(&p.root, &p.root_key)
            .unwrap(),
    );
    let r = Verifier::new(&roots).crls(&s).verify_server(
        &p.leaf2,
        std::slice::from_ref(&p.ca),
        "b.test",
    );
    assert_eq!(r, Err(Error::Revoked(Some(RevocationReason::CaCompromise))));
    // A CRL without cRLSign in the issuer's keyUsage is not used.
    let mut no_crl_sign = CertificateParams::ca("Gen CA");
    no_crl_sign.key_usage = Some(akio_x509::KeyUsage::KEY_CERT_SIGN);
    let ca3 = no_crl_sign
        .signed_by(&p.ca_key.public_key(), &p.root, &p.root_key)
        .unwrap();
    assert_eq!(base_crl.verify_signed_by(&ca3), Err(Error::KeyUsage));
}

#[test]
fn openssl_ocsp_responses() {
    let (ca, good) = (cert("ca"), cert("good"));
    let r = ocsp("ocsp_good_delegated.der");
    assert_eq!(r.status(), OcspResponseStatus::Successful);
    let b = r.basic().unwrap();
    let t = b.produced_at() + 60;
    let v = OcspValidation::new().at_time(t);
    assert_eq!(b.responses().len(), 1);
    assert_eq!(b.certs(), [cert("responder")]);
    assert_eq!(r.verify(&good, &ca, &v), Ok(RevocationStatus::Good));
    assert_eq!(OcspResponse::from_der(r.as_der()).unwrap(), r);
    for f in [
        "ocsp_good_by_ca.der",
        "ocsp_good_by_key.der",
        "ocsp_good_sha256.der",
        "ocsp_good_no_next.der",
    ] {
        assert_eq!(
            ocsp(f).verify(&good, &ca, &v),
            Ok(RevocationStatus::Good),
            "{f}"
        );
    }
    assert!(matches!(
        ocsp("ocsp_good_by_key.der").basic().unwrap().responder_id(),
        akio_x509::ResponderId::ByKey(_)
    ));
    assert!(matches!(
        ocsp("ocsp_revoked.der").verify(&cert("revoked"), &ca, &v),
        Ok(RevocationStatus::Revoked {
            reason: Some(RevocationReason::KeyCompromise),
            ..
        })
    ));
    assert!(matches!(
        ocsp("ocsp_hold.der").verify(&cert("hold"), &ca, &v),
        Ok(RevocationStatus::Revoked {
            reason: Some(RevocationReason::CertificateHold),
            ..
        })
    ));
    assert_eq!(
        ocsp("ocsp_unknown.der").verify(&cert("unlisted"), &ca, &v),
        Ok(RevocationStatus::Unknown)
    );
    let multi = ocsp("ocsp_multi.der");
    assert_eq!(multi.verify(&good, &ca, &v), Ok(RevocationStatus::Good));
    assert!(matches!(
        multi.verify(&cert("revoked"), &ca, &v),
        Ok(RevocationStatus::Revoked { .. })
    ));
}

#[test]
fn openssl_ocsp_negatives() {
    let (ca, good) = (cert("ca"), cert("good"));
    let r = ocsp("ocsp_good_delegated.der");
    let t = r.basic().unwrap().produced_at() + 60;
    let v = OcspValidation::new().at_time(t);
    // Wrong signers: no OCSPSigning EKU, issued by another CA, not included.
    assert_eq!(
        ocsp("ocsp_rogue.der").verify(&good, &ca, &v),
        Err(Error::UnauthorizedResponder)
    );
    assert_eq!(
        ocsp("ocsp_outsider.der").verify(&good, &ca, &v),
        Err(Error::UnauthorizedResponder)
    );
    assert_eq!(
        ocsp("ocsp_good_no_certs.der").verify(&good, &ca, &v),
        Err(Error::UnauthorizedResponder)
    );
    // Another certificate, another issuer.
    assert_eq!(
        r.verify(&cert("revoked"), &ca, &v),
        Err(Error::NoMatchingResponse)
    );
    assert_eq!(
        r.verify(&good, &cert("root"), &v),
        Err(Error::UnauthorizedResponder)
    );
    // Expired (7 days), within and beyond the skew; not yet valid.
    let next = r.basic().unwrap().responses()[0].next_update.unwrap();
    let at = |s| OcspValidation::new().at_time(s);
    assert_eq!(
        r.verify(&good, &ca, &at(next + 299)),
        Ok(RevocationStatus::Good)
    );
    assert_eq!(
        r.verify(&good, &ca, &at(next + 301)),
        Err(Error::RevocationInfoExpired)
    );
    let by_ca = ocsp("ocsp_good_by_ca.der");
    let this = by_ca.basic().unwrap().responses()[0].this_update;
    assert_eq!(
        by_ca.verify(&good, &ca, &at(this - 301)),
        Err(Error::RevocationInfoNotYetValid)
    );
    assert_eq!(
        by_ca.verify(&good, &ca, &at(this - 60).clock_skew(30)),
        Err(Error::RevocationInfoNotYetValid)
    );
    // No nextUpdate: usable for max_age.
    let nn = ocsp("ocsp_good_no_next.der");
    let this = nn.basic().unwrap().responses()[0].this_update;
    assert_eq!(
        nn.verify(&good, &ca, &at(this + 86_000)),
        Ok(RevocationStatus::Good)
    );
    assert_eq!(
        nn.verify(&good, &ca, &at(this + 3600).max_age(600)),
        Err(Error::RevocationInfoExpired)
    );
    // A signed field changed (producedAt's tens of seconds).
    let mut der = data("ocsp_good_by_ca.der");
    let i = der.windows(2).position(|w| w == [0x18, 0x0f]).unwrap() + 2 + 12;
    der[i] = if der[i] == b'0' { b'1' } else { b'0' };
    assert_eq!(
        OcspResponse::from_der(der).unwrap().verify(&good, &ca, &v),
        Err(Error::BadSignature)
    );
    // Unsuccessful statuses carry no body.
    let try_later = OcspResponse::from_der(vec![0x30, 3, 0x0a, 1, 3]).unwrap();
    assert_eq!(try_later.status(), OcspResponseStatus::TryLater);
    assert_eq!(
        try_later.verify(&good, &ca, &v),
        Err(Error::OcspStatus(OcspResponseStatus::TryLater))
    );
    assert!(OcspResponse::from_der(vec![0x30, 3, 0x0a, 1, 0]).is_err());
    assert!(OcspResponse::from_der(vec![0x30, 3, 0x0a, 1, 4]).is_err());
    // Every truncation fails to parse.
    let der = data("ocsp_good_delegated.der");
    for cut in 0..der.len() {
        assert!(OcspResponse::from_der(&der[..cut]).is_err(), "cut {cut}");
    }
}

#[test]
fn ocsp_nonce_and_request() {
    let (ca, good) = (cert("ca"), cert("good"));
    // OpenSSL's request ends with the 16-byte nonce; ours with that nonce is identical.
    let req = data("ocsp_good_nonce_req.der");
    let nonce = &req[req.len() - 16..];
    let ours = OcspRequest::new(&good, &ca).unwrap().nonce(nonce).to_der();
    assert_eq!(ours, req);
    assert_eq!(ours.len(), req.len());
    let r = ocsp("ocsp_good_nonce.der");
    assert_eq!(r.basic().unwrap().nonce(), Some(nonce));
    let t = r.basic().unwrap().produced_at() + 60;
    let v = OcspValidation::new().at_time(t);
    assert_eq!(
        r.verify(&good, &ca, &v.clone().nonce(nonce)),
        Ok(RevocationStatus::Good)
    );
    assert_eq!(
        r.verify(&good, &ca, &v.clone().nonce(&[1u8; 16][..])),
        Err(Error::NonceMismatch)
    );
    // A response without a nonce fails a nonce check.
    assert_eq!(
        ocsp("ocsp_good_delegated.der").verify(&good, &ca, &v.nonce(nonce)),
        Err(Error::NonceMismatch)
    );
}

#[test]
fn generated_ocsp_responses() {
    let p = pki();
    let v = OcspValidation::new();
    // Signed by the issuer, byName and byKey, SHA-256 CertID.
    let mut params = OcspResponseParams::new(RevocationStatus::Good);
    let r = OcspResponse::from_der(params.sign(&p.leaf, &p.ca, &p.ca, &p.ca_key).unwrap()).unwrap();
    assert_eq!(r.verify(&p.leaf, &p.ca, &v), Ok(RevocationStatus::Good));
    params.responder_by_key = true;
    params.hash = akio_x509::CertIdHash::Sha256;
    params.nonce = Some(b"0123456789abcdef".to_vec());
    let r = OcspResponse::from_der(params.sign(&p.leaf, &p.ca, &p.ca, &p.ca_key).unwrap()).unwrap();
    assert_eq!(
        r.verify(&p.leaf, &p.ca, &v.clone().nonce(&b"0123456789abcdef"[..])),
        Ok(RevocationStatus::Good)
    );
    // Revoked with a reason.
    let rev = OcspResponseParams::new(RevocationStatus::Revoked {
        time: 1_700_000_000,
        reason: Some(RevocationReason::Superseded),
    });
    let r = OcspResponse::from_der(rev.sign(&p.leaf, &p.ca, &p.ca, &p.ca_key).unwrap()).unwrap();
    assert_eq!(
        r.verify(&p.leaf, &p.ca, &v),
        Ok(RevocationStatus::Revoked {
            time: 1_700_000_000,
            reason: Some(RevocationReason::Superseded)
        })
    );
    // A delegated responder: with OCSPSigning it works, without it does not, and the root
    // (not the issuer) cannot sign for the leaf.
    let rkey = p256();
    let mut rp = CertificateParams::new(["responder"]);
    rp.extended_key_usage = vec![ext::OCSP_SIGNING.to_vec()];
    let responder = rp.signed_by(&rkey.public_key(), &p.ca, &p.ca_key).unwrap();
    let mut good = OcspResponseParams::new(RevocationStatus::Good);
    good.include_signer = true;
    let r = OcspResponse::from_der(good.sign(&p.leaf, &p.ca, &responder, &rkey).unwrap()).unwrap();
    assert_eq!(r.verify(&p.leaf, &p.ca, &v), Ok(RevocationStatus::Good));
    let plain = CertificateParams::new(["responder"])
        .signed_by(&rkey.public_key(), &p.ca, &p.ca_key)
        .unwrap();
    let r = OcspResponse::from_der(good.sign(&p.leaf, &p.ca, &plain, &rkey).unwrap()).unwrap();
    assert_eq!(
        r.verify(&p.leaf, &p.ca, &v),
        Err(Error::UnauthorizedResponder)
    );
    let r =
        OcspResponse::from_der(good.sign(&p.leaf, &p.ca, &p.root, &p.root_key).unwrap()).unwrap();
    assert_eq!(
        r.verify(&p.leaf, &p.ca, &v),
        Err(Error::UnauthorizedResponder)
    );
    // A responder certificate that expired.
    let mut old = rp;
    old.not_before -= 400 * 86_400;
    old.not_after = old.not_before + 86_400;
    let expired = old.signed_by(&rkey.public_key(), &p.ca, &p.ca_key).unwrap();
    let r = OcspResponse::from_der(good.sign(&p.leaf, &p.ca, &expired, &rkey).unwrap()).unwrap();
    assert_eq!(
        r.verify(&p.leaf, &p.ca, &v),
        Err(Error::UnauthorizedResponder)
    );
    // A request about the leaf matches the response's CertID.
    let req = OcspRequest::new(&p.leaf, &p.ca).unwrap();
    assert!(req.cert_ids()[0].matches(&p.leaf, &p.ca));
    assert!(!req.cert_ids()[0].matches(&p.leaf2, &p.ca));
}
