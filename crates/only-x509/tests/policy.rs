//! Certificate policy processing (RFC 5280 §6.1), indirect CRLs and CRLs signed by another
//! key of the CA (§6.3.3), and the rfc822Name / URI name constraints, on generated chains.
//! NIST PKITS covers the same ground more widely (`tests/pkits.rs`).
#![allow(clippy::unwrap_used)]

use only_crypto::der::{Writer, tag};
use only_crypto::pkey::PrivateKey;
use only_x509::{
    Certificate, CertificateParams, CrlParams, CrlSet, Error, Extension, GeneralName,
    GeneralSubtree, IssuingDistributionPoint, Name, NameConstraints, PolicyOptions, RevocationMode,
    RevocationReason, RootStore, Usage, ValidPolicies, Verifier, attr, ext,
};

fn key() -> PrivateKey {
    PrivateKey::P256(only_crypto::p256::SecretKey::generate().unwrap())
}

fn pol(n: u8) -> Vec<u8> {
    vec![0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x02, 0x01, 0x30, n]
}

fn extension(oid: &[u8], critical: bool, f: impl FnOnce(&mut Writer)) -> Extension {
    let mut w = Writer::new();
    f(&mut w);
    Extension {
        oid: oid.to_vec(),
        critical,
        value: w.into_vec(),
    }
}

fn policies(ps: &[Vec<u8>]) -> Extension {
    extension(ext::CERTIFICATE_POLICIES, false, |w| {
        w.sequence(|w| {
            for p in ps {
                w.sequence(|w| w.oid(p));
            }
        });
    })
}

fn mappings(m: &[(Vec<u8>, Vec<u8>)]) -> Extension {
    extension(ext::POLICY_MAPPINGS, true, |w| {
        w.sequence(|w| {
            for (a, b) in m {
                w.sequence(|w| {
                    w.oid(a);
                    w.oid(b);
                });
            }
        });
    })
}

fn constraints(require: Option<u8>, inhibit_mapping: Option<u8>) -> Extension {
    extension(ext::POLICY_CONSTRAINTS, true, |w| {
        w.sequence(|w| {
            if let Some(r) = require {
                w.tlv(tag::implicit(0) & 0x9f, &[r]);
            }
            if let Some(m) = inhibit_mapping {
                w.tlv(0x81, &[m]);
            }
        });
    })
}

fn inhibit_any(n: u8) -> Extension {
    extension(ext::INHIBIT_ANY_POLICY, true, |w| {
        w.small_uint(u64::from(n));
    })
}

/// root → ca (extensions `ca_ext`) → leaf (extensions `leaf_ext`).
struct Chain {
    roots: RootStore,
    ca: Certificate,
    ca_key: PrivateKey,
    leaf: Certificate,
    root: Certificate,
    root_key: PrivateKey,
}

fn chain(root_ext: Vec<Extension>, ca_ext: Vec<Extension>, leaf_ext: Vec<Extension>) -> Chain {
    let root_key = key();
    let mut rp = CertificateParams::ca("Policy Root");
    rp.custom_extensions = root_ext;
    let root = rp.self_signed(&root_key).unwrap();
    let ca_key = key();
    let mut cp = CertificateParams::ca("Policy CA");
    cp.custom_extensions = ca_ext;
    let ca = cp
        .signed_by(&ca_key.public_key(), &root, &root_key)
        .unwrap();
    let leaf_key = key();
    let mut lp = CertificateParams::new(["leaf.example"]);
    lp.custom_extensions = leaf_ext;
    let leaf = lp.signed_by(&leaf_key.public_key(), &ca, &ca_key).unwrap();
    let mut roots = RootStore::new();
    roots.add(root.clone());
    Chain {
        roots,
        ca,
        ca_key,
        leaf,
        root,
        root_key,
    }
}

impl Chain {
    fn verify(&self, opts: PolicyOptions) -> Result<ValidPolicies, Error> {
        Verifier::new(&self.roots)
            .policies(opts)
            .verify_path(&self.leaf, std::slice::from_ref(&self.ca), None)
            .map(|p| p.policies)
    }
}

fn opts(explicit: bool, set: &[Vec<u8>]) -> PolicyOptions {
    let mut o = PolicyOptions::new();
    o.explicit_policy = explicit;
    o.initial_policy_set = set.to_vec();
    o
}

#[test]
fn same_policy() {
    // The root is a trust anchor: its own extensions do not take part.
    let c = chain(vec![], vec![policies(&[pol(1)])], vec![policies(&[pol(1)])]);
    assert_eq!(
        c.verify(opts(false, &[])),
        Ok(ValidPolicies::Set(vec![pol(1)]))
    );
    assert_eq!(
        c.verify(opts(true, &[])),
        Ok(ValidPolicies::Set(vec![pol(1)]))
    );
    assert!(c.verify(opts(true, &[pol(1)])).unwrap().contains(&pol(1)));
    assert_eq!(c.verify(opts(true, &[pol(2)])), Err(Error::PolicyViolation));
    // Not required: valid, for no acceptable policy.
    assert_eq!(
        c.verify(opts(false, &[pol(2)])),
        Ok(ValidPolicies::Set(vec![]))
    );
    assert_eq!(
        c.verify(PolicyOptions::require([pol(1), pol(2)])),
        Ok(ValidPolicies::Set(vec![pol(1)]))
    );
    assert_eq!(c.ca.certificate_policies(), Some(&[pol(1)][..]));
}

#[test]
fn no_policies() {
    let c = chain(vec![], vec![], vec![]);
    assert_eq!(c.verify(opts(false, &[])), Ok(ValidPolicies::Set(vec![])));
    assert_eq!(c.verify(opts(true, &[])), Err(Error::PolicyViolation));
    // The default verifier is unaffected.
    Verifier::new(&c.roots)
        .verify_server(&c.leaf, std::slice::from_ref(&c.ca), "leaf.example")
        .unwrap();
}

#[test]
fn require_explicit_policy() {
    // requireExplicitPolicy 0 in the CA: the leaf must carry an acceptable policy.
    let c = chain(
        vec![],
        vec![policies(&[pol(1)]), constraints(Some(0), None)],
        vec![policies(&[pol(2)])],
    );
    assert_eq!(c.verify(opts(false, &[])), Err(Error::PolicyViolation));
    let c = chain(
        vec![],
        vec![policies(&[pol(1)]), constraints(Some(0), None)],
        vec![policies(&[pol(1)])],
    );
    assert_eq!(
        c.verify(opts(false, &[])),
        Ok(ValidPolicies::Set(vec![pol(1)]))
    );
    // requireExplicitPolicy 1: counts the leaf; a leaf without policies fails.
    let c = chain(
        vec![],
        vec![policies(&[pol(1)]), constraints(Some(1), None)],
        vec![],
    );
    assert_eq!(c.verify(opts(false, &[])), Err(Error::PolicyViolation));
    // requireExplicitPolicy 2 is not reached within the path.
    let c = chain(
        vec![],
        vec![policies(&[pol(1)]), constraints(Some(2), None)],
        vec![],
    );
    assert_eq!(c.verify(opts(false, &[])), Ok(ValidPolicies::Set(vec![])));
}

#[test]
fn any_policy_and_inhibit() {
    let c = chain(
        vec![],
        vec![policies(&[ext::ANY_POLICY.to_vec()])],
        vec![policies(&[pol(3)])],
    );
    assert_eq!(
        c.verify(opts(true, &[])),
        Ok(ValidPolicies::Set(vec![pol(3)]))
    );
    assert_eq!(
        c.verify(opts(true, &[pol(3)])),
        Ok(ValidPolicies::Set(vec![pol(3)]))
    );
    // A leaf asserting anyPolicy is good for any policy.
    let c = chain(
        vec![],
        vec![policies(&[ext::ANY_POLICY.to_vec()])],
        vec![policies(&[ext::ANY_POLICY.to_vec()])],
    );
    assert_eq!(c.verify(opts(true, &[])), Ok(ValidPolicies::Any));
    assert_eq!(
        c.verify(opts(true, &[pol(5)])),
        Ok(ValidPolicies::Set(vec![pol(5)]))
    );
    // initial-any-policy-inhibit: anyPolicy matches nothing.
    let mut o = opts(true, &[]);
    o.inhibit_any_policy = true;
    assert_eq!(c.verify(o), Err(Error::PolicyViolation));
    // inhibitAnyPolicy 0 in the CA: the leaf's anyPolicy no longer counts.
    let c = chain(
        vec![],
        vec![policies(&[ext::ANY_POLICY.to_vec()]), inhibit_any(0)],
        vec![policies(&[ext::ANY_POLICY.to_vec()])],
    );
    assert_eq!(c.verify(opts(true, &[])), Err(Error::PolicyViolation));
    assert_eq!(c.ca.inhibit_any_policy(), Some(0));
}

#[test]
fn mappings_and_inhibit() {
    // The CA maps its policy 1 to the leaf's policy 2: the path is good for policy 1.
    let c = chain(
        vec![],
        vec![policies(&[pol(1)]), mappings(&[(pol(1), pol(2))])],
        vec![policies(&[pol(2)])],
    );
    assert_eq!(
        c.verify(opts(true, &[pol(1)])),
        Ok(ValidPolicies::Set(vec![pol(2)]))
    );
    assert_eq!(c.verify(opts(true, &[pol(2)])), Err(Error::PolicyViolation));
    let mut o = opts(true, &[]);
    o.inhibit_policy_mapping = true;
    assert_eq!(c.verify(o), Err(Error::PolicyViolation));
    assert_eq!(c.ca.policy_mappings(), &[(pol(1), pol(2))]);
    // inhibitPolicyMapping 0 in the CA applies to the certificates after it, not to its own
    // mappings (RFC 5280 §6.1.4 (b) before (i)).
    let c = chain(
        vec![],
        vec![
            policies(&[pol(1)]),
            mappings(&[(pol(1), pol(2))]),
            constraints(None, Some(0)),
        ],
        vec![policies(&[pol(2)])],
    );
    assert_eq!(
        c.verify(opts(true, &[pol(1)])),
        Ok(ValidPolicies::Set(vec![pol(2)]))
    );
    // Mapping anyPolicy is forbidden.
    let c = chain(
        vec![],
        vec![
            policies(&[pol(1)]),
            mappings(&[(ext::ANY_POLICY.to_vec(), pol(2))]),
        ],
        vec![policies(&[pol(2)])],
    );
    assert_eq!(c.verify(opts(false, &[])), Err(Error::PolicyViolation));
}

#[test]
fn malformed_policy_extensions() {
    let bad = [
        extension(ext::CERTIFICATE_POLICIES, false, |w| w.sequence(|_| {})),
        extension(ext::CERTIFICATE_POLICIES, false, |w| {
            w.sequence(|w| {
                w.sequence(|w| w.oid(&pol(1)));
                w.sequence(|w| w.oid(&pol(1)));
            });
        }),
        extension(ext::POLICY_CONSTRAINTS, true, |w| w.sequence(|_| {})),
        extension(ext::POLICY_MAPPINGS, true, |w| w.sequence(|_| {})),
    ];
    let k = key();
    for e in bad {
        let mut p = CertificateParams::ca("Bad");
        p.custom_extensions = vec![e];
        assert_eq!(p.self_signed(&k).map(|_| ()), Err(Error::Encoding));
    }
}

/// A cRLDistributionPoints extension with one point whose cRLIssuer is `issuer`.
fn cdp_crl_issuer(issuer: &Name) -> Extension {
    extension(ext::CRL_DISTRIBUTION_POINTS, false, |w| {
        w.sequence(|w| {
            w.sequence(|w| {
                w.nested(0xa2, |w| w.nested(0xa4, |w| w.raw(issuer.as_der())));
            });
        });
    })
}

const DAY: i64 = 86_400;

#[test]
fn indirect_crl() {
    let c = chain(vec![], vec![], vec![]);
    // A CRL issuer certified by the root, and a leaf of the CA pointing at it.
    let crl_key = key();
    let mut cp = CertificateParams::ca("Indirect CRL Issuer");
    cp.key_usage = Some(only_x509::KeyUsage::CRL_SIGN);
    cp.is_ca = only_x509::IsCa::No;
    let crl_issuer = cp
        .signed_by(&crl_key.public_key(), &c.root, &c.root_key)
        .unwrap();
    let leaf_key = key();
    let mut lp = CertificateParams::new(["leaf.example"]);
    lp.custom_extensions = vec![cdp_crl_issuer(crl_issuer.subject())];
    let leaf = lp
        .signed_by(&leaf_key.public_key(), &c.ca, &c.ca_key)
        .unwrap();
    assert_eq!(
        leaf.crl_distribution_points()[0].crl_issuer,
        vec![GeneralName::DirectoryName(crl_issuer.subject().clone())]
    );

    let indirect = |revoke: bool| {
        let mut p = CrlParams::new();
        p.issuing_distribution_point = Some(IssuingDistributionPoint {
            indirect_crl: true,
            ..Default::default()
        });
        if revoke {
            p = p.revoke(&leaf, Some(RevocationReason::KeyCompromise));
            p.revoked[0].certificate_issuer =
                Some(vec![GeneralName::DirectoryName(c.ca.subject().clone())]);
        }
        p.sign(&crl_issuer, &crl_key).unwrap()
    };
    // The CA's own (direct) CRL covers the CA via the root.
    let root_crl = CrlParams::new().sign(&c.root, &c.root_key).unwrap();
    let run = |crls: &CrlSet, signers: &[Certificate]| {
        Verifier::new(&c.roots)
            .crls(crls)
            .crl_signers(signers)
            .revocation_mode(RevocationMode::HardFail)
            .verify_server(&leaf, std::slice::from_ref(&c.ca), "leaf.example")
            .map(|_| ())
    };
    let mut set = CrlSet::new();
    set.add(root_crl.clone());
    set.add(indirect(false));
    let signers = [crl_issuer.clone()];
    run(&set, &signers).unwrap();
    // Without the CRL issuer's certificate, its CRL cannot be authenticated.
    assert_eq!(run(&set, &[]), Err(Error::RevocationUnknown));
    let mut set = CrlSet::new();
    set.add(root_crl.clone());
    set.add(indirect(true));
    assert_eq!(
        run(&set, &signers),
        Err(Error::Revoked(Some(RevocationReason::KeyCompromise)))
    );
    let e = &set.crls()[1].revoked()[0];
    assert_eq!(
        e.certificate_issuer,
        Some(vec![GeneralName::DirectoryName(c.ca.subject().clone())])
    );
    assert!(
        set.crls()[1]
            .find_for(leaf.serial(), c.ca.subject())
            .is_some()
    );
    assert!(
        set.crls()[1]
            .find_for(leaf.serial(), crl_issuer.subject())
            .is_none()
    );
    // The CRL issuer revoked by the root: its CRLs are not trusted.
    let mut set = CrlSet::new();
    set.add(
        CrlParams::new()
            .revoke(&crl_issuer, None)
            .sign(&c.root, &c.root_key)
            .unwrap(),
    );
    set.add(indirect(false));
    assert_eq!(run(&set, &signers), Err(Error::RevocationUnknown));
    // An indirect CRL is not used for a certificate that does not name its issuer.
    let mut set = CrlSet::new();
    set.add(root_crl);
    set.add(indirect(false));
    let plain = Verifier::new(&c.roots)
        .crls(&set)
        .crl_signers(&signers)
        .revocation_mode(RevocationMode::HardFail)
        .verify(&c.leaf, std::slice::from_ref(&c.ca), None);
    assert_eq!(plain.map(|_| ()), Err(Error::RevocationUnknown));
}

#[test]
fn crl_signed_by_another_key() {
    let c = chain(vec![], vec![], vec![]);
    // A second certificate for the CA's name, for CRL signing only, issued by the root.
    let crl_key = key();
    let mut cp = CertificateParams::ca("Policy CA");
    cp.subject = c.ca.subject().clone();
    cp.key_usage = Some(only_x509::KeyUsage::CRL_SIGN);
    let crl_cert = cp
        .signed_by(&crl_key.public_key(), &c.root, &c.root_key)
        .unwrap();
    let run = |crls: &CrlSet| {
        Verifier::new(&c.roots)
            .crls(crls)
            .crl_signers(std::slice::from_ref(&crl_cert))
            .revocation_mode(RevocationMode::HardFail)
            .verify(&c.leaf, std::slice::from_ref(&c.ca), None)
            .map(|_| ())
    };
    let root_crl = CrlParams::new().sign(&c.root, &c.root_key).unwrap();
    let mut set = CrlSet::new();
    set.add(root_crl.clone());
    set.add(CrlParams::new().sign(&crl_cert, &crl_key).unwrap());
    run(&set).unwrap();
    // CrlSet::status alone only trusts the issuer's own key.
    assert_eq!(
        set.status(&c.leaf, &c.ca, only_x509_now(), 300),
        only_x509::RevocationStatus::Unknown
    );
    let mut set = CrlSet::new();
    set.add(root_crl);
    set.add(
        CrlParams::new()
            .revoke(&c.leaf, None)
            .sign(&crl_cert, &crl_key)
            .unwrap(),
    );
    assert_eq!(run(&set), Err(Error::Revoked(None)));
    // The CRL signing certificate revoked by the root.
    let mut set = CrlSet::new();
    set.add(
        CrlParams::new()
            .revoke(&crl_cert, None)
            .sign(&c.root, &c.root_key)
            .unwrap(),
    );
    set.add(CrlParams::new().sign(&crl_cert, &crl_key).unwrap());
    assert_eq!(run(&set), Err(Error::RevocationUnknown));
    // Expired CRL signer.
    let mut cp2 = cp;
    cp2.not_after = cp2.not_before + DAY;
    cp2.not_before -= 10 * DAY;
    cp2.not_after -= 10 * DAY;
    let old = cp2
        .signed_by(&crl_key.public_key(), &c.root, &c.root_key)
        .unwrap();
    let mut set = CrlSet::new();
    set.add(CrlParams::new().sign(&c.root, &c.root_key).unwrap());
    set.add(CrlParams::new().sign(&old, &crl_key).unwrap());
    let r = Verifier::new(&c.roots)
        .crls(&set)
        .crl_signers(std::slice::from_ref(&old))
        .revocation_mode(RevocationMode::HardFail)
        .verify(&c.leaf, std::slice::from_ref(&c.ca), None);
    assert_eq!(r.map(|_| ()), Err(Error::RevocationUnknown));
}

fn only_x509_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

#[test]
fn negative_serial() {
    let c = chain(vec![], vec![], vec![]);
    let leaf_key = key();
    let mut lp = CertificateParams::new(["leaf.example"]);
    lp.serial = Some(vec![0x00, 0xff]); // 255
    let leaf = lp
        .signed_by(&leaf_key.public_key(), &c.ca, &c.ca_key)
        .unwrap();
    assert_eq!(leaf.serial(), &[0x00, 0xff]);
    let mut p = CrlParams::new();
    p = p.revoke(&leaf, None);
    p.revoked[0].serial = vec![0xff]; // -1
    let crl = p.sign(&c.ca, &c.ca_key).unwrap();
    assert!(crl.find(leaf.serial()).is_none());
    assert!(crl.find(&[0xff]).is_some());
}

#[test]
fn rfc822_and_uri_constraints() {
    let root_key = key();
    let mut rp = CertificateParams::ca("NC Root");
    rp.name_constraints = Some(NameConstraints {
        permitted: vec![
            GeneralSubtree(GeneralName::Email(".example.com".into())),
            GeneralSubtree(GeneralName::Email("ops@example.org".into())),
            GeneralSubtree(GeneralName::Uri("host.example.net".into())),
        ],
        excluded: vec![GeneralSubtree(GeneralName::Email("bad.example.com".into()))],
    });
    let root = rp.self_signed(&root_key).unwrap();
    let mut roots = RootStore::new();
    roots.add(root.clone());
    let leaf_with = |names: Vec<GeneralName>, email_dn: Option<&str>| {
        let mut lp = CertificateParams::new(std::iter::empty::<&str>());
        lp.subject_alt_names = names;
        if let Some(e) = email_dn {
            lp.subject =
                Name::from_attributes([(attr::COMMON_NAME, "x"), (attr::EMAIL_ADDRESS, e)]);
        }
        let k = key();
        let leaf = lp.signed_by(&k.public_key(), &root, &root_key).unwrap();
        Verifier::new(&roots)
            .usage(Usage::Any)
            .verify(&leaf, &[], None)
            .map(|_| ())
    };
    let email = |s: &str| GeneralName::Email(s.into());
    let uri = |s: &str| GeneralName::Uri(s.into());
    leaf_with(vec![email("a@mail.example.com")], None).unwrap();
    leaf_with(vec![email("ops@example.org")], None).unwrap();
    leaf_with(vec![uri("https://HOST.example.net:8443/x?y")], None).unwrap();
    leaf_with(vec![uri("ldap://user@host.example.net")], None).unwrap();
    for bad in [
        email("a@example.com"),
        email("a@bad.example.com"),
        email("Ops@example.org"),
        email("not-an-address"),
        uri("https://other.example.net/"),
        uri("urn:isbn:123"),
        uri("https://[::1]/"),
    ] {
        assert_eq!(
            leaf_with(vec![bad.clone()], None),
            Err(Error::NameConstraintViolation),
            "{bad:?}"
        );
    }
    // The legacy emailAddress in the subject name counts as an rfc822Name.
    leaf_with(vec![], Some("x@mail.example.com")).unwrap();
    assert_eq!(
        leaf_with(vec![], Some("x@elsewhere.test")),
        Err(Error::NameConstraintViolation)
    );
}
