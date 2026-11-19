//! Revocation in memory between our client and server, TLS 1.3 and 1.2: stapled OCSP
//! responses under each policy, CRLs for the server's and the client's chains.

use only_crypto::pkey;
use only_x509::{
    CertificateParams, CrlParams, OcspResponseParams, RevocationReason, RevocationStatus, ext,
};

use super::alert::Alert;
use super::msgs::ClientHello;
use super::record::RecordLayer;
use super::tests::{Side, connect};
use crate::{
    Certificate, ClientConfig, ClientConfigBuilder, Crls, PrivateKey, RevocationPolicy, RootCerts,
    ServerConfig,
};

/// A CA, a server leaf and a client leaf it issued, and a delegated OCSP responder.
struct Pki {
    ca: only_x509::Certificate,
    ca_key: pkey::PrivateKey,
    leaf: only_x509::Certificate,
    leaf_key: pkey::PrivateKey,
    client: only_x509::Certificate,
    client_key: pkey::PrivateKey,
    responder: only_x509::Certificate,
    responder_key: pkey::PrivateKey,
}

fn p256() -> pkey::PrivateKey {
    pkey::PrivateKey::P256(only_crypto::p256::SecretKey::generate().unwrap())
}

fn pki() -> Pki {
    let ca_key = p256();
    let ca = CertificateParams::ca("Revocation Test CA")
        .self_signed(&ca_key)
        .unwrap();
    let leaf_key = p256();
    let leaf = CertificateParams::new(["localhost"])
        .signed_by(&leaf_key.public_key(), &ca, &ca_key)
        .unwrap();
    let client_key = p256();
    let client = CertificateParams::new(["client"])
        .signed_by(&client_key.public_key(), &ca, &ca_key)
        .unwrap();
    let responder_key = p256();
    let mut rp = CertificateParams::new(["ocsp responder"]);
    rp.extended_key_usage = vec![ext::OCSP_SIGNING.to_vec()];
    let responder = rp
        .signed_by(&responder_key.public_key(), &ca, &ca_key)
        .unwrap();
    Pki {
        ca,
        ca_key,
        leaf,
        leaf_key,
        client,
        client_key,
        responder,
        responder_key,
    }
}

fn tls_cert(c: &only_x509::Certificate) -> Certificate {
    Certificate::from_der(c.as_der().to_vec())
}

fn tls_key(k: &pkey::PrivateKey) -> PrivateKey {
    PrivateKey::from_pkcs8_der(k.to_pkcs8_der())
}

impl Pki {
    fn roots(&self) -> RootCerts {
        let mut r = RootCerts::empty();
        r.add(&tls_cert(&self.ca)).unwrap();
        r
    }

    fn server(&self, ocsp: Option<Vec<u8>>) -> ServerConfig {
        let mut b = ServerConfig::builder(
            vec![tls_cert(&self.leaf), tls_cert(&self.ca)],
            tls_key(&self.leaf_key),
        )
        .session_tickets(true);
        if let Some(r) = ocsp {
            b = b.ocsp_response(r);
        }
        b.build().unwrap()
    }

    fn client(&self, tls12: bool) -> ClientConfigBuilder {
        ClientConfig::builder()
            .roots(self.roots())
            .__tls12_only(tls12)
    }

    /// A response about the server leaf, signed by the CA.
    fn ocsp(&self, p: &OcspResponseParams) -> Vec<u8> {
        p.sign(&self.leaf, &self.ca, &self.ca, &self.ca_key)
            .unwrap()
    }
}

fn alert(r: Result<(super::conn::Connection, super::conn::Connection), Side>) -> Option<Alert> {
    match r {
        Ok(_) => None,
        Err(Side::Client(f) | Side::Server(f)) => Some(f.alert),
    }
}

#[test]
fn stapled_ocsp_policies() {
    let p = pki();
    let good = p.ocsp(&OcspResponseParams::new(RevocationStatus::Good));
    let mut delegated = OcspResponseParams::new(RevocationStatus::Good);
    delegated.include_signer = true;
    let delegated = delegated
        .sign(&p.leaf, &p.ca, &p.responder, &p.responder_key)
        .unwrap();
    let revoked = p.ocsp(&OcspResponseParams::new(RevocationStatus::Revoked {
        time: 1_700_000_000,
        reason: Some(RevocationReason::KeyCompromise),
    }));
    let unknown = p.ocsp(&OcspResponseParams::new(RevocationStatus::Unknown));
    let mut old = OcspResponseParams::new(RevocationStatus::Good);
    old.this_update -= 10 * 86_400;
    old.next_update = Some(old.this_update + 86_400);
    let expired = p.ocsp(&old);
    // Signed by another CA's key: unauthorized.
    let other_key = p256();
    let other = CertificateParams::ca("Revocation Test CA")
        .self_signed(&other_key)
        .unwrap();
    let forged = OcspResponseParams::new(RevocationStatus::Good)
        .sign(&p.leaf, &p.ca, &other, &other_key)
        .unwrap();
    // A response about another certificate.
    let about_client = OcspResponseParams::new(RevocationStatus::Good)
        .sign(&p.client, &p.ca, &p.ca, &p.ca_key)
        .unwrap();
    // Well-formed outside, opaque inside.
    let mut opaque = vec![0x30, 0, 0x0a, 1, 0, 0xa0, 0x20];
    opaque.extend([7u8; 0x20]);
    opaque[1] = (opaque.len() - 2) as u8;

    use RevocationPolicy::{HardFail, Off, SoftFail};
    let bad = Some(Alert::BadCertificateStatusResponse);
    let rev = Some(Alert::CertificateRevoked);
    type Case = (&'static str, Option<Vec<u8>>, [Option<Alert>; 3]);
    let cases: [Case; 9] = [
        ("good", Some(good.clone()), [None, None, None]),
        ("delegated", Some(delegated), [None, None, None]),
        ("revoked", Some(revoked), [None, rev, rev]),
        ("unknown", Some(unknown), [None, None, bad]),
        ("expired", Some(expired), [None, None, bad]),
        ("forged", Some(forged), [None, None, bad]),
        ("other certificate", Some(about_client), [None, None, bad]),
        ("opaque", Some(opaque), [None, None, bad]),
        ("none", None, [None, None, bad]),
    ];
    for tls12 in [false, true] {
        for (what, resp, want) in &cases {
            let scfg = p.server(resp.clone());
            for (policy, want) in [Off, SoftFail, HardFail].into_iter().zip(want) {
                let ccfg = p.client(tls12).ocsp_policy(policy).build().unwrap();
                let got = alert(connect(&scfg, &ccfg, "localhost"));
                assert_eq!(got, *want, "{what} tls12={tls12} {policy:?}");
            }
        }
        // A policy asks for the response; insecure mode does not check it.
        let none = p.server(None);
        let ccfg = ClientConfig::builder()
            .insecure_skip_verify()
            .ocsp_policy(HardFail)
            .__tls12_only(tls12)
            .build()
            .unwrap();
        assert_eq!(alert(connect(&none, &ccfg, "localhost")), None);
        // Resumed sessions are not checked again (no certificate, no response).
        let scfg = p.server(Some(good.clone()));
        let ccfg = p.client(tls12).ocsp_policy(HardFail).build().unwrap();
        connect(&scfg, &ccfg, "localhost").unwrap();
        let (c, _) = connect(&scfg, &ccfg, "localhost").unwrap();
        assert!(c.resumed(), "tls12={tls12}");
    }
}

#[test]
fn ocsp_policy_requests_stapling() {
    let p = pki();
    for (policy, asked) in [
        (RevocationPolicy::Off, false),
        (RevocationPolicy::SoftFail, true),
        (RevocationPolicy::HardFail, true),
    ] {
        let ccfg = p.client(false).ocsp_policy(policy).build().unwrap();
        let mut c = crate::__proto::client(&ccfg, "localhost").unwrap();
        let mut out = Vec::new();
        c.recv(&[], &mut Vec::new(), &mut out).unwrap();
        let n = RecordLayer::frame(&out).unwrap().unwrap();
        assert_eq!(
            ClientHello::parse(&out[9..n]).unwrap().status_request,
            asked,
            "{policy:?}"
        );
    }
}

fn crls(c: &only_x509::Crl) -> Crls {
    let mut s = Crls::new();
    s.add_der(c.as_der()).unwrap();
    assert_eq!(s.len(), 1);
    s
}

#[test]
fn crls_for_the_server_chain() {
    let p = pki();
    let empty = CrlParams::new().sign(&p.ca, &p.ca_key).unwrap();
    let revoking = CrlParams::new()
        .revoke(&p.leaf, Some(RevocationReason::Superseded))
        .sign(&p.ca, &p.ca_key)
        .unwrap();
    let scfg = p.server(None);
    for tls12 in [false, true] {
        let run = |c: Crls, policy| {
            let ccfg = p.client(tls12).crls(c, policy).build().unwrap();
            alert(connect(&scfg, &ccfg, "localhost"))
        };
        use RevocationPolicy::{HardFail, Off, SoftFail};
        assert_eq!(run(crls(&empty), HardFail), None);
        assert_eq!(
            run(crls(&revoking), SoftFail),
            Some(Alert::CertificateRevoked)
        );
        assert_eq!(run(crls(&revoking), Off), None);
        assert_eq!(run(Crls::new(), SoftFail), None);
        assert_eq!(run(Crls::new(), HardFail), Some(Alert::CertificateUnknown));
        // PEM in.
        let mut pem = Crls::new();
        assert_eq!(pem.add_pem(revoking.to_pem().as_bytes()).unwrap(), 1);
        assert_eq!(run(pem, HardFail), Some(Alert::CertificateRevoked));
    }
    assert!(Crls::new().add_der(b"not a CRL").is_err());
}

#[test]
fn crls_for_client_certificates() {
    let p = pki();
    let revoking = CrlParams::new()
        .revoke(&p.client, Some(RevocationReason::KeyCompromise))
        .sign(&p.ca, &p.ca_key)
        .unwrap();
    let other = CrlParams::new()
        .revoke(&p.leaf, None)
        .sign(&p.ca, &p.ca_key)
        .unwrap();
    for tls12 in [false, true] {
        for (set, want) in [(&revoking, Some(Alert::CertificateRevoked)), (&other, None)] {
            let scfg = ServerConfig::builder(
                vec![tls_cert(&p.leaf), tls_cert(&p.ca)],
                tls_key(&p.leaf_key),
            )
            .client_auth_required(p.roots())
            .client_crls(crls(set), RevocationPolicy::HardFail)
            .build()
            .unwrap();
            let ccfg = p
                .client(tls12)
                .client_cert(vec![tls_cert(&p.client)], tls_key(&p.client_key))
                .build()
                .unwrap();
            let r = connect(&scfg, &ccfg, "localhost");
            if want.is_some() {
                assert!(matches!(r, Err(Side::Server(_))), "tls12={tls12}");
            }
            assert_eq!(alert(r), want, "tls12={tls12}");
        }
    }
}

/// A client's OCSP response in TLS 1.3 client authentication (ADR-049): asked for in the
/// CertificateRequest under `client_ocsp_policy`, stapled from `client_cert_ocsp_response`,
/// validated by the server as a server's is by a client.
#[test]
fn client_ocsp_in_client_auth() {
    let p = pki();
    let about_client = |status| {
        OcspResponseParams::new(status)
            .sign(&p.client, &p.ca, &p.ca, &p.ca_key)
            .unwrap()
    };
    let good = about_client(RevocationStatus::Good);
    let revoked = about_client(RevocationStatus::Revoked {
        time: 1_700_000_000,
        reason: None,
    });
    let unknown = about_client(RevocationStatus::Unknown);
    let mut delegated = OcspResponseParams::new(RevocationStatus::Good);
    delegated.include_signer = true;
    let delegated = delegated
        .sign(&p.client, &p.ca, &p.responder, &p.responder_key)
        .unwrap();
    // About the server's leaf, not the client's.
    let wrong = p.ocsp(&OcspResponseParams::new(RevocationStatus::Good));
    use RevocationPolicy::{HardFail, Off, SoftFail};
    let bad = Some(Alert::BadCertificateStatusResponse);
    let rev = Some(Alert::CertificateRevoked);
    type Case<'a> = (&'a str, Option<&'a Vec<u8>>, [Option<Alert>; 3]);
    let cases: [Case<'_>; 6] = [
        ("good", Some(&good), [None, None, None]),
        ("delegated", Some(&delegated), [None, None, None]),
        ("revoked", Some(&revoked), [None, rev, rev]),
        ("unknown", Some(&unknown), [None, None, bad]),
        ("other certificate", Some(&wrong), [None, None, bad]),
        ("none", None, [None, None, bad]),
    ];
    let server = |policy| {
        ServerConfig::builder(
            vec![tls_cert(&p.leaf), tls_cert(&p.ca)],
            tls_key(&p.leaf_key),
        )
        .client_auth_required(p.roots())
        .client_ocsp_policy(policy)
        .session_tickets(true)
        .build()
        .unwrap()
    };
    let client = |tls12: bool, resp: Option<&Vec<u8>>| {
        let mut b = p
            .client(tls12)
            .client_cert(vec![tls_cert(&p.client)], tls_key(&p.client_key));
        if let Some(r) = resp {
            b = b.client_cert_ocsp_response(r.clone());
        }
        b.build().unwrap()
    };
    for (what, resp, want) in &cases {
        for (policy, want) in [Off, SoftFail, HardFail].into_iter().zip(want) {
            let r = connect(&server(policy), &client(false, *resp), "localhost");
            if want.is_some() {
                assert!(matches!(r, Err(Side::Server(_))), "{what} {policy:?}");
            }
            if let Ok((_, s)) = &r {
                // The server sees the response only when it asked for one.
                let seen = s.ocsp_response().map(<[u8]>::to_vec);
                let asked = policy != Off;
                assert_eq!(seen.as_ref(), resp.filter(|_| asked), "{what} {policy:?}");
            }
            assert_eq!(alert(r), *want, "{what} {policy:?}");
        }
    }
    // TLS 1.2 cannot carry a client's response: soft fail passes, hard fail refuses.
    assert_eq!(
        alert(connect(
            &server(SoftFail),
            &client(true, Some(&good)),
            "localhost"
        )),
        None
    );
    assert_eq!(
        alert(connect(
            &server(HardFail),
            &client(true, Some(&good)),
            "localhost"
        )),
        bad
    );
    // Resumed sessions are not checked again.
    let scfg = server(HardFail);
    let ccfg = client(false, Some(&good));
    connect(&scfg, &ccfg, "localhost").unwrap();
    let (c, _) = connect(&scfg, &ccfg, "localhost").unwrap();
    assert!(c.resumed());
}
