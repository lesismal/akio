//! rustls configurations for quinn-proto, built from `only-tls`'s configs (whose own TLS no
//! longer is rustls). Temporary: the in-house QUIC of the next wave drives `only_tls::quic`
//! instead, and this module and the rustls dependency go away.

use std::collections::HashMap;
use std::sync::Arc;

use only::tls;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn certs(chain: &[Vec<u8>]) -> Vec<CertificateDer<'static>> {
    chain
        .iter()
        .map(|c| CertificateDer::from(c.clone()))
        .collect()
}

fn key(der: &[u8]) -> PrivateKeyDer<'static> {
    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der.to_vec()))
}

fn roots(ders: &[Vec<u8>]) -> Result<rustls::RootCertStore, rustls::Error> {
    let mut r = rustls::RootCertStore::empty();
    for d in ders {
        r.add(CertificateDer::from(d.clone()))
            .map_err(|e| rustls::Error::General(format!("bad root: {e}")))?;
    }
    Ok(r)
}

/// The default chain, or the one registered for the SNI name.
#[derive(Debug)]
struct Resolver {
    default: Arc<CertifiedKey>,
    by_name: HashMap<String, Arc<CertifiedKey>>,
}

impl ResolvesServerCert for Resolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let named = hello
            .server_name()
            .and_then(|n| self.by_name.get(&n.to_ascii_lowercase()));
        Some(named.unwrap_or(&self.default).clone())
    }
}

pub(crate) fn server(cfg: &tls::ServerConfig) -> Result<rustls::ServerConfig, rustls::Error> {
    let p = cfg.__parts();
    let prov = provider();
    let b = rustls::ServerConfig::builder_with_provider(prov.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?;
    let b = match &p.client_auth {
        None => b.with_no_client_auth(),
        Some((ders, required)) => {
            let v = rustls::server::WebPkiClientVerifier::builder_with_provider(
                Arc::new(roots(ders)?),
                prov.clone(),
            );
            let v = if *required {
                v
            } else {
                v.allow_unauthenticated()
            };
            let v = v
                .build()
                .map_err(|e| rustls::Error::General(format!("client roots: {e}")))?;
            b.with_client_cert_verifier(v)
        }
    };
    let certified = |chain: &[Vec<u8>], der: &[u8]| -> Result<Arc<CertifiedKey>, rustls::Error> {
        let signing = prov.key_provider.load_private_key(key(der))?;
        Ok(Arc::new(CertifiedKey::new(certs(chain), signing)))
    };
    let default = certified(&p.chain, &p.key_pkcs8)?;
    let mut by_name = HashMap::new();
    for (name, chain, der) in &p.sni {
        by_name.insert(name.clone(), certified(chain, der)?);
    }
    let mut r = b.with_cert_resolver(Arc::new(Resolver { default, by_name }));
    r.alpn_protocols.clone_from(&p.alpn);
    r.session_storage = if p.session_cache == 0 {
        Arc::new(rustls::server::NoServerSessionStorage {})
    } else {
        rustls::server::ServerSessionMemoryCache::new(p.session_cache)
    };
    if p.tickets {
        r.ticketer = rustls::crypto::ring::Ticketer::new()?;
    }
    Ok(r)
}

pub(crate) fn client(cfg: &tls::ClientConfig) -> Result<rustls::ClientConfig, rustls::Error> {
    let p = cfg.__parts();
    let prov = provider();
    let b = rustls::ClientConfig::builder_with_provider(prov.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?;
    let b = if p.insecure {
        b.dangerous()
            .with_custom_certificate_verifier(Arc::new(AnyCert(prov)))
    } else {
        b.with_root_certificates(roots(&p.roots)?)
    };
    let mut r = match &p.client_cert {
        None => b.with_no_client_auth(),
        Some((chain, der)) => b.with_client_auth_cert(certs(chain), key(der))?,
    };
    r.alpn_protocols.clone_from(&p.alpn);
    r.enable_sni = p.sni;
    if !p.resumption {
        r.resumption = rustls::client::Resumption::disabled();
    }
    Ok(r)
}

/// Accepts every server certificate (signatures are still checked).
#[derive(Debug)]
struct AnyCert(Arc<CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for AnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}
