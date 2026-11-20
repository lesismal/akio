//! Fuzz entry points (feature `fuzzing`; not a public API). The `fuzz/` cargo-fuzz project
//! calls them; the unit tests below replay `fuzz/corpus/<target>` on stable.

use std::sync::OnceLock;

use crate::proto::Connection;
use crate::proto::codec::Reader;
use crate::proto::common::Keys;
use crate::proto::msgs::{
    ClientHello, CompAlgs, ServerHello, compressed_certificate, decompress_certificate,
    parse_certificate_status, parse_certificate12, parse_certificate13,
};
use crate::proto::record::RecordLayer;
use crate::proto::suites;
use crate::{Certificate, ClientConfig, PrivateKey, RootCerts, ServerConfig};

struct Fixture {
    server: ServerConfig,
    server_auth: ServerConfig,
    client: ClientConfig,
    client12: ClientConfig,
}

fn fixture() -> &'static Fixture {
    static F: OnceLock<Fixture> = OnceLock::new();
    F.get_or_init(|| {
        let key = only_crypto::pkey::PrivateKey::Ed25519(
            only_crypto::ed25519::SigningKey::from_seed(&[7; 32]),
        );
        let cert = only_x509::CertificateParams::new(["localhost"])
            .self_signed(&key)
            .unwrap_or_else(|_| unreachable!("fixed key"));
        let chain = vec![Certificate::from_der(cert.as_der().to_vec())];
        let pk = PrivateKey::from_pkcs8_der(key.to_pkcs8_der());
        let mut roots = RootCerts::empty();
        let _ = roots.add(&chain[0]);
        let build = |b: crate::ServerConfigBuilder| {
            b.build()
                .unwrap_or_else(|_| unreachable!("fixed configuration"))
        };
        // A stand-in OCSP response (only its outer structure is checked).
        let mut ocsp = vec![0x30, 0, 0x0a, 1, 0, 0xa0, 4, 0x30, 2, 5, 0];
        ocsp[1] = (ocsp.len() - 2) as u8;
        let server = build(
            ServerConfig::builder(chain.clone(), pk.clone())
                .alpn(["h2", "http/1.1"])
                .session_tickets(true)
                .early_data(16384)
                .record_size_limit(512)
                .ocsp_response(ocsp),
        );
        let server_auth = build(
            ServerConfig::builder(chain, pk)
                .client_auth_optional(roots.clone())
                .client_ocsp_policy(crate::RevocationPolicy::SoftFail)
                .__force_hello_retry(true),
        );
        let client = ClientConfig::builder()
            .roots(roots.clone())
            .alpn(["h2"])
            .early_data(true)
            .record_size_limit(256)
            .ocsp_stapling(true)
            .certificate_compression(true)
            .build()
            .unwrap_or_else(|_| unreachable!("fixed configuration"));
        let client12 = ClientConfig::builder()
            .roots(roots)
            .__tls12_only(true)
            .ocsp_stapling(true)
            .build()
            .unwrap_or_else(|_| unreachable!("fixed configuration"));
        Fixture {
            server,
            server_auth,
            client,
            client12,
        }
    })
}

/// Feeds `data` to `c` in pieces whose sizes come from the data itself.
fn feed(c: &mut Connection, data: &[u8]) {
    let (mut plain, mut out) = (Vec::new(), Vec::new());
    let mut rest = data;
    while !rest.is_empty() {
        let n = (usize::from(rest[0]) * 7 + 1).min(rest.len());
        let (a, b) = rest.split_at(n);
        rest = b;
        if c.recv(a, &mut plain, &mut out).is_err() {
            // A failed connection stays failed and keeps refusing.
            assert!(c.recv(b"x", &mut plain, &mut out).is_err());
            return;
        }
    }
    let _ = c.seal(b"after", &mut out);
    c.close(&mut out);
}

/// `tls_server`: arbitrary bytes as what a client sends to a server (TLS 1.3 / 1.2, with and
/// without client authentication (asking for the client's OCSP response) and a forced
/// HelloRetryRequest, record_size_limit, OCSP stapling); never panics. Also parses the input directly as handshake messages (a
/// CompressedCertificate among them, and the QUIC transport parameters peek of a whole
/// ClientHello), and what compresses decompresses to the same bytes.
pub fn server(data: &[u8]) {
    let f = fixture();
    let cfg = if data.first().is_some_and(|b| b & 1 == 1) {
        &f.server_auth
    } else {
        &f.server
    };
    let mut c = Connection::server(cfg.inner.clone());
    feed(&mut c, data);
    let _ = ClientHello::parse(data);
    let _ = crate::quic::client_hello_transport_params(data);
    let _ = parse_certificate13(data, data.first().is_some_and(|b| b & 2 == 2));
    let _ = parse_certificate12(data);
    let _ = decompress_certificate(data, 1 << 17, CompAlgs::ALL);
    if data.len() <= 4096 {
        // zlib, brotli, zstd by the first byte.
        let alg = 1 + u16::from(data.first().map_or(0, |b| b >> 1) % 3);
        if let Some(m) = compressed_certificate(data, alg) {
            let back = decompress_certificate(&m[4..], data.len(), CompAlgs::ALL)
                .unwrap_or_else(|e| panic!("own compressed certificate: {e}"));
            assert_eq!(back, (data.to_vec(), alg));
        }
    }
}

/// `tls_client`: arbitrary bytes as what a server sends back to our ClientHello (dual-version
/// and TLS 1.2-only clients); never panics.
pub fn client(data: &[u8]) {
    let f = fixture();
    let cfg = if data.first().is_some_and(|b| b & 1 == 1) {
        &f.client12
    } else {
        &f.client
    };
    let Ok(mut c) = Connection::client(cfg.inner.clone(), "localhost") else {
        return;
    };
    feed(&mut c, data);
    let _ = ServerHello::parse(data);
    let _ = parse_certificate_status(&mut Reader::new(data));
    let _ = decompress_certificate(data, 1 << 17, CompAlgs::ALL);
}

/// `tls_record`: arbitrary records decrypted under fixed keys of every suite (TLS 1.3 and 1.2
/// record formats); never panics, and what decrypts re-encrypts to the same record.
pub fn record(data: &[u8]) {
    let Some((&sel, rest)) = data.split_first() else {
        return;
    };
    let suite = suites::ALL[usize::from(sel) % suites::ALL.len()];
    let keys = if suite.is_tls13() {
        Keys::Tls13 {
            suite,
            secret: vec![sel; suite.hash.len()],
        }
    } else {
        Keys::Tls12 {
            suite,
            key: vec![sel; suite.aead.key_len()],
            iv: vec![sel; suite.aead.fixed_iv_len_12()],
        }
    };
    let mut r = RecordLayer::new();
    r.set_read(&keys);
    if sel & 0x80 != 0 {
        r.skip_early = 1 << 14;
    }
    let mut buf = rest.to_vec();
    let mut pos = 0;
    while let Ok(Some(n)) = RecordLayer::frame(&buf[pos..]) {
        let rec = &mut buf[pos..pos + n];
        if r.open(rec).is_err() {
            return;
        }
        pos += n;
    }
    // Round trip: what we seal, we open.
    let mut w = RecordLayer::new();
    w.set_write(&keys);
    let mut r2 = RecordLayer::new();
    r2.set_read(&keys);
    let mut out = Vec::new();
    if w.seal(23, rest, &mut out).is_ok() {
        let mut got = Vec::new();
        let mut pos = 0;
        while let Ok(Some(n)) = RecordLayer::frame(&out[pos..]) {
            let o = r2
                .open(&mut out[pos..pos + n])
                .unwrap_or_else(|e| panic!("own record does not open: {e}"));
            got.extend_from_slice(&out[pos + o.start..pos + o.end]);
            pos += n;
        }
        assert_eq!(got, rest);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn corpus(target: &str) -> Vec<Vec<u8>> {
        let dir = format!("{}/../../fuzz/corpus/{target}", env!("CARGO_MANIFEST_DIR"));
        let Ok(entries) = std::fs::read_dir(&dir) else {
            return Vec::new();
        };
        entries
            .filter_map(Result::ok)
            .filter_map(|e| std::fs::read(e.path()).ok())
            .collect()
    }

    fn replay(target: &str, f: fn(&[u8])) {
        let files = corpus(target);
        assert!(!files.is_empty(), "fuzz/corpus/{target} is empty");
        for d in files {
            f(&d);
            for cut in [1, d.len() / 2, d.len().saturating_sub(1)] {
                f(&d[..cut.min(d.len())]);
            }
            for i in (0..d.len()).step_by(61) {
                let mut g = d.clone();
                g[i] ^= 0x41;
                f(&g);
            }
        }
    }

    #[test]
    fn replay_tls_server() {
        replay("tls_server", server);
    }

    #[test]
    fn replay_tls_client() {
        replay("tls_client", client);
    }

    #[test]
    fn replay_tls_record() {
        replay("tls_record", record);
    }

    /// Regenerates the seed corpora: `cargo test -p only-tls --lib write_corpus -- --ignored`.
    #[test]
    #[ignore = "writes fuzz/corpus"]
    fn write_corpus() {
        let base = format!("{}/../../fuzz/corpus", env!("CARGO_MANIFEST_DIR"));
        let write = |t: &str, name: &str, d: &[u8]| {
            let dir = format!("{base}/{t}");
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(format!("{dir}/{name}"), d).unwrap();
        };
        let f = fixture();
        let mut i = 0;
        for (sname, scfg) in [("plain", &f.server), ("auth_hrr", &f.server_auth)] {
            for (cname, ccfg) in [("dual", &f.client), ("tls12", &f.client12)] {
                // Record what each side sends during a real handshake.
                let mut c = Connection::client(ccfg.inner.clone(), "localhost").unwrap();
                let mut s = Connection::server(scfg.inner.clone());
                let (mut c2s_all, mut s2c_all) = (Vec::new(), Vec::new());
                let mut plain = Vec::new();
                let mut c2s = Vec::new();
                c.recv(&[], &mut plain, &mut c2s).unwrap();
                for _ in 0..6 {
                    c2s_all.extend_from_slice(&c2s);
                    let mut s2c = Vec::new();
                    s.recv(&std::mem::take(&mut c2s), &mut plain, &mut s2c)
                        .unwrap();
                    s2c_all.extend_from_slice(&s2c);
                    c.recv(&s2c, &mut plain, &mut c2s).unwrap();
                }
                // The first byte selects the configuration in the targets.
                let tag = u8::from(sname == "auth_hrr");
                let mut d = vec![tag];
                d.extend_from_slice(&c2s_all);
                write("tls_server", &format!("{sname}_{cname}"), &c2s_all);
                write("tls_server", &format!("{sname}_{cname}_tagged"), &d);
                write("tls_client", &format!("{sname}_{cname}"), &s2c_all);
                let tag = u8::from(cname == "tls12");
                let mut d = vec![tag];
                d.extend_from_slice(&s2c_all);
                write("tls_client", &format!("{sname}_{cname}_tagged"), &d);
                i += 1;
            }
        }
        assert_eq!(i, 4);
        // The new messages' bodies as such: CompressedCertificate, CertificateStatus.
        let leaf = &f.server.inner.cert.chain[0];
        let chain = vec![leaf.clone(), leaf.clone()];
        let mut body = Vec::new();
        crate::proto::msgs::certificate13_body(&mut body, &[], &chain, None);
        for (alg, file) in [
            (1, "compressed_certificate"),
            (2, "compressed_certificate_brotli"),
            (3, "compressed_certificate_zstd"),
        ] {
            let m = compressed_certificate(&body, alg).unwrap();
            write("tls_server", file, &m[4..]);
            write("tls_client", file, &m[4..]);
        }
        let mut cs = Vec::new();
        crate::proto::msgs::certificate_status_body(&mut cs, &[0x30, 3, 0x0a, 1, 0]);
        write("tls_client", "certificate_status", &cs);
        for (n, s) in suites::ALL.iter().enumerate() {
            let sel = n as u8;
            let keys = if s.is_tls13() {
                Keys::Tls13 {
                    suite: s,
                    secret: vec![sel; s.hash.len()],
                }
            } else {
                Keys::Tls12 {
                    suite: s,
                    key: vec![sel; s.aead.key_len()],
                    iv: vec![sel; s.aead.fixed_iv_len_12()],
                }
            };
            let mut w = RecordLayer::new();
            w.set_write(&keys);
            let mut d = vec![sel];
            w.seal(23, b"hello fuzzer", &mut d).unwrap();
            w.seal(22, &[1, 0, 0, 0], &mut d).unwrap();
            w.seal(21, &[1, 0], &mut d).unwrap();
            write("tls_record", &format!("suite_{:04x}", s.id), &d);
        }
    }
}
