//! The TLS extensions added after the core: record_size_limit (RFC 8449), certificate
//! compression (RFC 8879) and OCSP stapling (RFC 6066 / RFC 8446 section 4.4.2.1), in memory
//! between our client and server over both versions, alone and combined.

use super::alert::Alert;
use super::conn::Connection;
use super::msgs::{self, ClientHello};
use super::record::RecordLayer;
use super::tests::{Kind, Pki, Side, client, exchange, pki, rename_extension, server, transfer};
use crate::{Certificate, ClientConfig, ServerConfig};

/// Every record in `wire`: `(content type, payload length)`.
fn records(wire: &[u8]) -> Vec<(u8, usize)> {
    let mut out = Vec::new();
    let mut pos = 0;
    while let Some(n) = RecordLayer::frame(&wire[pos..]).unwrap() {
        out.push((wire[pos], n - 5));
        pos += n;
    }
    assert_eq!(pos, wire.len(), "partial record");
    out
}

/// Asserts that the protected records of `wire` respect a record_size_limit of `limit`
/// (TLS 1.3: the inner plaintext, content type included; TLS 1.2 with AES-GCM: the plaintext,
/// after the CCS, or from the start when `keyed`). Returns how many protected records there
/// were.
fn assert_within(wire: &[u8], limit: usize, tls13: bool, keyed: bool) -> usize {
    let mut protected = tls13 || keyed;
    let mut n = 0;
    for (typ, len) in records(wire) {
        if typ == 20 {
            protected = true;
            continue;
        }
        if !protected || (tls13 && typ != 23) {
            continue;
        }
        let inner = if tls13 { len - 16 } else { len - 8 - 16 };
        assert!(inner <= limit, "record of {inner} bytes over {limit}");
        n += 1;
    }
    n
}

/// Connects like `tests::connect`, also returning everything each side sent.
fn connect_wire(
    scfg: &ServerConfig,
    ccfg: &ClientConfig,
    name: &str,
) -> Result<(Connection, Connection, Vec<u8>, Vec<u8>), Side> {
    let mut c = crate::__proto::client(ccfg, name).map_err(Side::Client)?;
    let mut s = crate::__proto::server(scfg);
    let (mut c2s_all, mut s2c_all) = (Vec::new(), Vec::new());
    let mut plain = Vec::new();
    let mut c2s = Vec::new();
    c.recv(&[], &mut plain, &mut c2s).map_err(Side::Client)?;
    for _ in 0..100 {
        if c2s.is_empty() && !c.handshaking() && !s.handshaking() {
            break;
        }
        c2s_all.extend_from_slice(&c2s);
        let mut s2c = Vec::new();
        s.recv(&std::mem::take(&mut c2s), &mut plain, &mut s2c)
            .map_err(Side::Server)?;
        s2c_all.extend_from_slice(&s2c);
        c.recv(&s2c, &mut plain, &mut c2s).map_err(Side::Client)?;
    }
    assert!(!c.handshaking() && !s.handshaking());
    assert!(plain.is_empty());
    Ok((c, s, c2s_all, s2c_all))
}

/// Sends `len` bytes from `a` to `b`, returning the wire bytes.
fn send(a: &mut Connection, b: &mut Connection, len: usize) -> Vec<u8> {
    let data: Vec<u8> = (0..len).map(|i| i as u8).collect();
    let mut wire = Vec::new();
    a.seal(&data, &mut wire).unwrap();
    let mut got = Vec::new();
    b.recv(&wire, &mut got, &mut Vec::new()).unwrap();
    assert_eq!(got, data);
    wire
}

// ---- record_size_limit ----

#[test]
fn record_size_limit_matrix() {
    let p = pki(Kind::P256, &["localhost"]);
    for tls12 in [false, true] {
        for (cl, sl) in [
            (64u16, 64u16),
            (64, 16385),
            (16385, 100),
            (1000, 513),
            (16385, 16385),
        ] {
            let mut sb = server(&p).record_size_limit(sl);
            if tls12 {
                sb = sb.__suites(&[0xc02b]);
            }
            let scfg = sb.build().unwrap();
            let ccfg = client(&p)
                .record_size_limit(cl)
                .__tls12_only(tls12)
                .build()
                .unwrap();
            let (mut c, mut s, c2s, s2c) = connect_wire(&scfg, &ccfg, "localhost").unwrap();
            let what = format!("tls12={tls12} client={cl} server={sl}");
            // TLS 1.2 caps the server's value at 2^14 (no inner content type).
            let sl_sent = if tls12 { sl.min(16384) } else { sl };
            assert_eq!(c.record_size_limits(), (cl, sl_sent), "{what}");
            assert_eq!(s.record_size_limits(), (sl_sent, cl), "{what}");
            // The handshake already honoured them (the client's from the server's first
            // protected record on).
            let to_client = usize::from(cl).min(16384 + usize::from(!tls12));
            let to_server = usize::from(sl_sent);
            assert!(assert_within(&s2c, to_client, !tls12, false) > 0, "{what}");
            assert_within(&c2s, to_server, !tls12, false);
            // Bulk data both ways.
            let w = send(&mut c, &mut s, 40_000);
            let n = assert_within(&w, to_server, !tls12, true);
            let room = to_server - usize::from(!tls12);
            assert_eq!(n, 40_000usize.div_ceil(room.min(16384)), "{what}");
            let w = send(&mut s, &mut c, 40_000);
            assert_within(&w, to_client, !tls12, true);
            exchange(&mut c, &mut s);
        }
    }
}

#[test]
fn record_size_limit_needs_both_sides() {
    // A client that sends none gets none back and no limit is applied (the client side of
    // this, a server not answering, is what OpenSSL and Go do in tools/interop/tls/run.sh).
    let p = pki(Kind::P256, &["localhost"]);
    for tls12 in [false, true] {
        let scfg = server(&p).record_size_limit(100).build().unwrap();
        let ccfg = client(&p)
            .record_size_limit(64)
            .__tls12_only(tls12)
            .build()
            .unwrap();
        let mut c = crate::__proto::client(&ccfg, "localhost").unwrap();
        let mut s = crate::__proto::server(&scfg);
        let (mut plain, mut ch) = (Vec::new(), Vec::new());
        c.recv(&[], &mut plain, &mut ch).unwrap();
        let hello = ClientHello::parse(&ch[9..]).unwrap();
        assert_eq!(hello.record_limit, Some(64));
        rename_extension(&mut ch, msgs::EXT_RECORD_SIZE_LIMIT, 0x7a7a);
        let mut s2c = Vec::new();
        s.recv(&ch, &mut plain, &mut s2c).unwrap();
        assert_eq!(s.record_size_limits(), (0, 0), "tls12={tls12}");
        if tls12 {
            // The ServerHello leads the first record.
            let len = usize::from(u16::from_be_bytes([s2c[7], s2c[8]]));
            let sh = msgs::ServerHello::parse(&s2c[9..9 + len]).unwrap();
            assert_eq!(sh.record_limit, None);
        }
    }
}

#[test]
fn record_over_the_limit_is_record_overflow() {
    let p = pki(Kind::P256, &["localhost"]);
    for tls12 in [false, true] {
        let scfg = server(&p).record_size_limit(100).build().unwrap();
        let ccfg = client(&p).__tls12_only(tls12).build().unwrap();
        let (mut c, mut s, _, _) = connect_wire(&scfg, &ccfg, "localhost").unwrap();
        // A client ignoring the server's limit.
        c.test_record_layer().write_limit = 0;
        let mut wire = Vec::new();
        c.seal(&[1; 101], &mut wire).unwrap();
        let mut back = Vec::new();
        let e = s.recv(&wire, &mut Vec::new(), &mut back).unwrap_err();
        assert_eq!(e.alert, Alert::RecordOverflow, "tls12={tls12}");
        // Exactly the limit is fine (TLS 1.3: 99 bytes and the content type).
        let (mut c, mut s, _, _) = connect_wire(&scfg, &ccfg, "localhost").unwrap();
        c.test_record_layer().write_limit = 0;
        transfer(&mut c, &mut s, &vec![2; if tls12 { 100 } else { 99 }]);
    }
}

#[test]
fn record_size_limit_values_are_checked() {
    let p = pki(Kind::P256, &["localhost"]);
    for bad in [0u16, 63, 16386, u16::MAX] {
        assert!(server(&p).record_size_limit(bad).build().is_err(), "{bad}");
        assert!(client(&p).record_size_limit(bad).build().is_err(), "{bad}");
    }
    let mut r = super::codec::Reader::new(&[0, 63]);
    assert_eq!(
        msgs::parse_record_limit(&mut r).unwrap_err().alert,
        Alert::IllegalParameter
    );
    // A larger value than the protocol allows is kept (and capped when used).
    let mut r = super::codec::Reader::new(&[0xff, 0xff]);
    assert_eq!(msgs::parse_record_limit(&mut r).unwrap(), 0xffff);
}

#[test]
fn early_data_goes_under_the_tickets_record_limit() {
    let p = pki(Kind::P256, &["localhost"]);
    let scfg = server(&p)
        .session_tickets(true)
        .early_data(16384)
        .record_size_limit(200)
        .build()
        .unwrap();
    let ccfg = client(&p).early_data(true).build().unwrap();
    connect_wire(&scfg, &ccfg, "localhost").unwrap();
    let mut c = crate::__proto::client(&ccfg, "localhost").unwrap();
    let mut s = crate::__proto::server(&scfg);
    let early = vec![0x61u8; 1000];
    let mut c2s = Vec::new();
    c.seal(&early, &mut c2s).unwrap();
    // ClientHello, CCS, then early data records of at most 200 bytes each.
    let recs = records(&c2s);
    assert_eq!(recs[0].0, 22);
    let early_recs: Vec<_> = recs.iter().filter(|(t, _)| *t == 23).collect();
    assert!(early_recs.len() >= 6);
    assert!(early_recs.iter().all(|(_, l)| l - 16 <= 200));
    let (mut s_plain, mut c_plain) = (Vec::new(), Vec::new());
    for _ in 0..10 {
        let mut s2c = Vec::new();
        s.recv(&std::mem::take(&mut c2s), &mut s_plain, &mut s2c)
            .unwrap();
        c.recv(&s2c, &mut c_plain, &mut c2s).unwrap();
    }
    assert!(!c.handshaking() && !s.handshaking());
    assert_eq!(s.early_data(), crate::EarlyData::Accepted);
    assert_eq!(s_plain, early);
    assert_eq!(c.record_size_limits(), (16385, 200));
}

// ---- certificate compression ----

/// A chain that compresses well: the leaf three times (the extra copies are unused
/// intermediates).
fn padded(p: &Pki) -> Vec<Certificate> {
    vec![p.chain[0].clone(), p.chain[0].clone(), p.chain[0].clone()]
}

#[test]
fn certificate_compression_shrinks_the_server_flight() {
    let p = pki(Kind::Rsa, &["localhost"]);
    let cert_len = p.chain[0].as_der().len();
    let flight = |server_on: bool, client_on: bool, tls12: bool| {
        let scfg = ServerConfig::builder(padded(&p), p.key.clone())
            .certificate_compression(server_on)
            .build()
            .unwrap();
        let ccfg = client(&p)
            .certificate_compression(client_on)
            .__tls12_only(tls12)
            .build()
            .unwrap();
        let (mut c, mut s, _, s2c) = connect_wire(&scfg, &ccfg, "localhost").unwrap();
        assert_eq!(c.peer_certificates().len(), 3);
        assert_eq!(
            c.peer_certificate_compressed(),
            server_on && client_on && !tls12
        );
        exchange(&mut c, &mut s);
        s2c.len()
    };
    let on = flight(true, true, false);
    let off = flight(false, true, false);
    assert!(on + cert_len < off, "compressed {on}, plain {off}");
    // Either side off: plain.
    assert_eq!(flight(true, false, false), off);
    // TLS 1.2 has no certificate compression.
    assert_eq!(flight(true, true, true), flight(false, false, true));
    // Defaults: the server compresses, the client does not offer it.
    let scfg = server(&p).build().unwrap();
    let (c, _, c2s, _) = connect_wire(&scfg, &client(&p).build().unwrap(), "localhost").unwrap();
    let n = RecordLayer::frame(&c2s).unwrap().unwrap();
    assert_eq!(ClientHello::parse(&c2s[9..n]).unwrap().cert_comp, None);
    assert!(!c.peer_certificate_compressed());
    let ccfg = client(&p).certificate_compression(true).build().unwrap();
    let (c, _, _, _) = connect_wire(&scfg, &ccfg, "localhost").unwrap();
    assert!(c.peer_certificate_compressed());
}

#[test]
fn compressed_client_certificates() {
    let sp = pki(Kind::P256, &["localhost"]);
    let cp = pki(Kind::Ed25519, &["client"]);
    let cert_len = cp.chain[0].as_der().len();
    let flight = |server_on: bool, client_on: bool| {
        let scfg = server(&sp)
            .client_auth_required(cp.roots.clone())
            .certificate_compression(server_on)
            .build()
            .unwrap();
        let ccfg = client(&sp)
            .client_cert(padded(&cp), cp.key.clone())
            .certificate_compression(client_on)
            .build()
            .unwrap();
        let (mut c, mut s, c2s, _) = connect_wire(&scfg, &ccfg, "localhost").unwrap();
        assert_eq!(s.peer_certificates().len(), 3);
        assert_eq!(s.peer_certificate_compressed(), server_on && client_on);
        exchange(&mut c, &mut s);
        c2s.len()
    };
    let on = flight(true, true);
    let off = flight(false, false);
    assert!(on + cert_len < off, "compressed {on}, plain {off}");
    // Either side off: plain (the client's offer of three algorithms alone adds 11 bytes to
    // its ClientHello).
    assert_eq!(flight(false, true), off + 11);
    assert_eq!(flight(true, false), off);
}

#[test]
fn certificate_compression_algorithms() {
    use crate::CertCompression::{Brotli, Zlib, Zstd};
    let p = pki(Kind::Rsa, &["localhost"]);
    // What each algorithm alone makes of the chain; with all of them on both sides the server
    // picks the smallest.
    let flight = |server: &[crate::CertCompression], client_algs: &[crate::CertCompression]| {
        let scfg = ServerConfig::builder(padded(&p), p.key.clone())
            .certificate_compression_algorithms(server)
            .build()
            .unwrap();
        let ccfg = client(&p)
            .certificate_compression_algorithms(client_algs)
            .build()
            .unwrap();
        let (mut c, mut s, _, s2c) = connect_wire(&scfg, &ccfg, "localhost").unwrap();
        assert_eq!(c.peer_certificates().len(), 3);
        let alg = c.peer_certificate_compression();
        assert_eq!(c.peer_certificate_compressed(), alg.is_some());
        exchange(&mut c, &mut s);
        (alg, s2c.len())
    };
    let mut sizes = Vec::new();
    for a in [Zlib, Brotli, Zstd] {
        let (got, n) = flight(&[Zlib, Brotli, Zstd], &[a]);
        assert_eq!(got, Some(a));
        assert_eq!(flight(&[a], &[Zlib, Brotli, Zstd]), (Some(a), n));
        sizes.push((n, a));
    }
    let smallest = sizes.iter().map(|x| x.0).min().unwrap();
    let (got, n) = flight(&[Zlib, Brotli, Zstd], &[Zlib, Brotli, Zstd]);
    assert_eq!(n, smallest, "{sizes:?}");
    assert!(sizes.contains(&(n, got.unwrap())), "{sizes:?}");
    // No algorithm in common, or none at all: plain.
    let (plain, _) = flight(&[Brotli], &[Zstd]);
    assert_eq!(plain, None);
    assert_eq!(flight(&[], &[Zstd]).0, None);
    assert_eq!(flight(&[Zstd], &[]).0, None);
    // certificate_compression(true) is all three; the client offers brotli, zstd, zlib.
    let scfg = server(&p).build().unwrap();
    let ccfg = client(&p).certificate_compression(true).build().unwrap();
    let (_, _, c2s, _) = connect_wire(&scfg, &ccfg, "localhost").unwrap();
    let n = RecordLayer::frame(&c2s).unwrap().unwrap();
    assert_eq!(
        ClientHello::parse(&c2s[9..n]).unwrap().cert_comp,
        Some(vec![2, 3, 1])
    );
}

#[test]
fn compressed_certificate_decoding() {
    let body = msgs::certificate13(&[], &[vec![0x41; 3000], vec![0x42; 100]]);
    let body = &body[4..];
    for alg in [1u16, 2, 3] {
        let all = msgs::CompAlgs::ALL;
        let m = msgs::compressed_certificate(body, alg).unwrap();
        assert_eq!(m[0], msgs::COMPRESSED_CERTIFICATE);
        assert_eq!(u16::from_be_bytes([m[4], m[5]]), alg);
        assert_eq!(
            msgs::decompress_certificate(&m[4..], 1 << 17, all).unwrap(),
            (body.to_vec(), alg)
        );
        // Over the size we take.
        let e = msgs::decompress_certificate(&m[4..], 1000, all).unwrap_err();
        assert_eq!(e.alert, Alert::BadCertificate);
        // An algorithm we did not offer.
        let only = msgs::CompAlgs::NONE.with(alg % 3 + 1);
        let e = msgs::decompress_certificate(&m[4..], 1 << 17, only).unwrap_err();
        assert_eq!(e.alert, Alert::IllegalParameter);
        let mut bad = m[4..].to_vec();
        bad[1] = 4;
        let e = msgs::decompress_certificate(&bad, 1 << 17, all).unwrap_err();
        assert_eq!(e.alert, Alert::IllegalParameter);
        // Announced length wrong, either way.
        for d in [1u8, 0xff] {
            let mut bad = m[4..].to_vec();
            bad[4] = bad[4].wrapping_add(d);
            let e = msgs::decompress_certificate(&bad, 1 << 17, all).unwrap_err();
            assert_eq!(e.alert, Alert::BadCertificate, "alg {alg} delta {d}");
        }
        // Corrupt data: an error, never a panic, at every byte.
        for i in 9..m.len() {
            let mut bad = m[4..].to_vec();
            bad[i - 4] ^= 0x55;
            if let Ok((c, _)) = msgs::decompress_certificate(&bad, 1 << 17, all) {
                assert_eq!(c.len(), body.len());
            }
        }
        // Truncated at every length.
        for l in 0..m.len() - 4 {
            assert!(msgs::decompress_certificate(&m[4..4 + l], 1 << 17, all).is_err());
        }
    }
    // Empty compressed data.
    assert_eq!(
        msgs::decompress_certificate(&[0, 1, 0, 0, 5, 0, 0, 0], 1 << 17, msgs::CompAlgs::ALL)
            .unwrap_err()
            .alert,
        Alert::DecodeError
    );
    // Incompressible: not worth a CompressedCertificate.
    let noise: Vec<u8> = (0..200u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect();
    for alg in [1, 2, 3] {
        assert!(msgs::compressed_certificate(&noise, alg).is_none());
    }
    // An empty algorithm list.
    let mut r = super::codec::Reader::new(&[0]);
    assert_eq!(
        msgs::parse_cert_comp(&mut r).unwrap_err().alert,
        Alert::DecodeError
    );
}

// ---- OCSP stapling ----

/// A stand-in OCSP response: successful, with opaque response bytes (never verified).
fn ocsp(tag: u8) -> Vec<u8> {
    let mut v = vec![0x30, 0, 0x0a, 1, 0, 0xa0, 0x20];
    v.extend([tag; 0x20]);
    v[1] = (v.len() - 2) as u8;
    v
}

#[test]
fn ocsp_stapling() {
    let p = pki(Kind::P256, &["localhost", "alt.test"]);
    let alt = pki(Kind::P256, &["alt.test"]);
    let mut roots = p.roots.clone();
    roots.add(&alt.chain[0]).unwrap();
    for tls12 in [false, true] {
        for compression in [true, false] {
            let scfg = server(&p)
                .ocsp_response(ocsp(1))
                .sni_cert("alt.test", padded(&alt), alt.key.clone())
                .sni_ocsp_response("ALT.test", ocsp(2))
                .certificate_compression(compression)
                .session_cache(0)
                .build()
                .unwrap();
            let asking = ClientConfig::builder()
                .roots(roots.clone())
                .ocsp_stapling(true)
                .certificate_compression(compression)
                .__tls12_only(tls12)
                .build()
                .unwrap();
            let what = format!("tls12={tls12} compression={compression}");
            let (mut c, mut s, _, _) = connect_wire(&scfg, &asking, "localhost").unwrap();
            assert_eq!(c.ocsp_response(), Some(&ocsp(1)[..]), "{what}");
            assert_eq!(s.ocsp_response(), None);
            exchange(&mut c, &mut s);
            let (c, _, _, _) = connect_wire(&scfg, &asking, "alt.test").unwrap();
            assert_eq!(c.ocsp_response(), Some(&ocsp(2)[..]), "{what}");
            // Not asked for: not sent.
            let plain = ClientConfig::builder()
                .roots(roots.clone())
                .certificate_compression(compression)
                .__tls12_only(tls12)
                .build()
                .unwrap();
            let (_, _, c2s, s2c) = connect_wire(&scfg, &plain, "localhost").unwrap();
            let n = RecordLayer::frame(&c2s).unwrap().unwrap();
            assert!(!ClientHello::parse(&c2s[9..n]).unwrap().status_request);
            let (c, _, _, s2c_asked) = connect_wire(&scfg, &asking, "localhost").unwrap();
            assert_eq!(c.ocsp_response(), Some(&ocsp(1)[..]));
            assert!(s2c.len() < s2c_asked.len(), "{what}");
            // Nothing configured: none.
            let none = server(&p).build().unwrap();
            let (c, _, _, _) = connect_wire(&none, &asking, "localhost").unwrap();
            assert_eq!(c.ocsp_response(), None, "{what}");
        }
    }
}

#[test]
fn ocsp_not_on_resumption() {
    let p = pki(Kind::P256, &["localhost"]);
    for tls12 in [false, true] {
        let scfg = server(&p)
            .ocsp_response(ocsp(3))
            .session_tickets(true)
            .build()
            .unwrap();
        let ccfg = client(&p)
            .ocsp_stapling(true)
            .__tls12_only(tls12)
            .build()
            .unwrap();
        let (c, _, _, _) = connect_wire(&scfg, &ccfg, "localhost").unwrap();
        assert_eq!(c.ocsp_response(), Some(&ocsp(3)[..]));
        let (c, _, _, _) = connect_wire(&scfg, &ccfg, "localhost").unwrap();
        assert!(c.resumed(), "tls12={tls12}");
        assert_eq!(c.ocsp_response(), None);
    }
}

#[test]
fn ocsp_configuration_is_checked() {
    let p = pki(Kind::P256, &["localhost"]);
    for bad in [
        vec![],
        vec![0x30, 0],
        vec![0x30, 3, 0x0a, 1, 1], // unsuccessful, no responseBytes
        vec![0x30, 6, 0x0a, 1, 0, 0xa0, 0], // length past the end
        vec![0x04, 5, 0x0a, 1, 0, 0xa0, 0], // not a SEQUENCE
    ] {
        assert!(
            server(&p).ocsp_response(bad.clone()).build().is_err(),
            "{bad:?}"
        );
    }
    assert!(server(&p).ocsp_response(ocsp(1)).build().is_ok());
    // An SNI response without its certificate.
    let e = server(&p)
        .sni_ocsp_response("other.test", ocsp(1))
        .build()
        .unwrap_err();
    assert!(e.to_string().contains("other.test"));
}

// ---- all together ----

/// The in-memory matrix with the extensions on: versions, key types, small record limits both
/// ways, compression, OCSP and client certificates.
#[test]
fn extensions_matrix() {
    let cp = pki(Kind::P256, &["client"]);
    for kind in [Kind::P256, Kind::P384, Kind::Ed25519, Kind::Rsa] {
        let p = pki(kind, &["localhost"]);
        for tls12 in [false, true] {
            for (limit, compression, auth) in [
                (64u16, true, true),
                (777, false, true),
                (16385, true, false),
            ] {
                let mut sb = ServerConfig::builder(padded(&p), p.key.clone())
                    .record_size_limit(limit)
                    .certificate_compression(compression)
                    .ocsp_response(ocsp(9));
                if auth {
                    sb = sb.client_auth_required(cp.roots.clone());
                }
                let mut cb = client(&p)
                    .record_size_limit(limit)
                    .certificate_compression(compression)
                    .ocsp_stapling(true)
                    .__tls12_only(tls12);
                if auth {
                    cb = cb.client_cert(padded(&cp), cp.key.clone());
                }
                let what = format!("{kind:?} tls12={tls12} limit={limit} comp={compression}");
                let (mut c, mut s, _, _) =
                    connect_wire(&sb.build().unwrap(), &cb.build().unwrap(), "localhost")
                        .unwrap_or_else(|e| panic!("{what}: {e:?}"));
                assert_eq!(c.ocsp_response(), Some(&ocsp(9)[..]), "{what}");
                assert_eq!(s.peer_certificates().len(), if auth { 3 } else { 0 });
                let cap = if tls12 { limit.min(16384) } else { limit };
                assert_eq!(c.record_size_limits(), (limit, cap), "{what}");
                send(&mut c, &mut s, 20_000);
                send(&mut s, &mut c, 20_000);
                exchange(&mut c, &mut s);
            }
        }
    }
}

/// A KeyUpdate of the wrong length is decode_error, a wrong request_update illegal_parameter
/// (RFC 8446 section 4.6.3; tlsfuzzer's test-tls13-keyupdate.py "large KeyUpdate message").
#[test]
fn malformed_key_update_alerts() {
    let suite = &super::suites::TLS13_AES_128_GCM_SHA256;
    let (mut r, mut w) = (vec![1u8; 32], vec![2u8; 32]);
    let mut out = Vec::new();
    for (body, alert) in [
        (&[0u8, 0][..], Alert::DecodeError),
        (&[1; 300][..], Alert::DecodeError),
        (&[][..], Alert::DecodeError),
        (&[2][..], Alert::IllegalParameter),
    ] {
        let e = super::client::key_update(suite, body, &mut r, &mut w, &mut out).unwrap_err();
        assert_eq!(e.alert, alert, "{body:?}");
    }
    assert!(super::client::key_update(suite, &[1], &mut r, &mut w, &mut out).is_ok());
}

#[test]
fn status_request_v2_is_ignored() {
    // RFC 6961 (ocsp_multi, TLS 1.2 only, superseded by TLS 1.3's per-certificate
    // status_request): the client never offers it, the server answers a ClientHello that does
    // as if it were absent (ADR-062).
    const STATUS_REQUEST_V2: u16 = 17;
    let p = pki(Kind::P256, &["localhost"]);
    let scfg = server(&p).ocsp_response(ocsp(1)).build().unwrap();
    for tls12 in [false, true] {
        let ccfg = ClientConfig::builder()
            .roots(p.roots.clone())
            .ocsp_stapling(true)
            .__tls12_only(tls12)
            .build()
            .unwrap();
        let mut c = crate::__proto::client(&ccfg, "localhost").unwrap();
        let (mut plain, mut wire) = (Vec::new(), Vec::new());
        c.recv(&[], &mut plain, &mut wire).unwrap();
        let first = 5 + usize::from(u16::from_be_bytes([wire[3], wire[4]]));
        let ch = ClientHello::parse(&wire[9..first]).unwrap();
        assert!(!ch.exts.iter().any(|(t, _)| *t == STATUS_REQUEST_V2));
        // The same ClientHello asking with status_request_v2 instead of status_request.
        let mut v2 = wire[..first].to_vec();
        rename_extension(&mut v2, msgs::EXT_STATUS_REQUEST, STATUS_REQUEST_V2);
        let mut s = crate::__proto::server(&scfg);
        let mut out = Vec::new();
        s.recv(&v2, &mut plain, &mut out).unwrap();
        assert!(s.handshaking());
        // The ServerHello (plaintext in both versions) answers neither request, and no
        // CertificateStatus follows in TLS 1.2.
        let sh_len = usize::from(u16::from_be_bytes([out[3], out[4]]));
        let sh = &out[5..5 + sh_len];
        assert_eq!(sh[0], msgs::SERVER_HELLO);
        let exts = server_hello_extensions(&sh[4..]);
        assert!(!exts.contains(&STATUS_REQUEST_V2) && !exts.contains(&msgs::EXT_STATUS_REQUEST));
        if tls12 {
            let mut pos = 0;
            let flight = &out[5..];
            let mut types = Vec::new();
            while pos + 4 <= flight.len() && flight[pos] != 0x14 {
                types.push(flight[pos]);
                let l = (usize::from(flight[pos + 1]) << 16)
                    | (usize::from(flight[pos + 2]) << 8)
                    | usize::from(flight[pos + 3]);
                pos += 4 + l;
            }
            assert!(!types.contains(&msgs::CERTIFICATE_STATUS), "{types:?}");
        }
    }
}

/// The extension types of a ServerHello body.
fn server_hello_extensions(body: &[u8]) -> Vec<u16> {
    let mut r = super::codec::Reader::new(body);
    r.bytes(2 + 32).unwrap();
    r.vec8().unwrap();
    r.bytes(3).unwrap();
    let mut e = super::codec::Reader::new(r.vec16().unwrap());
    let mut types = Vec::new();
    while !e.is_empty() {
        types.push(e.u16().unwrap());
        e.vec16().unwrap();
    }
    types
}

#[test]
fn missing_key_share_is_missing_extension() {
    // supported_groups without key_share (RFC 8446 section 9.2): refused, not retried.
    let p = pki(Kind::P256, &["localhost"]);
    let scfg = server(&p).build().unwrap();
    let ccfg = ClientConfig::builder().roots(p.roots).build().unwrap();
    let mut c = crate::__proto::client(&ccfg, "localhost").unwrap();
    let (mut plain, mut wire) = (Vec::new(), Vec::new());
    c.recv(&[], &mut plain, &mut wire).unwrap();
    let first = 5 + usize::from(u16::from_be_bytes([wire[3], wire[4]]));
    let mut ch = wire[..first].to_vec();
    rename_extension(&mut ch, msgs::EXT_KEY_SHARE, 0xfafa);
    let mut s = crate::__proto::server(&scfg);
    let e = s.recv(&ch, &mut plain, &mut Vec::new()).unwrap_err();
    assert_eq!(e.alert, Alert::MissingExtension);
}
