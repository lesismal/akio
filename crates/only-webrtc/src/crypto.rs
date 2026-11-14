//! The pure-Rust crypto provider for str0m: DTLS 1.2/1.3 by `dimpl` on RustCrypto, SRTP
//! (AES-CM-SHA1-80, AEAD-AES-128-GCM, AEAD-AES-256-GCM), STUN HMAC-SHA1 and SHA-256
//! fingerprints on `only-crypto`, and a self-signed ECDSA P-256 certificate generator.
//!
//! Adapted from `str0m-rust-crypto` 0.6 (MIT OR Apache-2.0, by the str0m authors). That crate
//! generates certificates with `rcgen` on `aws-lc-rs` (a C library); here the certificate is
//! encoded directly, so the whole stack stays pure Rust with no C toolchain needed.

use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use only_crypto::aes::Aes;
use only_crypto::gcm::AesGcm;
use only_crypto::mac::Hmac;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use p256::pkcs8::EncodePrivateKey;

use str0m::config::{CryptoProvider, DtlsCert};
use str0m::crypto::dtls::{
    DtlsImplError, DtlsInstance, DtlsOutput, DtlsProvider, DtlsVersion, ProtocolVersion,
};
use str0m::crypto::{
    AeadAes128Gcm, AeadAes128GcmCipher, AeadAes256Gcm, AeadAes256GcmCipher, Aes128CmSha1_80Cipher,
    CryptoError, Sha1HmacProvider, Sha256Provider, SrtpProvider, SupportedAeadAes128Gcm,
    SupportedAeadAes256Gcm, SupportedAes128CmSha1_80,
};

/// The crypto provider every `Rtc` made by this crate uses (pure Rust: only-crypto + dimpl).
pub(crate) fn crypto_provider() -> Arc<CryptoProvider> {
    static SRTP: Srtp = Srtp;
    static SHA1_HMAC: Sha1Hmac = Sha1Hmac;
    static SHA256: Sha256 = Sha256;
    static DTLS: Dtls = Dtls;
    Arc::new(CryptoProvider {
        srtp_provider: &SRTP,
        sha1_hmac_provider: &SHA1_HMAC,
        sha256_provider: &SHA256,
        dtls_provider: &DTLS,
    })
}

/// A fresh self-signed ECDSA P-256 certificate (and PKCS#8 key) for DTLS, valid from a day ago
/// for a year, with a random 128-bit serial (Firefox wants serials unique across peers). Its
/// SHA-256 fingerprint goes into the SDP; peers verify the DTLS certificate against it.
pub(crate) fn generate_certificate() -> Option<DtlsCert> {
    let key = loop {
        let mut b = [0u8; 32];
        crate::fill_random(&mut b);
        if let Ok(k) = SigningKey::from_bytes(&b.into()) {
            break k;
        }
    };
    let pkcs8 = key.to_pkcs8_der().ok()?.as_bytes().to_vec();
    let point = key.verifying_key().to_encoded_point(false);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let mut serial = [0u8; 16];
    crate::fill_random(&mut serial);
    serial[0] = (serial[0] & 0x7f) | 0x40; // positive, no leading zero byte needed
    let tbs = der::tbs(&serial, now - 86_400, now + 365 * 86_400, point.as_bytes());
    let sig: Signature = key.sign(&tbs);
    let cert = der::certificate(&tbs, sig.to_der().as_bytes());
    Some(DtlsCert {
        certificate: cert,
        private_key: pkcs8,
    })
}

/// Just enough DER for a self-signed X.509 v3 certificate with an EC P-256 key.
mod der {
    const ECDSA_SHA256: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
    const EC_PUBLIC_KEY: &[u8] = &[0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
    const PRIME256V1: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
    const COMMON_NAME: &[u8] = &[0x06, 0x03, 0x55, 0x04, 0x03];

    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut v = vec![tag];
        let n = content.len();
        if n < 0x80 {
            v.push(n as u8);
        } else if n < 0x100 {
            v.extend_from_slice(&[0x81, n as u8]);
        } else {
            v.extend_from_slice(&[0x82, (n >> 8) as u8, n as u8]);
        }
        v.extend_from_slice(content);
        v
    }

    fn seq(parts: &[&[u8]]) -> Vec<u8> {
        tlv(0x30, &parts.concat())
    }

    /// `YYMMDDHHMMSSZ` (UTCTime) before 2050, `YYYYMMDDHHMMSSZ` (GeneralizedTime) after.
    fn time(unix: u64) -> Vec<u8> {
        let days = (unix / 86_400) as i64;
        let secs = unix % 86_400;
        // Howard Hinnant's civil_from_days.
        let z = days + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z - era * 146_097;
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let m = if mp < 10 { mp + 3 } else { mp - 9 };
        let y = yoe + era * 400 + i64::from(m <= 2);
        let hms = format!(
            "{m:02}{d:02}{:02}{:02}{:02}Z",
            secs / 3600,
            (secs / 60) % 60,
            secs % 60
        );
        if y < 2050 {
            tlv(0x17, format!("{:02}{hms}", y % 100).as_bytes())
        } else {
            tlv(0x18, format!("{y:04}{hms}").as_bytes())
        }
    }

    fn name() -> Vec<u8> {
        let cn = seq(&[COMMON_NAME, &tlv(0x0c, b"only-webrtc")]);
        seq(&[&tlv(0x31, &cn)])
    }

    pub(super) fn tbs(serial: &[u8; 16], not_before: u64, not_after: u64, point: &[u8]) -> Vec<u8> {
        let version = tlv(0xa0, &tlv(0x02, &[2]));
        let alg = seq(&[ECDSA_SHA256]);
        let validity = seq(&[&time(not_before), &time(not_after)]);
        let mut bits = vec![0u8];
        bits.extend_from_slice(point);
        let spki = seq(&[&seq(&[EC_PUBLIC_KEY, PRIME256V1]), &tlv(0x03, &bits)]);
        let name = name();
        seq(&[
            &version,
            &tlv(0x02, serial),
            &alg,
            &name,
            &validity,
            &name,
            &spki,
        ])
    }

    pub(super) fn certificate(tbs: &[u8], sig_der: &[u8]) -> Vec<u8> {
        let mut bits = vec![0u8];
        bits.extend_from_slice(sig_der);
        seq(&[tbs, &seq(&[ECDSA_SHA256]), &tlv(0x03, &bits)])
    }

    #[cfg(test)]
    pub(super) fn time_for_test(unix: u64) -> Vec<u8> {
        time(unix)
    }
}

// ---- DTLS ----

#[derive(Debug)]
struct Dtls;

impl DtlsProvider for Dtls {
    fn generate_certificate(&self) -> Option<DtlsCert> {
        generate_certificate()
    }

    fn new_dtls(
        &self,
        cert: &DtlsCert,
        now: Instant,
        dtls_version: DtlsVersion,
        mtu: Option<usize>,
    ) -> Result<Box<dyn DtlsInstance>, CryptoError> {
        let dimpl_cert = dimpl::DtlsCertificate {
            certificate: cert.certificate.clone(),
            private_key: cert.private_key.clone(),
        };
        // ICE verifies return routability before DTLS, which makes server cookies redundant.
        let mut builder = dimpl::Config::builder().use_server_cookie(false);
        if let Some(mtu) = mtu {
            builder = builder.mtu(mtu);
        }
        let config = Arc::new(
            builder
                .build()
                .map_err(|e| CryptoError::Other(format!("dimpl config: {e}")))?,
        );
        let dtls = match dtls_version {
            DtlsVersion::Dtls12 => dimpl::Dtls::new_12(config, dimpl_cert, now),
            DtlsVersion::Dtls13 => dimpl::Dtls::new_13(config, dimpl_cert, now),
            DtlsVersion::Auto => dimpl::Dtls::new_auto(config, dimpl_cert, now),
            _ => {
                return Err(CryptoError::Other(format!(
                    "unsupported DTLS version: {dtls_version}"
                )));
            }
        };
        Ok(Box::new(DtlsConn(dtls)))
    }
}

struct DtlsConn(dimpl::Dtls);

impl std::fmt::Debug for DtlsConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DtlsConn").finish_non_exhaustive()
    }
}

impl DtlsInstance for DtlsConn {
    fn set_active(&mut self, active: bool) {
        self.0.set_active(active);
    }
    fn handle_packet(&mut self, packet: &[u8]) -> Result<(), DtlsImplError> {
        self.0.handle_packet(packet)
    }
    fn poll_output<'a>(&mut self, buf: &'a mut [u8]) -> DtlsOutput<'a> {
        self.0.poll_output(buf)
    }
    fn handle_timeout(&mut self, now: Instant) -> Result<(), DtlsImplError> {
        self.0.handle_timeout(now)
    }
    fn send_application_data(&mut self, data: &[u8]) -> Result<(), DtlsImplError> {
        self.0.send_application_data(data)
    }
    fn is_active(&self) -> bool {
        self.0.is_active()
    }
    fn protocol_version(&self) -> Option<ProtocolVersion> {
        self.0.protocol_version()
    }
    fn is_closing(&self) -> bool {
        self.0.is_closing()
    }
    fn is_closed(&self) -> bool {
        self.0.is_closed()
    }
    fn close(&mut self) -> Result<(), DtlsImplError> {
        self.0.close()
    }
}

// ---- hashes ----

#[derive(Debug)]
struct Sha1Hmac;

impl Sha1HmacProvider for Sha1Hmac {
    fn sha1_hmac(&self, key: &[u8], payloads: &[&[u8]]) -> [u8; 20] {
        let mut mac = Hmac::<only_crypto::hash::Sha1>::new(key);
        for p in payloads {
            mac.update(p);
        }
        mac.finalize()
    }
}

#[derive(Debug)]
struct Sha256;

impl Sha256Provider for Sha256 {
    fn sha256(&self, data: &[u8]) -> [u8; 32] {
        only_crypto::hash::Sha256::digest(data)
    }
}

// ---- SRTP ----

struct CmCipher(Aes);

impl std::fmt::Debug for CmCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CmCipher").finish_non_exhaustive()
    }
}

impl Aes128CmSha1_80Cipher for CmCipher {
    fn encrypt(
        &mut self,
        iv: &[u8; 16],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        let out = output
            .get_mut(..input.len())
            .ok_or_else(|| CryptoError::Other("AES-CM: output too small".into()))?;
        out.copy_from_slice(input);
        self.0.apply_ctr(iv, out);
        Ok(())
    }

    fn decrypt(
        &mut self,
        iv: &[u8; 16],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        self.encrypt(iv, input, output)
    }
}

fn gcm_seal(
    c: &AesGcm,
    iv: &[u8; 12],
    aad: &[u8],
    input: &[u8],
    output: &mut [u8],
) -> Result<(), CryptoError> {
    if aad.len() < 12 {
        return Err(CryptoError::Other(
            "SRTP AEAD: AAD shorter than 12 octets".into(),
        ));
    }
    let n = input.len();
    let out = output
        .get_mut(..n + 16)
        .ok_or_else(|| CryptoError::Other("AES-GCM: output too small".into()))?;
    out[..n].copy_from_slice(input);
    let tag = c.encrypt_in_place_detached(iv, aad, &mut out[..n]);
    out[n..].copy_from_slice(&tag);
    Ok(())
}

fn gcm_open(
    c: &AesGcm,
    iv: &[u8; 12],
    aads: &[&[u8]],
    input: &[u8],
    output: &mut [u8],
) -> Result<usize, CryptoError> {
    let Some(n) = input.len().checked_sub(16) else {
        return Err(CryptoError::Other(
            "AES-GCM: input shorter than the tag".into(),
        ));
    };
    let joined;
    let aad = if aads.len() == 1 {
        aads[0]
    } else {
        joined = aads.concat();
        &joined
    };
    let out = output
        .get_mut(..n)
        .ok_or_else(|| CryptoError::Other("AES-GCM: output too small".into()))?;
    out.copy_from_slice(&input[..n]);
    c.decrypt_in_place_detached(iv, aad, out, &input[n..])
        .map_err(|e| CryptoError::Other(format!("AES-GCM decrypt: {e}")))?;
    Ok(n)
}

struct Gcm128(AesGcm);

impl std::fmt::Debug for Gcm128 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Gcm128").finish_non_exhaustive()
    }
}

impl AeadAes128GcmCipher for Gcm128 {
    fn encrypt(
        &mut self,
        iv: &[u8; AeadAes128Gcm::IV_LEN],
        aad: &[u8],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        gcm_seal(&self.0, iv, aad, input, output)
    }

    fn decrypt(
        &mut self,
        iv: &[u8; AeadAes128Gcm::IV_LEN],
        aads: &[&[u8]],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, CryptoError> {
        gcm_open(&self.0, iv, aads, input, output)
    }
}

struct Gcm256(AesGcm);

impl std::fmt::Debug for Gcm256 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Gcm256").finish_non_exhaustive()
    }
}

impl AeadAes256GcmCipher for Gcm256 {
    fn encrypt(
        &mut self,
        iv: &[u8; AeadAes256Gcm::IV_LEN],
        aad: &[u8],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        gcm_seal(&self.0, iv, aad, input, output)
    }

    fn decrypt(
        &mut self,
        iv: &[u8; AeadAes256Gcm::IV_LEN],
        aads: &[&[u8]],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, CryptoError> {
        gcm_open(&self.0, iv, aads, input, output)
    }
}

#[derive(Debug)]
struct Cm;

impl SupportedAes128CmSha1_80 for Cm {
    fn create_cipher(&self, key: [u8; 16], _encrypt: bool) -> Box<dyn Aes128CmSha1_80Cipher> {
        Box::new(CmCipher(Aes::new128(&key)))
    }
}

#[derive(Debug)]
struct G128;

impl SupportedAeadAes128Gcm for G128 {
    fn create_cipher(&self, key: [u8; 16], _encrypt: bool) -> Box<dyn AeadAes128GcmCipher> {
        Box::new(Gcm128(AesGcm::with_cipher(Aes::new128(&key))))
    }
}

#[derive(Debug)]
struct G256;

impl SupportedAeadAes256Gcm for G256 {
    fn create_cipher(&self, key: [u8; 32], _encrypt: bool) -> Box<dyn AeadAes256GcmCipher> {
        Box::new(Gcm256(AesGcm::with_cipher(Aes::new256(&key))))
    }
}

#[derive(Debug)]
struct Srtp;

/// AES-ECB of one block plus the PKCS#7 padding block, as the SRTP key derivation wants.
fn ecb_round(c: &Aes, input: &[u8], output: &mut [u8]) {
    let mut b = [[0u8; 16], [0x10u8; 16]];
    b[0].copy_from_slice(&input[..16]);
    c.encrypt_blocks(&mut b);
    output[..16].copy_from_slice(&b[0]);
    output[16..32].copy_from_slice(&b[1]);
}

impl SrtpProvider for Srtp {
    fn aes_128_cm_sha1_80(&self) -> &'static dyn SupportedAes128CmSha1_80 {
        &Cm
    }
    fn aead_aes_128_gcm(&self) -> &'static dyn SupportedAeadAes128Gcm {
        &G128
    }
    fn aead_aes_256_gcm(&self) -> &'static dyn SupportedAeadAes256Gcm {
        &G256
    }
    fn srtp_aes_128_ecb_round(&self, key: &[u8], input: &[u8], output: &mut [u8]) {
        let Ok(c) = Aes::new(&key[..16]) else {
            return;
        };
        ecb_round(&c, input, output);
    }
    fn srtp_aes_256_ecb_round(&self, key: &[u8], input: &[u8], output: &mut [u8]) {
        let Ok(c) = Aes::new(&key[..32]) else {
            return;
        };
        ecb_round(&c, input, output);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn der_times() {
        assert_eq!(der::time_for_test(0)[2..], *b"700101000000Z");
        // 2024-02-29 12:34:56
        assert_eq!(der::time_for_test(1_709_210_096)[2..], *b"240229123456Z");
        // 2050-01-01: GeneralizedTime
        let t = der::time_for_test(2_524_608_000);
        assert_eq!(t[0], 0x18);
        assert_eq!(t[2..], *b"20500101000000Z");
    }

    /// RFC 3711 appendix B.2 (AES-CM keystream) and the SRTP providers' plumbing.
    #[test]
    fn srtp_primitives() {
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let iv = [
            0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd,
            0x00, 0x00,
        ];
        let mut c = Cm.create_cipher(key, true);
        let mut out = [0u8; 48];
        c.encrypt(&iv, &[0u8; 48], &mut out).unwrap();
        assert_eq!(
            out[..16],
            [
                0xe0, 0x3e, 0xad, 0x09, 0x35, 0xc9, 0x5e, 0x80, 0xe1, 0x66, 0xb1, 0x6d, 0xd9, 0x2b,
                0x4e, 0xb4
            ]
        );
        assert_eq!(
            out[32..],
            [
                0x41, 0xe9, 0x5b, 0x3b, 0xb0, 0xa2, 0xe8, 0xdd, 0x47, 0x79, 0x01, 0xe4, 0xfc, 0xa8,
                0x94, 0xc0
            ]
        );

        let mut g = G128.create_cipher(key, true);
        let aad = [7u8; 12];
        let mut sealed = [0u8; 21];
        g.encrypt(&[1; 12], &aad, b"hello", &mut sealed).unwrap();
        let mut opened = [0u8; 5];
        let n = g
            .decrypt(&[1; 12], &[&aad[..4], &aad[4..]], &sealed, &mut opened)
            .unwrap();
        assert_eq!(&opened[..n], b"hello");
        sealed[0] ^= 1;
        assert!(g.decrypt(&[1; 12], &[&aad], &sealed, &mut opened).is_err());
        assert!(g.encrypt(&[1; 12], &aad[..11], b"x", &mut [0; 17]).is_err());

        let mut ecb = [0u8; 32];
        Srtp.srtp_aes_128_ecb_round(&key, &[0; 16], &mut ecb);
        let mut b = [0u8; 16];
        Aes::new128(&key).encrypt_block(&mut b);
        assert_eq!(ecb[..16], b);
    }

    #[test]
    fn certificate_loads_into_dimpl() {
        let c = generate_certificate().unwrap();
        assert_eq!(c.certificate[0], 0x30);
        let p = crypto_provider();
        let d = p
            .dtls_provider
            .new_dtls(&c, Instant::now(), DtlsVersion::Dtls12, None);
        assert!(d.is_ok());
    }
}
