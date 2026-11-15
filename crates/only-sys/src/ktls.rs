//! Linux kernel TLS (the `tls` upper-layer protocol, `linux/tls.h`): after a handshake done in
//! user space, the record keys are handed to the kernel, which then encrypts (`TLS_TX`) and
//! decrypts (`TLS_RX`) records itself; the socket carries plaintext for the application, and
//! `sendfile(2)` / splice work on it.
//!
//! Control records (alerts, post-handshake handshake messages) travel with a record-type
//! control message: [`ktls_send_record`] and [`ktls_recv`].

use std::io;
use std::os::fd::RawFd;

use crate::ffi;

/// The AEAD of the offloaded records.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KtlsCipher {
    /// AES-128-GCM.
    Aes128Gcm,
    /// AES-256-GCM.
    Aes256Gcm,
    /// ChaCha20-Poly1305.
    ChaCha20Poly1305,
}

/// The direction to offload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KtlsDir {
    /// Records the socket sends (`TLS_TX`).
    Tx,
    /// Records the socket receives (`TLS_RX`).
    Rx,
}

/// One direction's record protection, as the TLS record layer holds it.
#[derive(Clone, Copy)]
pub struct KtlsKeys<'a> {
    /// TLS 1.3 (otherwise TLS 1.2).
    pub tls13: bool,
    /// The AEAD.
    pub cipher: KtlsCipher,
    /// The traffic key (16 or 32 bytes).
    pub key: &'a [u8],
    /// TLS 1.3 and ChaCha20-Poly1305: the 12-byte IV the sequence number is XORed into. TLS 1.2
    /// GCM: the 4-byte implicit salt in the first bytes (the explicit nonce is the sequence
    /// number, as this workspace's record layer writes it).
    pub iv: [u8; 12],
    /// The sequence number of the next record.
    pub seq: u64,
}

impl std::fmt::Debug for KtlsKeys<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KtlsKeys")
            .field("tls13", &self.tls13)
            .field("cipher", &self.cipher)
            .field("seq", &self.seq)
            .finish_non_exhaustive()
    }
}

fn setsockopt<T>(fd: RawFd, level: i32, name: i32, value: &T) -> io::Result<()> {
    // SAFETY: `value` is a live, initialized `T` readable for `size_of::<T>()` bytes for the
    // duration of the call; the kernel copies it and keeps no pointer.
    let r = unsafe {
        ffi::setsockopt(
            fd,
            level,
            name,
            std::ptr::from_ref(value).cast(),
            size_of::<T>() as ffi::socklen_t,
        )
    };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Overwrites key material that was copied for the kernel (best effort: volatile writes).
fn wipe(b: &mut [u8]) {
    for x in b.iter_mut() {
        // SAFETY: `x` is a valid, aligned, exclusive reference.
        unsafe { std::ptr::write_volatile(x, 0) };
    }
}

/// Attaches the `tls` upper-layer protocol to a connected TCP socket. Fails with `ENOENT` when
/// the kernel has no `tls` module, `EEXIST`/`EBUSY` when another ULP is attached, `ENOTCONN`
/// before the connection is established.
pub fn ktls_attach(fd: RawFd) -> io::Result<()> {
    let name = *b"tls";
    // SAFETY: `name` is readable for its 3 bytes during the call (the kernel takes the length,
    // no terminator needed).
    let r = unsafe {
        ffi::setsockopt(
            fd,
            ffi::IPPROTO_TCP,
            ffi::TCP_ULP,
            name.as_ptr().cast(),
            name.len() as ffi::socklen_t,
        )
    };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Installs `keys` for one direction of a socket the `tls` ULP is attached to. Installing a
/// direction again (TLS 1.3 KeyUpdate) needs a kernel with rekey support (Linux 6.14 and
/// later); older kernels fail with `EBUSY`.
pub fn ktls_set(fd: RawFd, dir: KtlsDir, keys: &KtlsKeys<'_>) -> io::Result<()> {
    let name = match dir {
        KtlsDir::Tx => ffi::TLS_TX,
        KtlsDir::Rx => ffi::TLS_RX,
    };
    let version = if keys.tls13 {
        ffi::TLS_1_3_VERSION
    } else {
        ffi::TLS_1_2_VERSION
    };
    let seq = keys.seq.to_be_bytes();
    let bad = || io::Error::from(io::ErrorKind::InvalidInput);
    match keys.cipher {
        KtlsCipher::Aes128Gcm | KtlsCipher::Aes256Gcm => {
            let mut salt = [0u8; 4];
            salt.copy_from_slice(&keys.iv[..4]);
            let mut iv = [0u8; 8];
            if keys.tls13 {
                iv.copy_from_slice(&keys.iv[4..]);
            } else {
                // TLS 1.2: the explicit nonce of the next record (the sequence number).
                iv = seq;
            }
            if keys.cipher == KtlsCipher::Aes128Gcm {
                let mut ci = ffi::tls12_crypto_info_aes_gcm_128 {
                    info: ffi::tls_crypto_info {
                        version,
                        cipher_type: ffi::TLS_CIPHER_AES_GCM_128,
                    },
                    iv,
                    key: keys.key.try_into().map_err(|_| bad())?,
                    salt,
                    rec_seq: seq,
                };
                let r = setsockopt(fd, ffi::SOL_TLS, name, &ci);
                wipe(&mut ci.key);
                r
            } else {
                let mut ci = ffi::tls12_crypto_info_aes_gcm_256 {
                    info: ffi::tls_crypto_info {
                        version,
                        cipher_type: ffi::TLS_CIPHER_AES_GCM_256,
                    },
                    iv,
                    key: keys.key.try_into().map_err(|_| bad())?,
                    salt,
                    rec_seq: seq,
                };
                let r = setsockopt(fd, ffi::SOL_TLS, name, &ci);
                wipe(&mut ci.key);
                r
            }
        }
        KtlsCipher::ChaCha20Poly1305 => {
            let mut ci = ffi::tls12_crypto_info_chacha20_poly1305 {
                info: ffi::tls_crypto_info {
                    version,
                    cipher_type: ffi::TLS_CIPHER_CHACHA20_POLY1305,
                },
                iv: keys.iv,
                key: keys.key.try_into().map_err(|_| bad())?,
                rec_seq: seq,
            };
            let r = setsockopt(fd, ffi::SOL_TLS, name, &ci);
            wipe(&mut ci.key);
            r
        }
    }
}

/// Sends `data` as one record (or more, when longer than a record) of content type `typ` on a
/// socket with `TLS_TX` installed: alerts and post-handshake handshake messages. Blocks or not
/// as the socket does; returns the bytes taken.
pub fn ktls_send_record(fd: RawFd, typ: u8, data: &[u8]) -> io::Result<usize> {
    let mut cbuf = [0u64; ffi::cmsg_space(1).div_ceil(8)];
    let mut iov = ffi::iovec {
        iov_base: data.as_ptr().cast_mut().cast(),
        iov_len: data.len(),
    };
    let msg = ffi::msghdr {
        msg_name: std::ptr::null_mut(),
        msg_namelen: 0,
        msg_iov: &raw mut iov,
        msg_iovlen: 1,
        msg_control: cbuf.as_mut_ptr().cast(),
        msg_controllen: ffi::cmsg_space(1),
        msg_flags: 0,
    };
    // SAFETY: `msg` points at `cbuf`, which is 8-aligned and `cmsg_space(1)` bytes long, so the
    // first header and its one data byte lie inside it.
    unsafe {
        let c = ffi::cmsg_firsthdr(&raw const msg);
        (*c).cmsg_level = ffi::SOL_TLS;
        (*c).cmsg_type = ffi::TLS_SET_RECORD_TYPE;
        (*c).cmsg_len = ffi::cmsg_len(1);
        *ffi::cmsg_data(c) = typ;
    }
    // SAFETY: `msg`, its iovec (pointing at `data`, read-only for the kernel) and the control
    // buffer all outlive the call.
    let n = unsafe { ffi::sendmsg(fd, &raw const msg, 0) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(n as usize)
}

/// Receives from a socket with `TLS_RX` installed (blocking or not as the socket does): the
/// content type of the record the bytes came from and their length. The kernel never mixes
/// record types in one call, so a control record (alert, handshake message) arrives alone; give
/// it a buffer of at least 16 KiB so that one fits. `Ok((_, 0))` at end of stream.
pub fn ktls_recv(fd: RawFd, buf: &mut [u8]) -> io::Result<(u8, usize)> {
    let mut cbuf = [0u64; ffi::cmsg_space(1).div_ceil(8)];
    let mut iov = ffi::iovec {
        iov_base: buf.as_mut_ptr().cast(),
        iov_len: buf.len(),
    };
    let mut msg = ffi::msghdr {
        msg_name: std::ptr::null_mut(),
        msg_namelen: 0,
        msg_iov: &raw mut iov,
        msg_iovlen: 1,
        msg_control: cbuf.as_mut_ptr().cast(),
        msg_controllen: size_of_val(&cbuf),
        msg_flags: 0,
    };
    // SAFETY: `msg`, the iovec (pointing at `buf`, writable for its length) and the control
    // buffer all outlive the call.
    let n = unsafe { ffi::recvmsg(fd, &raw mut msg, 0) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut typ = 23; // application data unless the kernel says otherwise
    // SAFETY: `msg` is valid and its control buffer is readable for `msg_controllen` bytes
    // (the kernel shrank it to what it wrote); the walk stays inside it.
    unsafe {
        let mut c = ffi::cmsg_firsthdr(&raw const msg);
        while !c.is_null() {
            if (*c).cmsg_level == ffi::SOL_TLS
                && (*c).cmsg_type == ffi::TLS_GET_RECORD_TYPE
                && (*c).cmsg_len >= ffi::cmsg_len(1)
            {
                typ = *ffi::cmsg_data(c);
            }
            c = ffi::cmsg_nxthdr(&raw const msg, c);
        }
    }
    Ok((typ, n as usize))
}

/// The running kernel's `(major, minor)` version, from `uname(2)`.
fn kernel_version() -> (u32, u32) {
    // SAFETY: `utsname` is plain bytes; all-zero is a valid value.
    let mut u: ffi::utsname = unsafe { std::mem::zeroed() };
    // SAFETY: `u` is valid for writes for the duration of the call.
    if unsafe { ffi::uname(&raw mut u) } != 0 {
        return (0, 0);
    }
    let rel: Vec<u8> = u
        .release
        .iter()
        .take_while(|&&c| c != 0)
        .map(|&c| c.to_ne_bytes()[0])
        .collect();
    let rel = String::from_utf8_lossy(&rel);
    let mut it = rel
        .split(|c: char| !c.is_ascii_digit())
        .filter(|s| !s.is_empty());
    (
        it.next().and_then(|s| s.parse().ok()).unwrap_or(0),
        it.next().and_then(|s| s.parse().ok()).unwrap_or(0),
    )
}

/// Whether the kernel can install new keys on a direction already offloaded (TLS 1.3
/// KeyUpdate): Linux 6.14 and later. Without it a TLS 1.3 connection must stay in user space,
/// since the peer may send a KeyUpdate at any time.
pub fn ktls_rekey_supported() -> bool {
    kernel_version() >= (6, 14)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_bad_key_lengths() {
        let k = KtlsKeys {
            tls13: true,
            cipher: KtlsCipher::Aes128Gcm,
            key: &[0; 15],
            iv: [0; 12],
            seq: 0,
        };
        let e = ktls_set(-1, KtlsDir::Tx, &k).expect_err("short key");
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn kernel_version_parses() {
        assert!(kernel_version() >= (3, 0));
    }

    #[test]
    fn attach_fails_on_a_non_socket() {
        assert!(ktls_attach(-1).is_err());
    }
}
