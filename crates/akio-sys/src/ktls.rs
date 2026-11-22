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

/// Promises the kernel that the files sent with `sendfile(2)` on this socket do not change
/// while in flight, so that a NIC encrypting the records (TLS device offload) reads the page
/// cache directly instead of a copy (`TLS_TX_ZEROCOPY_RO`, Linux 6.0). Without device offload
/// the option has no effect. Set after the send keys.
pub fn ktls_tx_zerocopy_ro(fd: RawFd) -> io::Result<()> {
    setsockopt(fd, ffi::SOL_TLS, ffi::TLS_TX_ZEROCOPY_RO, &1u32)
}

/// TLS 1.3 receive direction: expects the peer not to pad its records, so the kernel decrypts
/// straight into the caller's buffer (and decrypts again, counting `TlsRxNoPadViolation`, when
/// a record turns out padded) (`TLS_RX_EXPECT_NO_PAD`, Linux 6.0). Set after the receive keys.
pub fn ktls_rx_expect_no_pad(fd: RawFd) -> io::Result<()> {
    setsockopt(fd, ffi::SOL_TLS, ffi::TLS_RX_EXPECT_NO_PAD, &1u32)
}

/// The kernel TLS offload features a network interface has turned on (`ethtool -k`:
/// `tls-hw-tx-offload`, `tls-hw-rx-offload`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NetdevTls {
    /// The NIC encrypts the records it sends.
    pub tx: bool,
    /// The NIC decrypts the records it receives.
    pub rx: bool,
}

/// A datagram socket for `ioctl`s, closed on drop.
struct IoctlSock(RawFd);

impl IoctlSock {
    fn new() -> io::Result<IoctlSock> {
        // SAFETY: a plain system call with constant arguments.
        let fd = unsafe { ffi::socket(ffi::AF_INET, ffi::SOCK_DGRAM | ffi::SOCK_CLOEXEC, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(IoctlSock(fd))
    }

    /// `SIOCETHTOOL` on interface `name` with the command buffer `data`.
    fn ethtool(&self, name: &str, data: &mut [u32]) -> io::Result<()> {
        if name.is_empty() || name.len() >= ffi::IFNAMSIZ || name.contains('\0') {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let mut ifr = ffi::ifreq_data {
            ifr_name: [0; ffi::IFNAMSIZ],
            ifr_data: data.as_mut_ptr().cast(),
            _pad: [0; 16],
        };
        for (d, s) in ifr.ifr_name.iter_mut().zip(name.bytes()) {
            *d = s as ffi::c_char;
        }
        // SAFETY: `ifr` is a valid `struct ifreq` naming a NUL-terminated interface, and its
        // `ifr_data` points at `data`, which the caller sized for the command it holds (the
        // kernel writes no more than the counts written in it). Both outlive the call.
        let r = unsafe { ffi::ioctl(self.0, ffi::SIOCETHTOOL, &raw mut ifr) };
        if r < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

impl Drop for IoctlSock {
    fn drop(&mut self) {
        // SAFETY: `self.0` is a descriptor this value owns.
        unsafe { ffi::close(self.0) };
    }
}

/// Reads the TLS offload features of interface `name` with the ethtool `ioctl`s (no privilege
/// needed). An interface without them (loopback, a bridge, most NICs) reports both off.
pub fn netdev_tls_offload(name: &str) -> io::Result<NetdevTls> {
    let f = netdev_features(name, &["tls-hw-tx-offload", "tls-hw-rx-offload"])?;
    Ok(NetdevTls { tx: f[0], rx: f[1] })
}

/// Whether each of the netdev features `want` (by their ethtool names) is active on interface
/// `name`; a name the kernel does not know reads as off.
pub fn netdev_features(name: &str, want: &[&str]) -> io::Result<Vec<bool>> {
    let sock = IoctlSock::new()?;
    // How many features there are: `struct ethtool_sset_info` (cmd, reserved, a u64 mask of
    // string sets, then one u32 count per set in the mask).
    let mut info = [0u32; 5];
    info[0] = ffi::ETHTOOL_GSSET_INFO;
    info[2] = 1 << ffi::ETH_SS_FEATURES; // the low half of the u64 mask (little-endian)
    sock.ethtool(name, &mut info)?;
    let none = vec![false; want.len()];
    if info[2] & (1 << ffi::ETH_SS_FEATURES) == 0 {
        return Ok(none);
    }
    let count = info[4] as usize;
    if count == 0 || count > 4096 {
        return Ok(none);
    }
    // Their names: `struct ethtool_gstrings` (cmd, string_set, len, then len * 32 bytes).
    let words = ffi::ETH_GSTRING_LEN / 4;
    let mut strings = vec![0u32; 3 + count * words];
    strings[0] = ffi::ETHTOOL_GSTRINGS;
    strings[1] = ffi::ETH_SS_FEATURES;
    strings[2] = count as u32;
    sock.ethtool(name, &mut strings)?;
    let count = count.min(strings[2] as usize);
    let bytes: Vec<u8> = strings[3..].iter().flat_map(|w| w.to_ne_bytes()).collect();
    let index: Vec<Option<usize>> = want
        .iter()
        .map(|w| {
            bytes
                .chunks_exact(ffi::ETH_GSTRING_LEN)
                .take(count)
                .position(|s| s.split(|&b| b == 0).next() == Some(w.as_bytes()))
        })
        .collect();
    if index.iter().all(Option::is_none) {
        return Ok(none);
    }
    // Their state: `struct ethtool_gfeatures` (cmd, size, then `size` blocks of four u32s:
    // available, requested, active, never_changed).
    let blocks = count.div_ceil(32);
    let mut feats = vec![0u32; 2 + 4 * blocks];
    feats[0] = ffi::ETHTOOL_GFEATURES;
    feats[1] = blocks as u32;
    sock.ethtool(name, &mut feats)?;
    let active =
        |i: &Option<usize>| i.is_some_and(|i| feats[2 + 4 * (i / 32) + 2] & (1 << (i % 32)) != 0);
    Ok(index.iter().map(active).collect())
}

/// The addresses of the host's network interfaces, with the interface names (`getifaddrs(3)`).
pub fn interface_addrs() -> io::Result<Vec<(String, std::net::IpAddr)>> {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    let mut head: *mut ffi::ifaddrs = std::ptr::null_mut();
    // SAFETY: `head` is valid for writes; on success it holds a list freed below.
    if unsafe { ffi::getifaddrs(&raw mut head) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut out = Vec::new();
    let mut p = head;
    while !p.is_null() {
        // SAFETY: `p` is an entry of the list `getifaddrs` returned, alive until
        // `freeifaddrs`; its name is a NUL-terminated string and its address, when not null,
        // a socket address of the size its family implies (read unaligned).
        unsafe {
            let e = &*p;
            if !e.ifa_addr.is_null() && !e.ifa_name.is_null() {
                let family = std::ptr::read_unaligned(e.ifa_addr.cast::<ffi::sa_family_t>());
                let ip = match i32::from(family) {
                    ffi::AF_INET => {
                        let a = std::ptr::read_unaligned(e.ifa_addr.cast::<ffi::sockaddr_in>());
                        Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(a.sin_addr.s_addr))))
                    }
                    ffi::AF_INET6 => {
                        let a = std::ptr::read_unaligned(e.ifa_addr.cast::<ffi::sockaddr_in6>());
                        Some(IpAddr::V6(Ipv6Addr::from(a.sin6_addr.s6_addr)))
                    }
                    _ => None,
                };
                if let Some(ip) = ip {
                    let name = std::ffi::CStr::from_ptr(e.ifa_name);
                    out.push((name.to_string_lossy().into_owned(), ip));
                }
            }
            p = e.ifa_next;
        }
    }
    // SAFETY: `head` came from a successful `getifaddrs` and is freed once.
    unsafe { ffi::freeifaddrs(head) };
    Ok(out)
}

/// Counters of the kernel TLS module (`/proc/net/tls_stat`, per network namespace).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TlsStat {
    /// Send directions installed in software (`TlsTxSw`), cumulative.
    pub tx_sw: u64,
    /// Receive directions installed in software (`TlsRxSw`), cumulative.
    pub rx_sw: u64,
    /// Send directions a NIC took (`TlsTxDevice`), cumulative.
    pub tx_device: u64,
    /// Receive directions a NIC took (`TlsRxDevice`), cumulative.
    pub rx_device: u64,
}

/// Reads [`TlsStat`]; `NotFound` while the `tls` module is not loaded.
pub fn tls_stat() -> io::Result<TlsStat> {
    Ok(parse_tls_stat(&std::fs::read_to_string(
        "/proc/net/tls_stat",
    )?))
}

fn parse_tls_stat(text: &str) -> TlsStat {
    let mut s = TlsStat::default();
    for line in text.lines() {
        let mut it = line.split_whitespace();
        let (Some(k), Some(v)) = (it.next(), it.next()) else {
            continue;
        };
        let Ok(v) = v.parse() else { continue };
        match k {
            "TlsTxSw" => s.tx_sw = v,
            "TlsRxSw" => s.rx_sw = v,
            "TlsTxDevice" => s.tx_device = v,
            "TlsRxDevice" => s.rx_device = v,
            _ => {}
        }
    }
    s
}

/// Whether the running kernel is at least `major.minor`.
pub fn kernel_at_least(major: u32, minor: u32) -> bool {
    kernel_version() >= (major, minor)
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
    fn tls_stat_parses() {
        let s = parse_tls_stat(
            "TlsCurrTxSw   \t1\nTlsTxSw  \t7\nTlsRxSw 6\nTlsTxDevice 3\nTlsRxDevice\t2\nbad\n",
        );
        let want = TlsStat {
            tx_sw: 7,
            rx_sw: 6,
            tx_device: 3,
            rx_device: 2,
        };
        assert_eq!(s, want);
    }

    #[test]
    fn loopback_has_no_tls_offload() {
        let lo = interface_addrs()
            .unwrap()
            .into_iter()
            .find(|(_, ip)| ip.is_loopback())
            .map(|(n, _)| n)
            .expect("a loopback address");
        assert_eq!(netdev_tls_offload(&lo).unwrap(), NetdevTls::default());
        // The bit lookup: `ethtool -k lo` shows "loopback: on [fixed]" and "ntuple-filters:
        // off [fixed]"; an unknown name reads as off.
        let f = netdev_features(&lo, &["loopback", "rx-ntuple-filter", "no-such-feature"]);
        assert_eq!(f.unwrap(), [true, false, false]);
        assert!(netdev_tls_offload("no-such-if0").is_err());
        assert!(netdev_tls_offload("").is_err());
    }

    #[test]
    fn attach_fails_on_a_non_socket() {
        assert!(ktls_attach(-1).is_err());
    }
}
