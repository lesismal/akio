//! Kernel TLS glue (Linux): hands the keys of a finished handshake to the kernel and carries out
//! what control records received afterwards ask for; for the engine (ADR-067), the socket
//! operations of [`TlsTransport`](crate::TlsTransport) and the detection of NICs that do TLS
//! themselves. The system calls are in `only-sys`.

use std::io;
use std::net::IpAddr;
use std::os::fd::RawFd;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

use only_sys::ktls::{KtlsCipher, KtlsDir, KtlsKeys, NetdevTls};

use crate::proto::suites::AeadAlg;
use crate::proto::{DirKeys, Offload, OffloadEvent};

/// A control record (alert, handshake message) to send through the kernel, in order with the
/// connection's other output.
pub(crate) struct SendRecord {
    typ: u8,
    data: Vec<u8>,
    off: usize,
}

impl only_core::SocketOp for SendRecord {
    fn run(&mut self, fd: RawFd) -> io::Result<bool> {
        while self.off < self.data.len() {
            match only_sys::ktls::ktls_send_record(fd, self.typ, &self.data[self.off..]) {
                Ok(n) => self.off += n,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(false),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(true)
    }
}

/// New send keys (TLS 1.3 key update), installed once the KeyUpdate queued before them is out.
pub(crate) struct InstallTx {
    tls13: bool,
    aead: AeadAlg,
    keys: DirKeys,
}

impl only_core::SocketOp for InstallTx {
    fn run(&mut self, fd: RawFd) -> io::Result<bool> {
        only_sys::ktls::ktls_set(fd, KtlsDir::Tx, &keys(self.tls13, self.aead, &self.keys))?;
        Ok(true)
    }
}

/// Turns what the connection asked for into socket operations, in order. New receive keys
/// (the peer's key update) are installed right away: the kernel reads nothing more until
/// they are.
pub(crate) fn to_ops(
    fd: RawFd,
    tls13: bool,
    aead: AeadAlg,
    ev: &mut Vec<OffloadEvent>,
    ops: &mut Vec<Box<dyn only_core::SocketOp>>,
) -> io::Result<()> {
    for e in ev.drain(..) {
        match e {
            OffloadEvent::Send(typ, data) => ops.push(Box::new(SendRecord { typ, data, off: 0 })),
            OffloadEvent::TxKeys(k) => ops.push(Box::new(InstallTx {
                tls13,
                aead,
                keys: k,
            })),
            OffloadEvent::RxKeys(k) => {
                only_sys::ktls::ktls_set(fd, KtlsDir::Rx, &keys(tls13, aead, &k))?;
            }
        }
    }
    Ok(())
}

/// Installs one direction of `fd` (the `tls` ULP attached). `verify`: report whether a NIC
/// took it (from the kernel's `TlsTxDevice` / `TlsRxDevice` counters, read around the install
/// under a process-wide lock); otherwise reports `false`.
pub(crate) fn install_dir(
    fd: RawFd,
    dir: KtlsDir,
    tls13: bool,
    aead: AeadAlg,
    k: &DirKeys,
    verify: bool,
) -> io::Result<bool> {
    static VERIFY: Mutex<()> = Mutex::new(());
    if !verify {
        only_sys::ktls::ktls_set(fd, dir, &keys(tls13, aead, k))?;
        return Ok(false);
    }
    let _g = VERIFY.lock().unwrap_or_else(|p| p.into_inner());
    let before = only_sys::ktls::tls_stat().ok();
    only_sys::ktls::ktls_set(fd, dir, &keys(tls13, aead, k))?;
    let after = only_sys::ktls::tls_stat().ok();
    Ok(match (before, after) {
        (Some(b), Some(a)) => match dir {
            KtlsDir::Tx => a.tx_device > b.tx_device,
            KtlsDir::Rx => a.rx_device > b.rx_device,
        },
        _ => false,
    })
}

// ---- NICs with TLS offload ----

/// How long the interface table is trusted.
const NETDEV_TTL_MS: u64 = 30_000;

/// The host's interfaces with their TLS offload features, and what the kernel refused.
#[derive(Default)]
struct Netdevs {
    /// (address, interface, features) for every address of an interface with any feature.
    ifaces: Vec<(IpAddr, String, NetdevTls)>,
    /// (interface, send direction, TLS 1.3, AEAD) the kernel installed in software although
    /// the interface claims offload: not tried in hardware again.
    refused: Vec<(String, bool, bool, AeadAlg)>,
}

static NETDEVS: Mutex<Netdevs> = Mutex::new(Netdevs {
    ifaces: Vec::new(),
    refused: Vec::new(),
});
/// Some interface offloads TLS (as of the last look).
static ANY_HW: AtomicBool = AtomicBool::new(false);
/// When to look again, in ms since `epoch()` (0: never looked).
static NEXT_LOOK: AtomicU64 = AtomicU64::new(0);

fn now_ms() -> u64 {
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    // At least 1, so that 0 in NEXT_LOOK means "never looked".
    EPOCH.get_or_init(Instant::now).elapsed().as_millis() as u64 + 1
}

fn look(n: &mut Netdevs) {
    n.ifaces.clear();
    let mut names: Vec<(String, NetdevTls)> = Vec::new();
    for (name, ip) in only_sys::ktls::interface_addrs().unwrap_or_default() {
        let f = match names.iter().find(|(n, _)| *n == name) {
            Some((_, f)) => *f,
            None => {
                let f = only_sys::ktls::netdev_tls_offload(&name).unwrap_or_default();
                names.push((name.clone(), f));
                f
            }
        };
        if f.tx || f.rx {
            n.ifaces.push((ip, name, f));
        }
    }
    ANY_HW.store(!n.ifaces.is_empty(), Ordering::Relaxed);
    if !n.ifaces.is_empty() {
        only_log::debug!(target: "only::tls", "kTLS: NICs with TLS offload: {:?}",
            names.iter().filter(|(_, f)| f.tx || f.rx).collect::<Vec<_>>());
    }
}

/// The directions a NIC would take for a connection from local address `local` with this
/// version and AEAD, and the interface: `None` when none would (no such NIC, ChaCha20, or
/// refused before). Lock-free while the host has no such NIC.
pub(crate) fn hardware_dirs(local: IpAddr, tls13: bool, aead: AeadAlg) -> Option<(String, bool)> {
    if aead == AeadAlg::ChaCha20Poly1305 || !any_hardware() {
        return None;
    }
    let n = NETDEVS.lock().unwrap_or_else(|p| p.into_inner());
    hw_lookup(&n, local, tls13, aead)
}

/// Whether some interface of the host offloads TLS (looked up again every 30 s). Lock-free
/// between looks; [`crate::Ktls::Hardware`] connections on a host without such a NIC keep no
/// kernel TLS state at all.
pub(crate) fn any_hardware() -> bool {
    let now = now_ms();
    if now >= NEXT_LOOK.load(Ordering::Relaxed) {
        let mut n = NETDEVS.lock().unwrap_or_else(|p| p.into_inner());
        if now >= NEXT_LOOK.load(Ordering::Relaxed) {
            look(&mut n);
            NEXT_LOOK.store(now + NETDEV_TTL_MS, Ordering::Relaxed);
        }
    }
    ANY_HW.load(Ordering::Relaxed)
}

fn hw_lookup(n: &Netdevs, local: IpAddr, tls13: bool, aead: AeadAlg) -> Option<(String, bool)> {
    let local = local.to_canonical();
    let (_, name, f) = n.ifaces.iter().find(|(ip, ..)| *ip == local)?;
    let refused = |tx: bool| {
        n.refused
            .iter()
            .any(|r| r.0 == *name && r.1 == tx && r.2 == tls13 && r.3 == aead)
    };
    if !f.tx || refused(true) {
        return None;
    }
    Some((name.clone(), f.rx && !refused(false)))
}

/// The kernel installed a direction in software although interface `name` offloads TLS: do
/// not try it in hardware again for this version and AEAD.
pub(crate) fn refuse(name: &str, tx: bool, tls13: bool, aead: AeadAlg) {
    let mut n = NETDEVS.lock().unwrap_or_else(|p| p.into_inner());
    let key = (name.to_owned(), tx, tls13, aead);
    if !n.refused.contains(&key) {
        only_log::info!(target: "only::tls",
            "kTLS: {name} did not take the {} direction of a TLS {} {aead:?} connection; \
             staying in user space for those from now on",
            if tx { "send" } else { "receive" }, if tls13 { "1.3" } else { "1.2" });
        n.refused.push(key);
    }
}

fn cipher(a: AeadAlg) -> KtlsCipher {
    match a {
        AeadAlg::Aes128Gcm => KtlsCipher::Aes128Gcm,
        AeadAlg::Aes256Gcm => KtlsCipher::Aes256Gcm,
        AeadAlg::ChaCha20Poly1305 => KtlsCipher::ChaCha20Poly1305,
    }
}

fn keys<'a>(tls13: bool, aead: AeadAlg, k: &'a DirKeys) -> KtlsKeys<'a> {
    KtlsKeys {
        tls13,
        cipher: cipher(aead),
        key: &k.key,
        iv: k.iv,
        seq: k.seq,
    }
}

/// Moves both directions of `fd` into the kernel. `Ok(false)`: the kernel cannot (no `tls`
/// module, suite not supported) and nothing changed, carry on in user space. An error after
/// the receive direction was installed leaves the socket unusable.
pub(crate) fn install(fd: RawFd, o: &Offload) -> io::Result<bool> {
    if o.tls13 && !only_sys::ktls::ktls_rekey_supported() {
        // The peer may send a KeyUpdate at any time, which this kernel could not follow.
        only_log::debug!(target: "only::tls", "kTLS: kernel without TLS 1.3 rekey support");
        return Ok(false);
    }
    if let Err(e) = only_sys::ktls::ktls_attach(fd) {
        only_log::debug!(target: "only::tls", "kTLS unavailable: {e}");
        return Ok(false);
    }
    // The receive direction first: if the kernel refuses this suite it does so here, before
    // anything moved. The send direction uses the same cipher code.
    if let Err(e) = only_sys::ktls::ktls_set(fd, KtlsDir::Rx, &keys(o.tls13, o.aead, &o.rx)) {
        only_log::debug!(target: "only::tls", "kTLS refused the receive keys: {e}");
        return Ok(false);
    }
    only_sys::ktls::ktls_set(fd, KtlsDir::Tx, &keys(o.tls13, o.aead, &o.tx))?;
    Ok(true)
}

/// Carries out the events of a control record (or of our KeyUpdate), in order. `send` writes a
/// control record whole.
pub(crate) fn apply(
    fd: RawFd,
    tls13: bool,
    aead: AeadAlg,
    ev: &mut Vec<OffloadEvent>,
    mut send: impl FnMut(u8, &[u8]) -> io::Result<()>,
) -> io::Result<()> {
    for e in ev.drain(..) {
        match e {
            OffloadEvent::Send(typ, data) => send(typ, &data)?,
            OffloadEvent::RxKeys(k) => {
                only_sys::ktls::ktls_set(fd, KtlsDir::Rx, &keys(tls13, aead, &k))?;
            }
            OffloadEvent::TxKeys(k) => {
                only_sys::ktls::ktls_set(fd, KtlsDir::Tx, &keys(tls13, aead, &k))?;
            }
        }
    }
    Ok(())
}

/// Sends `data` as records of type `typ`, blocking until all of it is taken.
pub(crate) fn send_all(fd: RawFd, typ: u8, mut data: &[u8]) -> io::Result<()> {
    while !data.is_empty() {
        match only_sys::ktls::ktls_send_record(fd, typ, data) {
            Ok(n) => data = &data[n..],
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

// ---- engine connections ----

/// The kernel TLS state of one engine connection (`TlsTransport`).
pub(crate) struct KtlsState {
    cfg: crate::config::KtlsConfig,
    stats: crate::TlsStats,
    /// The socket, once the send direction is in the kernel.
    fd: RawFd,
    tls13: bool,
    aead: AeadAlg,
    tx: Option<crate::KtlsPath>,
    rx: Option<crate::KtlsPath>,
    /// The receive direction should follow the send direction.
    want_rx: bool,
    /// No more offload attempts.
    done: bool,
    /// The NIC expected to take the connection ([`crate::Ktls::Hardware`], or a capable NIC
    /// under [`crate::Ktls::Software`]).
    iface: Option<String>,
    ev: Vec<OffloadEvent>,
    /// Operations `kernel_record` produced, for the next `take_ops`.
    ops: Vec<Box<dyn only_core::SocketOp>>,
}

impl KtlsState {
    pub(crate) fn new(cfg: crate::config::KtlsConfig, stats: crate::TlsStats) -> KtlsState {
        KtlsState {
            cfg,
            stats,
            fd: -1,
            tls13: false,
            aead: AeadAlg::Aes128Gcm,
            tx: None,
            rx: None,
            want_rx: false,
            done: false,
            iface: None,
            ev: Vec::new(),
            ops: Vec::new(),
        }
    }

    pub(crate) fn wants(&self) -> bool {
        !self.done
    }

    pub(crate) fn paths(&self) -> (Option<crate::KtlsPath>, Option<crate::KtlsPath>) {
        (self.tx, self.rx)
    }

    fn current(&self) -> only_core::Offloaded {
        only_core::Offloaded::new(self.tx.is_some(), self.rx.is_some())
    }

    /// Gives up: what is in the kernel stays, the rest stays in user space.
    fn finish(&mut self, conn: &mut crate::proto::Connection) {
        self.done = true;
        if self.rx.is_none() {
            conn.skip_offload();
        }
    }

    /// `Transport::offload`: the send direction first, then (if wanted and possible) the
    /// receive direction, each once its side is clean.
    pub(crate) fn offload(
        &mut self,
        conn: &mut crate::proto::Connection,
        fd: RawFd,
        local: IpAddr,
        rx_ok: bool,
    ) -> io::Result<only_core::Offloaded> {
        if self.done || conn.handshaking() {
            return Ok(self.current());
        }
        if self.tx.is_none() {
            let Some((tls13, aead)) = conn.tx_offload_params() else {
                if conn.failed_or_closed() {
                    self.finish(conn);
                }
                return Ok(self.current()); // something still queued: later
            };
            if tls13 && !only_sys::ktls::ktls_rekey_supported() {
                // The peer may ask for a key update at any time, which needs Linux 6.14.
                only_log::debug!(target: "only::tls", "kTLS: kernel without TLS 1.3 rekey support");
                self.finish(conn);
                return Ok(self.current());
            }
            // Decided before any key is derived: a connection no NIC takes costs nothing more.
            let hw = hardware_dirs(local, tls13, aead);
            let (rx, iface) = match (self.cfg.mode, hw) {
                (crate::Ktls::Hardware, Some((name, rx))) => (rx, Some(name)),
                (crate::Ktls::Software, hw) => (true, hw.map(|h| h.0)),
                (crate::Ktls::SoftwareTx, hw) => (false, hw.map(|h| h.0)),
                _ => {
                    self.finish(conn);
                    return Ok(self.current());
                }
            };
            let Some((_, _, tx_keys)) = conn.tx_offload_keys() else {
                self.finish(conn);
                return Ok(self.current());
            };
            if let Err(e) = only_sys::ktls::ktls_attach(fd) {
                // No `tls` module (or another ULP): nothing changed.
                only_log::debug!(target: "only::tls", "kTLS unavailable: {e}");
                self.finish(conn);
                return Ok(self.current());
            }
            let verify = iface.is_some();
            let device = match install_dir(fd, KtlsDir::Tx, tls13, aead, &tx_keys, verify) {
                Ok(d) => d,
                Err(e) => {
                    // Refused this suite: no key went in, the socket passes bytes through.
                    only_log::debug!(target: "only::tls", "kTLS refused the send keys: {e}");
                    self.finish(conn);
                    return Ok(self.current());
                }
            };
            conn.commit_tx_offload();
            self.fd = fd;
            self.tls13 = tls13;
            self.aead = aead;
            self.want_rx = rx;
            if let (Some(name), false) = (&iface, device) {
                if self.cfg.mode == crate::Ktls::Hardware {
                    refuse(name, true, tls13, aead);
                }
            }
            if device && self.cfg.zerocopy_sendfile {
                if let Err(e) = only_sys::ktls::ktls_tx_zerocopy_ro(fd) {
                    only_log::debug!(target: "only::tls", "kTLS: TLS_TX_ZEROCOPY_RO: {e}");
                }
            }
            let p = path(device);
            self.tx = Some(p);
            self.iface = iface;
            self.stats.ktls_installed(true, p);
        }
        if self.want_rx && self.rx.is_none() {
            if conn.failed_or_closed() {
                self.want_rx = false;
            } else if !rx_ok {
                // The backend cannot switch its reads now: it asks again when it can.
            } else if let Some(rx_keys) = conn.rx_offload_keys() {
                let verify = self.iface.is_some();
                match install_dir(fd, KtlsDir::Rx, self.tls13, self.aead, &rx_keys, verify) {
                    Ok(device) => {
                        conn.commit_rx_offload();
                        if self.tls13 {
                            // Linux 6.0: one decryption pass; older kernels refuse, harmlessly.
                            let _ = only_sys::ktls::ktls_rx_expect_no_pad(fd);
                        }
                        if let (Some(name), false) = (&self.iface, device) {
                            if self.cfg.mode == crate::Ktls::Hardware {
                                refuse(name, false, self.tls13, self.aead);
                            }
                        }
                        let p = path(device);
                        self.rx = Some(p);
                        self.stats.ktls_installed(false, p);
                    }
                    Err(e) => {
                        only_log::debug!(target: "only::tls", "kTLS refused the receive keys: {e}");
                        self.want_rx = false;
                    }
                }
            }
            // Otherwise a partial record is buffered here: try again after the next read.
        }
        if !self.want_rx || self.rx.is_some() {
            self.finish(conn);
        }
        Ok(self.current())
    }

    /// `Transport::kernel_send`.
    pub(crate) fn kernel_send(
        &mut self,
        conn: &mut crate::proto::Connection,
        len: usize,
        ops: &mut Vec<Box<dyn only_core::SocketOp>>,
    ) -> io::Result<()> {
        // At least one record per write, and one per 16 KiB.
        let records = 1 + (len as u64 >> 14);
        conn.kernel_records_sent(records)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        self.take_ops(conn, ops);
        Ok(())
    }

    /// `Transport::take_ops`.
    pub(crate) fn take_ops(
        &mut self,
        conn: &mut crate::proto::Connection,
        ops: &mut Vec<Box<dyn only_core::SocketOp>>,
    ) {
        ops.append(&mut self.ops);
        conn.take_kernel_events(&mut self.ev);
        if self.ev.is_empty() {
            return;
        }
        // Only records and send keys come this way (receive keys with `kernel_record`).
        if let Err(e) = to_ops(self.fd, self.tls13, self.aead, &mut self.ev, ops) {
            only_log::debug!(target: "only::tls", "kTLS: {e}");
        }
    }

    /// `Transport::kernel_record`.
    pub(crate) fn kernel_record(
        &mut self,
        conn: &mut crate::proto::Connection,
        typ: u8,
        content: &[u8],
    ) -> io::Result<bool> {
        let r = conn.offloaded_record(typ, content, &mut self.ev);
        conn.take_kernel_events(&mut self.ev);
        to_ops(self.fd, self.tls13, self.aead, &mut self.ev, &mut self.ops)?;
        r.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }
}

fn path(device: bool) -> crate::KtlsPath {
    if device {
        crate::KtlsPath::Hardware
    } else {
        crate::KtlsPath::Software
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn table() -> Netdevs {
        let hw = NetdevTls { tx: true, rx: true };
        let tx_only = NetdevTls {
            tx: true,
            rx: false,
        };
        Netdevs {
            ifaces: vec![
                (ip("192.0.2.1"), "eth0".into(), hw),
                (ip("2001:db8::1"), "eth0".into(), hw),
                (ip("198.51.100.1"), "eth1".into(), tx_only),
            ],
            refused: vec![("eth0".into(), false, true, AeadAlg::Aes256Gcm)],
        }
    }

    #[test]
    fn hardware_lookup_by_local_address() {
        let n = table();
        let a = AeadAlg::Aes128Gcm;
        let eth0 = Some(("eth0".to_owned(), true));
        assert_eq!(hw_lookup(&n, ip("192.0.2.1"), true, a), eth0);
        // An IPv4-mapped IPv6 local address (dual-stack listener) is the IPv4 one.
        assert_eq!(hw_lookup(&n, ip("::ffff:192.0.2.1"), false, a), eth0);
        assert_eq!(hw_lookup(&n, ip("2001:db8::1"), true, a), eth0);
        let eth1 = Some(("eth1".to_owned(), false));
        assert_eq!(hw_lookup(&n, ip("198.51.100.1"), true, a), eth1);
        assert_eq!(hw_lookup(&n, ip("127.0.0.1"), true, a), None);
        // Refused before: the receive direction of TLS 1.3 with AES-256 on eth0.
        let r = hw_lookup(&n, ip("192.0.2.1"), true, AeadAlg::Aes256Gcm);
        assert_eq!(r, Some(("eth0".to_owned(), false)));
        let r = hw_lookup(&n, ip("192.0.2.1"), false, AeadAlg::Aes256Gcm);
        assert_eq!(r, eth0);
    }

    #[test]
    fn chacha_and_loopback_never_go_to_hardware() {
        let a = AeadAlg::Aes128Gcm;
        assert_eq!(hardware_dirs(ip("127.0.0.1"), true, a), None);
        let c = AeadAlg::ChaCha20Poly1305;
        assert_eq!(hardware_dirs(ip("192.0.2.1"), true, c), None);
    }
}
