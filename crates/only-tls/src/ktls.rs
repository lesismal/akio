//! Kernel TLS glue (Linux): hands the keys of a finished handshake to the kernel and carries out
//! what control records received afterwards ask for. The system calls are in `only-sys`.

use std::io;
use std::os::fd::RawFd;

use only_sys::ktls::{KtlsCipher, KtlsDir, KtlsKeys};

use crate::proto::suites::AeadAlg;
use crate::proto::{DirKeys, Offload, OffloadEvent};

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
