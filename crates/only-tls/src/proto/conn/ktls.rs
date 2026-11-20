//! Kernel TLS offload: the traffic keys and sequence numbers the kernel needs to take over the
//! record layer after the handshake, and the handling of the control records (alerts,
//! post-handshake messages) that still pass through user space afterwards.

use super::super::alert::{Alert, Fatal, fatal};
use super::super::common::{Action, Keys};
use super::super::msgs::{TLS12, TLS13};
use super::super::record::{CT_ALERT, CT_APPLICATION_DATA, CT_HANDSHAKE, MAX_PLAINTEXT};
use super::super::suites::AeadAlg;
use super::{Connection, MAX_HANDSHAKE, MAX_WARNINGS};

/// One direction's record protection: the AEAD key, the 12-byte IV (TLS 1.2 GCM: the 4-byte
/// salt in the first bytes; the explicit nonce is the sequence number) and the next sequence
/// number. The key is wiped on drop.
pub struct DirKeys {
    /// The AEAD key.
    pub key: Vec<u8>,
    /// The IV, see above.
    pub iv: [u8; 12],
    /// The sequence number of the next record.
    pub seq: u64,
}

impl Drop for DirKeys {
    fn drop(&mut self) {
        self.key.fill(0);
        self.iv.fill(0);
    }
}

impl std::fmt::Debug for DirKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DirKeys")
            .field("seq", &self.seq)
            .finish_non_exhaustive()
    }
}

impl DirKeys {
    pub(super) fn new(k: &Keys, seq: u64) -> DirKeys {
        let mut iv = [0u8; 12];
        match k {
            Keys::Tls13 { suite, secret } => {
                let h = suite.hash;
                let key = h.expand_label(secret, b"key", &[], suite.aead.key_len());
                iv.copy_from_slice(&h.expand_label(secret, b"iv", &[], 12));
                DirKeys { key, iv, seq }
            }
            Keys::Tls12 { key, iv: fixed, .. } => {
                iv[..fixed.len()].copy_from_slice(fixed);
                DirKeys {
                    key: key.clone(),
                    iv,
                    seq,
                }
            }
        }
    }
}

/// Everything the kernel needs to take over both directions.
#[derive(Debug)]
pub struct Offload {
    /// TLS 1.3 (otherwise TLS 1.2).
    pub tls13: bool,
    /// The AEAD.
    pub aead: AeadAlg,
    /// What this side sends.
    pub tx: DirKeys,
    /// What this side receives.
    pub rx: DirKeys,
}

/// What a control record received after the offload asks the caller to do, in order.
#[derive(Debug)]
pub enum OffloadEvent {
    /// Send a record of this content type (alert or handshake) through the kernel.
    Send(u8, Vec<u8>),
    /// Install new receive keys (TLS 1.3 KeyUpdate from the peer).
    RxKeys(DirKeys),
    /// Install new send keys (after sending our KeyUpdate).
    TxKeys(DirKeys),
}

impl Connection {
    /// Keeps the raw traffic keys so that [`take_offload`](Self::take_offload) can hand them to
    /// the kernel. Set before the handshake.
    pub fn set_keep_keys(&mut self, keep: bool) {
        self.keep_keys = keep;
    }

    /// The record layer can move to the kernel now: the handshake is done, nothing is buffered
    /// in either direction (no partial record, no held-back data, no unsent bytes) and the
    /// connection is healthy.
    pub fn offload_ready(&self) -> bool {
        self.keep_keys
            && !self.offloaded
            && !self.tx_kernel
            && !self.m.handshaking()
            && matches!(self.m.version(), TLS12 | TLS13)
            && self.rx.is_empty()
            && self.hs.is_empty()
            && self.pending.is_empty()
            && self.out_pending.is_empty()
            && self.hs_out.is_empty()
            && self.error.is_none()
            && !self.received_close
            && !self.sent_close
            && self.read_keys.is_some()
            && self.write_keys.is_some()
            // The kernel writes full 16 KiB records: not under a peer's smaller limit.
            && self.rec.max_fragment(CT_APPLICATION_DATA) == MAX_PLAINTEXT
    }

    /// The keys for the kernel, `None` unless [`offload_ready`](Self::offload_ready). Nothing
    /// changes until [`commit_offload`](Self::commit_offload): if the kernel refuses the keys,
    /// the connection carries on in user space.
    pub fn offload_keys(&self) -> Option<Offload> {
        if !self.offload_ready() {
            return None;
        }
        let (r, w) = (self.read_keys.as_ref()?, self.write_keys.as_ref()?);
        Some(Offload {
            tls13: self.m.version() == TLS13,
            aead: self.m.suite()?.aead,
            tx: DirKeys::new(w, self.rec.write_seq()),
            rx: DirKeys::new(r, self.rec.read_seq()),
        })
    }

    /// The kernel took the keys: from now on only the `offloaded_*` calls may be used.
    pub fn commit_offload(&mut self) {
        self.offloaded = true;
        self.tx_kernel = true;
        self.keep_keys = false;
        self.read_keys = None;
        self.write_keys = None;
    }

    /// The send direction alone can move to the kernel now: the handshake is done, nothing
    /// is waiting to be sent or held back, and the connection is healthy. What has been
    /// received does not matter: the receive direction stays here.
    pub fn tx_offload_ready(&self) -> bool {
        self.keep_keys
            && !self.tx_kernel
            && !self.m.handshaking()
            && matches!(self.m.version(), TLS12 | TLS13)
            && self.pending.is_empty()
            && self.out_pending.is_empty()
            && self.hs_out.is_empty()
            && self.error.is_none()
            && !self.sent_close
            && self.write_keys.is_some()
            // The kernel writes full 16 KiB records: not under a peer's smaller limit.
            && self.rec.max_fragment(CT_APPLICATION_DATA) == MAX_PLAINTEXT
    }

    /// The receive direction can follow the send direction into the kernel now: no partial
    /// record or handshake message is buffered and the connection is healthy.
    pub fn rx_offload_ready(&self) -> bool {
        self.keep_keys
            && self.tx_kernel
            && !self.offloaded
            && self.rx.is_empty()
            && self.hs.is_empty()
            && self.error.is_none()
            && !self.received_close
            && self.read_keys.is_some()
    }

    /// The version, AEAD and send keys for the kernel, `None` unless
    /// [`tx_offload_ready`](Self::tx_offload_ready). Nothing changes until
    /// [`commit_tx_offload`](Self::commit_tx_offload).
    pub fn tx_offload_keys(&self) -> Option<(bool, AeadAlg, DirKeys)> {
        if !self.tx_offload_ready() {
            return None;
        }
        let w = self.write_keys.as_ref()?;
        Some((
            self.m.version() == TLS13,
            self.m.suite()?.aead,
            DirKeys::new(w, self.rec.write_seq()),
        ))
    }

    /// The receive keys for the kernel, `None` unless
    /// [`rx_offload_ready`](Self::rx_offload_ready).
    pub fn rx_offload_keys(&self) -> Option<DirKeys> {
        if !self.rx_offload_ready() {
            return None;
        }
        Some(DirKeys::new(self.read_keys.as_ref()?, self.rec.read_seq()))
    }

    /// The kernel took the send keys: from now on what this side sends (alerts, handshake
    /// messages, new send keys) comes out of [`take_kernel_events`](Self::take_kernel_events)
    /// instead of the `out` buffers, and application data is written to the socket as is.
    /// Receiving stays as before ([`recv`](Self::recv)) until
    /// [`commit_rx_offload`](Self::commit_rx_offload).
    pub fn commit_tx_offload(&mut self) {
        self.tx_kernel = true;
        self.write_keys = None;
    }

    /// The kernel took the receive keys too: as after [`commit_offload`](Self::commit_offload).
    pub fn commit_rx_offload(&mut self) {
        self.offloaded = true;
        self.keep_keys = false;
        self.read_keys = None;
    }

    /// Whether the send direction is in the kernel.
    pub fn tx_offloaded(&self) -> bool {
        self.tx_kernel
    }

    /// The connection failed, or a side closed it: nothing more will be offloaded.
    pub fn failed_or_closed(&self) -> bool {
        self.error.is_some() || self.received_close || self.sent_close
    }

    /// Moves what this side has to send through the kernel since the last call (send
    /// direction offloaded) into `ev`, in order.
    pub fn take_kernel_events(&mut self, ev: &mut Vec<OffloadEvent>) {
        ev.append(&mut self.kernel_ev);
    }

    /// With the send direction in the kernel: `records` more records went out. Starts a TLS
    /// 1.3 key update (into [`take_kernel_events`](Self::take_kernel_events)) once as many
    /// went under the current keys as [`set_key_update_after`](Self::set_key_update_after)
    /// allows.
    pub fn kernel_records_sent(&mut self, records: u64) -> Result<(), Fatal> {
        self.kernel_records = self.kernel_records.saturating_add(records);
        if self.m.version() != TLS13
            || self.kernel_records < self.key_update_after
            || self.error.is_some()
            || self.sent_close
        {
            return Ok(());
        }
        self.kernel_records = 0;
        let mut ev = std::mem::take(&mut self.kernel_ev);
        let r = self.offloaded_key_update(&mut ev);
        self.kernel_ev = ev;
        r
    }

    /// No offload will happen: drop the kept keys.
    pub fn skip_offload(&mut self) {
        self.keep_keys = false;
        self.read_keys = None;
        self.write_keys = None;
    }

    /// Whether the record layer is in the kernel.
    pub fn offloaded(&self) -> bool {
        self.offloaded
    }

    /// Handles one record the kernel decrypted that is not application data. `Ok(false)` once
    /// close_notify arrived. On error, `ev` holds the alert to send.
    pub fn offloaded_record(
        &mut self,
        typ: u8,
        content: &[u8],
        ev: &mut Vec<OffloadEvent>,
    ) -> Result<bool, Fatal> {
        if let Some(e) = &self.error {
            return Err(e.clone());
        }
        if self.received_close {
            return Ok(false);
        }
        let r = self.offloaded_record_inner(typ, content, ev);
        if let Err(e) = &r {
            if !e.from_peer && !self.sent_close {
                ev.push(OffloadEvent::Send(CT_ALERT, vec![2, e.alert.code()]));
            }
            self.error = Some(e.clone());
        }
        r
    }

    fn offloaded_record_inner(
        &mut self,
        typ: u8,
        content: &[u8],
        ev: &mut Vec<OffloadEvent>,
    ) -> Result<bool, Fatal> {
        match typ {
            CT_HANDSHAKE => {
                if content.is_empty() {
                    return fatal(Alert::UnexpectedMessage, "empty handshake record");
                }
                self.warnings = 0;
                self.hs.extend_from_slice(content);
                while self.hs.len() >= 4 {
                    let len = (usize::from(self.hs[1]) << 16)
                        | (usize::from(self.hs[2]) << 8)
                        | usize::from(self.hs[3]);
                    if len > MAX_HANDSHAKE {
                        return fatal(Alert::DecodeError, "handshake message too long");
                    }
                    if self.hs.len() < 4 + len {
                        break;
                    }
                    let msg: Vec<u8> = self.hs.drain(..4 + len).collect();
                    let mut acts = Vec::new();
                    self.m.handle(&msg, &mut acts)?;
                    for a in acts {
                        match a {
                            Action::Msg(_, m) => ev.push(OffloadEvent::Send(CT_HANDSHAKE, m)),
                            Action::ReadKeys(_, k) => {
                                if !self.hs.is_empty() {
                                    return fatal(
                                        Alert::UnexpectedMessage,
                                        "handshake data across a key change",
                                    );
                                }
                                ev.push(OffloadEvent::RxKeys(DirKeys::new(&k, 0)));
                            }
                            Action::WriteKeys(_, k) => {
                                ev.push(OffloadEvent::TxKeys(DirKeys::new(&k, 0)));
                            }
                            Action::Warning(alert) => {
                                ev.push(OffloadEvent::Send(CT_ALERT, vec![1, alert.code()]));
                            }
                            Action::Done => {}
                            Action::Ccs
                            | Action::RejectEarlyData
                            | Action::EarlyOffered(_)
                            | Action::EarlyAccepted(_)
                            | Action::RecordLimit { .. } => {
                                return fatal(Alert::UnexpectedMessage, "unexpected message");
                            }
                        }
                    }
                }
                Ok(true)
            }
            CT_ALERT => {
                if !self.hs.is_empty() {
                    return fatal(Alert::UnexpectedMessage, "alert inside a handshake message");
                }
                if content.len() != 2 {
                    return fatal(Alert::DecodeError, "bad alert");
                }
                let (level, desc) = (content[0], Alert::from_code(content[1]));
                if desc == Alert::CloseNotify {
                    self.received_close = true;
                    return Ok(false);
                }
                if desc == Alert::UserCanceled || (level == 1 && self.m.version() == TLS12) {
                    self.warnings += 1;
                    if self.warnings > MAX_WARNINGS {
                        return fatal(Alert::UnexpectedMessage, "too many warning alerts");
                    }
                    return Ok(true);
                }
                Err(Fatal::peer(desc))
            }
            CT_APPLICATION_DATA => {
                if !self.hs.is_empty() {
                    return fatal(Alert::UnexpectedMessage, "data inside a handshake message");
                }
                self.warnings = 0;
                Ok(true)
            }
            _ => fatal(Alert::UnexpectedMessage, "unexpected record type"),
        }
    }

    /// Starts a TLS 1.3 KeyUpdate of the send direction (not requesting one back): the
    /// KeyUpdate message to send, then the new send keys to install.
    pub fn offloaded_key_update(&mut self, ev: &mut Vec<OffloadEvent>) -> Result<(), Fatal> {
        if self.m.version() != TLS13 || self.error.is_some() || self.sent_close {
            return fatal(Alert::InternalError, "no KeyUpdate here");
        }
        let mut acts = Vec::new();
        self.m.initiate_key_update(&mut acts)?;
        for a in acts {
            match a {
                Action::Msg(_, m) => ev.push(OffloadEvent::Send(CT_HANDSHAKE, m)),
                Action::WriteKeys(_, k) => ev.push(OffloadEvent::TxKeys(DirKeys::new(&k, 0))),
                _ => {}
            }
        }
        Ok(())
    }

    /// The close_notify alert to send through the kernel, once.
    pub fn offloaded_close(&mut self) -> Option<OffloadEvent> {
        if self.sent_close || self.error.is_some() {
            return None;
        }
        self.sent_close = true;
        Some(OffloadEvent::Send(CT_ALERT, vec![1, 0]))
    }
}
