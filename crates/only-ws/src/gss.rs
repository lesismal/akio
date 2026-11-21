//! GSS-API authentication for SOCKS5 (RFC 1961, method `0x01`), with the GSS-API mechanism
//! supplied by the application (ADR-071): [`GssContext`] is one security context (Kerberos
//! through the system's GSS-API library, SSPI, a test mechanism ...); this module has the
//! RFC 1961 messages, the protection-level negotiation and the per-message protection layer
//! ([`GssLayer`]) both sides put on the connection afterwards.
//!
//! Message format (RFC 1961 §3): `VER(1) = 1`, `MTYP(1)`, `LEN(2, big-endian)`, `TOKEN`;
//! `MTYP` 1 carries context-establishment tokens, 2 the protection level (one octet, wrapped
//! with `gss_wrap` without confidentiality), 3 encapsulated data (`gss_wrap`, with
//! confidentiality at level 2). An establishment failure is answered with `VER = 1`,
//! `MTYP = 0xff` and nothing else.
//!
//! Not public API on its own: `only_socks::gssapi` re-exports what applications use.

use std::{any::Any, fmt, io, sync::Arc};

use only::Transport;

/// One GSS-API security context (RFC 2743), initiator or acceptor, as the application's
/// mechanism provides it. Created per connection by the factory given to the client or the
/// server; it must be `Send` (it moves to a worker thread for the establishment steps).
///
/// * [`step`](Self::step) is `GSS_Init_sec_context` / `GSS_Accept_sec_context`. It may block
///   (a Kerberos initiator may ask the KDC for a service ticket): only-socks never calls it on
///   an I/O thread — the server runs it on the logical pool, the client on a helper thread.
/// * [`wrap`](Self::wrap) / [`unwrap`](Self::unwrap) are `GSS_Wrap` / `GSS_Unwrap`, called on
///   the connection's I/O thread for every protected message: they must not block.
pub trait GssContext: Send {
    /// One establishment step: `token` is the peer's last token (empty on the initiator's first
    /// call). Returns the token to send and whether the context is now established.
    fn step(&mut self, token: &[u8]) -> io::Result<GssStep>;

    /// Protects `msg` (integrity; confidentiality too when `confidential`), returning the token.
    fn wrap(&mut self, confidential: bool, msg: &[u8]) -> io::Result<Vec<u8>>;

    /// Checks and opens a token made by the peer's [`wrap`](Self::wrap).
    fn unwrap(&mut self, token: &[u8]) -> io::Result<Vec<u8>>;

    /// The authenticated peer, once established (the acceptor: the client's principal, which
    /// the server's access-control hook sees as the user name). Default: none.
    fn peer_name(&self) -> Option<String> {
        None
    }
}

/// What one [`GssContext::step`] produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GssStep {
    /// The context needs another token from the peer; send this one (`GSS_S_CONTINUE_NEEDED`).
    Continue(Vec<u8>),
    /// The context is established; send this token first when it is not empty
    /// (`GSS_S_COMPLETE`).
    Complete(Vec<u8>),
}

/// Makes the [`GssContext`] of one connection (called once per handshake, off the I/O
/// threads). The client's factory is given the proxy's host name, to name the service
/// (`rcmd@proxy.example.com`, the RFC 1961 convention, or the application's own).
pub type GssFactory = Arc<dyn Fn(&str) -> io::Result<Box<dyn GssContext>> + Send + Sync>;

/// The per-message protection after authentication (RFC 1961 §4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Protection {
    /// None: the SOCKS request and the tunnel go in the clear (level 0; outside RFC 1961, as
    /// Dante's `clear`). Authentication only.
    None,
    /// Every message carries an integrity check (level 1).
    Integrity,
    /// Every message is encrypted and integrity-checked (level 2).
    Confidentiality,
}

impl Protection {
    /// The protection-level octet.
    pub fn level(self) -> u8 {
        match self {
            Protection::None => 0,
            Protection::Integrity => 1,
            Protection::Confidentiality => 2,
        }
    }

    /// The level for octet `b`; 3 (RFC 1961 "selective per-message") is taken as integrity,
    /// which is what each message then gets at the least.
    pub fn from_level(b: u8) -> Option<Protection> {
        match b {
            0 => Some(Protection::None),
            1 | 3 => Some(Protection::Integrity),
            2 => Some(Protection::Confidentiality),
            _ => None,
        }
    }
}

/// RFC 1961 message version.
pub const VERSION: u8 = 1;
/// `MTYP`: a context-establishment token.
pub const MTYP_AUTH: u8 = 1;
/// `MTYP`: the protection-level negotiation.
pub const MTYP_PROTECTION: u8 = 2;
/// `MTYP`: encapsulated data.
pub const MTYP_DATA: u8 = 3;
/// `MTYP`: the establishment failed (the message has no length and no token).
pub const MTYP_ABORT: u8 = 0xff;
/// The abort message.
pub const ABORT: [u8; 2] = [VERSION, MTYP_ABORT];
/// Plaintext per encapsulated message: the wrapped token must fit in 65,535 bytes with the
/// mechanism's overhead (Kerberos adds well under 100 bytes).
pub const MAX_CHUNK: usize = 32 << 10;

fn bad(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

/// Appends one message.
pub fn push_msg(out: &mut Vec<u8>, mtyp: u8, token: &[u8]) -> io::Result<()> {
    let len = u16::try_from(token.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "GSS-API token over 64 KiB"))?;
    out.extend_from_slice(&[VERSION, mtyp]);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(token);
    Ok(())
}

/// One message from the front of `b`: its type, its token and its length on the wire; `None`
/// when incomplete. An abort is `(MTYP_ABORT, [], 2)`.
pub fn parse_msg(b: &[u8]) -> io::Result<Option<(u8, &[u8], usize)>> {
    let (Some(&ver), Some(&mtyp)) = (b.first(), b.get(1)) else {
        return Ok(None);
    };
    if ver != VERSION {
        return Err(bad("bad SOCKS GSS-API message version"));
    }
    if mtyp == MTYP_ABORT {
        return Ok(Some((MTYP_ABORT, &[], 2)));
    }
    let Some(len) = b.get(2..4) else {
        return Ok(None);
    };
    let len = usize::from(u16::from_be_bytes([len[0], len[1]]));
    Ok(b.get(4..4 + len).map(|t| (mtyp, t, 4 + len)))
}

/// The protection-negotiation message for `p`.
pub fn protection_msg(
    ctx: &mut dyn GssContext,
    p: Protection,
    out: &mut Vec<u8>,
) -> io::Result<()> {
    let token = ctx.wrap(false, &[p.level()])?;
    push_msg(out, MTYP_PROTECTION, &token)
}

/// The level in a protection-negotiation token.
pub fn protection_of(ctx: &mut dyn GssContext, token: &[u8]) -> io::Result<Protection> {
    match ctx.unwrap(token)?.as_slice() {
        [b] => Protection::from_level(*b).ok_or_else(|| bad("unknown GSS-API protection level")),
        _ => Err(bad("bad GSS-API protection-level message")),
    }
}

/// Wraps `plain` in encapsulated-data messages.
pub fn seal_data(
    ctx: &mut dyn GssContext,
    confidential: bool,
    plain: &[u8],
    out: &mut Vec<u8>,
) -> io::Result<()> {
    for chunk in plain.chunks(MAX_CHUNK) {
        let token = ctx.wrap(confidential, chunk)?;
        push_msg(out, MTYP_DATA, &token)?;
    }
    Ok(())
}

/// Unwraps the complete encapsulated-data messages at the front of `rx` into `plain`, keeping
/// an incomplete one.
pub fn open_data(
    ctx: &mut dyn GssContext,
    rx: &mut Vec<u8>,
    plain: &mut Vec<u8>,
) -> io::Result<()> {
    let mut used = 0;
    while let Some((mtyp, token, n)) = parse_msg(&rx[used..])? {
        match mtyp {
            MTYP_DATA => plain.extend_from_slice(&ctx.unwrap(token)?),
            MTYP_ABORT => {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "SOCKS GSS-API peer aborted",
                ));
            }
            _ => return Err(bad("unexpected SOCKS GSS-API message")),
        }
        used += n;
    }
    rx.drain(..used);
    Ok(())
}

/// The per-message protection of a SOCKS GSS-API connection, as a [`Transport`]: what is read
/// is unwrapped (then given to `inner`, the target's own transport, if any), what is sent is
/// sealed by `inner` and then wrapped.
///
/// The server installs one in pass-through mode on every connection of a GSS-API server and
/// [`activates`](Self::activate) it once the protection level is agreed; the client puts one
/// under its tunnel when the handshake ends.
pub struct GssLayer {
    /// `None`: pass-through (not activated).
    ctx: Option<Box<dyn GssContext>>,
    confidential: bool,
    /// Received bytes of an incomplete message.
    rx: Vec<u8>,
    inner: Option<Box<dyn Transport>>,
}

impl fmt::Debug for GssLayer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GssLayer")
            .field("active", &self.ctx.is_some())
            .field("confidential", &self.confidential)
            .finish_non_exhaustive()
    }
}

impl GssLayer {
    /// A layer that passes bytes through until [`activate`](Self::activate)d.
    pub fn passthrough() -> GssLayer {
        GssLayer {
            ctx: None,
            confidential: false,
            rx: Vec::new(),
            inner: None,
        }
    }

    /// An active layer over `inner` (`p` must not be [`Protection::None`]).
    pub fn new(
        ctx: Box<dyn GssContext>,
        p: Protection,
        inner: Option<Box<dyn Transport>>,
    ) -> GssLayer {
        GssLayer {
            ctx: Some(ctx),
            confidential: p == Protection::Confidentiality,
            rx: Vec::new(),
            inner,
        }
    }

    /// Whether messages are wrapped.
    pub fn is_active(&self) -> bool {
        self.ctx.is_some()
    }

    /// Starts protecting with `ctx` at level `p`. `pending`: bytes already read past the
    /// protection negotiation (passed through as they came); their unwrapped content is
    /// appended to `plain`.
    pub fn activate(
        &mut self,
        ctx: Box<dyn GssContext>,
        p: Protection,
        pending: &[u8],
        plain: &mut Vec<u8>,
    ) -> io::Result<()> {
        self.confidential = p == Protection::Confidentiality;
        let ctx = self.ctx.insert(ctx);
        self.rx.extend_from_slice(pending);
        open_data(ctx.as_mut(), &mut self.rx, plain)
    }

    /// Wraps bytes `inner` already sealed (the client's held first flight).
    pub fn wrap_raw(&mut self, raw: &[u8], out: &mut Vec<u8>) -> io::Result<()> {
        match &mut self.ctx {
            Some(ctx) => seal_data(ctx.as_mut(), self.confidential, raw, out),
            None => {
                out.extend_from_slice(raw);
                Ok(())
            }
        }
    }

    /// Gives already-unwrapped bytes (left over from the handshake) to `inner`.
    pub fn recv_unwrapped(
        &mut self,
        data: &[u8],
        plain: &mut Vec<u8>,
        out: &mut Vec<u8>,
    ) -> io::Result<()> {
        let mut sealed = Vec::new();
        let r = match &mut self.inner {
            Some(t) => t.recv(data, plain, &mut sealed),
            None => {
                plain.extend_from_slice(data);
                Ok(())
            }
        };
        self.wrap_raw(&sealed, out)?;
        r
    }
}

impl Transport for GssLayer {
    fn recv(&mut self, cipher: &[u8], plain: &mut Vec<u8>, out: &mut Vec<u8>) -> io::Result<()> {
        let Some(ctx) = &mut self.ctx else {
            plain.extend_from_slice(cipher);
            return Ok(());
        };
        self.rx.extend_from_slice(cipher);
        let mut opened = Vec::new();
        open_data(ctx.as_mut(), &mut self.rx, &mut opened)?;
        if self.inner.is_none() {
            plain.append(&mut opened);
            return Ok(());
        }
        // Also with nothing new: lets the inner transport make progress.
        self.recv_unwrapped(&opened, plain, out)
    }

    fn seal(&mut self, plain: &[u8], out: &mut Vec<u8>) -> io::Result<()> {
        match &mut self.inner {
            Some(t) => {
                let mut sealed = Vec::new();
                t.seal(plain, &mut sealed)?;
                self.wrap_raw(&sealed, out)
            }
            None => self.wrap_raw(plain, out),
        }
    }

    fn shutdown(&mut self, out: &mut Vec<u8>) {
        if let Some(t) = &mut self.inner {
            let mut sealed = Vec::new();
            t.shutdown(&mut sealed);
            let _ = self.wrap_raw(&sealed, out);
        }
    }

    fn as_any(&mut self) -> &mut dyn Any {
        // `only::tls::tls_info` downcasts to the target's TLS transport: hand out the inner one.
        if self.inner.is_none() {
            return self;
        }
        self.inner.as_mut().expect("checked above").as_any()
    }

    fn name(&self) -> &'static str {
        match &self.inner {
            Some(t) => t.name(),
            None => "gssapi",
        }
    }

    fn handshaking(&self) -> bool {
        self.inner.as_ref().is_some_and(|t| t.handshaking())
    }

    fn handshake_timeout(&self) -> Option<std::time::Duration> {
        self.inner.as_ref().and_then(|t| t.handshake_timeout())
    }
}

/// A test mechanism (not secure: a keyed checksum and an XOR "cipher"), for tests and the fuzz
/// target. Both sides know the secret; establishment is a two-token exchange of the client
/// name and a proof, so that tokens, failures and multi-step contexts are exercised.
#[doc(hidden)]
pub mod toy {
    use super::{GssContext, GssStep};
    use std::io;

    /// The toy mechanism's context.
    #[derive(Debug)]
    pub struct Toy {
        secret: u8,
        initiator: bool,
        name: String,
        peer: Option<String>,
        state: u8,
        seq_out: u32,
        seq_in: u32,
    }

    impl Toy {
        /// An initiator authenticating as `name` with `secret`.
        pub fn initiator(name: &str, secret: u8) -> Toy {
            Toy {
                secret,
                initiator: true,
                name: name.into(),
                peer: None,
                state: 0,
                seq_out: 0,
                seq_in: 0,
            }
        }

        /// An acceptor checking for `secret`.
        pub fn acceptor(secret: u8) -> Toy {
            Toy {
                initiator: false,
                name: "server".into(),
                ..Toy::initiator("", secret)
            }
        }

        fn sum(&self, seq: u32, b: &[u8]) -> u8 {
            b.iter()
                .fold(self.secret ^ seq as u8, |a, x| a.rotate_left(3) ^ x)
        }
    }

    fn denied() -> io::Error {
        io::Error::new(io::ErrorKind::PermissionDenied, "toy: bad credentials")
    }

    impl GssContext for Toy {
        fn step(&mut self, token: &[u8]) -> io::Result<GssStep> {
            match (self.initiator, self.state) {
                // Initiator: "N" + name, then expects "P" + proof of the secret.
                (true, 0) => {
                    self.state = 1;
                    let mut t = b"N".to_vec();
                    t.extend_from_slice(self.name.as_bytes());
                    Ok(GssStep::Continue(t))
                }
                (true, 1) => {
                    if token != [b'P', self.secret ^ 0x5a] {
                        return Err(denied());
                    }
                    self.state = 2;
                    self.peer = Some("server".into());
                    Ok(GssStep::Complete(Vec::new()))
                }
                // Acceptor: a name, answered with the proof; a name "deny" is refused.
                (false, 0) => {
                    let name = token.strip_prefix(b"N").ok_or_else(denied)?;
                    if name == b"deny" {
                        return Err(denied());
                    }
                    self.peer = Some(String::from_utf8_lossy(name).into_owned());
                    self.state = 2;
                    Ok(GssStep::Complete(vec![b'P', self.secret ^ 0x5a]))
                }
                _ => Err(io::Error::other("toy: step after completion")),
            }
        }

        fn wrap(&mut self, confidential: bool, msg: &[u8]) -> io::Result<Vec<u8>> {
            let mut t = vec![u8::from(confidential), self.sum(self.seq_out, msg)];
            let k = if confidential { self.secret } else { 0 };
            t.extend(msg.iter().map(|b| b ^ k));
            self.seq_out += 1;
            Ok(t)
        }

        fn unwrap(&mut self, token: &[u8]) -> io::Result<Vec<u8>> {
            let [conf, sum, body @ ..] = token else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "toy: short token",
                ));
            };
            let k = if *conf == 1 { self.secret } else { 0 };
            let msg: Vec<u8> = body.iter().map(|b| b ^ k).collect();
            if *sum != self.sum(self.seq_in, &msg) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "toy: bad checksum",
                ));
            }
            self.seq_in += 1;
            Ok(msg)
        }

        fn peer_name(&self) -> Option<String> {
            self.peer.clone()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{toy::Toy, *};

    #[test]
    fn messages_round_trip() {
        let mut out = Vec::new();
        push_msg(&mut out, MTYP_AUTH, b"tok").unwrap();
        assert_eq!(out, b"\x01\x01\x00\x03tok");
        assert_eq!(parse_msg(&out).unwrap(), Some((MTYP_AUTH, &b"tok"[..], 7)));
        assert_eq!(parse_msg(&out[..6]).unwrap(), None);
        assert_eq!(parse_msg(&[1]).unwrap(), None);
        assert_eq!(parse_msg(&ABORT).unwrap(), Some((MTYP_ABORT, &[][..], 2)));
        assert!(parse_msg(&[5, 1, 0, 0]).is_err());
        assert!(push_msg(&mut out, MTYP_DATA, &vec![0; 65_536]).is_err());
    }

    #[test]
    fn protection_levels() {
        let (mut a, mut b) = (Toy::initiator("c", 7), Toy::acceptor(7));
        for p in [
            Protection::None,
            Protection::Integrity,
            Protection::Confidentiality,
        ] {
            let mut m = Vec::new();
            protection_msg(&mut a, p, &mut m).unwrap();
            let (t, tok, _) = parse_msg(&m).unwrap().unwrap();
            assert_eq!(t, MTYP_PROTECTION);
            assert_eq!(protection_of(&mut b, tok).unwrap(), p);
        }
        assert_eq!(Protection::from_level(3), Some(Protection::Integrity));
        assert_eq!(Protection::from_level(4), None);
    }

    #[test]
    fn layer_wraps_and_unwraps_across_reads() {
        let mut tx = GssLayer::new(
            Box::new(Toy::initiator("c", 9)),
            Protection::Confidentiality,
            None,
        );
        let mut rx = GssLayer::passthrough();
        let big: Vec<u8> = (0..100_000u32).map(|i| i as u8).collect();
        let mut wire = Vec::new();
        tx.seal(&big, &mut wire).unwrap();
        tx.seal(b"tail", &mut wire).unwrap();
        // Four messages: three chunks of the big write and the tail; nothing in the clear.
        assert!(wire.windows(4).all(|w| w != b"tail"));
        // Activated with the first 10 bytes already read, then fed a byte at a time and in
        // larger pieces.
        let mut plain = Vec::new();
        rx.activate(
            Box::new(Toy::acceptor(9)),
            Protection::Confidentiality,
            &wire[..10],
            &mut plain,
        )
        .unwrap();
        assert!(plain.is_empty());
        let mut out = Vec::new();
        for b in &wire[10..1000] {
            rx.recv(std::slice::from_ref(b), &mut plain, &mut out)
                .unwrap();
        }
        rx.recv(&wire[1000..], &mut plain, &mut out).unwrap();
        assert!(out.is_empty());
        assert_eq!(plain.len(), big.len() + 4);
        assert_eq!(&plain[..big.len()], &big[..]);
        assert_eq!(&plain[big.len()..], b"tail");
        // A tampered message fails; an abort is an error too.
        let mut w2 = Vec::new();
        tx.seal(b"x", &mut w2).unwrap();
        *w2.last_mut().unwrap() ^= 1;
        assert!(rx.recv(&w2, &mut plain, &mut out).is_err());
        let mut rx2 = GssLayer::passthrough();
        rx2.activate(
            Box::new(Toy::acceptor(9)),
            Protection::Integrity,
            &[],
            &mut plain,
        )
        .unwrap();
        assert_eq!(
            rx2.recv(&ABORT, &mut plain, &mut out).unwrap_err().kind(),
            io::ErrorKind::ConnectionAborted
        );
    }

    #[test]
    fn passthrough_until_activated() {
        let mut l = GssLayer::passthrough();
        let (mut plain, mut out) = (Vec::new(), Vec::new());
        l.recv(b"abc", &mut plain, &mut out).unwrap();
        l.seal(b"def", &mut out).unwrap();
        assert_eq!(
            (plain.as_slice(), out.as_slice()),
            (&b"abc"[..], &b"def"[..])
        );
        assert!(!l.is_active());
        assert_eq!(l.name(), "gssapi");
    }
}
