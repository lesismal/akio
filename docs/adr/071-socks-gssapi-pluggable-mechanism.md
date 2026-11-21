# ADR-071: SOCKS5 GSS-API authentication with the mechanism supplied by the application

English | [简体中文](071-socks-gssapi-pluggable-mechanism.zh-CN.md)

Status: accepted (2026-11-21)

## Context

RFC 1928 makes GSS-API (method `0x01`, RFC 1961) the one authentication method a SOCKS5
implementation "MUST" support; only-socks had none (DEV-PLAN: "Not done: GSSAPI"). In practice
GSS-API means Kerberos (corporate networks behind Dante or a Windows proxy).

RFC 1961 has three parts: context establishment (`MTYP` 1 tokens until both sides are
complete), the protection-level negotiation (`MTYP` 2: one octet, wrapped with `GSS_Wrap`
without confidentiality; levels 1 integrity, 2 confidentiality, 3 selective; Dante adds 0,
"clear"), and, above level 0, per-message protection of everything that follows (`MTYP` 3
messages carrying `GSS_Wrap` tokens: the SOCKS request, the replies and the relayed data).

Constraints:

- Every runtime dependency is in-house (ADR-005), and `unsafe` stays in only-sys and the
  backends. Linking `libgssapi_krb5` / Heimdal / SSPI would take a C library and FFI.
- A pure in-house Kerberos is not realistic: the protocol is only part of it (KDC exchanges,
  ticket caches and keytabs in their on-disk formats, the enctypes, PAC, cross-realm, DNS
  canonicalisation, credential delegation), and deployments rely on the system's configuration
  (`krb5.conf`, `KRB5CCNAME`, `KRB5_KTNAME`, `kinit`, SSSD). Any reimplementation would differ
  from the site's Kerberos in exactly the places that matter.
- Rule 1 (docs/rules.md): nothing blocks an I/O thread. `GSS_Init_sec_context` may block: a
  Kerberos initiator without a service ticket asks the KDC for one; an acceptor may read a
  keytab and a replay cache from disk.

## Decision

### 1. The mechanism is the application's: `GssContext`

`only_socks::gssapi::GssContext` (defined in `only_ws::gss`, where the sans-io client handshake
lives, and re-exported) is one security context:

- `step(&mut self, token) -> io::Result<GssStep>` (`GSS_Init_sec_context` /
  `GSS_Accept_sec_context`; `GssStep::Continue(token)` or `GssStep::Complete(token)`);
- `wrap(&mut self, confidential, msg)` / `unwrap(&mut self, token)` (`GSS_Wrap` / `GSS_Unwrap`);
- `peer_name(&self)` (the acceptor's view of the client principal).

It must be `Send` (it moves to a worker for the establishment steps). The application
implements it over its GSS-API binding of choice; only-socks runs RFC 1961 around it.

### 2. Establishment off the I/O threads

- Server: each step runs on the logical pool (`Conn::spawn_blocking`); the session buffers
  what arrives meanwhile (one 64 KiB token and a little, instead of 4 KiB) and continues when
  the step completes. The factory (`Fn() -> io::Result<Box<dyn GssContext>>`) runs there too.
- Client: the handshake is sans-io inside the tunnel transport. `Handshake::feed` queues a
  `GssJob` instead of calling the context; the tunnel runs it on a short-lived helper thread
  (`only-socks-gss`) and resumes through the connection's `TransportWaker` (ADR-062). Two steps
  for Kerberos with mutual authentication, so at most two threads per tunnel, once. The
  blocking helpers run the steps inline (they block anyway). The factory gets the proxy's host
  name, to build the service name (`rcmd@host` by RFC 1961 convention and Dante's default).
- `wrap` / `unwrap` are local computations and run on the I/O thread, per message, like TLS
  record protection.

### 3. Per-message protection as a transport: `GssLayer`

`GssLayer` implements `only::Transport`: it unwraps `MTYP` 3 messages into plaintext (across
reads) and wraps what is sent in messages of at most 32 KiB of plaintext (so tokens fit the
16-bit length with any mechanism overhead). `ConnInner::send` seals under the connection's
lock, so wrapping (and the mechanism's sequence numbers) follows the order of sends from any
thread: replies sent from the upstream's I/O thread, the BIND thread or the pool stay in order.

- Server: a GSS-API server installs a pass-through `GssLayer` on each connection. When the
  protection level is agreed above none, the session reaches it with `Conn::with_transport`,
  downcasts and activates it, handing over the bytes read past the negotiation message (they
  came through pass-through and are wrapped). From then on the session and the relay see
  plaintext and every send is wrapped. A server served inside `Tls::server` has no such layer
  (TLS is the transport): such clients are closed at that point.
- Client: when the handshake is done with protection, the tunnel replaces its inner transport
  (TLS to the target, if any) with a `GssLayer` over it, wraps what the inner transport had
  already sealed and passes on tunnel bytes the proxy put in the reply's own message.

### 4. Policy

- Levels `Protection::{None, Integrity, Confidentiality}` (0, 1, 2; a client's 3 is taken as
  integrity, the least each message then gets). The server grants the client's level clamped
  to a configured range (`Socks::gssapi(factory, min..=max)`); the client asks for its level
  and refuses less (`SocksClient::gssapi(factory, level)`).
- A GSS-API server turns SOCKS4 off and no longer accepts "no authentication"; with
  `Socks::auth` too, either method works. The client offers GSS-API (and username/password
  when credentials are set), never "no authentication", so a peer cannot downgrade it.
- `UDP ASSOCIATE` is refused above level none (RFC 1961 wraps each datagram; the relay sockets
  do not share the control connection's context, and Kerberos sequence checks do not suit
  reordered datagrams): reply 7 from the server, `Unsupported` from the client at any level.
- The client's blocking helpers return a `TcpStream`: they refuse protection above none, also
  when the proxy grants more than was asked.
- The `sockmap` fast path does not apply to protected tunnels (the kernel cannot wrap).
- Failures follow RFC 1961: a failed step or bad token is answered with `VER 1, MTYP 0xff` and
  the close; the client reports a refusal (`ProxyRefused`, 407).

### 5. Verification without a GSS-API library in the workspace

- A toy mechanism (`only_ws::gss::toy`, `#[doc(hidden)]`: keyed checksum and XOR, insecure on
  purpose) drives the unit and engine tests: every level, 1 MiB both ways, BIND, TLS to the
  target inside a protected tunnel, refusals, the access hook's user, the wire format by hand.
- `tools/interop/socks/gssapi.sh`: a KDC (MIT krb5) in Docker; the mechanism is a test-only
  Python shim over `python3-gssapi` (`gss_shim.py`) that the `socks-gss-interop` example adapts
  to `GssContext` over a pipe. only-socks' client and server, Dante rebuilt from Debian's source
  package `--with-gssapi` (the packaged one, and Alpine's, have no GSS-API), and an independent
  Python RFC 1961 client checked against Dante first: 15/15 at every level. Debian 12's
  curl 7.88 cannot take part: its SOCKS state machine resets `allow_gssapi` when it resumes
  after a partial read, so it fails against every server.

## Consequences

- Applications with Kerberos get RFC 1961 interop with Dante and RFC 1961 clients by writing a
  small adapter over their GSS-API binding; only-socks stays free of C dependencies and FFI.
- Nothing changes for servers and clients without GSS-API: no transport is installed, the
  relay and the tunnel's data path are untouched (no benchmark needed).
- The establishment steps cost a pool task (server) or a thread spawn (client) each: fine for
  a handshake, and it keeps KDC latency off the I/O threads.
- Not done: UDP ASSOCIATE with protection; GSS-API for the HTTP and WebSocket clients'
  `socks5://` proxies (the handshake supports it, the proxy URL has no way to name a mechanism).
