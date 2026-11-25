# ADR-156: Spliced tunnels and a connection's TCP counters

English | [简体中文](156-spliced-tunnels-and-tcp-counters.zh-CN.md)

Status: accepted (2026-11-26). Extends [ADR-027](027-ebpf-xdp-pinning-socks-splice.md); asked
for by akit (A170).

## Context

ADR-027 gave akio-socks a kernel fast path for `CONNECT` tunnels: the sockmap `Relay`, a splice
whose callback writes the SOCKS reply ahead of the relayed bytes (`splice_inner_with`), and
`byte_counts(&TcpStream)`, from which socks keeps its idle timeout and closes a side only once
the other's data reached it (`SpliceCtl`, private, with its own drain thread).

akit splices its `tcp` services the same way and had to reach the sockets through the
doc-hidden `Conn::inner`, copy socks's drain machinery, and count what userspace read from the
client to know where the kernel's relaying began. A PROXY header read by akio-mux's
`ProxyProtocol` is consumed without saying how long it was, so akit kept such connections in
userspace.

## Decision

1. **A connection's counters.** `conn_byte_counts(&Conn<H>)` and `inner_byte_counts(&ConnInner)`
   in akio-ebpf (the counters are Linux socket options, akio-ebpf already reads them).
   `ByteCounts` (`#[non_exhaustive]`) gains `unread` (`SIOCINQ`) and `consumed()`
   (`received - unread`): what userspace read, whatever layer read it, so a proxy needs no count
   of its own. `TCP_INFO`, `SIOCINQ` and `SIOCOUTQ` are three calls; they are read again (up to
   eight times) until `TCP_INFO` is the same before and after the two `ioctl`s.
2. **Base counters in every splice of connections.** `RelayInner::splice` reads them while the
   gate (`SO_RCVLOWAT`) holds the verdict back: each socket's `consumed` before the sockets enter
   the map (once a socket has a psock, `tcp_bpf_ioctl` may answer `SIOCINQ` with the psock's
   queue), and `received` / `written` after the `before_relaying` write. `unread` of the base is
   `received - consumed`. `Splice::base() -> Option<[ByteCounts; 2]>`: always `Some` for
   connections (a failure to read fails and undoes the splice), best effort for raw fds.
3. **A first write without a callback.** `splice_conns_with(&Conn<A>, &Conn<B>, first)` (and
   `splice_inner_first`) writes `first` to `b`'s non-blocking socket inside the gate. A short
   write fails the splice (`WouldBlock`) and is undone; `SpliceError { error, written }` tells
   the caller what to send through the engine.
4. **`Tunnel`, public.** socks's `SpliceCtl` becomes `akio_ebpf::Tunnel` (`Relay::tunnel`,
   `tunnel_inner`): `base`, `counts`, `relayed_from`, `activity`, `moved`,
   `close_after_forward(TunnelSide, stall)` and `late_payload`. It holds the connections as
   `Weak<ConnInner>` (no cycle through handlers that hold the tunnel). Drains run on one
   process-wide `akio-ebpf-drain` thread polling every millisecond while any wait; it polls
   without the list's lock, so an I/O thread adding a drain never waits on a poll. Each tunnel
   adds at most one drain a side. The drain target of a side is
   `base(to).written + received(from) - base(from).consumed()`, which also counts bytes that
   waited in `from`'s receive queue at the splice (socks's old target did not). akio-socks keeps
   only what is its own (refusing to splice when it holds early client bytes, its counter).
5. **The PROXY header's length.** `ProxyHeader` gains a private `wire_len`, set by `parse`
   (and so on the header `ProxyProtocol` attaches), read with `wire_len() -> Option<usize>`.
   The header cannot be recomputed from the fields: `LOCAL` blocks, `UNKNOWN` lines and padding
   are discarded. A private field instead of a second attachment keeps `Conn::attachment::
   <ProxyHeader>()` working; equality and hashing ignore it. Struct literals outside akio-mux
   no longer compile (a pre-release change, `docs/api-stability.md`); `proxy` and `local` build
   headers.

## Consequences

- akit drops `Conn::inner` and its copy of the drain: `Relay::tunnel` replaces
  `sockmap::splice`, `Tunnel::moved` its probe and `close_after_forward` its `Drain`, and
  connections of listeners with `proxy_protocol` can be spliced (the base counts the header).
- The counters and the tunnel are Linux-only like the relay: elsewhere they report
  `Unsupported`, and a tunnel cannot be made.
- The drain thread polls at 1 ms while drains wait; it sleeps on a condition variable otherwise.
