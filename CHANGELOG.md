# Changelog

[中文](CHANGELOG.zh-CN.md)

All notable changes to `only` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and `only` adheres to
[Semantic Versioning](https://semver.org/) from 1.0.0 on, as defined in
[docs/api-stability.md](docs/api-stability.md). Deprecations follow
[docs/deprecation.md](docs/deprecation.md). All crates of the workspace share one version.

## [Unreleased]

### Added: SOCKS5 UDP ASSOCIATE with GSS-API protection (only-socks, only-ws)

ADR-071's update of 2026-11-22, no API change:

- With GSS-API per-message protection, `UDP ASSOCIATE` is no longer refused: each datagram
  between the client and the relay is one RFC 1961 encapsulated-data message (§5) wrapped with
  the control connection's context, in the server's relay, `SocksClient::udp_associate` and
  `SocksClient::udp_associate_blocking` (which now accepts protection); datagrams that do not
  unwrap are dropped.
- `GssContext` documentation: `unwrap` should accept out-of-sequence tokens, since datagrams are
  lost and reordered.
- `tools/interop/socks/gssapi.sh` gains UDP cases: the independent Python client against Dante
  and only-socks' server, only-socks' client (engine and blocking) against both, levels 0 to 2.
  27/27 in all.

### Added: compressed streamed responses (only-http, only-brotli)

ADR-074 (docs/adr/074-compressed-streamed-responses.md), additive:

- `Compress::stream: Option<StreamCompress>` (off by default): the `compress` middleware also
  compresses streamed responses (`Context::stream_response`), the coding negotiated from
  `Accept-Encoding` as for buffered ones (br, zstd when offered, gzip, deflate), on status 200
  with a compressible type and no `Content-Encoding`; `Content-Length` is dropped and
  `Vary: Accept-Encoding` set. One encoder per stream, on HTTP/1.1, HTTP/1.0, HTTP/2 and HTTP/3.
- Every `BodyStream::write` is encoded and flushed (deflate sync flush, zstd and brotli
  `Flush::Flush`), so each server-sent event can be decoded on arrival; `finish` ends the
  coding. Small defaults (`StreamCompress`): gzip / deflate 1, zstd 1 with `zstd_window_log` 17,
  brotli 4 with `brotli_window_bits` 18: about 0.3, 0.5 and 1.3 MiB per open stream.
- only-brotli's streaming `Compressor` slides its buffer at two windows (it waited for a window
  plus a 1 MiB meta-block), so small windows keep a stream small: quality 4, window bits 18
  from 2.0 to 1.3 MiB per stream. Output unchanged.
- Fixed: `etag()` gave streamed 200 responses the ETag of an empty body.
- Measured (same-run A/B against main on gpu51. With `stream` unset streamed responses run at
  main's speed (16 small events per response 0.999x, 16 x 16 KiB 1.011x); compressed, the
  server's CPU is the limit: 6 / 27 / 110 us more per 16-event response for gzip / zstd / br
  (17 us uncompressed), 0.93 / 0.54 / 0.16 GB/s of HTML per core, event bytes down to 35% / 34% /
  26%, HTML to 18% / 6.1% / 5.4%. Server RSS per held stream (1,000 streams) 148 / 112 /
  424 KiB after 3 events and 268 / 324 / 1,106 KiB after 6,000, against 1.2-2.6 KiB uncompressed; docs/BENCHMARKS.md).

### Added: mDNS over IPv6 with hop limit 255, on IPv6-only links (only-sys, only, only-webrtc)

ADR-078 (docs/adr/078-mdns-ipv6-hop-limit-ipv6-only.md), additive:

- `only_sys::set_multicast_hops_v6` / `multicast_hops_v6` (`IPV6_MULTICAST_HOPS`, which std
  lacks). `Engine::bind_udp_multicast_on` with an IPv6 group now sends with hop limit 255 and
  multicast loopback on, as the IPv4 path sends with TTL 255 (RFC 6762 §11; avahi with
  `check-response-ttl=yes` ignored IPv6 answers sent with the default hop limit 1).
- `Endpoint::conceal_host_candidates` works when the IPv4 or the IPv6 mDNS socket holds the
  shared port: on an IPv6-only link (no route to `224.0.0.251`) names are answered over
  `ff02::fb` instead of the call failing.
- `tools/interop/webrtc/mdns6.sh`: an IPv6-only container (veth, link-local and ULA addresses)
  running the mDNS tests on epoll and io_uring, and avahi 0.8 resolving our concealed name and
  publishing one we resolve and connect to; `browser.sh` checks Chrome 157 against an endpoint
  whose only host candidate is a concealed IPv6 address. New `webrtc-interop` modes
  `mdns-conceal` and `mdns-resolve`.

### Added: TURN TCP allocations, RFC 6062 (only-turn)

ADR-076 (docs/adr/076-turn-tcp-allocations.md):

- Server: TCP and TLS clients may ask for `REQUESTED-TRANSPORT` TCP. The relayed address is a
  listening TCP socket (one accept thread per server polls them all and hands connections to
  the engine); Connect opens a connection to the peer from the relayed address (446, 447);
  peers holding a permission that connect to it are announced with ConnectionAttempt; a
  ConnectionBind on a new client connection (same credentials, the control connection's nonce
  accepted) turns it into a raw pipe to the peer. Bound connections bypass the allocation
  shards; backpressure is linked both ways (`hold_reads` / `on_drain`), a peer's bytes before
  the bind are held up to the same mark. Unbound connections close after 30 s; closing either
  side closes the other; the allocation going closes all of them.
- `TurnConfig::{tcp_relays (true), max_tcp_connections (64), tcp_relay_buffer (64 KiB)}`,
  `TurnStats::tcp_connections`; `TurnEnv` gains defaulted methods for TCP relays and
  connections, `TurnCore` gains `tcp_connected`, `tcp_incoming`, `tcp_closed`.
- Client: `ClientConfig::tcp_allocation`, `Client::{connect, create_permission,
  data_connection}`, `ClientEvent::{Connected, ConnectFailed, ConnectionAttempt}`,
  `client::{DataConnection, DataState}` (a sans-io ConnectionBind that hands back the peer's
  first bytes).
- STUN: `Method::{CONNECT, CONNECTION_BIND, CONNECTION_ATTEMPT}`, `attr::CONNECTION_ID`.
- Changed: an Allocate for TCP over UDP or DTLS is now 400 (RFC 6062 section 5.1) instead of
  442; transports other than UDP and TCP stay 442.
- Fuzz target `turn_tcp`; `tools/interop/webrtc/turn-tcp.sh`: coturn's
  `turnutils_uclient -T` against only-turn, the only_turn client against coturn, pion/turn and
  only-turn, pion/turn's TCP allocation client against only-turn and coturn, over TCP and TLS.
- UDP relay path unchanged: same-run A/B against main on gpu51, `turn-relay-bench 8 6 4` (8 pairs, 100-byte datagrams both ways), 6 alternating rounds under quiet.sh: 308.6k vs 268.0k datagrams/s mean total (1.15x; rounds vary by about ±20 %, so read it as no regression, not a gain).

### Added: SOCKS5 GSS-API authentication, mechanism supplied by the application (only-socks, only-ws)

ADR-071 (docs/adr/071-socks-gssapi-pluggable-mechanism.md), additive:

- RFC 1961 (method 1) in the server (`Socks::gssapi(factory, levels)`) and the client
  (`SocksClient::gssapi(factory, level)`): context establishment, the protection-level
  negotiation, and at `Protection::Integrity` / `Protection::Confidentiality` the wrapping of the
  request, the replies and the whole tunnel (`Protection::None`: authentication only). The
  GSS-API mechanism is the application's, behind `only_socks::gssapi::GssContext` (`step`,
  `wrap`, `unwrap`, `peer_name`); the workspace links no GSS-API library.
- Establishment steps never run on an I/O thread: the server runs them on the logical pool, the
  client on a helper thread resumed through `TransportWaker`. The server's access hook sees the
  GSS-API peer as `Request::user()`. A GSS-API server turns SOCKS4 and "no authentication" off.
- Refused with protection: `UDP ASSOCIATE` (server reply 7; the client refuses GSS-API for UDP;
  lifted since, see the entry above), the client's blocking helpers (also when the proxy grants
  more than asked), `sockmap`
  splicing, a server inside `Tls::server`.
- `tools/interop/socks/gssapi.sh`: MIT Kerberos KDC in Docker, only-socks client and server
  (through a test-only `python3-gssapi` shim), Dante rebuilt with GSS-API and an independent
  RFC 1961 client: 15/15 at every level.

### Added: protobuf `utf8_validation = NONE` (only-protobuf, only-protobuf-build)

Additive:

- `string` fields with `features.utf8_validation = NONE` are generated as
  `only_protobuf::ProtoString` (bytes, decoded without a UTF-8 check: `to_str`,
  `to_string_lossy`, `as_bytes`; codec `encoding::ProtoStringCodec`), in every shape (singular,
  repeated, map keys and values, oneofs, extensions); their getters return `&[u8]`.
  `Config::proto2_unchecked_strings(true)` does the same for proto2 strings (their legacy NONE);
  by default proto2 strings stay `String` and are checked, as before.
- Dynamic messages follow the descriptor: a `string` field that does not require UTF-8 (`NONE`,
  and proto2) keeps contents that are not UTF-8 as `Value::Bytes` (`DynamicMessage::set` accepts
  it there); JSON prints them lossily, the text format escapes and parses them. Behaviour change:
  dynamic decoding of a proto2 string that is not UTF-8 now succeeds (it failed before).
- Descriptors: a map field's features are copied to its entry's key and value, as protoc does.
- Generated code of files without `NONE` is byte-identical; conformance runner v35.1 still
  5627 + 909 passed / 0 failed.

### Changed: musl layout tests (only-sys)

- `only_sys::ffi`'s layouts and constants are now checked against the `libc` crate on
  `aarch64-unknown-linux-musl` and `x86_64-unknown-linux-musl` (Alpine) too. musl's
  `struct cmsghdr` is 4-aligned where the kernel's and ours are 8-aligned (sizes and offsets
  agree); nothing else differs. docs/api-stability.md lists Linux with musl as tier 2.

### Added: monoio in the benchmark harness, quiche interop (tools)

- `tools/bench-ref/monoio-ref`: a monoio 0.2 reference server (thread-per-core, one runtime and
  one `SO_REUSEPORT` listener per thread; TCP echo, HTTP/1.1 `/plaintext` and `/json` with
  pipelining), run by `tools/bench` as `monoio-uring` and `monoio-epoll` (its io_uring and legacy
  drivers); `http.sh` skips the h2c cases for servers without HTTP/2 (`has_h2`). Results and
  method in docs/BENCHMARKS.md.
- `tools/interop/quic/quiche.sh`: quiche 0.30.1 (built from its release tag in Docker) against
  `only-h3` / `only-quic` both ways: quiche-client against the HTTP/3 server (Version
  Negotiation, 50 requests on one connection, a 300 KB POST, a streamed response, 0-RTT, client
  migration) and over HTTP/0.9 (`hq-interop`) against `only-quic`; `H3Client` and only-quic's
  client against quiche-server with and without Retry (405 after STOP_SENDING on a 3 MiB upload,
  more concurrent requests than its 100-stream limit, a paused streamed response). The
  `quic-interop` example gains an `hq` mode (server and client), `h3-interop` a `client-quiche`
  mode. No bug found on either side.

### Added: IPv6 autoconfiguration, Accurate ECN and AF_XDP shared UMEM / jumbo frames in the userspace stack (only-dpdk, only-ebpf)

ADR-068 (docs/adr/068-userspace-stack-slaac-accecn-af-xdp-multibuffer.md), additive (all off by
default):

- `DpdkConfig::ipv6_slaac`: router solicitations, and from router advertisements a global address
  per /64 prefix (EUI-64), default routers, on-link prefixes, the MTU and the hop limit, with
  RFC 4862 lifetimes. Turns IPv6 on without `address6`. `only_dpdk::ipv6_addresses(&Device)`
  reports the usable addresses.
- `DpdkConfig::ipv6_dad`: duplicate address detection (RFC 4862 5.4, RFC 7527 nonce) before an
  address is used; a duplicate link-local address turns IPv6 off.
- `DpdkConfig::tcp_accecn`: Accurate ECN (RFC 9768) in the userspace TCP, falling back to RFC 3168
  ECN or none; interoperates with Linux 6.18+ (`net.ipv4.tcp_ecn = 3`).
- `AfXdpConfig::shared_umem` (`XDP_SHARED_UMEM`: one UMEM for all queues, `frames` in total) and
  `AfXdpConfig::multi_buffer` (`XDP_USE_SG`: frames over several chunks, so `DpdkConfig::mtu` up
  to 9000 over AF_XDP); `only_ebpf::xsk::XskConfig::shared_umem` / `multi_buffer` and
  `XskSocket::send_frags` underneath.
- Router advertisements are copied to every queue of a multi-queue device, like neighbor
  discovery; `#[doc(hidden)] only_dpdk::tcp_ecn_stats`.

Fixed: on a multi-queue device an ICMP / ICMPv6 error (destination unreachable, packet too big)
for a dialed connection is handed to the queue owning that connection, like its other packets.
RSS hashes such an error by its addresses only, so it could land on another queue and be lost
(a UDP dial to a closed port then timed out instead of failing with "unreachable").

### Added: reconnecting RTMP / RTSP clients, RTCP A/V sync, HLS I-frame playlists, rendition reports, session keys, H.265 `cbcs` (only-media)

ADR-070 (docs/adr/070-media-reconnect-av-sync-iframes-hevc-cbcs.md), additive:

- **Reconnects**: `only_media::Reconnect` (`initial_delay` 500 ms, `max_delay` 30 s,
  `max_attempts` `None`; `Reconnect::new(&Arc<Engine>)` holds the engine weakly) in the new
  `RtmpClientConfig::reconnect` and `RtspClientConfig::reconnect` (default `None`). Errors
  another try may cure reconnect after a doubling, bounded backoff that resets once a session
  is live; bad URLs, hub errors and refused credentials stay final. A pull keeps its hub path
  and subscribers and republishes the new session's tracks (a timeline restart for the sinks);
  a push resubscribes from the cached GOP (RTSP: the stream's current tracks announced again).
  RTMP: `ClientState::Reconnecting`, `RtmpClient::reconnects()`, the first connection retried
  too. RTSP: tries on a short-lived thread, `RtspClient::{reconnects, is_live}`; the first
  session must come up.
- **RTSP A/V sync**: `RtspClientConfig::rtcp_sync` (default `true`): a pull maps each track's
  RTP timestamps to the server's NTP clock from its RTCP sender reports, relative to the first
  track synchronized; corrections only move times forward and apply before the stream goes
  live when the reports come early.
- **HLS I-frame playlists**: `HlsConfig::iframe_playlist` (default `false`):
  `/<path>/iframes.m3u8` (`EXT-X-I-FRAMES-ONLY`, `EXT-X-BYTERANGE`; MPEG-TS ranges of the PAT,
  PMT and keyframe PES, an fMP4 fragment per keyframe), `EXT-X-I-FRAME-STREAM-INF` in
  multivariant playlists; not with AES-128. Segment, part and init responses answer a single
  byte range (206 / 416, `Accept-Ranges: bytes`).
- **Rendition reports**: LL-HLS media playlists of a multivariant group carry
  `EXT-X-RENDITION-REPORT` (`LAST-MSN`, `LAST-PART`) for the other renditions.
- **`EXT-X-SESSION-KEY`**: the current key of each encrypted rendition in multivariant
  playlists.
- **SAMPLE-AES `cbcs` for H.265 in fMP4**: the H.265 SPS / PPS / slice segment header parser
  keeps every slice header clear (matches ffmpeg's `trace_headers` on 200 slices).
- Fixed on the way: an RTSP client's hub path is free once `is_closed()` is true (as for RTMP).
- Fuzz target `h265_sample_encryption`; `tests/client_bench.rs` benchmarks the RTMP and RTSP
  pull ingest.
- Performance (gpu51, `quiet.sh`, one pinned core, 7 alternating rounds, medians, head / base):
  HLS segmenting (`bench_segmenting`, ns per packet) MPEG-TS 0.939, MPEG-TS LL-HLS 0.996,
  fMP4 0.950, fMP4 LL-HLS 0.921 (the segment being written is now borrowed in place instead of
  moved out of the stream state and back for every packet; the I-frame state is boxed),
  AES-128 0.987 to 0.996, SAMPLE-AES MPEG-TS 0.997, `cbcs` fMP4 1.019 (the H.264 / H.265
  dispatch per NAL unit); RTMP pull ingest 1.013 and RTSP pull ingest 1.015 (246 and 269 ns per
  message / RTP packet, `tests/client_bench.rs`).

### Added: a pacer, libwebrtc's FEC masks and protection policy, ECN in RFC 8888, network-state and raised-maximum probing (only-webrtc, only-rtp)

ADR-073 (docs/adr/073-webrtc-pacer-fec-policy-ecn.md):

- **Pacer** (only-webrtc): with the bandwidth estimator on, video, FEC and retransmissions leave
  through a queue drained at 2.5 times the estimate with a 40 ms burst allowance
  (retransmissions first, the queue bounded at 8192 packets / 8 MB, drained faster when its
  oldest packet would wait 2 s); audio is never delayed; transport-wide sequence numbers and
  abs-send-time are written as packets leave; queued media fills probe slots; optional padding
  (`RtcConfig::set_padding_rate`). `RtcConfig::enable_pacing(false)` turns it off; without the
  estimator nothing is queued.
- **Probing** (only-rtp `BandwidthEstimator`): `set_bounds` at run time probes a raised maximum
  (only-webrtc: `RtcConfig::set_bwe_bounds`, `Peer::set_bitrate_bounds`);
  `set_network_state_estimate` caps probes at an external link-capacity estimate and probes
  towards it (every 5 s, every 3 s while the delay-based rate holds the estimate under 70 % of
  it); the estimator's own link capacity estimate (`link_capacity`) drives the 3 s probes.
- **FEC** (only-rtp `fec`): libwebrtc's random / bursty mask tables for groups of up to 12
  packets (`packet_masks`, `FecMaskType`), its group rules across frames and key-frame factors
  (`FecProtection`, `FecEncoder::{set_protection, push_frame}`), and its protection policy
  (`ProtectionPolicy`, `protection_factors`: the code-rate table by loss and bits per frame,
  the RTT-aware NACK/FEC hybrid). only-webrtc uses them per sent stream; `set_fec_protection`
  bounds the factors; `RtcConfig::set_fec_mask(FecMask::{Random, Bursty})`.
- **ECN in RFC 8888 reports**: the endpoint passes each datagram's ECN codepoint (already read
  by the UDP backends) to the peer, RFC 8888 feedback reports it, and the estimator counts
  CE-marked packets as lost (`PacketResult::ecn`, `BandwidthEstimator::ecn_counts`).
- **FlexFEC on simulcast lines** (one unsignaled FlexFEC stream per encoding, named by MID and
  the repaired RID); **RED for PCMU, PCMA and G.722** (`RtcConfig::enable_audio_red`,
  `red/8000`); **video RED without FEC** (`FecMechanism::Red`; `red` without `ulpfec` accepted).
- **Partially rebuilt ULPFEC packets** reach the depacketizer (`FecDecoder::take_partials`,
  `FrameAssembler::push_partial`, `Frame::partial`; such frames are not `contiguous`).
- **R factor and MOS** from the E-model (ITU-T G.107: `EModel`, `mos_from_r`,
  `BurstLossModel::{loss_fraction, burst_ratio}`) in only-webrtc's RTCP XR VoIP metrics.
- Statistics (`PeerStats` event): `fec_partial`, `paced_dropped`, `ecn_ect_received`,
  `ecn_ce_received`, `ecn_ce_reported`.
- Changed behaviour: media is paced when the estimator runs; FEC protection follows
  libwebrtc's policy instead of three times the loss (with NACK and an RTT under 20 ms, delta
  frames get no FEC); FlexFEC is offered on simulcast lines; VoIP metrics carry R and MOS.
  only-rtp (internal tier): `PacketResult` has a new field `ecn` and `Frame` a new field
  `partial`.
- Tests: simulated time (a keyframe spread over 156 ms at a 1 Mbps estimate while audio leaves at
  once, retransmission order, queue bounds, a raised maximum probed, ECN through RFC 8888, PCMU
  RED at 10 % loss 297-298 of 300 frames against 263-268, partial frames, simulcast FlexFEC);
  libwebrtc's tables and policy values; estimator links (a raised maximum reached in 0.15 s, a
  network state estimate holding probes, 20 % CE cutting the estimate as 20 % loss). Interop:
  `tools/interop/webrtc/pacing.sh` with Chrome 157 (largest burst towards Chrome 4 packets
  paced against 7 unpaced, 0 against 15 bursts of 6+; Chrome decodes 299-300 of 300 frames),
  `fec.sh` unchanged (ULPFEC 381/400, FlexFEC 391/400 frames at 5 % loss without NACK); real
  loss (`tests/netem.rs`, `tc netem loss 5%` in Docker, NACK removed): 251 of 300 frames whole
  without FEC, 300 with ULPFEC, 299 with FlexFEC, 300 with FlexFEC paced.
- Benchmarks (gpu51, same-run A/B): same-run A/B against the branch point 57696b6b on gpu51 (`quiet.sh`,
  CPUs 2-9, 7 alternating rounds, medians), one-way VP8 between two loopback `Endpoint`s:
  default configuration (no estimator, so no pacer) 0.999x (142.7 vs 142.8 MB/s); FEC held at
  64/256, ULPFEC 0.993x (120.2 vs 121.1 MB/s) and FlexFEC 0.994x (122.2 vs 122.9 MB/s), the
  difference being libwebrtc's masks, whose FEC packets cover more media packets than the
  interleaved ones did (a first build that re-evaluated the policy per frame measured 0.988x /
  0.981x).

### Added: WebRTC transports without BUNDLE or ICE, SDES MKIs and data channels, channel priorities, TURN DTLS connection IDs (only-webrtc, only-turn, only-ice)

ADR-072 (docs/adr/072-webrtc-transports-sdes-priorities-turn-cids.md), additive:

- Data channel priorities (`ChannelPriority` in `ChannelConfig`, sent in DCEP and read from the
  peer's; `Peer::channel_priority` / `set_channel_priority`) and the SCTP stream scheduler
  (`ChannelScheduler`, `RtcConfig::set_sctp_scheduler`; weighted fair queueing by default).
- Sessions without BUNDLE: `RtcConfig::set_bundle_policy(BundlePolicy::Disabled)`, remote offers
  without `a=group:BUNDLE` and answers that refuse ours get an ICE agent, DTLS association and
  SRTP keys per section (Chrome `bundlePolicy: "max-compat"` works both ways);
  `Endpoint::bind_transport_socket` gives the transports sockets of their own;
  `Peer::add_remote_candidate_in` trickles a candidate to its section. Without rtcp-mux such a
  session may now carry several sections and data channels. Transport-wide congestion control
  is not negotiated in an unbundled session.
- RTCP on component 2: server-reflexive and relayed candidates gathered from the RTCP socket by
  `gather_srflx` / `gather_relay(_via)`; `RtcServer::rtcp_candidates` and `RtcServer::rtcp()`
  (`RtcRtcp`) for an ICE-lite server's RTCP listener.
- SDES-SRTP without ICE (`RtcConfig::enable_ice(false)`, or a remote SDP without ICE: plain
  `c=` / `m=` port media, `a=rtcp`), with MKIs and several master keys
  (`RtcConfig::set_sdes_mki_length` for our offers), and next to data channels (DTLS in the
  application section).
- only-turn: the TURN-over-DTLS listener negotiates 8-byte connection IDs; a client's path
  follows an authenticated record from a new address while its allocation stays
  (`TurnServer::dtls_with_connection_ids` for another length or none). only-webrtc's DTLS relay
  client sends the server's CID.
- only-ice: `mdns::MULTICAST_V6`, `mdns::multicast_v6_on`, `Candidate::with_scope_id`,
  `IceAgent::set_fixed_pair` / `is_fixed` (paths without ICE).

### Changed: remote offers without BUNDLE (only-webrtc)

A remote offer of several sections without `a=group:BUNDLE` is answered with a transport per
section (it was answered with a BUNDLE group the offer did not ask for, which did not connect).

### Added: streaming, dictionaries and better top-level ratios in only-brotli and only-zstd

ADR-069 (docs/adr/069-brotli-zstd-streaming-dictionaries-ratios.md), additive API:

- Streaming in both crates, shaped like only-deflate's: `Compressor::compress(input, &mut out,
  Flush)` (`Flush::{None, Flush, Finish}`, a window setting, `reset`) and
  `Decompressor::decompress_vec` / `decompress` returning `Progress { consumed, produced, done }`,
  with bounded memory whatever the input: the zstd decoder gathers at most a block and holds the
  frame's window (`max_window`, 8 MiB by default); the brotli decoder resumes at the last
  complete command or header unit, so input split anywhere (a byte at a time included) costs
  little more than whole input, and decodes at most 1 MiB ahead of delivery
  (`max_window_bits`). zstd `Flush` writes the pending input as a block, brotli's ends the
  meta-block with an empty metadata block.
- zstd dictionaries: `Dictionary` (raw content, or the trained format of `zstd --train` with
  its Dictionary_ID, tables and repeat offsets), `compress_with_dictionary`,
  `decompress_with_dictionary`, `with_dictionary` on the streaming types; new errors
  `WrongDictionary`, `BadDictionary`. brotli raw (LZ77 prefix) dictionaries, as `brotli -D` and
  Google's `BROTLI_SHARED_DICTIONARY_RAW` use them: `compress_with_dictionary`,
  `decompress_with_dictionary`, `with_dictionary`; new error `WindowTooLarge`. Both checked
  against the CLIs in both directions.
- Ratios: zstd levels 16..=22 parse optimally (libzstd's `btopt` / `btultra`: binary-tree match
  finder, a shortest path priced from symbol statistics carried from block to block, 1-3
  passes) and every level may repeat the previous block's tables; brotli 10..=11 use static
  dictionary words. zstd 19 is now 0.3-1.4% larger than libzstd on the benchmark corpus (was
  1.3-7.6%) and level 16 smaller on Silesia and JSON, brotli 11 0.9-4.7% larger
  than libbrotli (was 3.5-11.4%; brotli block splitting is still not done).
- Compression at those levels is slower, as in the reference encoders: zstd 19 3.5-10.9 MB/s
  (libzstd 3.9-12), brotli 10-11 about half the speed on text (docs/BENCHMARKS.md).
- Decoding speed about unchanged (same-run A/B against main on the quiet host: -2.2..+4.9% per
  cell; small certificate chains up to 2% slower, about 0.15 us; docs/BENCHMARKS.md).
- Fuzz targets `zstd_stream`, `zstd_stream_roundtrip`, `brotli_stream`, `brotli_stream_roundtrip`.
- only-http unchanged: streamed responses stay uncompressed (ADR-069 section 4; compressed since, ADR-074).

### Added: kernel TLS for engine connections, hardware-first (only-tls, only-core, only-sys, only)

ADR-067 (docs/adr/067-kernel-tls-engine-offload.md), additive (off by default):

- `ServerConfigBuilder::ktls` / `ClientConfigBuilder::ktls` with `only_tls::Ktls`: after the
  handshake a `Tls` connection on epoll or io_uring hands its record layer to Linux.
  `Ktls::Hardware` offloads only what a NIC with TLS offload does itself (`tls-hw-tx-offload` /
  `tls-hw-rx-offload` on the interface of the local address; AES-GCM), confirms it with the
  kernel's `TlsTxDevice` / `TlsRxDevice` counters and stops offering a combination the driver
  turned down; on hosts without such a NIC it changes nothing. `Ktls::Software` /
  `Ktls::SoftwareTx` use software kTLS (both directions / the send direction only).
  `ktls_zerocopy_sendfile(true)` sets `TLS_TX_ZEROCOPY_RO` on device-offloaded connections.
- With the send direction in the kernel, application bytes skip user-space sealing and
  `send_file` / static files go out with `sendfile(2)`; control records and key updates are
  queued in order. With the receive direction in the kernel, `on_data` gets the decrypted bytes
  directly and control records (alerts, KeyUpdate, close_notify) are read with `recvmsg`.
  io_uring moves the receive direction after stopping its multishot recv on a record boundary.
- `TlsInfo::ktls_tx` / `ktls_rx` (`KtlsPath::Software` / `Hardware`), `TlsCounts::ktls_*` and
  the `only_tls_ktls_total{side, dir, path}` metric.
- only-core: `Transport::{wants_offload, offload, kernel_send, take_ops, kernel_record}`
  (default methods), `Offloaded`, `SocketOp` (Linux).
- only-sys: `netdev_tls_offload`, `netdev_features`, `interface_addrs`, `tls_stat`,
  `ktls_tx_zerocopy_ro`, `ktls_rx_expect_no_pad`, `kernel_at_least` (hidden module).
- Features: `only-tls/ktls` and `only/ktls`; `experimental-ktls` stays as an alias.
- The benchmark servers take `ONLY_KTLS=off|hardware|software|software-tx`;
  `tools/bench/ktls-engine.sh` runs the engine A/B.
- Performance (docs/BENCHMARKS.md, "Kernel TLS in the engine"): the default build and
  `Ktls::Hardware` on a host without a TLS-offload NIC are unchanged against main (handshakes/s
  and HTTPS req/s within 0.5% on epoll and io_uring). Software kTLS stays slower on this CPU
  (HTTPS 0.77x), as evaluated before. The hardware path is not measured (no such NIC on the test
  host).
- Tests: `crates/only/tests/ktls.rs` (epoll and io_uring), curl / `openssl s_client` against
  `http-bench` with kTLS (10/10), `tools/interop/tls/run.sh` with `ONLY_INTEROP_KTLS=require`
  (175/175).

### Added: change notifications for the static file cache (only-http, only-sys)

ADR-066 (docs/adr/066-static-files-change-notifications.md), additive (off by default):

- `Files::watch(true)`: the cache follows the disk through inotify (Linux) or kqueue
  `EVFILT_VNODE` (macOS) instead of re-checking every `check_interval`. An entry whose
  directories (root down), file and compressed twins are watched is served without touching the
  disk until a change drops it: a write or attribute change, a rename or deletion of the file, a
  twin or a directory on its path, or a lost-event overflow. One `only-files-watch` thread per
  `Files`; it exits when the `Files` is dropped.
- Entries the notifications cannot vouch for keep the interval rule: on Linux, symlinks and
  files with several hard links; entries read while a change was being reported; entries past
  `Files::max_watches(n)` (default 1024: directory watches, plus one file descriptor per cached
  file on macOS); everything if notifications cannot be set up or break. Not for network or FUSE
  file systems, where other machines' changes produce no notification.
- only-sys: `FsWatcher` (`watch_dir`, `watch_file`, `unwatch`, `wait`, `wake`), `FsEvent`,
  `WatchId`.
- The hit path on the I/O thread reads one more relaxed atomic; with `watch` off, nothing else
  changes.

### Added: connectionless UDP listeners, `DatagramsHandler` (only, only-core, only-epoll, only-uring)

ADR-065 (docs/adr/065-connectionless-datagrams.md), additive (per-peer UDP listeners are
unchanged):

- `Listener::udp(addr).serve_datagrams(factory)`: one `DatagramsHandler` per I/O thread instead
  of a `Conn` per peer. `on_datagrams(&Datagrams, &mut Replies)` gets each receive batch as
  `(peer, &[u8])` pairs; replies to any address queued on `Replies` leave together when it
  returns (`sendmmsg`, runs of equal-size datagrams to one address as UDP GSO, on Linux). No peer
  table, idle timeout or `on_open` / `on_close`: memory does not grow with the number of peers;
  `on_shutdown` sends last datagrams.
- `DatagramSender` (`Send + Sync + Clone`; from the factory, `Replies::sender` or
  `Engine::datagram_sender`) sends to any address from any thread.
- Bounded: the reply queue counts against `Config::max_queued_bytes` (`send_to` then fails with
  `WouldBlock`); datagrams waiting for socket space pause reading on that thread.
- epoll, kqueue and io_uring (a ring poll per socket, the same `recvmmsg` / `sendmmsg` path;
  `ONLY_DEFAULT_BACKEND=uring` applies); not DPDK (`Unsupported`). `Engine::set_threads` is
  refused, as for per-peer UDP listeners.
- Example `udp-dns` (a DNS-style responder); `bench-server udp-dgram`. 64 B echo A/B on
  gpu51: per-peer UDP unchanged (1.02x req/s, 1.00x CPU per request); `serve_datagrams` 1.08x
  (epoll) / 1.09x (io_uring) req/s with 7-8% less server CPU per request.

### Added: cookie jar, Happy Eyeballs, DNS cache and `https://` proxies in the clients; SOCKS fragments and TLS; macOS trust settings (only, only-http, only-ws, only-socks, only-tls)

ADR-059 (docs/adr/059-client-cookies-happy-eyeballs-proxy-tls.md), additive:

- `only_http::cookie::CookieJar` and `Client::with_cookies`: RFC 6265 cookies with the RFC
  6265bis rules (Domain and public suffixes: single labels and IPs always, a list through
  `CookieJar::public_suffixes`; Path; Secure, `__Secure-` / `__Host-`; HttpOnly; SameSite across
  redirect chains that leave the first site; Max-Age / Expires, 400-day cap), bounded
  (`CookieLimits`: 4096 bytes, 50 per domain, 3000 in all, least recently used first), applied
  on every hop of a redirect chain. Off unless attached.
- `only::dns`: a bounded answer cache (`CacheConfig`: fixed TTL of 30 s since `getaddrinfo`
  gives none, 1024 names, failures not cached by default; `set_cache`, `clear_cache`) and
  shared in-flight lookups; Happy Eyeballs v2 (`HappyEyeballs`, RFC 8305: families interleaved,
  an attempt every 250 ms or at once after a failure, losers closed before sending) on one
  bounded racer thread handing the winner to the engine. The HTTP/1 client
  (`ClientOptions::happy_eyeballs`), the WebSocket client (`DialOptions::happy_eyeballs`) and
  the new `H2Client::connect(engine, host, port, ...)` race this way.
- `https://` proxy URLs (TLS to the proxy, its certificate checked by name; TLS inside TLS for
  `https://` / `wss://` targets) for the HTTP and WebSocket clients and `Proxy::from_env`.
- only-socks: `SocksClient::tls` (TLS to the proxy on the engine methods), sending UDP datagrams
  in fragments (`UdpAssociation::send_fragmented`, `BlockingUdp::send_fragmented`, and the
  server's opt-in `Socks::udp_fragment_size`); the client's UDP association tries the proxy's
  next address when one is unreachable.
- `RootCerts::system()` on macOS applies the user, admin and system trust settings (`security
  trust-settings-export`): distrusted CAs are left out, CAs trusted in the System or login
  keychain are roots, the System keychain's untrusted certificates no longer are.
- Fuzz targets `cookie_parse` and `tls_trust_plist`. Not done: PAC, the Windows store, GSSAPI.

### Added: a complete QPACK encoder and streamed responses on the HTTP/3 client (only-h3, only-quic)

ADR-061 (docs/adr/061-qpack-encoder-h3-streamed-responses.md), additive (defaults unchanged: the
encoder stays off, `qpack_encoder_capacity: 0`):

- QPACK encoder (RFC 9204), when `qpack_encoder_capacity` is set: inserts with static or dynamic
  name references or literal names, only for fields seen twice (never paths, dates, lengths,
  validators, ranges, credentials or cookies); Duplicate for referenced entries about to be
  evicted; dynamic name references in literal field lines; post-base references to entries the
  same section inserted; sections that reference unacknowledged entries only within the peer's
  `SETTINGS_QPACK_BLOCKED_STREAMS` (now read from its SETTINGS; at most 64); eviction of
  acknowledged, unreferenced entries only; Section Acknowledgement, Stream Cancellation and Insert
  Count Increment handled as before.
- `H3Client::open(method, path, headers, on_event) -> H3Upload`: a streamed response reported as
  `H3Event::{Head, Data, Trailers, End, Error}` on the connection's I/O thread (not buffered, not
  bounded by `max_body_bytes`), with the request body written through the returned `H3Upload`
  (upload and download at once work). `H3Upload::hold_reads(bool)` pauses and resumes reading
  the response, so QUIC flow control holds the server back; `H3Upload::cancel()` abandons the
  request. `request_timeout` applies until the head.
- `only_quic::Connection::hold_reads(id, bool)`: hold a stream's delivery; held data stays in the
  receive buffer and the stream window is not extended until resumed.
- Server push stays out (browsers dropped it; ADR-061).
- Testing: unit tests per encoder rule, a new fuzz target `qpack_encoder` (our encoder against our
  decoder over a link that delays and splits the encoder stream, delays acknowledgements and
  cancels streams), `tools/interop/h3/nghttp3-qpack.py` (libnghttp3's QPACK decoder, the one curl
  uses, checks our encoder through the new `qpack-pipe` example: over the wire, curl, quic-go and
  fib advertise no decoder table), end-to-end tests for streamed responses.
- `quic-bench h3` (gpu51, two same-run A/Bs of 7 alternating rounds against main b22519ae): default configuration (encoder off) at parity, 0.997x and 1.001x in two runs (0.999x over all 14 rounds, 863.9k vs 864.8k req/s; the client's request path only gained a check for streamed responses); with both encoders on, 0.991x of the previous encoder with both on (722.1k vs 728.9k), which is 0.833x of the default (the previous encoder: 0.839x), hence the encoder stays off by default.

### Added: asynchronous 0-RTT anti-replay store, rotating session ticket keys, BoGo (only-tls, only-core, only-quic)

ADR-062 (docs/adr/062-tls-async-anti-replay-ticket-rotation-bogo.md), additive (default
configurations behave as before):

- `AsyncAntiReplayStore` / `ReplayCheck` with `ServerConfigBuilder::async_anti_replay_store`:
  a remote store (Redis and the like) answered without blocking the I/O thread. A 0-RTT
  ClientHello that needs the check suspends its handshake (bytes arriving meanwhile wait,
  bounded) and resumes on its I/O thread when the store calls `ReplayCheck::complete` from any
  thread; `ServerConfigBuilder::anti_replay_timeout` (1 s) rejects the early data when no
  answer comes (fail closed, the handshake goes on as a 1-RTT resumption). Over TCP and QUIC.
- only-core: `Transport::set_waker` (provided method) and `TransportWaker`, which lets a
  transport waiting on something other than the peer have its I/O thread poll it again.
- `TicketKeys` with `ServerConfigBuilder::session_ticket_keys`: rotating session ticket keys,
  one sealing and up to three earlier ones (`MAX_TICKET_KEYS`) still opening their tickets;
  rotated by the application (`rotate`, `set`), per period from a secret the servers share
  (`TicketKeys::derived`: servers sharing tickets rotate in step), or per period at random
  (`TicketKeys::random`). Scheduled keys cap the advertised ticket lifetime at one period.
- `status_request_v2` (RFC 6961): never sent, ignored when received (decision and reasons in
  the ADR). OCSP validation was already done (ADR-038, ADR-049); DEV-PLAN corrected.
- BoGo: a shim (`crates/only-tls/examples/bogo-shim.rs`) and `tools/interop/tls/bogo.sh` run BoringSSL's test runner at a pinned commit with `tools/interop/tls/bogo_config.json` (disabled areas and known failures, each with a reason): 882 of 8,110 tests pass, none fail unexpectedly, 1,122 unimplemented, 6,106 disabled.

### Fixed (only-media)

- RTMP pull: once `RtmpClient::is_closed` is true (or `close` / dropping the handle returns), the hub path is free again; before, a connected pull released it only when its connection finished closing, so pulling the same path right away could fail with `HubError::StreamBusy`. The session now shares the publisher through an `Arc`; a same-run A/B on gpu51 (`quiet.sh`, one pinned core, a pull session fed 282,001 messages of the sample FLV) measured 47.17 ms against 47.24 ms before (0.999×).

### Fixed (only-tls)

- Found by BoGo: a server without TLS 1.3 no longer refuses TLS_FALLBACK_SCSV (RFC 7507); a ClientHello with supported_groups and no key_share gets `missing_extension` instead of a HelloRetryRequest (RFC 8446 §9.2); the TLS 1.2 server acknowledges server_name (RFC 6066 §3); TLS 1.3 padded plaintexts over 2^14 + 1 bytes are `record_overflow` (RFC 8446 §5.4); the TLS 1.2 client refuses a non-empty server_name acknowledgement, and an unsolicited TLS 1.3 one is `unsupported_extension`; a peer leaf whose keyUsage lacks digitalSignature is `bad_certificate` (RFC 8446 §4.4.2.2); CertificateEntry extensions not asked for are `unsupported_extension` (RFC 8446 §4.4.2); a malformed TLS 1.3 pre_shared_key no longer fails a TLS 1.2 handshake; no tickets for a client without psk_dhe_ke (RFC 8446 §4.2.9); several update_requested KeyUpdates before our next application data get one answer (RFC 8446 §4.6.3).

### Added: cross-process BPF steering, listener migration on prefork reloads, and AF_XDP (only-ebpf, only-prefork, only-dpdk)

ADR-063 (docs/adr/063-shared-steering-migration-af-xdp.md), additive (nothing changes unless
asked for):

- `only_ebpf::SharedSteering`: one `SK_REUSEPORT` program, socket array and Maglev table pinned
  in bpffs and shared by the `SO_REUSEPORT` sockets of several processes. `create` (owner,
  removes the pins on drop), `open`, `at(first, count)` and `join(fds)`, the latter filling this
  process's slots. CPU or hash steering, with the same hash and table as `attach_reuseport`. On
  Linux 5.14+ the program is loaded for `BPF_SK_REUSEPORT_SELECT_OR_MIGRATE` (`migrates()`): a
  closing listener's accept queue and pending handshakes move to the socket now in their slot,
  whatever `net.ipv4.tcp_migrate_req` says. `SteerInfo::{shared, migrate}`,
  `Probe::{reuseport_migrate, af_xdp}`, `EbpfConfig::shared` (facade).
- `Prefork::bpf_steering(BpfSteering { steering, threads, dir, strict })` (`ListenMode::ReusePort`,
  Linux): the supervisor pins one group per address (`workers * threads` slots), and each
  worker's `listener(i)` joins its own slots. A restarted or reloaded worker takes its slots
  over, so a reload hands the old worker's share to the new one as soon as it is built, and what
  was still queued migrates when the old listeners close. Without privileges or bpffs the
  workers use the kernel's hashing as before (`strict` fails instead). A `ReusePort` reload
  that cannot migrate logs a warning. `Supervisor::bpf_steering`, `DEFAULT_BPF_DIR`.
- `only_dpdk::Device::AfXdp(AfXdpConfig)`: AF_XDP sockets as a link of the userspace stack,
  next to TAP and AF_PACKET, without DPDK. One socket and one I/O thread per queue, a UMEM per
  socket, the four rings polled by the thread, and a hand-assembled XDP program that redirects
  each queue to its socket. Zero-copy where the driver has it, copy mode otherwise
  (`ZeroCopy`); native, else generic XDP (`XdpMode`, re-exported). The default MAC is the
  interface's own.
- Tests on veth pairs and namespaces only: shared slots, accept-queue and request migration,
  multi-process steering, reloads and a stopped-then-killed worker under connection churn
  (nothing lost, accept counts add up), and the AF_XDP kernel-peer suite (native, generic,
  IPv6, two queues). Fallbacks are tested without capabilities. `tools/bench/afxdp.sh` and the
  `link-bench` example compare AF_XDP with AF_PACKET (docs/BENCHMARKS).

### Added: WebSocket over HTTP/2 (RFC 8441, only-http)

ADR-060 (docs/adr/060-h2-websocket.md), additive:

- Server: the HTTP/2 server advertises `SETTINGS_ENABLE_CONNECT_PROTOCOL` and accepts extended
  CONNECT (`:protocol`, with `:scheme`, `:path` and `:authority`; malformed ones are reset with
  `PROTOCOL_ERROR`). `Context::upgrade_websocket` accepts `:protocol websocket` on HTTP/2 as it
  does on HTTP/3 (version 13, origin policy, subprotocol, `permessage-deflate`, answered `200`),
  and a `Router` GET route answers it, so one `.get("/ws", ...)` serves WebSocket over HTTP/1.1,
  HTTP/2 and HTTP/3. `H2Config::enable_connect_protocol` (default on) turns it off.
- Client: `H2Client::websocket(url, &H2WsOptions, handler, done)` and `websocket_blocking` open
  a WebSocket on a stream of the client's connection, next to its requests; they wait for the
  server's SETTINGS. New `H2WsOptions` (config, deflate offer, subprotocols, origin, headers,
  close timeout, `timeout` 10 s, `max_queued_bytes` 8 MiB) and `ClientError::Status(u16)` for a
  refusal.
- Each WebSocket is paced by its stream's and the connection's flow control; sends fail with
  `Overloaded` past `max_pending_bytes` (server, per stream; `max_conn_pending_bytes` per
  connection) or `max_queued_bytes` (client). Close frames end our half of the stream, the
  peer's END_STREAM ends its half; `RST_STREAM` and a lost connection are a close without
  handshake (1006); graceful shutdown closes WebSockets with 1001. A peer that does not end its
  half within 5 s of ours, or does not answer a client's close within its close timeout, is
  reset (`CANCEL`).
- Interop with Go's HTTP/2 both ways over h2c and TLS (`tools/interop/h2ws/run.sh`: net/http
  server, golang.org/x/net/http2 client), and with headless Chrome, which opens the WebSocket on
  the HTTP/2 connection of the page it loaded. New fuzz target `h2_websocket`; `h2_server` seeds with
  extended CONNECT.
- Performance: requests without `:protocol` take the same branches as before. Same-run A/B on
  gpu51 against `b22519ae` (7 interleaved rounds under `quiet.sh`, epoll): h2c 64 × 16 per-round
  ratio median 0.991, h2c 16 × 128 1.004, both inside the rounds' spread (±10–36%); see
  docs/BENCHMARKS.md. Fuzzing on gpu51: `h2_server` 4.8 M and `h2_websocket` 2.3 M runs
  (10 min each), no crashes.

### Added: OTLP over gRPC and TLS, OTLP logs, span events and links, exemplars, export retry (only-export, only-log, only-core, only-http)

ADR-064 (docs/adr/064-otlp-grpc-tls-logs-events-exemplars.md), additive API:

- only-export: `ExporterBuilder::otlp_grpc` / `otlp_grpc_with(endpoint, metadata)` export over
  OTLP/gRPC with only-grpc's client (a private engine with one client I/O thread, started at
  the first push). `https://` endpoints, for gRPC and HTTP, go over only-tls: the system's roots
  or `tls_roots(RootCerts)`, `tls_client_cert(chain, key)` for mutual TLS, `tls_server_name`.
- only-export: `logs(level)` installs an only-log logger whose records go out as OTLP
  `LogRecord`s (`/v1/logs` or `LogsService/Export`): body, severity, key-values,
  `code.file.path` / `code.line.number`, and the trace and span ids of the span current where
  they were logged. `forward_logs(logger, level)` keeps another logger fed; `log_queue(max,
  batch)` bounds the queue (default 4096 / 512); records from the exporter's own threads are
  not exported.
- only-log: span events and links: `SpanEvent`, `SpanLink`, `Span::add_event` / `push_event` /
  `add_link`, `SpanBuilder::link`, at most `MAX_EVENTS` / `MAX_LINKS` (128) per span with
  `SpanData::dropped_events` / `dropped_links`; exported over OTLP.
- only-core: exemplars: `Exemplar`, `ExemplarReservoir`, `ExemplarHistogram`,
  `Registry::histogram_with_exemplars`, `HistogramSnapshot::exemplars` / `with_exemplars`.
  only-http: `HttpMetrics::with_exemplars()` keeps the request span's ids on the latency
  histogram. Exported over OTLP (not in the Prometheus text format).
- only-export: `ExportStats` gains `otlp_logs_ok` / `otlp_logs_failed`, `otlp_retried`,
  `metric_points_rejected`, `spans_rejected`, `logs_exported` / `logs_dropped` /
  `logs_rejected` / `logs_queued`; the stats collector the matching `only_export_*` series.

### Changed: only-export retries failed pushes

- A retryable failure (no connection, timeout, HTTP 429 / 502 / 503 / 504, gRPC `UNAVAILABLE`
  and the other retryable codes) backs the collector off (`retry(initial, max, max_elapsed)`,
  default 1 s to 30 s with jitter, or `Retry-After`) and keeps each signal's failed batch until
  it is `max_elapsed` old (default 5 min), instead of dropping it; metrics are pushed from a
  fresh snapshot when the backoff ends. `retry(.., .., Duration::ZERO)` drops failed batches as
  before. Other failures still drop the batch. Partial successes are counted.
- `flush()` stops at the first retryable failure (what is left stays queued); `spans_queued`
  includes the batch waiting to be retried.
- `https://` endpoints are accepted (they were an error).

### Added: RTCP on its own ICE component, XR receipt blocks and ULPFEC levels in WebRTC peers (only-webrtc)

ADR-058 (docs/adr/058-webrtc-rtcp-components-xr-ulpfec-levels.md), additive (a default peer's
SDP and behaviour are unchanged):

- Streams without rtcp-mux (RFC 5761, ICE components from ADR-055): `Endpoint::bind_rtcp`
  binds a second socket whose host candidate is ICE component 2 (`Endpoint::rtcp_addr`). Offers
  without `a=rtcp-mux` (SIP endpoints, older RTP stacks) are then answered with `a=rtcp` and RTCP
  on component 2; offers with it (browsers, pion) as before. `RtcConfig::set_rtcp_mux_policy`
  (`RtcpMuxPolicy::Require` default, `Negotiate`, `Off`) decides what our offers say. DTLS-SRTP
  runs a handshake per component (RFC 5764 §4.1: SRTCP keyed by component 2's), SDES-SRTP keys
  both from the SDP; connected once both components are. Such a session has one media section
  and no data channels (no BUNDLE without rtcp-mux); component 2 has host and peer-reflexive
  candidates only; `RtcServer` has none.
- `RtcConfig::enable_rtcp_xr_blocks(XrBlocks)`: RTCP XR loss RLE, duplicate RLE, packet
  receipt times and VoIP metrics (RFC 3611, `a=rtcp-xr:pkt-loss-rle pkt-dup-rle pkt-rcpt-times
  voip-metrics`, sent when both sides list them; VoIP metrics on audio only) about received
  streams, once a second from a receipt log, thinned to fit a datagram; received ones become
  `XrReceipts` / `VoipMetrics` events and totals in the statistics.
- `RtcConfig::set_ulpfec_level0(Some(l0))`: ULPFEC with protection levels (RFC 5109 §5) on sent
  video, for receivers that read levels (this stack; Chrome reads level 0 only). Off by
  default.
- The CNAME is RFC 7022's random one (`only_rtp::random_cname`), new per peer connection;
  received SDES items are reported typed (`SourceDescription` event); `PeerStats` says whether
  RTCP is muxed.
- Fuzzing: `webrtc_sdp` also runs a configuration with component-2 candidates, every XR block
  and ULPFEC levels; two seeds without rtcp-mux. Interop: pion has neither a non-mux policy
  nor ICE components, so the check without rtcp-mux is between `Endpoint`s; the browser and
  pion scripts see unchanged SDP.

### Added: several components per ICE stream (only-ice)

ADR-055 (docs/adr/055-ice-components.md), additive (one-component agents behave as before):

- `IceConfig::components` (default 1): an agent, full or lite, handles a stream of several
  components (RFC 8445), e.g. RTP (component 1) and RTCP (component 2) on their own ports without
  rtcp-mux. `Candidate::with_component(n)` makes a local candidate of component `n` (its priority
  changes, its foundation stays); remote candidates carry their component as before.
- One checklist for every component with the RFC 8445 §6.1.2.6 initial states (of each foundation
  the pair of the lowest component is Waiting, the others Frozen, also when candidates trickle in
  another order) and unfreezing across components; nomination (regular, aggressive,
  renomination), selection, consent freshness and the lite agent's state per component; ICE
  restarts cover every component, each keeping its selected pair until the new generation
  nominates one. The state is `Connected` / `Completed` only once every component has a selected
  pair, `Disconnected` when consent expires on any, `Failed` when a component can no longer get
  one.
- `IceEvent::ComponentSelectedPair { component, local, remote }`,
  `IceAgent::{components, selected_pair_of, send_pair_of}`; `SelectedPair`, `selected_pair()`
  and `send_pair()` stay component 1's.
- Interop: `tests/libnice.rs` and `tools/interop/ice/run.sh` check two components against
  libnice 0.1.21 in five setups (libnice controlling with aggressive and with regular nomination,
  controlled, lite; only-ice lite). The `ice_stun` fuzz target also drives two-component agents.
  only-webrtc still muxes RTP and RTCP on component 1; streams without rtcp-mux there are a
  follow-up.

### Added: ULPFEC protection levels, XR blocks from received packets, typed SDES items (only-rtp)

ADR-053 (docs/adr/053-ulpfec-levels-xr-receipts-sdes-items.md):

- **ULPFEC levels** (RFC 5109 §7.4, any number): `FecHeader::ulp_levels` / `write_level`;
  `FecEncoder::encode_ulp` builds packets from explicit levels and enforces the §7.4 rules;
  `FecEncoder::set_ulp_level0(Some(l0))` protects the first `l0` bytes of every packet with the
  interleaved FEC packets and the rest of the group once (a single loss per group still comes
  back whole, for about `m * l0 + longest - l0` repair bytes instead of `m * longest`). The
  decoder rebuilds packets range by range in any order and returns them once complete
  (`FecDecoder::partially_recovered` counts the rest). The RFC 5109 §10.2 example matches byte
  for byte (M recovery bit per erratum 3461).
- **XR blocks from received packets** (RFC 3611 §4.1-4.3): `ReceiptLog` builds loss RLE,
  duplicate RLE and packet receipt times blocks (with thinning; receipt times in the RTP
  clock), `RecvStream::{enable_receipt_log, receipt_blocks}` feed one from the stream;
  `RleReport::{encode, decode, reported_seqs}` reproduce the §4.1 examples. Bytes match
  pion/rtcp v1.2.20 (whose writer drops the null chunk of odd chunk counts; ours adds it).
- **VoIP metrics** (§4.7): `BurstLossModel::report` with `VoipQuality` (round trip and end
  system delay, signal / noise level, RERL, R factors and MOS when the application has them,
  sent as 127 otherwise or when out of range, PLC, jitter buffer); `pcm_level_dbm0`.
- **SDES items**: `SdesItem` (text items with constants for every registered type, CNAME ..
  MID; PRIV with prefix and value) converts the pairs of `Rtcp::SourceDescription`;
  `random_cname` (RFC 7022). PRIV prefix lengths above 127 now survive parsing (they became
  U+FFFD); texts and BYE reasons are cut to 255 bytes at a character boundary. Bytes match
  pion/rtcp v1.2.20.
- API additive except `FecHeader`'s new public field `ulp_levels` (only-rtp is internal tier).
  The `rtp_rtcp` and `rtp_fec` fuzz targets cover all of it (gpu51, 16 min each: `rtp_rtcp` 2.90 M runs, `rtp_fec` 1.59 M runs, no finding in the code; an earlier `rtp_rtcp` run caught a too-strict check in the target itself (RLE chunks ending before the block's interval), kept as a regression input).
- Not done: wiring into only-webrtc (XR receipt / VoIP blocks, ULPFEC levels, random CNAMEs);
  partially recovered packets are not handed out; no R factor / MOS estimation.

### Added: TURN over DTLS, mDNS over IPv6 and SDES-SRTP (only-turn, only-webrtc, only)

ADR-054 (docs/adr/054-turn-dtls-mdns-ipv6-sdes.md):

- `TurnServer::dtls(&tls::ServerConfig)`: TURN over DTLS (RFC 7350) on a UDP listener, with
  the TLS listener's certificate: stateless cookies, DTLS 1.3 with a DTLS 1.2 fallback, one
  STUN / ChannelData message per record, an allocation per DTLS association (freed by
  close_notify, a fatal alert, idle timeout or a new handshake from the same address);
  `TurnServer::dtls_relay_of`. only-turn now depends on only-dtls.
- `RelayServer::dtls` and `turns:host[:port]?transport=udp` URLs (no longer an error):
  `Endpoint` allocations inside a DTLS association on the endpoint's own UDP socket, the
  server's certificate verified against the TLS client configuration's roots; a UDP relayed
  candidate plus the server-reflexive one; made again after a lost association.
- mDNS over IPv6: `Endpoint::resolve_mdns` adds a `[::]:5353` socket joined to `ff02::fb` on
  every interface with a link-local address, queries per interface, answers on the query's link;
  remote link-local addresses keep their interface (SDP carries no scope id). IPv4 behaviour is
  unchanged; hosts without IPv6 run IPv4 only.
- `only`: `Engine::bind_udp_multicast_on(group, interfaces, acceptor)` joins an IPv6 multicast
  group on each listed interface index (0: the default one; interfaces refusing the join are
  skipped). IPv4 groups take only `&[0]` (`InvalidInput` otherwise). `bind_udp_multicast` is
  `bind_udp_multicast_on(group, &[0], ..)`, unchanged.
- `RtcConfig::enable_sdes_srtp` (off by default): SDES-SRTP (RFC 4568) for SIP gateways: offers
  `RTP/SAVPF` with an `a=crypto` line per suite (AEAD-AES-256/128-GCM, AES-256/128-CM-HMAC-SHA1-80,
  AES-128-CM-HMAC-SHA1-32) and answers SDES offers; SRTP keyed from the SDP, no DTLS, no data
  channels; no MKIs or session parameters. DTLS-SRTP offers are still answered with DTLS-SRTP:
  browsers never see `a=crypto`.
- Fuzzing: new target `turn_dtls`; `webrtc_sdp` tries an SDES configuration.
- Interop: `tools/interop/webrtc/turn-dtls.sh` (coturn 4.6 in Docker): `turnutils_uclient -S`
  against only-turn's DTLS listener, the only_turn client and two relayed `Endpoint`s against
  coturn's DTLS listener (DTLS 1.2 negotiated).

### Added: AES-f8 and SEED in SRTP (only-srtp), SEED in only-crypto

ADR-052 (docs/adr/052-srtp-f8-seed.md), additive:

- **only-crypto**: `seed` with `Seed` (RFC 4269: blocks both ways, CTR), `SeedGcm` (SP 800-38D,
  full or truncated tags) and `SeedCcm` (RFC 3610). Constant time without tables: the S-boxes are
  the fixsliced AES's Boyar-Peralta inversion circuit behind a field isomorphism plus affine maps
  (checked against the RFC 4269 tables for every input), G bitsliced over sixteen words (sixteen
  blocks in flight for ECB / CTR / GCM), a one-word path for single blocks and CCM's CBC-MAC; no
  hardware path. ct-dudect targets `seed-key` and `seed-block`.
- **only-srtp**: `Profile::{AesF8HmacSha1_80, AesF8HmacSha1_32}` (AES-f8, RFC 3711 §4.1.2; SDES
  `F8_128_HMAC_SHA1_80/32`) and `Profile::{SeedCtrHmacSha1_80, SeedCcm80, SeedGcm96}` (RFC 5669,
  SEED-CTR PRF; `SEED_CTR_128_HMAC_SHA1_80`, `SEED_128_CCM_80`, `SEED_128_GCM_96`), with MKIs,
  key derivation rates, RFC 6904 header extension encryption and cryptex like the other profiles.
  `Profile::ALL` lists fifteen; `is_aead` is true for SEED-CCM / SEED-GCM; new
  `Profile::session_salt_len` (12 for AEAD; the SEED AEAD master salt stays 14 bytes). No
  DTLS-SRTP ids, so `only-webrtc` does not negotiate them (SDES is not implemented there).
- Verified with RFC 3711 B.1, RFC 4269 B, RFC 5669 A.1-A.3 (A.1's tag is HMAC over the
  plaintext without the ROC, so only its keystream is used), RFC 3610 (the CCM construction, with
  AES), OpenSSL `seed-ecb`, and an independent Python implementation (`testdata/f8_seed.py` on
  pyca/cryptography): the libsrtp cross-check's 25 cases / 115 packets under the five profiles,
  byte for byte both ways.
- Benchmarks (gpu51, `quiet.sh`, CPU 2, 1200-byte payloads, protect): AES-f8 2.26 µs (AES-128-CM
  1.18 µs), SEED-CTR 18.3 µs (66 MB/s), SEED-GCM 20.4 µs, SEED-CCM 98 µs (12 MB/s); 160 bytes:
  354 ns, 3.6, 3.9 and 16.1 µs. The existing profiles against main aca9e988 (three alternating
  rounds): AES-CM and 160-byte AES-GCM within ±1.6 %, 1200-byte AES-GCM at parity measured alone
  (+1.5-2.2 % protect inside the full case sequence); two regressions the A/B found on the way
  (+3 % and +2.4 % for AES-GCM) were removed (ADR-052).

### Changed: faster brotli decoding (only-brotli)

No public API change, output unchanged (docs/BENCHMARKS.md, "Brotli and Zstandard"). Decoding
takes 1.08–1.34× libbrotli 1.2.1's time on the HTTP payloads of `tools/codec-bench brotli` (was
1.42–1.73×) and 1.04–1.32× on Silesia (was 1.13–1.56×).

- The command loop keeps its state (bit reader, output, position, last distances) in locals and
  checks the meta-block end, the output limit and the window's spare room with one comparison per
  write; distance contexts and short distance codes come from tables, roots have a fixed size.
- Prefix code tables are built from the code lengths as they are read, without passes over symbols
  that have no code, and the code length code gets a 32-entry table: table building was 40% of
  decoding a 2.7 KB certificate chain.
- Copies of up to 32 bytes with a period under 16 go in 8-byte chunks.
- The output is zeroed ahead only up to the end of the meta-block, so a small output decoded under
  a large limit no longer zeroes 128 KiB first (2.7 KB chain with a 16 MiB limit: 266 → 370 MB/s).
- `tools/codec-bench`: `BENCH_BR_LIMIT=N` decodes with an output limit of `N` instead of the exact
  size.

### Added: DTLS 1.3 by default, cryptex, encrypted header extensions, Opus RED and FEC on simulcast lines in WebRTC peers (only-webrtc)

ADR-048 (docs/adr/048-webrtc-dtls13-cryptex-opus-red-simulcast-fec.md):

- **Changed**: peers offer DTLS 1.3 (RFC 9147) with a DTLS 1.2 fallback by default
  (`RtcConfig::enable_dtls13`, `false` for DTLS 1.2 only). Nothing changes in SDP. Chrome 157
  negotiates DTLS 1.3 in either DTLS role; pion and other DTLS 1.2 peers are answered with
  DTLS 1.2 (checked in both roles).
- `RtcConfig::enable_cryptex`: `a=cryptex` (RFC 9335) offered and accepted; once both sides
  signal it, header extensions and CSRCs of sent RTP are encrypted. Checked both ways against
  Chrome 157's `rtpHeaderEncryptionPolicy: "require"` (behind
  `--enable-experimental-web-platform-features`).
- `RtcConfig::enable_encrypted_header_extensions`: RFC 6904 encrypted extension variants
  (`urn:ietf:params:rtp-hdrext:encrypt`) offered for audio level, MID, RID, repaired RID, video
  orientation and playout delay on free one-byte ids, and taken in answers. No browser offers
  them. SRTP MKIs stay out of WebRTC: DTLS-SRTP has no SDP for them and browsers do not use them.
- `RtcConfig::enable_opus_red(Option<u8>)`: Opus RED (`red/48000/2`, payload type 63) listed
  before Opus, which is what makes libwebrtc send it; received redundancy stands in for lost
  packets (duplicates dropped), sent Opus carries up to two earlier packets. Under 10 % loss each
  way Chrome 157 conceals 2-3 % of its audio instead of 20 %.
- ULPFEC on simulcast lines (`FecMechanism::Ulpfec`): each encoding has its own FEC encoder,
  loss estimate and rate, RED and ULPFEC on the encoding's SSRC with its RID, as Chrome sends
  it; received simulcast is repaired per layer (up to 8 FEC decoders per peer). FlexFEC is not
  used on simulcast lines (RID-based simulcast signals no FEC stream).
- Statistics events report the DTLS version, packets received with cryptex and packets
  recovered from RED.
- Interop: `tools/interop/webrtc/browser.sh` (DTLS 1.3 both roles, cryptex both ways, our
  simulcast line with per-encoding ULPFEC through 5 % loss without NACK: Chrome decodes all of it,
  next to nothing without FEC), `fec.sh` (Opus RED under loss, Chrome's per-layer ULPFEC),
  `run.sh` (pion falls back to DTLS 1.2), Firefox 158 with DTLS 1.3 (both DTLS roles). The
  `webrtc-interop` example takes `ONLY_INTEROP_*` switches and a lossy proxy for the SFU.
- Benchmark (gpu51 same-run A/B against main 436b47e7, `quiet.sh`, CPUs 2-9, in-process peers with DTLS 1.2 on both sides, medians of the six quiet pairs: peer connections per second 0.990x, VP8 media 4000-byte frames 0.995x (752 vs 756 MB/s), 120-byte frames 0.993x: no regression. With the new default DTLS 1.3 a handshake costs about 5 % more CPU than DTLS 1.2; media throughput is the same, and with cryptex too).

### Added: P-521, RSA-PSS keys and the client's OCSP response in TLS 1.3 (only-crypto, only-x509, only-tls)

ADR-049 (docs/adr/049-p521-rsa-pss-keys-client-ocsp.md), additive:

- **only-crypto**: `p521` (ECDH and ECDSA on NIST P-521 with the API of `p256` / `p384`, 66-byte
  scalars, SHA-512 by default, RFC 6979 nonces; portable constant-time code on its own
  `2⁵²¹ - 1` field and complete formulas; ct-dudect targets `p521-ecdh`, `p521-keygen`,
  `p521-sign`); `pkey::PublicKey::{P521, RsaPss}`, `pkey::PrivateKey::{P521, RsaPss}` and
  `pkey::PssParams` for `id-RSASSA-PSS` keys (RFC 4055) with or without parameters, which sign
  and verify RSA-PSS only, within their parameters; `der::oid::SECP521R1`. Wycheproof P-521
  ECDSA / ECDH and RFC 6979 A.2.7 vectors, OpenSSL-made PSS keys.
- **only-x509**: P-521 and RSA-PSS-key certificates parse, verify and are issued (OpenSSL-made
  chains in `tests/data/pss-p521`).
- **only-tls**: group secp521r1 (offered last), `ecdsa_secp521r1_sha512` and
  `rsa_pss_pss_sha256/384/512` (server and client certificates, TLS 1.3 and 1.2);
  `ServerConfigBuilder::client_ocsp_policy` asks TLS 1.3 clients for an OCSP response with
  their certificate and validates it (ADR-038 policies; TLS 1.2 client certificates are refused
  under hard fail), `ClientConfigBuilder::client_cert_ocsp_response` sends one when asked, and
  the server's `TlsInfo::ocsp_response` holds it. Interop with OpenSSL and Go
  (`tools/interop/tls/run.sh`). `status_request_v2` stays unimplemented (TLS 1.2 only, obsolete).
- Default ClientHellos list secp521r1 (2 more bytes); nothing else changes in default handshakes.

### Added: bandwidth probing in the estimator (only-rtp, only-webrtc)

ADR-050 (docs/adr/050-bwe-probing.md). `only_rtp::BandwidthEstimator` probes the path like
libwebrtc, so video ramps up in a fraction of a second instead of tens of seconds:

- **only-rtp**: probe clusters (15 ms / 5 packets or more, paced at a target rate) at 3 and 6
  times the start rate, doubling while results keep up; every 5 s while application-limited
  (`application_limited()`); after a large drop of the estimate; from scratch after
  `on_network_change(now)`. `poll_probe(now)` / `probe_timeout()` / `on_probe_sent` /
  `cancel_probes` drive the sending, `TwccSender::on_sent_probe` and `CcfbSender::on_sent_probe` tag the packets,
  `PacketResult::probe` carries the cluster back, and the measured delivery rate lifts the
  delay- and loss-based rates. `SendStream::padding` builds probe packets (RTX copies of recent
  media, or padding). On by default; `with_probing(false)` keeps the previous behaviour.
  **Breaking** (internal tier): `PacketResult` has a new public field `probe`.
- **only-webrtc**: with `enable_bwe`, the probes go out as RTX copies of the most active stream's
  recent packets, paced through `poll_output`'s timeout; a new ICE selected pair restarts the
  estimate. Public API unchanged.
- Simulated links, start 300 kbps: 90 % of 0.5 / 2 / 10 Mbps after 0.15 / 0.25 / 0.35 s (was
  5.4 / 23 / 44 s), peaks at most 1.12x the capacity. With Chrome 157 as receiver
  (`tools/interop/webrtc/bwe.sh`, new): 10 Mbps 0.2 s after the connection (the estimate used to
  stay at its 1 Mbps start).

### Changed: faster Zstandard decoding, second pass (only-zstd)

No public API change (docs/BENCHMARKS.md, "zstd decoding, second pass", "zstd literals" and "zstd
double-symbol Huffman tables"; quiet gpu51, against libzstd 1.5.7 in `tools/codec-bench zstd`):

- Decompression takes 1.16–1.39× libzstd's time on the HTTP payloads (was 1.46–1.64×): JavaScript
  1.38–1.39× (was 1.59–1.61×), certificate chains 1.16–1.27× (was 1.49–1.64×), JSON 1.37–1.38×,
  HTML 1.31–1.33×; Silesia 1.22–1.24× at levels 1 and 3 and 1.39× at 19 (was 1.32–1.33× and
  1.57×). The decoder keeps its tables and literals buffer per thread between calls, as libzstd's
  reused context does (about 20 KB, plus up to 32 KiB of literals), decodes sequences in batches
  of 64 before executing them (one bit read per sequence when the extra bits allow), and decodes
  the four Huffman streams with libzstd's fast loop. Still `#![forbid(unsafe_code)]`, no BMI2
  paths. Fuzzed 16 min per target (`zstd_decompress`, `zstd_roundtrip`).
- Large Huffman-coded literal sections (by libzstd's `HUF_selectDecoder` rule) are decoded with a
  double-symbol table, one or two symbols per lookup: literal decoding 13–21% faster on Zen 4
  and 35–37% on Apple M-series (JavaScript literals, 16–60 KB); end to end JSON, JavaScript and
  HTML 1.6–3% faster, Silesia −0.8…+1.4%. The per-thread decoder keeps the table (16 KB more).
- Compressed output changes: the encoder keeps literals raw unless Huffman coding saves more than
  2 bytes plus 1/64 of them, and below 64 literals, as libzstd does (`ZSTD_minGain`). Our own
  certificate-chain frames decode 2.3–3.2× faster (they decoded at under half the speed of
  libzstd's frames) and are 4–17 bytes larger; JSON, HTML and JavaScript are byte-identical,
  Silesia 0.004% larger.
- `tools/codec-bench`: `BENCH_OWN=0` skips decoding each library's own output, `BENCH_DUMP=DIR`
  writes the zstd frames that are timed.

### Changed: faster brotli and Zstandard decoding and encoding (only-brotli, only-zstd)

No public API change (docs/BENCHMARKS.md, "Brotli and Zstandard"; against libbrotli 1.2.1 and
libzstd 1.5.7 in `tools/codec-bench`, which now has `brotli` / `zstd` modes and a corpus script).

- **Decoders** (output unchanged): decompression takes 1.3–1.7× libzstd's time (was 1.7–2.4×) and
  1.1–1.7× libbrotli's (was 1.4–3.1×); on Silesia zstd level 1 decodes 849 MB/s (was 541,
  libzstd 1,120) and brotli level 5 467 MB/s (was 333, libbrotli 716). The output doubles as a window zeroed ahead (never past the limit) so literals and
  matches are copied in 16-byte chunks; branch-free bit reads kept in registers; zstd's four
  Huffman streams decoded in lockstep and predefined sequence tables no longer copied per block;
  brotli decodes three literals per refill through a per-block-type context → tree table. Bounds
  are unchanged: memory stays within the limit, truncated brotli input is caught once per command
  instead of once per literal (still bounded by the output).
- **zstd encoder** (output changes): levels 1–2 use libzstd's `fast` match finder and 3–4
  `double_fast` instead of lazy hash chains, plus a faster Huffman code construction and bit
  writer: 2.1–3.2× faster; sizes within −3…+2% of libzstd's (level 3 is 1–7% larger than before on
  small HTTP payloads, where the old lazy search beat libzstd's level 3).
- **brotli encoder** (output changes): per-hash buckets instead of chains at levels 0–6 (5-byte
  hashes at 5–6), Google's candidate counts at levels 2–4 (level 4: 4 instead of 16), Google's
  skipping through incompressible data, cheaper context clustering below level 10: Silesia 3.4×
  (q4), 2.4× (q5), 2.6× (q6) faster; q5–q6 sizes −1.2…+0.8% (+2–3% on certificate chains, which
  use level 11 in only-tls), q4 1–9% larger but no longer smaller than libbrotli's q4 at four
  times its search effort. Brotli levels 10–11 and zstd levels 5–22 keep their speed and, but for
  small differences from the context clustering and Huffman code construction, their output.

### Changed: route constraints run on `only-regex` (only-http, only-regex)

ADR-051 (docs/adr/051-router-on-only-regex.md). The router's regexp parameters
(`/users/{id:[0-9]+}`, also inside partial segments) are now matched by `only-regex`, the engine
behind only-log's message filters; the router's own engine (`only_http::re`, `#[doc(hidden)]`,
not a public API) is gone from normal builds.

- **Same matches.** Constraints still match the whole segment, and `\d \w \s` stay ASCII. Every
  pattern the old engine accepted matches exactly the same segments: a differential test (every
  regexp route in the repository, the old engine's test patterns, 3 000 generated patterns with
  about 30 subjects each, 20 000 random syntax soups) and the `regex_match` fuzz target compare
  the two, with the old engine kept, frozen, as a test-only reference.
- **More syntax**: flags `(?i)` (Unicode case folding), `(?m)`, `(?s)`, `(?U)`, negated and
  scoped; `\A \z`; `\b \B` (ASCII word boundaries); Unicode and dotted group names; programs of
  up to 20 000 instructions. **One narrowing**: two groups with the same name in one constraint
  now panic at registration, as the `regex` crate refuses them (names were never captured).
- **Faster**: about a third less time per constraint check (`[0-9]+` on 7 digits 8.5 → 5.7 ns,
  `\d{4}-\d{2}-\d{2}` 11.9 → 7.6 ns); router-bench's varied-regexp table 46.0 → 42.0 ns per
  lookup, the `[0-9]+` table unchanged at 28.1 ns. Compiling a constraint builds a DFA: 7–13 µs
  at registration instead of 2.1 µs.
- **only-regex** (internal tier): `RegexBuilder` with `whole_text` (match the whole text, as
  `\A(?:...)\z`) and `ascii_classes` (ASCII `\d \w \s` and `\b`); `Regex` equality includes the
  options. `Regex::is_match` runs the ahead-of-time DFA in a tight loop first, a few percent faster
  for only-log's message filters too.

### Performance: AES-GCM whole messages on the VAES-AVX2 kernel; P-256 divsteps on aarch64 (only-crypto)

No API change.

- **VAES-AVX2 AES-GCM kernel** (CPUs with VAES but no AVX-512: Zen 3, Alder Lake / Raptor
  Lake): one call now does the whole message, as the AVX-512 kernel does: `E(J0)`, the AAD (up to
  256 bytes), the 256-byte groups, the tail after them and the length block. AVX2 has no byte
  masks, so the tail goes through a zero-padded stack buffer (four or eight ymm vectors, the
  keystream masked by a constant table). Before, everything but whole 256-byte groups ran on the
  128-bit kernel. Measured on Zen 4 with the AVX2 kernel forced, against the 128-bit kernel in
  the same runs: 200 B 1.00× → 1.84–1.90×, 1 KiB 1.47–1.75× → 1.81–2.12×, 1400 B 1.50–1.70× →
  1.82–2.09×, 64 B 0.91–1.01× → 1.12–1.20×; against ring 1 KiB 0.88–1.00× → 1.03–1.13×. No Zen 3
  or Alder Lake host was available to measure on.
- **aarch64 P-256**: safegcd divsteps in assembly (inversion 1.66 → 1.26 µs on an Apple M4 Pro)
  and OpenSSL's addition formulas on the twin. Sign +9% (1.15× → 1.25× ring), key generation
  +3.5%, ECDH 0.98× → 1.00× ring. First measurement of the aarch64 assembly: P-256 verify 1.04×
  ring, X25519 1.04× (docs/BENCHMARKS.md).

### Added: mDNS ICE candidates, aggressive nomination and renomination, simultaneous-open ICE-TCP (only-ice, only-webrtc, only)

ADR-044 (docs/adr/044-ice-mdns-renomination-tcp-so.md), additive (nothing changes unless used):

- **only-webrtc**: `Endpoint::resolve_mdns(&engine, timeout)` resolves the `<uuid>.local` host
  candidates browsers send (in descriptions and trickled; one-shot mDNS queries over the shared
  port 5353 and `224.0.0.251`, answers cached, never blocking an I/O thread), so an `Endpoint`
  reaches a browser host to host; `Endpoint::conceal_host_candidates()` writes our own host
  candidates as mDNS names and answers the queries for them. Tested with headless Chrome 157
  with its mDNS concealment on (each side resolves the other's name).
  `RtcConfig::enable_ice_renomination` (`a=ice-options:renomination`) and
  `RtcConfig::enable_ice_aggressive_nomination`. `Endpoint::listen_tcp_so(&engine, addr)`: a
  simultaneous-open ICE-TCP candidate (RFC 6544 `tcptype so`). `Peer::add_remote_candidate`
  accepts mDNS lines when the endpoint resolves them.
- **only-ice**: `mdns` module (RFC 6762 codec), `Candidate::{parse_resolved, with_hostname,
  hostname, with_related}`, `IceConfig::{aggressive_nomination, renomination}`,
  `IceAgent::set_remote_renomination` (NOMINATION attribute; a better pair found after
  nomination is used). A controlled agent now selects the highest NOMINATION value, or without
  one the highest-priority nominated pair, instead of the last nomination. Fuzz target
  `ice_mdns`.
- **only**: `Engine::bind_udp_multicast(group, acceptor)` (a multicast group's port shared with
  other members) and `Engine::dial_from(local, addr, acceptor, on_error)` (a connect from a
  bound, shared local port); only-sys `connect_nonblocking_from`.

### Added: DTLS 1.3 connection ID updates, post-handshake client authentication and early data (only-dtls)

ADR-045 (docs/adr/045-dtls13-cid-updates-pha-early-data.md), additive and off by default:

- **Connection ID updates** (RFC 9147 §9): `Connection::new_connection_ids(count, immediate)`
  (NewConnectionId), `request_connection_ids(n)` (RequestConnectionId, answered automatically
  by the peer), `rotate_connection_id()`, `spare_connection_ids()`, `local_connection_ids()`,
  `peer_connection_id()`; at most 8 live CIDs, our older CIDs retire once the peer sends with a
  later one, `Event::LocalConnectionIds` reports the set a listener should route.
  `AlertDescription::TooManyCidsRequested`.
- **Post-handshake client authentication** (RFC 8446 §4.6.2): `Config::with_post_handshake_auth`
  (client), `Connection::request_client_certificate` and `Event::ClientCertificate` (server).
- **Early data (0-RTT)** with tickets: `Config::with_early_data(max)`, `Config::with_anti_replay`,
  `AntiReplayStore` / `MemoryAntiReplay` (binder recording and a ticket-age freshness check),
  `Connection::send_early_data`, `Session::max_early_data`, `Event::EarlyData`,
  `HandshakeInfo::early_data`. A ClientHello whose early data is accepted skips the
  HelloRetryRequest cookie exchange.
- `Error::NotAvailable` for operations the connection did not negotiate or is not ready for.
- Post-handshake flights (NewSessionTicket, KeyUpdate and the new messages) share one queue.
- Tests `tests/dtls13_post.rs`; fuzz target `dtls_post_handshake`; interop with wolfSSL 5.8.4
  (early data and post-handshake authentication both ways; the interop image now builds wolfSSL
  with `--enable-earlydata --enable-postauth`, `DTLS_INTEROP_IMAGE` names it); example
  `dtls-hs-bench` (handshakes per second, DTLS 1.3 records). Non-ECDHE key exchanges and CBC
  suites stay out on purpose (README, ADR-045).

### Added: certificate policies, indirect CRLs, Ed448, X448 and DSA verification (only-x509, only-crypto, only-tls)

ADR-046 (docs/adr/046-x509-policies-indirect-crls-ed448-dsa.md):

- **only-x509**: certificate policy processing (RFC 5280 §6.1 on the RFC 9618 policy graph):
  `Verifier::policies(PolicyOptions)` (initial policy set, explicit policy, inhibit policy
  mapping / anyPolicy), `Verifier::verify_path` → `VerifiedPath { chain, policies:
  ValidPolicies }`, `Error::PolicyViolation`; `Certificate::{certificate_policies,
  policy_mappings, policy_constraints, inhibit_any_policy, is_self_issued}`,
  `PolicyConstraints`, `ext::{ANY_POLICY, POLICY_MAPPINGS, POLICY_CONSTRAINTS,
  INHIBIT_ANY_POLICY}`. Indirect CRLs and CRLs signed by another key of the CA (the signer's
  path is validated to the same root, with revocation): `Verifier::crl_signers`,
  `Crl::find_for`, `RevokedCertificate::certificate_issuer`,
  `DistributionPoint::relative_name`, `IssuingDistributionPoint::relative_name` (new public
  fields); CRL scopes now follow the certificate's distribution points and their reasons.
  rfc822Name and URI name constraints (and the subject's emailAddress), self-issued
  intermediates exempt from name constraints and pathLen, `Verifier::allow_ca_end_entity`,
  `attr::EMAIL_ADDRESS`; Ed448 and DSA certificates and CRLs. NIST PKITS harness
  (`tests/pkits.rs`, `tools/pkits/prepare.sh`): 242/248 runs as expected.
- **only-crypto**: `hash::{Shake128, Shake256}`, `ed448`, `x448`, `dsa` (verification only),
  `rsa::HashAlg::Sha224`, `pkey::SignatureAlgorithm::{Ed448, DsaSha1, DsaSha224, DsaSha256}`,
  `pkey::{PublicKey, PrivateKey}::Ed448`, `pkey::PublicKey::Dsa`, `der::oid::{ED448, X448, DSA,
  DSA_WITH_SHA1, DSA_WITH_SHA224, DSA_WITH_SHA256}`; `pk_bench 448`; ct-dudect targets `x448`,
  `ed448-keygen`, `ed448-sign`.
- **only-tls**: group x448 (0x001e, offered last) and signature scheme ed448 (0x0808), TLS 1.3
  and 1.2; interop cases against OpenSSL in `tools/interop/tls/run.sh`.
- Fuzz targets `x509_policy` and `crypto_ed448_dsa`; `x509_parse` and `x509_crl` cover the new
  extensions and indirect-CRL entries.

### Changed: path validation details (only-x509)

- With CRLs configured, revocation is checked once a candidate path reaches a root (top down)
  instead of while it is built. Paths whose policyConstraints require an explicit policy that
  is absent now fail (`Error::PolicyViolation`), and a certificate with a malformed policy
  extension no longer parses. CRL serial numbers compare as signed INTEGERs (a CRL entry for −1
  no longer matches serial 255), and `CrlParams` / OCSP CertIDs write serials as given.

### Added: FEC, RTCP XR, TMMBR and RFC 8888 feedback in WebRTC peers (only-webrtc, only-rtp)

ADR-039 (docs/adr/039-webrtc-fec-xr-tmmbr-ccfb.md), additive and off by default (a default peer's
SDP is unchanged):

- **only-webrtc**: `RtcConfig::enable_fec(Option<FecMechanism>)` (`FecMechanism::FlexFec`:
  `flexfec-03` with an `a=ssrc-group:FEC-FR` stream; `FecMechanism::Ulpfec`: `red` + RTX +
  `ulpfec`) on video lines without simulcast: received FEC repairs packets before the frame
  assembler and NACK, sent video is protected at three times the loss before repair within
  `RtcConfig::set_fec_protection(min, max)` (per 256 media packets, default 0..=128).
  `RtcConfig::enable_ccfb` negotiates RFC 8888 (`ack ccfb`; the answer drops transport-cc), which
  then replaces transport-wide feedback both for acknowledging and for the bandwidth estimator.
  `RtcConfig::enable_rtcp_xr` (`a=rtcp-xr:rcvr-rtt=all`, `rrtr`): receiver reference times and
  DLRR give a receiving line its RTT; received RRTRs are always answered. `RtcConfig::enable_tmmbr`
  (`ccm tmmbr`) and `Peer::request_max_bitrate(mid, Option<u64>)`; received TMMBRs are answered
  with TMMBN and cap the estimate with REMB. RTCP NTP times now follow the peer's monotonic clock.
- **only-rtp**: `RecvStream::receive_recovered` (a FEC-rebuilt packet: not NACKed, not counted as
  received) and `FrameAssembler::skip` (a sequence number without media, e.g. ULPFEC or padding,
  is not a gap).
- Interop: `tools/interop/webrtc/fec.sh` against headless Chrome 157 (FlexFEC and ULPFEC both
  ways under loss, RFC 8888 both ways, XR DLRR RTT, TMMBR); the `fec-server` mode of the
  `webrtc-interop` example puts a lossy UDP proxy in front of the server.

### Added: SRTP MKIs and re-keying, key derivation rates, AES-192/256-CM and NULL, RFC 6904 header extension encryption, cryptex (only-srtp); DTLS-SRTP MKI (only-dtls)

ADR-040 (docs/adr/040-srtp-mki-cryptex.md):

- **Profiles**: `Profile::Aes192CmHmacSha1_80/32`, `Aes256CmHmacSha1_80/32` (RFC 6188) and
  `NullHmacSha1_80/32` (RFC 5764; SRTCP sent with the E flag clear). `Profile::sdes_name` /
  `from_sdes_name`, `Profile::encrypts`.
- **MKIs and re-keying**: `Context::new_with_mki`, `add_master_key`, `set_send_mki`,
  `remove_master_key`, `send_mki`, `mki_len` (up to 16 master keys, MKIs of 1-255 bytes; the
  packet's MKI selects the key, `Error::UnknownMki` otherwise; rollover counters and replay
  windows stay per SSRC across keys).
- **Key derivation rate**: `Context::with_key_derivation_rate` (0 or a power of two up to 2^24,
  RFC 3711 §4.3.1), session keys cached per master key and stream for the last `r`.
- **Header encryption**: `Context::with_encrypted_header_extensions` (RFC 6904; AES-CM keystream
  for AEAD too, RFC 7714 §8.3) and `Context::with_cryptex` (RFC 9335: CSRCs and whole extension
  bodies, `0xC0DE` / `0xC2DE`, an empty extension added for CSRCs alone; non-cryptex packets still
  accepted).
- **Allocation-free variants**: `protect_rtp_into`, `unprotect_rtp_into`, `protect_rtcp_into`,
  `unprotect_rtcp_into`.
- **only-dtls**: `Config::with_srtp_mki` (client offer), `Config::with_srtp_accept_mki` (server
  echo, default off), `HandshakeInfo::srtp_mki`; a different non-empty MKI from the server fails
  the handshake (RFC 5764 §4.1.3), DTLS 1.2 and 1.3.
- Tests: RFC 6188, RFC 6904 and RFC 9335 vectors; 230 packets cross-checked byte for byte with
  libsrtp main (`tools/interop/srtp`, every profile, MKIs, RFC 6904, cryptex); new fuzz target
  `srtp_features`. RFC 6904 follows the RFC where libsrtp does not advance its keystream over
  padding between extension elements.
- Benchmark (gpu51, `examples/srtp_bench.rs`, ns per packet, base -> this change): existing profiles unchanged within noise or faster: unprotect 0-5 % faster everywhere (AES-128-CM 160 B 255.2 -> 243.0, AES-128-GCM 1200 B 178.3 -> 176.3), AES-CM protect within ±1.3 %, AEAD protect 1200 B within ±0.3 % and 160 B +1-2 % (AES-128-GCM 86.8 -> 88.6). The per-SSRC state is now looked up once per packet instead of twice. New features at 1200 B with a CSRC and three extension elements, AES-128-GCM protect / unprotect: plain 542.7 / 175.9, MKI 547.6 / 179.3, cryptex 555.7 / 187.1, RFC 6904 626.4 / 252.7.
- Not yet negotiated by `only-webrtc` (SDP `a=cryptex`, encrypt extmaps, DTLS-SRTP MKI).

### Changed: `only_srtp::Profile` (breaking, internal tier)

`Profile` is `#[non_exhaustive]`, `Profile::ALL` has ten entries and `Profile::id` returns
`Option<u16>` (the RFC 6188 profiles have no DTLS-SRTP id). New `Error::Config`,
`Error::UnknownMki`, `Error::Unsupported`.

### Added: SCTP HEARTBEATs, peer restart, zero checksum and incoming reset requests (only-sctp)

ADR-042 (docs/adr/042-sctp-heartbeat-restart-zero-checksum.md); only-sctp is Internal tier:

- **HEARTBEATs** (RFC 9260 §8.3, `Config::heartbeat_interval`, default 30 s): an idle
  association measures its RTT (`Association::rtt`) and notices a vanished peer: unanswered
  HEARTBEATs count towards `max_retransmissions` (Path.Max.Retrans with one path), then the
  association fails, 60-150 s after the last exchange. Previously only answered.
- **Peer restart** (RFC 9260 §5.2.2, §5.2.4): an INIT on a live association gets an INIT ACK
  with a new tag and Tie-Tags; a restarted peer's COOKIE ECHO closes every channel, drops queued
  data and starts over, with the new `Event::Restarted`. Duplicates get COOKIE ACK, other
  combinations are discarded, restarts while shutting down are refused. Previously ignored.
- **Zero checksum** (RFC 9653, `Config::zero_checksum`, default on): "SCTP over DTLS"
  announced in INIT / INIT ACK; zero checksums accepted, and sent after the handshake when the
  peer announces it too (`Association::zero_checksum`): no CRC-32C on either end of the data
  path. In-memory SCTP 1.20-1.31x faster (`examples/sctp_bench.rs`, same-run A/B against
  46f25f81 on gpu51, medians of 7 rounds); data channels between two loopback `Endpoint`s,
  DTLS included, 1.003x. Firefox 158 and Chrome 157 do not offer it; pion/sctp does.
- **Incoming SSN Reset** and **SSN/TSN Reset** requests (RFC 6525 §5.2.3-4) are performed
  instead of refused: the first is answered with our Outgoing SSN Reset Request (channels
  close), the second once none of our data is in flight (new TSNs both ways, SSNs back to 0).
- `Event` is now `#[non_exhaustive]`.
- Interop: Firefox 158 (usrsctp) through only-webrtc, both offer directions, with a 150 s idle
  spell (new `tools/interop/webrtc/firefox.sh`, WebDriver BiDi; the `webrtc-interop` example
  takes `ONLY_INTEROP_BIND`); pion/sctp with zero checksums (`tools/interop/sctp/run.sh`);
  Chrome 157 unchanged. Fuzz `sctp_packet` with new seeds, 11 minutes on gpu51, no crash.
- Not implemented, as WebRTC uses none of them: multi-homing, AUTH, ASCONF, ECN.

### Added: SRT rendezvous, AV1 in MPEG-TS, recording to MPEG-TS, HLS SAMPLE-AES (only-media)

ADR-043 (docs/adr/043-media-srt-rendezvous-av1-ts-sample-aes.md), additive:

- **SRT rendezvous** (HSv5): `srt::Conn::rendezvous` / `Conn::is_rendezvous` and
  `srt::{rendezvous, push_rendezvous, pull_rendezvous}(engine, local, remote, ..)` on a UDP
  socket bound at `local`. Both sides wave, libsrt's cookie contest picks the initiator (HSREQ,
  KMREQ with its key), the responder answers HSRSP / KMRSP and connects on AGREEMENT (or the
  initiator's next packet). Ten times `handshake_timeout`. Tested against libsrt 1.5.4
  (`srt-live-transmit`) pushing and pulling, clear and encrypted.
- **AV1 in MPEG-TS** (AOM "Carriage of AV1 in MPEG-2 TS"): stream type 0x06 with the `AV01`
  registration and AV1 video descriptors, OBUs after start codes with emulation prevention, a
  temporal delimiter per PES; the demuxer also reads GStreamer's `AV1G`. AV1 now goes over SRT,
  HLS MPEG-TS and MPEG-TS recordings. VP8 / VP9 have no MPEG-TS mapping (documented).
- **Recording to MPEG-TS**: `RecordFormat::MpegTs` (`.ts`), tables repeated before every video
  keyframe.
- **HLS SAMPLE-AES**: `hls::EncryptionMethod::{Aes128, SampleAes}`, `HlsEncryption::method`
  (field and builder). MPEG-TS: Apple's sample encryption (stream types 0xdb / 0xcf, `zavc` /
  `aacd` / `apad`; H.264 slices 1:9 after 32 clear bytes, AAC frames), one random IV per key in
  the `IV` attribute. fMP4: `cbcs` (`encv` / `enca` with `sinf` / `tenc` and a constant IV,
  `senc` / `saiz` / `saio`; H.264 slice headers parsed and kept clear). H.264 and AAC tracks
  only (others left out of the segments). ffmpeg decodes both frame for frame.
- Fuzz targets `srt_rendezvous` and `h264_sample_encryption`; AV1 seeds for `mpegts_demux`.

### Added: in-house brotli and Zstandard (only-brotli, only-zstd), in certificate compression (only-tls) and HTTP (only-http)

ADR-041 (docs/adr/041-brotli-zstd.md), additive:

- **`only-brotli`** (new internal crate, RFC 7932) and **`only-zstd`** (new internal crate,
  RFC 8878): pure safe Rust, no dependencies, one-shot `decompress(data, limit)` and
  `compress(Level, data)`. The decoders cover the whole formats (brotli: every window size,
  metadata and uncompressed meta-blocks, block switching, context modes and maps, the static
  dictionary and its 121 transforms; zstd: concatenated and skippable frames, Huffman and
  treeless literals, predefined / RLE / FSE / repeat tables, repeat offsets, content size and
  XXH64 checksum) and accept and reject what the reference decoders do; output and memory stop
  at `limit` (`Error::TooLarge`), so a decompression bomb costs no more than that. The encoders
  (LZ77 over hash chains, Huffman / FSE coding) compress certificate chains at least as well as
  zlib level 9. `only_zstd::xxh64` is public. Tested with the official test vectors (all 44
  brotli `testdata` streams; zstd's golden decompression, error and compression files, 1000
  `decodecorpus` frames), the `brotli` and `zstd` CLIs in both directions, and differential
  fuzz targets against Google's brotli decoder (`brotli-decompressor`) and libzstd
  (`brotli_decompress`, `brotli_roundtrip`, `zstd_decompress`, `zstd_roundtrip`).
- **only-tls**: certificate compression (RFC 8879) with brotli and zstd besides zlib. The
  client offers brotli, zstd, zlib; a server sends the smallest of the algorithms the client
  offers (each compressed once per certificate and cached), and the same for client
  certificates. New: `CertCompression { Zlib, Brotli, Zstd }` and
  `certificate_compression_algorithms(&[CertCompression])` on both builders;
  `certificate_compression(true)` now means all three (defaults unchanged: on for servers, off
  for clients). Interop with OpenSSL 3.5 built with brotli, zstd and zlib in both directions
  (`tools/interop/tls/certcomp.Dockerfile`, `tools/interop/tls/run.sh`; `tls-interop
  --cert-comp`).
- **only-http**: `Compress::brotli` and `Compress::zstd` (levels, default `None`) make
  `middleware::compress` answer `br` / `zstd` to clients that accept them (preference br, zstd,
  gzip, deflate); `Files` also serves `.zst` twins (`Content-Encoding: zstd`).

### Added: HLS encryption and recording (only-media), AES-CBC (only-crypto)

ADR-034 (docs/adr/034-media-hls-encryption-recording.md), additive:

- **HLS AES-128**: `HlsConfig::encryption` (`HlsEncryption { keys, rotate_every }`) encrypts
  every segment and LL-HLS part (MPEG-TS and fMP4) with AES-128-CBC + PKCS #7, IV = media
  sequence number (parts separately, from their segment's IV), `#EXT-X-KEY:METHOD=AES-128`
  before the first media of each key; fMP4 init segments stay clear (`METHOD=NONE` before a map
  that follows a key). `KeyProvider` (`key(path, n) -> HlsKey`, `authorize(path, n, &Context)`)
  issues keys and decides requests for `/<path>/key-<n>.key` (403 when refused);
  `HlsKey::with_uri` names an external key server; `RandomKeys` issues random keys. Keys rotate
  every `rotate_every` segments and are served only while a kept segment uses them. `MediaHttp`
  routes `.key` to `Hls`. Tested with ffmpeg playing the encrypted live playlists.
- **Recording**: `only_media::record::{Recorder, RecordConfig, RecordFormat, RecordHooks,
  RecordFile, NoHooks}` records hub streams to fMP4 or FLV files, cut at keyframes by
  `segment_duration` / `segment_bytes` and at republishes, rotated with `max_files`, with
  `file_name`, `on_start`, `on_stop` (after `sync_all`) and `on_remove` hooks. Files are
  written by the recorder's own writer thread, never an I/O thread; the queue is bounded by
  `max_queued_bytes` (32 MiB), past which the file is closed and packets dropped until the next
  keyframe (`Recorder::dropped`). Recorded files are checked with ffprobe / ffmpeg.
- **only-crypto**: `Aes::{encrypt_cbc, decrypt_cbc, encrypt_cbc_padded, decrypt_cbc_padded}`
  (SP 800-38A vectors, PKCS #7 checked against OpenSSL).

### Added: ECN on macOS and over only-dpdk's UDP (only-sys, only-quic, only-dpdk)

ADR-035 (docs/adr/035-ecn-macos-and-userspace-udp.md). QUIC connections now mark ECT(0), read
received codepoints and validate ECN on macOS and over the userspace stack, not only on Linux.
only-sys gains, on macOS only, `enable_ecn`, `ecn_available`, `recv_from_ecn` and `send_to_ecn`
(one `sendmsg` / `recvmsg` per datagram with an `IP_TOS` / `IPV6_TCLASS` control message;
`ONLY_UDP_ECN=0` turns it off), used by the kqueue UDP loop and only-core's macOS datagram
writes. only-dpdk's UDP writes the codepoint into the IP header and reports the one it received
(`Conn::rx_ecn`); only-core keeps codepoints for virtual datagram sockets (hidden
`ConnInner::drain_output_ecn`). The `quic_conn` fuzz target now picks what the path does to
ECN (kept, bleached, CE, ECT(1)); before, its datagrams were never marked. The quic-go interop
script checks ECN validation on macOS too. The only-quic README
no longer lists compatible version negotiation as missing (done in ADR-013 and ADR-014). No
change to the Linux API snapshots; unsafe inventory: only-sys 91 → 97 blocks.

### Added: RTCP XR, TMMBR / TMMBN, RFC 8888 feedback and FEC (only-rtp)

ADR-036 (docs/adr/036-rtp-xr-tmmbr-ccfb-fec.md). `only-rtp` is Internal-tier; `Rtcp` gains four
variants (PT 207 and RTPFB 3 / 4 / 11 no longer parse as `Rtcp::Unknown`), everything else is
additive:

- **RTCP XR** (RFC 3611): `Rtcp::ExtendedReport` with `XrBlock` for every block (loss /
  duplicate RLE, receipt times, RRTR, DLRR, statistics summary, VoIP metrics, unknown).
  `RrtrResponder` answers RRTRs with DLRR; `rtt_from_dlrr` and `RecvStream::{handle_dlrr, rtt}`
  give a receiver without sender reports its RTT; `RecvStream::{statistics_summary,
  duplicates}`; `BurstLossModel` (Appendix A.2, reproducing the §4.7.2 example) for VoIP metrics.
- **TMMBR / TMMBN** (RFC 5104): `Rtcp::{Tmmbr, Tmmbn}` with `TmmbItem`; `bounding_set`,
  `bounded_bitrate`, `TmmbrHandler` (requests per requester, 25 s timeout, TMMBN).
- **RFC 8888**: `Rtcp::CongestionControl(CcfbFeedback)` (`CcfbStream`, `CcfbMetric`, ATO
  constants); `CcfbReceiver` generates feedback per media SSRC with ECN (50 ms / 100 packets);
  `CcfbSender` maps it onto `PacketResult`s for `BandwidthEstimator`.
- **FEC** (`only_rtp::fec`): `FecEncoder` / `FecDecoder` / `FecHeader` for ULPFEC (RFC 5109),
  FlexFEC as libwebrtc's `flexfec-03` and as RFC 8627; interleaved masks per frame, iterative
  byte-identical recovery; `fec::red` (RFC 2198 parse / write / wrap / unwrap).
- Tests against libwebrtc's unit-test vectors, the RFC 3611 example and simulated loss; new fuzz
  target `rtp_fec`, `rtp_rtcp` extended. Not wired into `only-webrtc` yet.

### Added: SCTP message interleaving (I-DATA) and stream schedulers (only-sctp)

ADR-037 (docs/adr/037-sctp-idata-schedulers.md), additive (only-sctp is Internal tier):

- **I-DATA / I-FORWARD-TSN (RFC 8260 §2)**, offered by default (`Config::message_interleaving`)
  and used when the peer offers them too (`Association::message_interleaving`): fragments of
  messages on different channels interleave, so a large message no longer holds up small ones
  on other channels (a 4-byte message queued after a 200 kB one on another channel now arrives
  in the first round trip instead of after it). DATA and FORWARD TSN otherwise, as before; the
  chunk kind not negotiated aborts the association (protocol violation).
- **Stream schedulers (RFC 8260 §3)**: `Config::scheduler` with `Scheduler::{FirstComeFirstServed,
  RoundRobin, RoundRobinPerPacket, Priority, FairCapacity, WeightedFairQueueing}` (default
  weighted fair queueing), by channel priority: `ChannelOptions::with_priority`, the peer's
  DATA_CHANNEL_OPEN value, `Association::set_channel_priority` (RFC 8832 semantics, higher is
  more important; 0 counts as 256). Previously messages went out first come, first served.
- Sender queues per stream with fragments cut as they get TSNs from one shared buffer per
  message; with I-DATA a new message starts only while the started ones fit in half the peer's
  window, so many large messages at once cannot fill it with partial messages; single-chunk
  messages skip reassembly and in-order I-DATA fragments are appended
  directly. Same-run A/B against 59d41cc2 on gpu51 (`quiet.sh`, CPUs 2-9, 7 alternating rounds, medians): in-memory SCTP (`examples/sctp_bench.rs`) 1 KiB messages 1.19x (DATA fallback 1.21x), 64 KiB 1.33x (1.14x), 16 KiB unordered 1.12x (1.08x), four channels 1.20x (1.07x); data-channel throughput between two loopback `Endpoint`s, DTLS included, 0.986x (189.0 vs 191.7 MB/s; 1.009x in an earlier run, rounds vary by ±5%): no regression.
- Interop: pion/sctp v1.12.0 over UDP (new `tools/interop/sctp/run.sh`: both roles, pion's
  interleaving on and off, with and without loss); pion WebRTC negotiates I-DATA; headless
  Chrome 157 both directions on DATA (default) and on I-DATA (`CHROME_ARGS` with its
  `WebRTC-DataChannelMessageInterleaving` field trial, new in `browser.sh`). Fuzz target
  `sctp_packet` drives an I-DATA and a DATA pair. only-webrtc gets the new defaults without an
  API change.

### Added: certificate revocation: CRLs, OCSP, stapled-response validation (only-x509, only-tls)

ADR-038 (docs/adr/038-x509-revocation.md), additive. No network access in the library: the
application fetches CRLs and OCSP responses.

- **only-tls**: `RevocationPolicy::{Off, SoftFail, HardFail}` (default off, no cost when off);
  `ClientConfigBuilder::ocsp_policy` validates the OCSP response stapled for the server's leaf
  in TLS 1.3 and 1.2 (signed by the issuer or a delegated id-kp-OCSPSigning responder, about the
  leaf, current within 5 minutes of skew) and asks for stapling: soft fail rejects only a valid
  "revoked" (`certificate_revoked`), hard fail requires a valid "good"
  (`bad_certificate_status_response` otherwise). `Crls` with `ClientConfigBuilder::crls` and
  `ServerConfigBuilder::client_crls` check every certificate of the peer chain below the root.
- **only-x509** (internal crate): `Crl`, `CrlSet` (complete and delta CRLs, reason codes,
  issuingDistributionPoint scopes, removeFromCRL), `Verifier::{crls, revocation_mode,
  clock_skew}`, `RevocationMode`, `OcspResponse` / `OcspValidation` / `OcspRequest` (RFC 6960,
  nonce, CertID SHA-1/256/384/512), `Certificate::{crl_distribution_points, ocsp_urls,
  ca_issuer_urls}`, builders `CrlParams` and `OcspResponseParams`, new `Error` variants.
- Tests with OpenSSL-made CRLs and OCSP responses (`tests/data/revocation/gen.sh`), in-memory TLS
  for every policy, interop against `openssl s_server -status_file` and OpenSSL CRLs; new fuzz
  targets `x509_crl` and `x509_ocsp`.

### Added: protobuf text format (only-protobuf)

ADR-030 (docs/adr/030-protobuf-text-format.md), additive: `only_protobuf::text` parses and prints
the text format for generated messages (`to_string`, `to_string_with`, `from_str`,
`from_str_with`) and `DynamicMessage`s (`parse_dynamic`, `to_text`, `from_text`), with
`PrintOptions` (`single_line`, `print_unknown_fields`, `type_pool`), `ParseOptions`
(`allow_unknown_fields`, `type_pool`) and `TextError` (line and column). Scalars, enums by name
or number, strings and bytes with every escape, messages in `{ }` or `< >`, repeated fields in
both forms, maps, oneofs, groups, extensions (`[pkg.ext]`), `Any` expansion
(`[type.googleapis.com/...]`), comments, separators, hex / octal integers, `inf` / `nan`.
Protobuf conformance runner v35.1: text format 909 passed, 0 failed (was 909 skipped); binary +
JSON unchanged at 5627. New fuzz target `protobuf_text` (parse → print → parse).

### Added: BitTorrent fast resume

`only-bittorrent` (ADR-033, docs/adr/033-bittorrent-fast-resume.md), additive:

- **`ClientConfig::resume_dir`** (default none) and **`resume_interval`** (30 s): each torrent's
  state is saved as `<info hash hex>.resume` on a timer when it changed, soon after a pause, and
  at `Client::close` (after the last write), atomically (temporary file, fsync, rename);
  `Client::remove` deletes it. A torrent added again starts from it without hash-checking its
  data.
- **Format**: versioned bencode closed by a SHA-256 checksum: the have-bitfield, the info
  dictionary, v2 piece layers, each file's size and modification time, peers, trackers, web
  seeds, upload/download totals and seeding time across sessions, rate and seed limits.
  Damaged, truncated, foreign or newer-version data is refused
  (`TorrentEvent::ResumeRejected`, then a full check); it never panics (fuzz target
  `bt_resume`).
- **Validation**: files whose size or time changed have their pieces checked again
  (`TorrentEvent::ResumeAccepted { pieces, rechecking }`, `TorrentStats::pieces_checked`). After
  a crash, files the client was still downloading are trusted on their size (the client's own
  later writes made them newer); the pieces of the last save interval are downloaded again.
- **Bytes**: `Torrent::resume_data`, `AddOptions::resume_data`, `Client::add_resume` (a torrent
  from resume data alone; `AddError::Resume`, `ResumeError`), `Torrent::save_resume_data`.
  Custom storage reports files through `Storage::file_stamps` (`FileStamp`).
- `TorrentStats` gains `total_uploaded` and `total_downloaded`; `seeding_time` and seed limits
  count across sessions when resumed.
- Tests: restart after `close` and after `SIGKILL` mid-download with no piece hashed again, a
  changed file checked again alone, v1, v2 and hybrid torrents, a v2 magnet's piece layers
  restored. bt-bench 512 MiB TCP on gpu51: 1.01x of before (noise). Fuzz `bt_resume` 11 min clean.

### Added: TURN over TCP and TLS from an `Endpoint`, active and server ICE-TCP, simulcast with Chrome

Additive (ADR-032, docs/adr/032-webrtc-turn-streams-ice-tcp-simulcast.md):

- **Relayed candidates over TCP and TLS**: `Endpoint::gather_relay_via(&engine, &server,
  timeout)` with a `RelayServer` (`udp`, `tcp`, `tls(addr, server_name, tls_config, ..)`, or
  `from_url("turn:host?transport=tcp" | "turns:host")` plus `tls_config` for `turns:`). The
  allocation lives on an engine connection; its candidate ranks below a UDP-allocated one and
  brings no server-reflexive candidate; relayed data is dropped past 256 KiB queued.
- **Allocations are made again when lost** (a connection closed, a refresh failed), after 1 s
  and doubling waits up to a minute, by `gather_relay` too: the new relayed candidate replaces
  the old one for new peers and is added to open peers, which keep going when the other side is
  reachable from the relay.
- **Active ICE-TCP**: `Endpoint::dial_tcp(&engine)` adds an active TCP candidate (port 9) and
  dials one connection per pair when its first check goes out; active and passive connections
  share the 256 bound.
- **Passive ICE-TCP on `RtcServer`**: `RtcServer::tcp_candidates(addrs)` and `RtcServer::tcp()`
  (an `RtcTcp` acceptor for the engine's TCP listener); at most twice `max_peers` connections.
- **`Endpoint::candidate_filter(f)`**: the local candidates new peers use and signal (a relay-only
  or TCP-only policy); `Candidate::kind()` and `Candidate::transport()`.
- **`Peer::request_layer_keyframe(mid, rid, kind)`**: PLI or FIR to one received simulcast layer
  (an SFU switching a viewer's layer). Simulcast verified with headless Chrome both ways: three
  VP8 layers from Chrome, layer selection decoded by Chrome, and our simulcast falling back to its
  first layer (Chrome does not receive simulcast).
- `only-ice` (internal tier): `Candidate::relayed_over_stream`. New fuzz target
  `webrtc_turn_url`. Interop: pion (relays over TCP/TLS on only-turn and pion/turn, ICE-TCP both
  ways), coturn (relays over TCP/TLS), Chrome (ICE-TCP only, relay only over UDP/TCP/TLS,
  simulcast and layer selection).

### Added: VP8, VP9 and AV1 in only-media, multivariant HLS playlists

Additive (ADR-031, docs/adr/031-media-vp8-vp9-av1-multivariant-hls.md):

- **VP8, VP9 and AV1 in the hub**: `Codec::{Vp8, Vp9, Av1}` with canonical forms (`vpcC` /
  `av1C` configuration records, frames, AV1 temporal units of sized OBUs) and keyframes from the
  bitstream, so GOP cache, HLS segmenting and slow-player dropping work for them. Carried by
  Enhanced RTMP / FLV (`vp09`, `av01`, `vp08`), RTSP (RFC 7741 / RFC 9628 / AV1 RTP through
  only-rtp, record and play), fMP4 HLS (`vp08` / `vp09` + `vpcC`, `av01` + `av1C`) and WHIP /
  WHEP (`webrtc::rtc_config` enables them). Not in MPEG-TS. New modules `codec::vp8`,
  `codec::vp9`, `codec::av1`; `Track::video_from_keyframe`, `Track::codec_string` (RFC 6381);
  `rtp::Depacketizer::picture_size`.
- **Multivariant HLS**: `Hls::add_multivariant(name, Multivariant)` serves `/<name>.m3u8` over
  renditions published as separate streams (`Variant`: path, bandwidth configured or measured
  from segments, audio group; `AudioRendition`: group, name, language, default), with
  `BANDWIDTH`, `AVERAGE-BANDWIDTH`, `CODECS`, `RESOLUTION`, `AUDIO` and `EXT-X-MEDIA` audio
  groups, in MPEG-TS and fMP4, with LL-HLS; `Hls::remove_multivariant`.
- Changed: `webrtc::rtc_config` now accepts VP8, VP9 and AV1, so WHIP offers with only those are
  published instead of refused (406). Fixed: `flv::parse_video` dropped the first 3 bytes of
  coded frames of FourCCs other than `avc1` / `hvc1`. HLS no longer stalls a stream whose video
  the segment format cannot carry (VP9 or AV1 in MPEG-TS): it is cut like an audio-only one.
  Fixed: a live playlist's `EXT-X-TARGETDURATION` could change between reloads (1 → 2 after a
  1.007 s segment), which Chrome's own HLS player refuses; it is now rounded to the nearest
  second per RFC 8216 and never decreases.
  Fixed: the RTP AAC depacketizer (RTSP record) panicked on an AU-headers-length of 1 to 8
  bits (found by fuzzing).
- Hot paths, same-run A/B against the previous main on gpu51 (5 alternating rounds, medians,
  head/base): hub fan-out to 1 / 16 / 256 subscribers 1.008 / 1.009 / 1.011; HLS segmenting
  TS 0.976, TS + parts 1.016, fMP4 1.005, fMP4 + parts 1.011; FLV decoding H.264 0.976,
  H.265 0.993. Retired instructions are equal or lower; per-case swings of 1-3% follow
  unrelated code changes (code layout).
- Interop: ffmpeg / ffprobe for VP9 and AV1 over Enhanced RTMP and fMP4 HLS, VP8 / VP9 / AV1
  over RTSP (record and play, TCP and UDP), multivariant playlists in both formats; headless
  Chrome publishes VP8, VP9, AV1 and H.264 over WHIP, decodes them over WHEP and plays a
  multivariant fMP4 LL-HLS playlist (`tools/interop/media/browser.sh`).

### Added: `/regex` message filters in only-log, on the new internal crate only-regex

Additive (ADR-047, docs/adr/047-log-regex-filters.md):

- **only-log**: `ONLY_LOG=info,only_http=debug/connection (reset|refused)` keeps only the
  records whose formatted message matches the pattern, as env_logger does (everything after the
  first `/` is the pattern; an empty one filters nothing). `Filter::message_regex`,
  `Filter::message_pattern` and `Filter::matches(&Record)` (levels and message; the message is
  streamed into the matcher, no string built); `Filter`'s `Display` writes the pattern back.
  `FmtLogger` matches the message it already formatted for the line. A filter without a pattern
  costs nothing extra. `"info/x".parse::<Filter>()`, an error before, now succeeds; an invalid
  pattern is a `ParseFilterError` naming `/pattern` and the byte where it fails.
- **only-regex** (new internal crate, no dependencies, `#![forbid(unsafe_code)]`): `Regex::new`,
  `is_match(&str)`, `is_match_fmt(fmt::Arguments)` (no allocation). The `regex` crate's syntax
  without captures, look-around and Unicode classes: Unicode-aware `\d \w \s`, classes, greedy
  and lazy repetition, alternation, groups, `^ $ \A \z \b \B`, flags `i` `m` `s` `U`. A Thompson
  NFA with a DFA built at compile time over character classes (ASCII table, intervals for the
  rest) and a Pike VM fallback: linear time on any pattern, about 1 ns per character.
  Unicode tables generated from regex-syntax by `tools/regex-tables`; differential fuzz target
  `regex_search` against the `regex` crate; `tools/codec-bench logregex` compares the two.

### Changed: faster P-256 key generation, signing and ECDH; RSA squaring by Karatsuba without IFMA

only-crypto on x86_64 with BMI2 + ADX and AVX2: the P-256 fixed-base comb and the ECDH
multiplication keep the accumulator in one assembly frame for the whole multiplication. On Zen 4
against ring: key generation 1.40x → 1.57x, signing 1.38x → 1.49x, ECDH 1.12x → 1.15x,
secp256r1 TLS handshakes 1.07x → 1.08x rustls+ring. On x86_64 CPUs without AVX-512 IFMA, RSA
squaring at 3072 and 4096 bits is one level of Karatsuba: verification +5% / +9%. Constant-time
properties unchanged (`tools/ct-dudect`: no leak). No public API change (docs/BENCHMARKS.md).

### Added: SOCKS client, SOCKS proxies for the HTTP/WebSocket clients, UDP fragment reassembly, SOCKS4 BIND

Additive (ADR-019, docs/adr/019-socks-client-fragments-socks4-bind.md):

- **`only_socks::SocksClient`**: SOCKS5 `CONNECT`, `BIND` and `UDP ASSOCIATE` (no
  authentication or username/password), SOCKS4 and SOCKS4a `CONNECT` and `BIND`. On the engine:
  `dial` (an acceptor, TLS inside the tunnel if it is a `Tls` acceptor), `bind` (`on_bound`
  gets where the proxy listens), `udp_associate` (a `UdpAssociation`: `send_to`, `close`;
  datagrams to `on_datagram`); every failure before the tunnel opens (unreachable proxy,
  refusal, garbage, timeout) goes to `on_error`. Blocking: `dial_blocking` (a `TcpStream`),
  `bind_blocking` (`BlockingBind::accept`), `udp_associate_blocking` (`BlockingUdp`).
  `from_url("socks5h://user:pass@host")`, `handshake_timeout` (10 s), `bind_timeout` (60 s),
  `Version`, `impl From<SocketAddr> for Dest`, `ProxyRefused` re-exported.
- **SOCKS proxies for `only_http::client::Client` and `only_ws::client::dial`**: `Proxy` takes
  `socks5://`, `socks5h://`, `socks4://` and `socks4a://` URLs (port 1080 by default, URL
  credentials as RFC 1929 credentials or the SOCKS4 user id); every request, `http://` too, is
  tunnelled; `socks5`/`socks4` resolve the target first (IPv4 first), `socks5h`/`socks4a` let
  the proxy resolve it. A refusal is a `ProxyRefused` with the closest HTTP status and the new
  `ProxyRefused::socks_reply()`.
- **UDP fragment reassembly** (RFC 1928 `FRAG`) in the SOCKS5 server's relay and the client's
  associations: in-order sequences up to 65,507 bytes, one per association, 5 s timer.
- **SOCKS4 `BIND`** on the server, under the same `Socks::bind(true)` switch and `allow` hook as
  SOCKS5's.
- Behaviour changes: `Proxy::from_env` also reads `all_proxy` / `ALL_PROXY`; a relay that
  dropped fragmented datagrams now reassembles them; SOCKS4 `BIND` requests are served when
  `bind(true)` is set.
- Interop (`tools/interop/socks/run.sh`, 15/15): our client against Dante and against
  only-socks, curl/PySocks/hand-written clients against the server (fragments, SOCKS4 BIND).
  New fuzz target `socks_client` (client handshake, tunnel transport, reassembly).

### Added: arpc middleware, coders and client pools (only-arpc)

Additive (ADR-023, docs/adr/023-arpc-middleware-coders-pools.md):

- **Middleware**: `Routes::middleware` (every request and notify) and
  `Routes::method_middleware(method, ..)` take `Fn(&mut Context, Next)`; `next.run(ctx)` runs the
  rest of the chain (code after it runs after the handler), returning without it aborts. Fixed
  order (global, then per method, then the handler) whatever the registration order. New
  `Context::values` / `values_mut` / `responded`. Routes without middleware call the handler
  directly.
- **Coders** (`only_arpc::coder`): `Coder` trait over whole frames, `Routes::coder`, encode in
  the order added and decode in reverse, as Go's `MessageCoder`. `Gzip::new(threshold)`
  (reserved bit 7, inflation bounded by `max_body_bytes`) and `Appender::new(name, bit)` (bit 0
  for tracing) are wire-compatible with `arpcex/extension/middleware/coder`. `Values` travel with
  `Peer::call_with` / `call_async_with` / `notify_with` and answers are coded with the request's
  values. Checked against fib's Go arpc both ways (`tools/interop/arpc/run.sh`); new fuzz target
  `arpc_coders`.
- **Pools**: `Pool::builder()` (`size`, `balance`: `Balance::RoundRobin` / `LeastPending`,
  `heartbeat`, `reconnect_interval`, `connect_timeout`) `.dial(..)`; calls go to a connection that
  is up, silent connections are closed and replaced by the heartbeat.
- **Bounded pending calls**: `Routes::max_pending_calls` (default
  `DEFAULT_MAX_PENDING_CALLS` = 65536 per connection); past it a call fails with the new
  `CallError::Overloaded`. New `Peer::pending_calls`, `Peer::ping`.
- Measured (gpu51, same-run A/B, medians of 10 rounds): calls without middleware 0.98x of
  before and one middleware 1.00x of none, both within the ~4% noise; +1.5% user instructions
  per call, cycles per call unchanged.

### Added: BitTorrent v2 and hybrid torrents, web seeds, LSD, IPv6 DHT, rate and seed limits

`only-bittorrent` (ADR-018, docs/adr/018-bittorrent-v2-webseeds-lsd-ipv6-limits.md):

- **BEP 52 v2 and hybrid torrents.** New `merkle` module (SHA-256 trees, piece layers, hash
  request proofs as libtorrent sends them). `metainfo`: `InfoHashV2`, `TorrentVersion`,
  `FileEntry::pieces_root`, `PieceLayers`, `MetaInfo::{info_hash_v2, piece_layers,
  verify_piece}`, `Info::{verify_piece_with, piece_file, file_pieces, ...}`,
  `Builder::version`. v2 files are laid out on piece boundaries (padding files synthesized for
  v2-only torrents), so one piece space serves all three kinds. `MetaInfo::info_hash` is the
  hash peers use (truncated SHA-256 for v2-only torrents). Magnet `urn:btmh:`. Peer wire: the v2
  handshake bit, hash request / hashes / hash reject (`Handshake::with_v2`; the client sets the bit for v2 and
  hybrid torrents only). The client announces and accepts hybrid
  torrents under both hashes, fetches missing piece layers of magnet links with hash requests
  and answers them. Parsing refuses piece layers that do not match their roots and hybrid
  torrents whose two parts disagree.
- **Web seeds (BEP 19)** through only-http's client: `ClientConfig::web_seeds` (on),
  `AddOptions::web_seeds`, `Torrent::add_web_seed`, `TorrentEvent::WebSeedError`; range requests
  of at most 4 MiB, one piece per web seed, backoff up to 10 minutes.
- **Local Service Discovery (BEP 14)**: module `lsd`, `ClientConfig::lsd` (on; never for
  private torrents), on a thread of its own, bounded to 50 announcements a second.
- **IPv6**: a client listening on `[::]:port` is dual-stack (IPv4 peers keep plain addresses);
  the DHT keeps an IPv6 routing table (BEP 32: `nodes6`, `want`, `Node::set_ipv6`,
  `compact_nodes6`, `Client::dht_nodes6`).
- **Rate limits** (`RateLimits`; `ClientConfig::rate_limits`, `Client::set_rate_limits`,
  `AddOptions::rate_limits`, `Torrent::set_rate_limits`) and **seed limits** (`SeedLimits`
  ratio and time; `TorrentEvent::SeedLimitReached` pauses the torrent). `TorrentStats` gains
  `seeding_time` and `web_seeds_active`.
- Interop: v2 and hybrid torrents both ways with libtorrent 2.0 (by .torrent and by magnet),
  hybrid torrents with aria2 1.37, web seeds from nginx, LSD on a Docker network. Fuzz targets
  `bt_lsd` and `bt_merkle`; `bt_bencode`, `bt_peer_wire`, `bt_krpc` extended.
- BEP 44 is not implemented, on purpose (ADR-018).

### Added: protobuf groups, extensions, editions, JSON and reflection; gRPC server reflection

ADR-022 (docs/adr/022-protobuf-gaps.md):

- **only-protobuf-build**: proto2 `group` fields, `extend` blocks (typed `Extension` /
  `RepeatedExtension` constants), extension ranges, MessageSet; editions 2023 and 2024 with
  feature resolution (presence, closed enums, packed / expanded, `DELIMITED`, naming style,
  `export` / `local`); custom options and text-format aggregates; descriptors as protoc writes
  them, embedded per package (`FILE_DESCRIPTOR_SET`, `descriptor_pool()`), `Config::descriptors`,
  `Config::file_descriptor_set_path`; `descriptor.proto`, `type.proto`, `api.proto`,
  `source_context.proto` built in.
- **only-protobuf**: `ExtensionSet`, `Extendable`, `Extension`, `RepeatedExtension`;
  `encoding::GroupCodec`, closed-enum decoders; `Enumeration::is_known`; `reflect`
  (`DescriptorPool`, descriptors, `DynamicMessage`, `Value`, `ReflectMessage`); `json`
  (canonical proto3 JSON, well-known types, `ignore_unknown_fields`); the descriptor well-known
  types in `well_known`.
- **only-grpc**: `reflection::register` (gRPC server reflection v1 and v1alpha, for grpcurl /
  grpcui), the reflection messages in `reflection::v1` / `v1alpha`; depends on only-protobuf.
- Verified: protobuf conformance runner v35.1, binary + JSON, 5627 passed, 0 failed
  (`tools/protobuf-test/conformance/run.sh`); descriptor sets equal protoc's; grpcurl
  (`tools/interop/grpc/grpcurl.sh`); fuzz targets `protobuf_json`, `protobuf_descriptor`.

Behaviour changes: proto2 (closed) enum fields keep unknown numbers as unknown fields instead of
storing them; extension fields of proto2 messages are now in `extensions`, not
`unknown_fields`; tags longer than 5 bytes are rejected (as C++ does). Encode/decode
cost is unchanged: same-run A/B against the previous commit on gpu51 (5 alternating runs, medians,
prost as control) gives Point 12/18 ns → 12/18 ns, Feature 19/47 ns → 18/45 ns, AllTypes
encode 309 → 312 ns (+1%, prost 509 → 505) and decode 1629 → 1448 ns (−11%, prost 1788 → 1749).

### Added: DTLS 1.3, connection IDs, PSKs and session resumption in only-dtls

Additive except where noted (ADR-021, docs/adr/021-dtls13-cid-resumption.md; only-dtls is an
Internal-tier crate):

- **DTLS 1.3** (RFC 9147) behind the same sans-io `Connection`: unified record headers with
  record number encryption, epochs with KeyUpdate (`Connection::update_keys`, automatic before
  a key's usage limit), ACKs with retransmission of only the unacknowledged fragments,
  stateless HelloRetryRequest cookies (`HelloVerifier::check` answers DTLS 1.3 ClientHellos with
  one), `use_srtp`, the TLS 1.3 exporter. `Config::with_versions` enables it (default: DTLS 1.2
  only, also in `Config::webrtc`); with both versions a connection falls back to DTLS 1.2 for a
  1.2-only peer, with the RFC 8446 downgrade check. New `Version`, `Connection::version`,
  `HandshakeInfo::version`, `CipherSuite::TLS13` and `CipherSuite::is_tls13`.
- **Connection IDs**: RFC 9146 `tls12_cid` records in DTLS 1.2 and DTLS 1.3 CIDs, with
  `Config::with_connection_id`, `Connection::local_connection_id`,
  `HandshakeInfo::{local_connection_id, peer_connection_id}` and `only_dtls::connection_id` to
  route datagrams by CID.
- **Session resumption**: DTLS 1.2 session IDs (a bounded 1024-entry cache) and RFC 5077
  tickets, DTLS 1.3 NewSessionTicket (`psk_dhe_ke`), with `Config::with_session_resumption`,
  `with_ticket_key` (`TicketKey`), `with_ticket_lifetime` (2 h default, 7 days at most),
  `Event::NewSession(Box<Session>)`, `Connection::client_resume` and `HandshakeInfo::resumed`.
- **External PSKs**: `Psk`, `Config::with_psks`, the DTLS 1.2 PSK / ECDHE-PSK AEAD suites
  (`CipherSuite::PSK`, `is_psk`) and DTLS 1.3 external PSKs; PSK-only servers need no
  certificate. `HandshakeInfo::psk_identity`; alerts `MissingExtension`, `UnknownPskIdentity`.
- Changed: the default `Config` suite list starts with the DTLS 1.3 and PSK suites (each used
  only with its version or a PSK, so DTLS 1.2-only configurations behave as before);
  `Connection::poll_timeout` can return a time after a DTLS 1.3 handshake (final flight until
  acknowledged, tickets, KeyUpdate).
- Tests: DTLS 1.3 over simulated lossy, reordering and duplicating links at MTU 256 with
  KeyUpdates and CIDs, partial-flight retransmission, lost final flight and ACK, cookies,
  resumption, PSKs, version negotiation; the key schedule against RFC 8448. Interop
  (`tools/interop/dtls/run.sh`, new `Dockerfile` and `dtls13.sh`): OpenSSL 4.1 and wolfSSL 5.8.4
  (DTLS 1.3 both ways, HRR, MTU 300, KeyUpdate, resumption, PSKs, version negotiation, CIDs with
  wolfSSL), pion/dtls v3 (CIDs, PSK suites). Fuzz targets `dtls_record` and `dtls_handshake`
  cover CID and unified-header records and the DTLS 1.3 machines. DTLS 1.2 record path, same-run
  A/B on gpu51 (new `dtls-bench` example): 64-byte records 0.97-1.01, 1 KiB 1.00-1.02 of before.

### Added: TURN over TCP and TLS, a TURN client, ICE-TCP and simulcast sending

Additive (ADR-017, docs/adr/017-webrtc-turn-gaps.md):

- **TURN over TCP and TLS** (`only-turn`): `TurnServer::stream()` returns a `TurnStream`
  acceptor for TCP listeners, and for TLS ones wrapped in `only::tls::Tls` (`turns:`), with the
  UDP listener's allocations, quotas and credentials. An allocation made over a connection ends
  with it (`TurnCore::remove_client`); new `TurnConfig::stream_allocate_timeout` (30 s: a
  connection that has not allocated is closed) and `max_stream_queue` (256 KiB: relayed data for
  a connection with more queued is dropped). `TurnServer::stream_relay_of`. STUN and ChannelData
  framing in `only_turn::framing` (`FrameReader`, `frame_len`, `MAX_FRAME`); `TurnEnv` gains the
  provided method `pads_channel_data`. RFC 6062 TCP relays are not implemented (`442`).
- **TURN client** `only_turn::client::{Client, ClientConfig, ClientEvent, ClientState,
  ClientError}`: sans-io, one allocation over UDP or a stream; long-term credentials, stale
  nonces, refreshes, channels with a permission fallback, binding refreshes while a peer is in
  use, UDP retransmissions; at most 64 peers and 64 KiB waiting for bindings by default.
- **Relayed candidates for `Endpoint`**: `Endpoint::gather_relay(server, username, password,
  timeout)` allocates over the endpoint's UDP socket and adds the relayed candidate (and the
  server-reflexive address the server saw); the allocation is shared by the endpoint's peers,
  refreshed on the WebRTC timer thread and deleted by `Endpoint::close`. At most 4 per
  endpoint. New `Error::Turn`.
- **ICE-TCP** (RFC 6544): `Endpoint::listen_tcp(&engine, addr)` adds a passive TCP host
  candidate on a port of its own; connections are accepted on a dedicated thread (at most 256),
  must send a check for one of the endpoint's peers within 10 seconds, and carry RFC 4571
  frames. TCP candidates rank below UDP ones. `only-ice` (internal tier) gains `TcpType`,
  `Candidate::host_tcp`, `Candidate::tcp_type` and `only_ice::tcp`; `ParseError::Tcp` is gone.
- **Simulcast sending** (RFC 8853): `SdpChanges::add_simulcast_media(kind, dir, rids, ..)` and
  `Peer::write_simulcast(mid, rid, ..)`: one RTP stream and RTX stream per RID, `a=rid` /
  `a=simulcast` in the SDP, MID and RID header extensions (repaired RID on retransmissions),
  per-encoding sender reports, NACKs and PLI/FIR (`KeyframeRequest::rid`); the answer's
  `a=simulcast:recv` picks the encodings sent. As an answerer the stack accepts simulcast offers
  (`a=simulcast:recv` in its answer, RTX mapped by repaired RID).
- Interop (`tools/interop/webrtc/run.sh`, new `linux.sh` running everything in Linux
  containers): pion/turn and coturn clients against `only-turn` over UDP, TCP and TLS; the
  `only_turn` client against pion/turn, coturn and `only-turn` over UDP, TCP and TLS; an
  `Endpoint` with only relayed candidates (from `only-turn`, pion/turn, coturn) and with only its
  passive TCP candidate to pion; simulcast h/m/l received by pion. New fuzz targets
  `turn_stream` and `ice_tcp`.

### Added: fMP4 HLS, RTMP and RTSP clients, WebRTC media in only-media

Additive (ADR-016, docs/adr/016-media-fmp4-clients-webrtc.md):

- **fMP4 / CMAF HLS**: `HlsConfig::format = SegmentFormat::Fmp4` serves `init-<n>.mp4`,
  `seg-<n>.m4s` and LL-HLS parts `part-<n>.<m>.m4s` (H.264, H.265, AAC, Opus) next to MPEG-TS,
  which stays the default. New module `fmp4` (`Muxer`, `Demuxer`, `write_styp`).
- **RTMP client** `rtmp::client::{push, pull}`: relays a hub stream to an RTMP server or pulls one
  into the hub (Enhanced RTMP H.265/Opus), with timeouts for connect, handshake, each command and
  idle, bounded messages and send queues.
- **RTSP client** `rtsp::client::{pull, push}` (play and record, TCP interleaved or UDP, Digest and
  Basic auth, keep-alives, RTCP reports); `rtsp::message::Reply` and `Parser::client`.
- **WHIP/WHEP media**: with the new cargo feature `webrtc`, `webrtc::RtcMedia` carries H.264,
  H.265, Opus and G.711 through only-webrtc: WHIP into the hub, WHEP out of it. `WhipServer`
  drops sessions whose peer ended without a `DELETE`.
- **Keyframe requests**: `Publisher::on_keyframe_request`, `Subscription::request_keyframe`,
  `Hub::request_keyframe`, throttled by `HubConfig::keyframe_request_interval` (500 ms); WebRTC
  viewers' PLI/FIR reach WHIP publishers as PLI.
- Interop: ffmpeg/ffprobe (fMP4 HLS plain and LL-HLS, RTMP and RTSP listen modes), mediamtx (RTMP,
  RTSP over TCP and UDP), ffmpeg's WHIP muxer and pion (WHIP, WHEP, PLI round trip). New fuzz
  targets `fmp4_demux`, `rtmp_client`, `rtsp_client`.
- Fixed: only-webrtc `Endpoint::config`, `close_on_disconnect` and `connect_timeout` panicked
  after `bind`.

### Added: XDP rate limiting, I/O-thread pinning, eBPF hash steering, spliced SOCKS tunnels

Additive (ADR-027, docs/adr/027-ebpf-xdp-pinning-socks-splice.md):

- **`only::ebpf::xdp::RateLimiter`**: per-source token buckets in XDP. It counts TCP SYNs
  (connection-flood protection) or every packet, keeps sources in a bounded per-CPU LRU map, and
  attaches natively or generically with a BPF link or netlink. It never replaces another
  program, detaches on drop, and exposes `stats()` and `forget()`.
- **`EbpfConfig::pin_threads`**: pins I/O thread `i` of `n` to the CPUs `c % n == i`, so
  `Steering::Cpu` lands on the thread running on the receiving CPU. Also adds
  `ebpf::cpu_pinning`, `SteerInfo::pinned_threads` and
  `only_sys::process::{allowed_cpus, pin_current_thread}`.
- **eBPF tier for `Steering::Hash`** (privileged): same hash and thread as the classic tier, with
  sockets named in a `REUSEPORT_SOCKARRAY`, independent of the order they joined the group.
- **Sockmap relay**: bytes queued before a splice are relayed instead of waiting for more data.
  New `Relay::splice_inner`, `Relay::splice_inner_with` (write a last handshake message before
  anything is relayed) and `ebpf::byte_counts`.
- **only-socks**: `ProxyConfig::sockmap` / `Socks::sockmap` splices SOCKS and HTTP `CONNECT`
  tunnels in the kernel (opt-in), falling back to userspace relaying when that is not possible.
- `ONLY_ACCEL` knob in `bench-server`, `ebpf-bench` example, `tools/bench/ebpf.sh`; fuzz target
  `xdp_rate_limit`.

### Added: IPv6, ECN and pacing in only-dpdk's userspace stack

Additive (ADR-026, docs/adr/026-userspace-ipv6-ecn-pacing.md; only-dpdk is experimental):

- **IPv6** on `Backend::Dpdk`: `DpdkConfig::address6` turns it on (plus a link-local address
  from the MAC), with `prefix_len6` (64) and `gateway6`. Listeners are dual-stack (the port
  serves both families; listener addresses `::`, `address6` or the link-local one), `dial` /
  `dial_udp` take IPv6 peers. Extension headers walked with limits and parameter problems,
  fragmentation and reassembly (RFC 5722 overlap discard, atomic fragments), ICMPv6 echo and
  errors, a path-MTU cache, NDP with the ARP cache's pending queue (no first-SYN drop), DAD
  probes for our addresses answered, MLDv2 reports; NDP frames fanned out to every queue,
  AF_PACKET joins all-multicast. Static addresses: no SLAAC, router advertisements or DAD.
- **ECN** (`DpdkConfig::tcp_ecn`, RFC 3168) and **pacing** (`DpdkConfig::tcp_pacing`, rate
  `cwnd / srtt` times 2 in slow start, 1.2 after), both off by default. Simulated 20-frame
  bottleneck: ECN 0 drops instead of 29, pacing 14 instead of 29.
- The neighbour cache bounds the bytes queued for unresolved neighbours (4 MiB per stack).
- IPv4 stays as fast as before (memory-wire `stack-bench` on x86, new / main): request/response
  1.02-1.04, UDP and bulk 1.01, sequential connections 0.99; the neighbour caches no longer hash
  with SipHash.
- Not done: checksum / TSO / LRO offloads (the PMDs in reach do them in software).
- Tests: IPv6 and ECN / pacing on the simulated lossy link, dual-stack memory-wire tests,
  kernel interop over IPv6 in Docker (TAP, AF_PACKET, DPDK `net_tap` with two queues: `ping -6`,
  UDP with fragments, TCP both ways, `netem` loss with ECN and pacing); fuzz targets
  `dpdk_ipv6`, `dpdk_icmpv6`, `dpdk_ndp`.

### Changed: UDP datagrams delivered in owned receive buffers (only-sys, only-epoll, only-quic; ADR-024)

The UDP loop (epoll, io_uring and macOS; servers and dialed sockets) receives into pooled receive
slabs and can hand each datagram to the handler as an owned buffer (hidden
`Handler::OWNED_DATA` / `on_data_owned`), GRO batches split without a copy. only-quic uses it and
decrypts packets in place, so no copy is left between the kernel and the decrypted payload. The
UDP peer table hashes with the keyed folded-multiply hasher (shared with only-quic as the hidden
`only_core::hash`) instead of SipHash. `only-buf` now allows unsafe code in one module (`slab`,
Miri- and loom-checked; docs/unsafe-review.md). Same-run A/B on loopback: QUIC bulk, HTTP/3,
handshakes and UDP echo within 1% (HTTP/3 1.01, the rest 1.00; docs/BENCHMARKS.md). Handlers that
do not opt in, including secured ones, see no change. No public API change.

### Changed: no boxed response sink and no target allocation per HTTP request (ADR-025)

The last two per-request allocations named after the HTTP/3 allocation pass are gone
(docs/adr/025-per-connection-response-sink.md):

- **Target buffers are reused.** When a handler is done with a request it did not detach or
  upgrade, its target buffer (up to 1 KiB) becomes the thread's spare. The next request parsed
  on that thread writes its target into it, on HTTP/1.1, HTTP/2 and HTTP/3. Per thread rather
  than per connection: a per-connection buffer is cold when that connection's turn comes again,
  and cost h2c about 100 cycles per request in a first version. `Request::target` stays a
  `String`, so handlers, routers and middleware are unchanged.
- **One response sink per connection.** only-http's transport hook (`only_http::transport`,
  `#[doc(hidden)]`, outside the semver promise) gets:
  - `ConnSink`: `send` / `start_stream`, each with a per-request `u64` tag;
  - `SharedSink`: a thin handle to it;
  - `dispatch_conn` / `start_conn`, and `request_target` for transports building requests.

  only-h3 answers every request of a connection through one sink (tag: stream index and HEAD
  flag), instead of boxing a sink and cloning three `Arc`s per request. Because the handle is a
  thin pointer, `Context`'s responder stays at 16 bytes. A fat `Arc<dyn ConnSink>` plus the tag
  grew `Context` by 8 bytes, which cost h2c about 1% of cycles, since HTTP/2 boxes a `Context`
  per request.
- Allocator calls per request (bpftrace on x86_64): `quic-bench h3` both ends 11.0 → 9.0;
  HTTP/1.1 server 6.0 → 5.0, pipelined 6.0 → 5.0, h2c 6.5 → 5.5. The earlier HTTP/3 entry's 8.6
  was counted another way; with this method, 776f001e (before ADR-011) makes 10.8.
- Same-run A/B on gpu51 (Zen 4, quiet host):
  - HTTP/3 GET, one connection, 64 in flight: 1.0059× (runs of 7 alternating rounds: 1.0087×
    and 1.0032×).
  - Server user-space cycles per request (`perf stat`, medians of 7): HTTP/1.1 0.951×,
    pipelined 0.968×, h2c 0.973×; instructions −1.2% to −1.4%.

| Before (deprecated, still compiles) | After |
|---|---|
| `impl ResponseSink for S` (`send(self: Box<Self>, resp)`) | `impl ConnSink for C` (`send(&self, tag, resp)`), one per connection |
| `transport::dispatch(&svc, req, Box::new(s))` | `let sink = SharedSink::new(c);` per connection, then `transport::dispatch_conn(&svc, req, &sink, tag)` |
| `transport::start(&svc, req, Box::new(s))` | `transport::start_conn(&svc, req, &sink, tag)` |
| `Request::new(m, path.to_owned())` | `Request::new(m, transport::request_target(path))` (optional) |

### Added: spans, push export (OTLP, StatsD), per-route HTTP labels, HTTP/2 gauges

Additive (ADR-020, docs/adr/020-spans-and-push-export.md):

- **Spans in only-log** (`only::log::span`): `Span`, `SpanBuilder`, `span!` / `info_span!` ...,
  `SpanContext` with W3C `traceparent` parsing and printing, `Tracer` (`set_tracer`), a maximum
  span level of its own (`set_max_span_level`, off by default: a disabled span costs one relaxed
  load), `enter` / `in_scope` / `enter_context` / `current`. `FmtLogger` adds `trace_id` /
  `span_id` inside a span. No `tracing` bridge (ADR-020 says why).
- **HTTP request and connection spans**: `only_http::request` (`info`, kind server) for every
  HTTP/1.x, HTTP/2 and HTTP/3 request, named `"GET /users/:id"` once routed, with method, path,
  route, protocol version, client address and status, child of an incoming `traceparent`;
  `only_http::connection` (`debug`) per connection. `Context::span_context()`,
  `Context::route()` (`RouteInfo`), `only_http::trace`.
- **Per-route HTTP metrics**: `HttpMetrics::with_routes(n)` labels requests and latency with
  the route's method and pattern (never the raw path), at most `n` routes (≤ 4096), then
  `route="other"`; unmatched requests are `route="unmatched"`. `HttpMetrics::route_snapshot()`,
  families `only_http_route_requests_total` and `only_http_route_request_duration_seconds`.
- **HTTP/2 gauges**: `observe::H2Stats` via the new `H2Config::stats`: connections and streams
  open and total, `RST_STREAM` and `GOAWAY` frames each way (`only_http2_*`).
- **New crate `only-export`**: pushes metrics (`Telemetry::collect_all()`, new, and extra
  collectors) and spans from one background thread to an OpenTelemetry collector over OTLP/HTTP
  (protobuf or JSON) and to StatsD / DogStatsD over UDP (counter deltas). Bounded span queue
  (drops and counts when full), failed pushes counted and not retried, timeouts on every OTLP
  step, sampling ratio. End-to-end test against the OpenTelemetry Collector in Docker
  (`tools/otel/e2e.sh`); fuzz targets `log_traceparent`, `export_http_response`, `export_otlp`.
- only-core: `Metrics::collect_into` and `Telemetry::collect_all` (the engine's series as
  `Families`, identical to the Prometheus rendering).

### Added: hot reload of the read buffer, backlog and UDP idle timeout; I/O thread resizing

ADR-028 (docs/adr/028-hot-reload-buffers-backlog-threads.md):

- `Engine::reload` now applies **`read_buffer`** (each I/O thread swaps its buffer between two
  batches of events, so open connections read with the new size from their next read; io_uring
  moves connections to a new provided-buffer group as their receives are re-armed), **`backlog`**
  (live listening sockets are `listen`ed again; new `only_sys::set_backlog`) and
  **`udp_idle_timeout`** (open peers' timers re-armed). `ReloadReport::ignored` now names
  `max_pending_responses`, `write_timeout`, `connect_timeout`, `udp_max_peers`, `udp_gro`.
  New `Live` getters/setters for the three settings.
- **`Engine::threads()` / `Engine::set_threads(index, n)`**: grow or shrink the I/O threads of a
  TCP listener or client group while the engine runs (epoll, kqueue, io_uring). Growing adds a
  `SO_REUSEPORT` socket per new thread (Linux) or a clone of the shared socket; shrinking retires
  the highest threads, which hand their listening sockets to the others (nothing queued is reset)
  and keep serving their own connections until they close: connections never move between
  threads. New `Config::retire_timeout` (default `None`, reloadable) shuts down what a retired
  thread still serves after it. `LoopMetrics::retiring`, Prometheus `only_loop_retiring`. UDP
  listeners, DPDK and BPF-steered listeners return `Unsupported`.
- only-prefork: **reload in place**: `Controller::reload_in_place` / `Supervisor::reload_in_place`
  and SIGUSR1 run each worker's `Worker::on_reload` hook (apply a new configuration and thread
  count without replacing processes); `Worker::reloads`, `Status::in_place_reloads`.
- Hot path unchanged (same-run A/B in docs/BENCHMARKS.md, "Hot reload").

### Added: documentation site for GitHub Pages, a runner for the book's examples

- `book/site.sh` builds the site published at `lesismal.github.io/only`: both books, a language
  switch and an API link on every page, localized 404 pages and a site-wide `404.html`, and the
  rustdoc of every published crate under `/api/`. `book/check-site.py` serves it under the same
  base path and checks every internal link, resource and fragment (also the crates' rustdoc
  links back to the book), that both books have the same pages, and the 404 handling.
  `.github/workflows/pages.yml` runs both and deploys on a published release or by hand; the
  release-only `book-deploy` job left `ci.yml`. Enabling Pages is a one-time repository setting.
- `book/check-guides.sh` runs every program the books include code from: the 21 `guide-*`
  examples (each exits 0 or fails), the serve-only ones (`guide-media`, `guide-media-rtsp`,
  `echo`, `udp-echo`, `hello`, `prefork-http`, probed from outside) and the gRPC chapter's
  generated stubs; on Linux in a private network namespace. Passes on macOS, Linux arm64 and
  Linux x86_64, on epoll and (`ONLY_DEFAULT_BACKEND=uring`) on io_uring.
- `ONLY_DEFAULT_BACKEND=uring` (ADR-029, Linux): TCP listeners that do not call
  `Listener::backend` are served by io_uring (non-strict: falls back to epoll with a warning).
  An explicit backend always wins; UDP listeners and client threads are not affected; read once
  per `Engine::build`. A test and diagnostic knob, so unchanged programs (the guide examples) can
  run on io_uring. No public API change.
- `book/check-includes.py` also checks that `book/en` and `book/zh-CN` have the same chapters
  with the same headings, includes, code blocks, table rows and list items.
- Docs brought in line with the code: WebSocket over HTTP/3 is no longer listed as missing;
  `H3Config` / `H3ClientOptions` field names and QPACK defaults, `DialOptions::proxy` /
  `max_redirects`, `ONLY_UDP_ECN` and `ONLY_LOG` in the configuration reference; only-quic is
  v1 and v2; the guide-example table lists all of them; the Chinese RTSP chapter gained the
  authentication bullet. Three broken rustdoc links fixed (only-log, only-h3, only-bittorrent).

### Added: WebSocket over HTTP/3, QPACK dynamic table, streamed HTTP/3 request bodies

Additive (ADR-011, docs/adr/011-h3-websocket-qpack-streaming.md):

- **WebSocket over HTTP/3** (RFC 9220). Servers advertise extended CONNECT;
  `Context::upgrade_websocket` accepts it with the same checks, subprotocols and
  `permessage-deflate` as on HTTP/1.1, answers `200` and carries the WebSocket on the request
  stream with the same `WsHandler` / `WsSender`. `Router` routes an extended CONNECT for
  `websocket` to the path's GET route, so one `.get("/ws", ...)` serves HTTP/1.1 and HTTP/3.
  New `Request::protocol` (`:protocol`). Client: `H3Client::websocket` /
  `websocket_blocking` with `H3WsOptions`; `H3Error::Status` for a refusal.
- **QPACK dynamic table** (RFC 9204), configured in `H3Config` on servers and in
  `H3ClientOptions` on clients (`H3Client::dial_with`): `qpack_max_table_capacity` (4096) and `qpack_blocked_streams` (16)
  for our decoder (encoder/decoder streams, blocked sections held in order, acknowledgements,
  increments and cancellations), `qpack_encoder_capacity` (0, off) for our encoder, which only
  references acknowledged entries so it never blocks the peer. New error codes
  `code::QPACK_ENCODER_STREAM_ERROR` / `QPACK_DECODER_STREAM_ERROR`. Servers now advertise a
  4 KiB table: nghttp3 (curl) and OpenSSL's QUIC use it at once.
- **Streamed request bodies on HTTP/3**: services with `BodyMode::Stream` get the body through
  `Context::on_body` as it arrives, as on HTTP/1 and HTTP/2, without `max_body_bytes`; the
  request reader never holds DATA payloads. Client: `H3Client::upload` returns an `H3Upload`
  (`write`, `finish`, `queued_bytes`).
- Interop: quic-go (WebSocket over HTTP/3 and streamed uploads both ways), libcurl with
  ngtcp2/nghttp3 and OpenSSL QUIC in Docker (nghttp3 fills our decoder's table). New fuzz
  target `qpack_dynamic`; `h3_frame` and `h3_request` cover the QPACK streams, blocked sections,
  extended CONNECT and the streaming reader.
- HTTP/3 throughput with the encoder off: `quic-bench h3` same-run A/B is 1.025x of the release
  without these features (881.3k vs 859.6k req/s on gpu51, two runs of 7 alternating rounds:
  1.024x and 1.027x, faster in all 14), about 300 fewer instructions per request (x86
  callgrind). A request or response that arrives whole (one HEADERS frame, at most one DATA
  frame) is read without the frame reader or per-stream state, the client decodes it before
  taking its lock, request deadlines index their queue by token instead of hashing, and a
  request opens its stream under the lock it already holds. Both QPACK encoders on cost
  18% on that benchmark (tiny requests, one acknowledgement each), which is why the encoder is
  off by default.

### Changed: safe defaults everywhere, loop-safe I/O, leaner hot paths (ADR-009, docs/rules.md)

New development rules (docs/rules.md, adapted from fit's): never block an I/O thread, bodies
streamed and bounded, linked backpressure, timeouts and safe-default limits everywhere, build
time over request time on the hot path, verification sized to the change. The code was audited
against them; every limit below has a safe default, and 0 / `None` stays the explicit opt-out.

**Engine (only-core, loops, only-tls)**
- `Config::write_timeout` 60 s (was `None`); `Config::udp_max_peers` 65536 (was `None`); new
  `Config::connect_timeout` (10 s) for `Engine::dial` on epoll, kqueue and io_uring.
- New `Config::max_pending_responses` (32): pipelined responses behind an unfinished one pause
  reads (and count toward the write watermark / `max_queued_bytes`) instead of piling up.
- TLS handshake timeout: `ServerConfigBuilder::handshake_timeout` /
  `ClientConfigBuilder::handshake_timeout` (10 s), enforced by the loops through the new
  `Transport::handshake_timeout`.
- Hot path: cork state is an atomic, the drain lock is skipped when nothing waits, command
  queues keep their capacity; ~7 → 4 uncontended lock operations per pipelined request.

**HTTP server (only-http)**
- `HttpConfig::head_timeout` 10 s (slowloris; 408), `keep_alive_timeout` 75 s, `body_timeout`
  60 s; HTTP/2 preface/SETTINGS deadline and idle GOAWAY.
- HTTP/2 Rapid Reset and flood budgets: `H2Config::max_resets` (100 per 30 s, MadeYouReset
  counted), `max_control_frames` (1000 per window) → GOAWAY ENHANCE_YOUR_CALM;
  `max_conn_pending_bytes` (32 MiB) over all streams.
- Static files touch the disk only on a pool (16 threads, 4096 queued, 503 when full); cache
  hits stay on the I/O thread, compressed twins (and their absence) are cached, headers are
  formatted once per entry, the cache is 16 RwLock shards.
- Request path: no shared `Arc` bump per routed request, 405 `Allow` precomputed, requests with
  a body routed once, metrics `in_flight` per shard, inline response filters, CORS / compress /
  limiter / csrf / request_id without per-request formatting or global locks. Pipelined
  HTTP/1.1 and h2c about +3–4% (same-run A/B), plain HTTP/1.1 within 1%.

**HTTP clients (only-http, only-h3)**: HTTP/1 response head 64 KiB, body 64 MiB, request
timeout 30 s, idle pool 32 per host / 256 in all, 90 s idle expiry; HTTP/2 frame size checked
before buffering, header blocks 2 × `max_header_list`, body 64 MiB, at most 32 pushes per
request; HTTP/3 body 8 MiB, field sections 64 KiB, request timeout 30 s. New
`ClientError::Timeout` / `TooLarge`, `H3Error::TooLarge`.

**gRPC and arpc**: the global `Mutex<Vec>` deadline threads are replaced by a cancellable,
sharded deadline service (calls with a deadline: gRPC ×17, arpc ×278 calls/s; without: +1%).
`grpc-timeout` clamped to `GrpcServer::max_deadline` (24 h), `GrpcClient::default_timeout`
(30 s), `max_collect_bytes` (64 MiB); arpc `Routes::max_streams_per_conn` (1024) and
`call_timeout` (30 s); fewer copies and locks per message.

**WebSocket, media, WebRTC**: compressed (permessage-deflate) messages are bounded too (close
1009); frames encoded on the stack and buffers reused (plain echo at 1 KiB +7–11%). RTMP chunk
reader parses in place (was O(n²) copying) with a 32 MiB partial cap; HLS segments cut at
`max_bytes` without keyframes; hub 1024 streams / 1000 subscribers per path, WHIP 256 sessions,
SRT 1024 connections, RTMP handshake 10 s / idle 60 s, RTSP session timeout enforced (60 s) and
request timeout 10 s; `RtcServer` / `Endpoint::max_peers` (1024).

**QUIC, HTTP/3, KCP**: per-stream and per-connection QUIC send buffers (16 MiB each) with
`Error::Overloaded` and `QuicHandler::on_stream_writable`; `receive_window` 10 MB (was
unlimited); `ServerConfig::max_connections` (10,000, stateless CONNECTION_REFUSED). HTTP/3 file
bodies are read on the pool only as the stream has room. KCP `max_sessions` 4096 and
`KcpHandler::on_writable`. A 4 MiB per-stream default cost QUIC single-stream bulk about 2.5%, so the stream default
equals the connection's (16 MiB matched the baseline on gpu51).

**SOCKS, mux, TURN, BitTorrent, log, DTLS**
- SOCKS / HTTP CONNECT: **destinations default to public addresses only** (loopback, private,
  link-local, CGNAT, multicast and reserved refused after resolution, including mapped forms;
  also for BIND and UDP ASSOCIATE); handshake 10 s, idle 5 min, early data capped at 256 KiB,
  CONNECT DNS on a bounded pool.
- only-mux sniff timeout 5 s. TURN allocations sharded by client (relay throughput about
  140k → 513k datagrams/s). BitTorrent tracker DNS off the I/O threads, tracker server 100k
  swarms / 1000 peers per swarm with eviction, uTP inbound table 1024. only-dtls bounds
  reassembly before the cookie exchange.
- only-log: opt-in `FmtLogger::non_blocking` (bounded queue, drops and counts); the default
  stays synchronous.

### Added: HTTP and WebSocket client redirects, timeouts, proxies, system roots (ADR-010)

- Redirects, opt-in: `client::RedirectPolicy` (`none()` by default, `limit(n)`,
  `allow_https_downgrade`) with `Client::with_redirects`. 301/302/303/307/308 with RFC 9110
  section 15.4 method and body rules, relative `Location`s, `Authorization` / `Cookie` /
  `Proxy-Authorization` dropped on a redirect to another origin, https → http not followed by
  default, `ClientError::TooManyRedirects` past the limit; `ClientResponse::url` is the URL that
  answered. The WebSocket handshake follows them with `DialOptions::max_redirects` (default 0;
  `WsClientError::TooManyRedirects`).
- Per-request timeout: `ClientRequest::timeout` / `.timeout(d)` and `Client::with_timeout`,
  covering resolution, connecting, TLS, the response and redirects (`ClientError::Timeout`, the
  connection is closed). `H2Client` honours it by resetting the stream.
- Name resolution off the calling thread: new `only::dns::resolve` (a dependency-free pool of up
  to four resolver threads; IP literals inline), used by the HTTP/1 and WebSocket clients.
- System root certificates: `only::tls::RootCerts::system()` (`SSL_CERT_FILE` / `SSL_CERT_DIR`,
  macOS keychains via `/usr/bin/security`, Linux/BSD CA bundles and directories). **Behaviour
  change:** `Client` without `with_tls` and `DialOptions::tls = None` now use it for `https://` /
  `wss://` instead of failing.
- HTTP proxies: `only_ws::proxy::Proxy` (re-exported as `only_http::client::Proxy`; `all`,
  `http`, `https`, `no_proxy`, opt-in `from_env` for `HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY`),
  `Client::with_proxy`, `DialOptions::proxy`. `http://` in absolute form, `https://`, `ws://` and
  `wss://` through `CONNECT`; credentials in the proxy URL become `Proxy-Authorization: Basic`;
  a refusal is an `io::Error` carrying `ProxyRefused`.
- The WebSocket client closes its open connections with 1001 (going away) when its engine shuts
  down gracefully (they ended with 1006).

### Added: SOCKS5 BIND and UDP ASSOCIATE, a SOCKS access-control hook, `Engine::adopt_tcp`

- `only-socks` serves SOCKS5 `BIND` and `UDP ASSOCIATE` (RFC 1928), both off by default
  (`Socks::bind(true)`, `Socks::udp_associate(true)`; `bind_timeout`, `udp_idle_timeout`).
  UDP: one relay socket per association (the engine needs `udp_client_threads`), client
  recognised by IP and port, fragments dropped, answers relayed only from destinations the
  client sent to, ends with the control connection or after the idle timeout. BIND: listener on
  the proxy's address, two replies, the accepted connection relayed with backpressure.
- `Socks::allow(|request| ..)`: an access-control hook over `CONNECT` (SOCKS5/4/4a), `BIND`,
  `UDP ASSOCIATE` and each UDP destination, with the new `Command`, `Dest` and `Request` types.
  Refusals answer reply 2 (SOCKS4: 0x5b) or drop the datagram.
- `Engine::adopt_tcp(stream, acceptor, on_error)` serves a TCP stream accepted outside the engine
  like a dialed connection (epoll and io_uring).
- Interop: `tools/interop/socks/run.sh` (curl, PySocks, BIND and UDP edge cases; Dante as the
  reference server). ADR-012. Additive API (`api/only-socks.txt`, `api/only.txt`).

### Added: `ONLY_LOG` filter directives and compile-time log level caps

- `only::log::Filter`: per-target levels from env_logger-style directives
  (`info,only_http=debug,only_quic::conn=trace,only_http::access=off`), parsed once.
  `only::log::init_from_env(default)` installs the formatted logger filtered by `ONLY_LOG`; it is
  opt-in, nothing reads the environment otherwise. `FmtLogger::filter` / `init_filtered` take a
  filter built in code.
- only-log cargo features `max_level_*` / `release_max_level_*` and `STATIC_MAX_LEVEL`, as in
  the `log` crate: statements above the cap are compiled out. Without them the generated code is
  unchanged (disabled `trace!`: 0.400 → 0.401 ns on x86_64, same binary on macOS). ADR-012.
  Additive API (`api/only-log.txt`).

### Added: shared 0-RTT anti-replay store (only-tls) and compatible version negotiation (only-quic)

Additive API (ADR-013, docs/adr/013-shared-anti-replay-and-compatible-vn.md):

- **`AntiReplayStore`** (only-tls): where a server records the ClientHellos whose early data it
  accepted. One method, `check_and_insert(binder, ttl) -> io::Result<bool>`, atomic, called on
  the handshake path only for ClientHellos whose early data would otherwise be accepted. Errors
  **fail closed** (the early data is rejected, the client sends it again after the handshake).
  `MemoryAntiReplay` is the default (the existing bounded per-configuration record, 100,000
  entries), now public. `ServerConfigBuilder::anti_replay_store(Arc<dyn AntiReplayStore>)`
  plugs in a shared one (Redis `SET key 1 NX PX ttl`, sketched in the book's TLS chapter);
  `ServerConfigBuilder::session_ticket_key([u8; 48])` lets servers in several processes or
  machines accept each other's tickets in the first place. QUIC servers get both through their
  TLS configuration. Accepted ClientHellos are now kept 30 s (was 20 s): twice the 10 s
  freshness window plus one window for the clocks of servers sharing a store to differ by.
- **Compatible version negotiation** (only-quic, RFC 9368 section 4):
  `ServerConfig::prefer_version(Version)` moves clients that start in the other version and list
  the preferred one in their version_information to it within the handshake, without a round
  trip; also when the ClientHello spans several packets, after a Retry, and with 0-RTT (whose
  packets stay in the client's first version, RFC 9369 section 4.1). Off by default: the server
  answers in the client's version. only-quic clients always follow such a switch (a forged
  Initial of the other version that does not decrypt does not move them).
- Tests: two TLS servers sharing a ticket key and a "remote" store reject a ClientHello replayed
  from one to the other (accepted with separate records), a failing store rejects early data,
  the same over QUIC on the simulated link; compatible negotiation on the simulated link (no
  extra round trip, Retry and 15% loss, a ClientHello over two packets, 0-RTT across the switch, v2
  to v1, no switch without the preference or without v2 in the client's list, a forged Initial).
  Fuzzing: the `quic_conn` pair now switches to v2, and `tls_server` also runs the ClientHello
  peek. Interop: `tools/interop/quic/ngtcp2-cvn.sh` (new) with ngtcp2 1.11, which implements RFC
  9368, both ways in Docker (its client moved to v2 by only-h3, with 0-RTT; only-quic moved to v2
  and to v1 by its server); quic-go does not implement RFC 9368, so `tools/interop/quic/run.sh`
  checks that its clients keep their version against servers preferring the other one.
- Cost: none measured (BENCHMARKS.md, handshake A/B).

### Changed: QUIC session tickets and tokens are bound to the QUIC version (only-tls, only-quic)

RFC 9369 section 5 (ADR-014, docs/adr/014-quic-version-bound-resumption.md):

- A session ticket or NEW_TOKEN token belongs to the QUIC version of the connection that issued
  it, the negotiated one after compatible version negotiation. Servers resume only a ticket from
  the version the client started in (another one gets a full handshake without 0-RTT) and
  validate addresses only with tokens from it; Retry tokens are bound the same way.
- Clients never present a v1 ticket or token in v2 or the reverse: they start in the version of
  their newest ticket for the server (else of their token) when they speak it, instead of
  `ClientConfig::version`. A client configured for v1 that a server preferring v2 moved to v2
  starts its next connection in v2 and resumes with 0-RTT, without a switch.
- Upgrading: tickets and tokens issued before are unbound and no longer accepted by QUIC servers
  (one full, unvalidated handshake per client). TLS over TCP is unaffected (format 2 sessions
  still decode). No public API change (the hidden `only_tls::quic` interface gains versioned
  constructors).
- Tests: only-tls tickets per version (offered, rejected, moved by `set_ticket_version`, unbound
  handshakes kept apart); only-quic token checks per version; on the simulated link a client
  moved to v2 resumes in v2 with ticket, token and 0-RTT, and a v1 ticket is not used in v2.
  Interop: `tools/interop/quic/ngtcp2-cvn.sh` now also checks that ngtcp2 1.11's client, which
  restarts in v1 with a ticket from a connection moved to v2, gets a full handshake, and resumes
  with 0-RTT when it starts in v2 (0-RTT across a switch still checked, with a v1 ticket from a
  twin port sharing the ticket key).

### Changed: Poly1305 on AVX2 for CPUs without AVX-512 IFMA

only-crypto's Poly1305 (and so ChaCha20-Poly1305) absorbs four blocks per step on AVX2 in radix
2²⁶ for runs of 512 bytes and more on x86_64 CPUs without AVX-512 IFMA (Zen 2 and 3, most Intel
client parts); it was the scalar loop. Measured on Zen 4 through the AVX2 path: ChaCha20-Poly1305
seal 16–64 KiB +20%, 1 KiB +7% (docs/BENCHMARKS.md). CPUs with IFMA and messages under 512 bytes
are unchanged. No public API change.

### Added: multi-range static file responses, open-file cache eviction, partial-segment routes

- `files::Files` answers several ranges (`Range: bytes=0-9,500-599`) with `206` and a
  `multipart/byteranges` body (RFC 9110 section 14.6), parts in request order. Overlapping ranges
  and ranges less than 80 bytes apart are coalesced (section 14.2); ranges past the end are
  dropped and `416` comes only when none is left; a header with more than 32 ranges, or parts
  adding up to more than 1 MiB, is ignored and the whole file is sent. `If-Range` applies as for
  single ranges. Malformed range specs keep answering `416`.
- The open-file cache (`Files::max_open_files`) evicts the least recently used handle (CLOCK)
  instead of serving new files uncached once it is full, notices a file renamed over a cached one
  (device and inode are compared along with size and modification time) and drops entries of
  deleted files.
- `Router` patterns may mix literal text and parameters in one segment: `/{name}.txt`,
  `/v{major:[0-9]+}.{minor}`, `/{owner}/{repo}.git` (ADR-007). Matching is linear, with no
  backtracking inside a segment; precedence is static > partial > regexp > parameter > wildcard.
  Lookups stay allocation-free. A static segment containing a `{…}` group is now a pattern, and
  unbalanced braces panic at registration.

No public API change (`api/only-http.txt` unchanged).

### Added: TLS record_size_limit, certificate compression and OCSP stapling (only-tls)

Additive configuration (ADR-008, docs/adr/008-tls-extensions.md):

- **record_size_limit** (RFC 8449, TLS 1.3 and 1.2): `ServerConfigBuilder::record_size_limit` /
  `ClientConfigBuilder::record_size_limit` (64 to 16385, default 16385). The client always sends
  its value, the server answers with its own when the client sent one; each side then cuts the
  protected records it writes to the peer's limit and refuses records over its own
  (`record_overflow`). Early data goes under the limit of the connection that issued the ticket.
  Not used over QUIC. Kernel TLS offload (experimental) is refused under a peer limit below
  16 KiB.
- **Certificate compression** (RFC 8879, TLS 1.3, zlib through only-deflate; no in-house
  brotli/zstd, so only zlib is offered): `certificate_compression(bool)` on both builders, **on
  by default on the server** (chains compressed once and reused, no cost per handshake) and
  **off by default on the client** (inflating a received chain costs about 1–2 µs, ~1% of an
  in-memory handshake). Client certificates are compressed when the server's
  CertificateRequest offers it. Received messages are inflated into
  at most 128 KiB and must match the announced length.
- **OCSP stapling**: `ServerConfigBuilder::ocsp_response(der)` / `sni_ocsp_response(name, der)`
  staple a DER response for clients that ask (TLS 1.3 CertificateEntry, TLS 1.2
  CertificateStatus; not on resumption); `ClientConfigBuilder::ocsp_stapling(true)` asks, and
  the new `TlsInfo::ocsp_response` holds the response. **Not validated** (no OCSP in only-x509
  yet); the server only checks the configured value is a successful `OCSPResponse` in shape.
- ClientHellos now carry record_size_limit (6 bytes). `only-tls` depends on `only-deflate`.
- Fixed: a TLS 1.3 KeyUpdate of the wrong length is `decode_error` (was `illegal_parameter`;
  tlsfuzzer's "large KeyUpdate message" probe failed at random).
- Tests: in-memory matrix with the extensions (both versions, key types, limits down to 64
  bytes both ways, compression either side off, OCSP with SNI and resumption), negative cases,
  fuzz corpora; interop (`tools/interop/tls/run.sh`) with OpenSSL (OCSP verified by s_client,
  zlib compression both ways with Debian's OpenSSL 3.5, max_fragment_length ignored), Go (OCSP
  both ways) and GnuTLS (record_size_limit and OCSP both ways); tlsfuzzer
  `test-record-size-limit.py`, `test-tls13-certificate-compression.py` and
  `test-tls13-client-certificate-compression.py`. Handshakes unchanged (same-run A/B,
  docs/BENCHMARKS.md).

### Added: pluggable metrics collectors (ADR-015)

Application and protocol metrics on the engine's `/metrics` endpoint, with no third-party crate.
New module `only::metrics` (`only_core::metrics`): the `Collector` trait, the `Families` snapshot
(Prometheus text 0.0.4 or JSON, or read through `iter` / `get`), instruments `Counter`, `Gauge`,
`Histogram` and a `Registry` of named instruments, `fn_collector`, `DEFAULT_BUCKETS`.
`Telemetry::register_collector(collector, labels)` / `unregister_collector`, `Telemetry::collect`
and `Telemetry::render_prometheus` (engine series, then the collectors), which
`observe::metrics_handler` now serves. Ready-made collectors: only-http `HttpMetrics` (plus a new
family `only_http_requests_by_version_total{version}`, field `HttpSnapshot::by_version`,
`observe::VERSION_LABELS`), only-quic `QuicServer` (`only_quic_*`: connections, datagrams and
bytes each way, packets sent and lost, congestion events; totals include closed connections) and
only-tls `Tls::stats()` → `TlsStats` / `TlsCounts` (`only_tls_handshakes_total{side, version}`,
`only_tls_resumed_total`, `only_tls_early_data_total{outcome}`). Additive only; the engine's own
series are unchanged. Example: `cargo run -p only-http --example guide-metrics`.

The engine's telemetry overhead was measured on a quiet host (same-run A/B, docs/BENCHMARKS.md
"Telemetry overhead"): no measurable cost on HTTP/1.1 (0.998–1.006× with callback timing off or
the counters compiled out); echo rows within their noise. `HttpMetrics::middleware()` with the new
per-version count: 0.997–1.005× the previous middleware.

### Changed: faster ChaCha20-Poly1305 for short messages on AVX-512

On x86_64 with AVX-512, only-crypto's ChaCha20 runs four blocks with one row of each block per
register (the head of a message and short tails), puts a partial last group through the kernel
under byte masks instead of a buffer, and picks a head of four or eight blocks by measured kernel
cost; the AEAD's Poly1305 skips its streaming buffer. Zen 4, same-run A/B: seal 64 B 408 → 481
MB/s (0.83× → 0.98× ring), 1 KiB 1.00× → 1.08×, 1400 B 0.99× → 1.21×; open 64 B 0.76× → 0.85×;
TLS 1.3 ChaCha20-Poly1305 records at 1 KiB 1.09× → 1.15× rustls + ring (docs/BENCHMARKS.md).
16 KiB and up unchanged. No public API change.

### Changed: RSA verification on AVX-512 IFMA, about 2.5–3.4× faster

On x86_64 with AVX-512 IFMA, the RSA public operation `sᵉ mod n` (signature verification, and the
check of each signature before it is released) now runs in radix 2⁵² for 2048-, 3072- and 4096-bit
moduli (new 3072- and 4096-bit almost-Montgomery multiplications), with 18 products for
`e = 65537` instead of 21; building a public key computes `R² mod n` with a faster long division
and no Montgomery multiplication. Zen 4, same-run A/B on a quiet host: RSA-2048 / 3072 / 4096
PKCS#1 verify 2.51× / 3.00× / 3.39× faster (1.22× / 1.10× / 1.09× → 3.07× / 3.30× / 3.70× ring),
verify including the key parse 2.31× / 2.76× / 3.04× (1.02× / 0.95× / 0.95× → 2.35× / 2.64× /
2.90× ring), signing 2–4%; TLS 1.3 handshakes with an RSA-2048 certificate 1.67× → 1.82× rustls +
ring (docs/BENCHMARKS.md). Without IFMA (and with `ONLY_CRYPTO_PORTABLE=1`) the fewer products and
the faster division still help: portable verify 0.59× → 0.70× ring at 2048 bits. Private-key
exponentiation and its constant-time properties are unchanged. No public API change.

### Changed: fewer allocations per HTTP/3 request

An HTTP/3 request and its response now cost 8.6 allocations at both ends of `quic-bench h3`
instead of 21.6: only-quic hands stream data to the application without temporary vectors;
only-h3 writes small response and request heads into only-quic's per-thread pooled buffers
(a hidden `Bytes::pooled`, not a public API) and widens a HEADERS frame's length in place;
only-http's `Context` owns its request until a `Detached` or a WebSocket upgrade shares it, and
`Headers` keeps its first two field positions inline (still 48 bytes). QPACK writes `:status`,
`content-length` and the date line (encoded once a second) without a static table search, and a
request head is checked as UTF-8 once. Zen 4, same-run A/B on a quiet host: HTTP/3 GET, one
connection, 64 in flight 820,741 → 883,127 req/s (1.08×); HTTP/1.1 and h2c unchanged within
noise (docs/BENCHMARKS.md). No public API change.

### Fixed: building an io_uring engine no longer exposes that thread to spurious `EINTR`

`io_uring_setup` attaches the calling thread to the new ring, and when a ring is torn down the
kernel's exit work sends every attached thread a signal-like task_work (`TIF_NOTIFY_SIGNAL`). The
backend probe and every I/O thread's ring were created on the thread that called
`EngineBuilder::build` (or `Engine::set_threads`). So when the probe's ring, or later the
engine's rings, were torn down, that thread could be interrupted. A blocking call the kernel
does not restart, such as a socket read with a timeout, then failed with `EINTR`. That happened
long after the build, in code that has nothing to do with io_uring. Rings are now created, and
the probe runs, on a short-lived thread of their own, which the kernel detaches when it exits;
each I/O thread still attaches itself when it enables its ring. This was the occasional failure
of only-socks' `udp_blocking_and_on_the_engine` on io_uring (about 3 runs in 100 under load):
its blocking `recv_from` returned `EINTR` although every hop of the relay had delivered the
datagram. The new test `uring_engine_teardown_does_not_interrupt_the_building_thread` (only's
`engine` tests) failed every run before. No public API change; the I/O path is unchanged.

### Fixed: a QUIC client's 0-RTT no longer goes out ahead of its Initial

`only_quic::dial` opens the client's UDP socket on an engine thread and keeps the datagrams sent
before that in a backlog. The socket was published before the backlog was flushed, so another
thread sending in between (a request right after an `H3Client::dial` resuming with 0-RTT) put its
0-RTT packets on the wire ahead of the Initial. The server, without 0-RTT keys yet, dropped them,
and the requests went again in 1-RTT after the handshake, unmarked, although the server had
accepted 0-RTT. A datagram queued just as the backlog was flushed could also stay there, unsent.
The backlog is now flushed, and the socket published, under the backlog's lock (the same for a
migration probe's socket). This was the occasional failure of only-h3's `zero_rtt` test (about 2
runs in 100 under load), which now holds the server's handshake flight in a relay until its
requests are sent, and waits for session tickets instead of sleeping. No public API change.

### Fixed: `only_bittorrent::Client::close` waits for its threads

TSan's first run (below) reported a thread leak: `close` shut the engine and the disk pool down
and returned at once, so I/O-thread callbacks and `Storage` calls could still run after it, and
dropping the client detached the threads. `close` now returns once the engine's I/O threads, the
disk pool and the maintenance thread have exited. It must therefore not be called from one of the
client's own threads (inside a `Storage` method, for example).

### Fixed: the HTTP client no longer holds an engine's graceful shutdown open

`only_http::client::Client` kept idle keep-alive connections in its pool through the engine's
graceful shutdown, so `Engine::wait` waited out the whole `Config::shutdown_timeout` (10 s by
default) whenever the client had made a request. Idle connections now close when the shutdown
starts; one with a request in flight delivers the response and then closes instead of going
back to the pool.

### Added: AddressSanitizer and ThreadSanitizer runs (`tools/sanitizers/`)

First ASan (with LeakSanitizer) and TSan run of the workspace tests, 2026-11-16: every crate in
Linux arm64 Docker on epoll and io_uring, the crates with unsafe code and the engine backends on
x86_64 (with the AVX-512/IFMA/VAES/BMI2 assembly paths). No memory error, memory leak or data
race; the thread leak above was the one report. `tools/sanitizers/run.sh` runs them per crate,
in Docker or natively, and the heavy CI job `sanitizers` now uses it for the whole workspace
instead of eight crates. Its `rustc-wrapper.sh` builds `compiler_builtins` uninstrumented, without
which every sanitized binary crashed at start-up on aarch64 with `-Zbuild-std`. Two tests were
adjusted for TSan: `only-sys`'s `signal_to_pipe` raises the signal on the waiting thread (TSan
never ran the handler of a signal delivered to a thread in a raw futex wait), and only-ws's
client tests scale their 10 s deadlines with `ONLY_TEST_TIMEOUT_SCALE`.

### Changed: RSA signing runs both CRT halves in one AVX-512 IFMA loop

On x86_64 with AVX-512 IFMA, the two half-exponentiations of an RSA private-key operation (mod p
and mod q) now advance together, one digit step of each per iteration of one assembly loop, so
their serial reduction chains overlap instead of each waiting on its own. Zen 4, same-run A/B on a
quiet host: RSA-2048 PKCS#1 sign 3,867 → 5,231/s (1.63× → 2.20× ring), RSA-3072 1,436 → 1,691
(2.19×), RSA-4096 753 → 870 (2.55×); TLS 1.3 handshakes with an RSA-2048 certificate 1.45× →
1.69× rustls + ring (docs/BENCHMARKS.md). Verification, other CPUs and keys whose primes differ in
size are unchanged. Still constant time (no branch on secret data, checked in the disassembly).
No public API change.

### Changed: TLS records sealed and opened without zero-filling the output first

The TLS record layer no longer zero-fills the space for a record's ciphertext or plaintext
before the AEAD writes it: only-crypto's AES-GCM and ChaCha20-Poly1305 gained hidden
`encrypt_append` / `decrypt_append`, which write straight into a `Vec<u8>`'s spare capacity
(through a small `unsafe` module, `only_crypto::fill`, that extends the vector only once every
byte was written; a failed open appends nothing and zeroes what it wrote). only-tls stays
`#![forbid(unsafe_code)]`. TLS 1.3 records on Zen 4 (seal + open, same-run A/B): AES-128-GCM
+6.9–8.3%, AES-256-GCM +7.4–8.7%, ChaCha20-Poly1305 +3.3–6.4% (docs/BENCHMARKS.md). No public
API change.

### Added: `Conn::set_relayed` for application-built relays

Relays built on `hold_reads` / `on_drain` can now opt out of the engine's write-watermark read
pause with `Conn::set_relayed(true)` (and `only_http::raw::RawConn::set_relayed` for `CONNECT` /
upgrade relays). Without it, a two-way relay to a peer that only reads once it can write could
deadlock: the same bug fixed inside only-socks, now avoidable in application code. Takes effect
at once; `Config::max_queued_bytes` still applies. Additive public API (snapshots updated).

### Renamed: the project is now `only`

The crates.io name `flash` is taken, so the project was renamed from **flash** to **only**
(DEV-PLAN "1.0.0 release decisions"). Every crate, path, identifier and name changed with it;
the entries below already use the new names.

| Before | After |
|---|---|
| crate `flash` (`use flash::...`) | `only` (`use only::...`) |
| crates `flash-*` (`flash_*` in code), directories `crates/flash-*` | `only-*` (`only_*`), `crates/only-*`: `flash-sys` → `only-sys`, `flash-buf` → `only-buf`, `flash-timer` → `only-timer`, `flash-pool` → `only-pool`, `flash-core` → `only-core`, `flash-epoll` → `only-epoll`, `flash-uring` → `only-uring`, `flash-tls` → `only-tls`, `flash-http` → `only-http`, `flash-ws` → `only-ws`, `flash-mux` → `only-mux`, `flash-socks` → `only-socks`, `flash-arpc` → `only-arpc`, `flash-grpc` → `only-grpc`, `flash-kcp` → `only-kcp`, `flash-quic` → `only-quic`, `flash-h3` → `only-h3`, `flash-ebpf` → `only-ebpf`, `flash-prefork` → `only-prefork`, `flash-dpdk` → `only-dpdk`, `flash-turn` → `only-turn`, `flash-webrtc` → `only-webrtc`, `flash-media` → `only-media`, `flash-bittorrent` → `only-bittorrent` |
| environment variables `FLASH_*` (`FLASH_TEST_BACKEND`, `FLASH_UDP_GSO`, `FLASH_UDP_GRO`, `FLASH_PREFORK_*`, `FLASH_CHAOS*`, `FLASH_DPDK_*` ...) | `ONLY_*` |
| Prometheus series `flash_*` (`flash_connections_open`, `flash_http_requests_total`, `flash_tls_handshake_failures_total` ...) | `only_*` |
| log targets `flash`, `flash_http::access`, `flash_webrtc` ... | `only`, `only_http::access`, `only_webrtc` ... |
| thread names `flash-io-*`, `flash-pool`, `flash-quic-timer` ... | `only-io-*`, `only-pool`, `only-quic-timer` ... |
| `flash_media::srt` alias `FlashConn` | `OnlyConn` |
| API snapshots `api/flash-*.txt`, tool Docker images and volumes `flash-*` | `api/only-*.txt`, `only-*` |

The GitHub repository and the documentation site keep their `lesismal/only` URLs until the
repository itself is renamed.

### Evaluated: io_uring registered files, `SEND_ZC`, `MSG_RING` wake-ups, ring-based sends (not adopted)

- Measured on Linux 7.0 / Ryzen 7 7800X3D against the rule "same-run gain of at least 3%, no
  regression elsewhere" (docs/BENCHMARKS.md, "io_uring features evaluation"); none qualified, so
  the io_uring backend is unchanged. `SEND_ZC` was 12–27% slower with 10–36% more CPU per request
  from 16 KiB to 256 KiB (loopback always copies); `MSG_RING` wake-ups from threads without a ring
  (`IORING_REGISTER_SEND_MSG_RING`) gave +1.5–4.8% on `spawn_blocking` round trips and −1.3% to
  +0.2% elsewhere; a registered ring fd −3.6% to +0.5%; registered files have nothing to save in
  the engine (no submission per request in steady state). Ring-based sends (`IORING_OP_SEND`)
  were +1–4% with 2–6% less CPU per request on a bare ring, but need a redesign of the shared
  write path (writes come from any thread) and are left as a follow-up.
- New measurement harness: the ignored `eval_server` test in only-uring (`src/eval.rs`, a minimal
  HTTP/1.1 responder on the raw ring: `write` / `SEND` / `SEND_ZC`, optional direct accept and
  registered files) and `tools/bench/uring-eval.sh`. The extra io_uring bindings it uses
  (`SEND`, `SEND_ZC`, direct accept, fixed-file close, sparse `REGISTER_FILES`, `MSG_RING` and
  `REGISTER_SEND_MSG_RING`) are compiled for tests only. No public API change.

### Added: TLS 1.3 early data and QUIC 0-RTT (opt-in, with replay protection)

- **`only-tls`**: early data (RFC 8446 section 4.2.10), off by default on both sides.
  `ServerConfigBuilder::early_data(max_bytes)` issues tickets with `max_early_data_size` and
  accepts early data for the ticket's first PSK, cipher suite, ALPN protocol and SNI name (never
  after a HelloRetryRequest; more than allowed is `unexpected_message`); it is read before the
  handshake completes and EndOfEarlyData ends it. `ClientConfigBuilder::early_data(true)` sends
  what the application writes before the handshake as early data, up to the ticket's limit, and
  sends it again after the handshake if the server rejects it (also after a HelloRetryRequest).
  New `EarlyData` (`NotAttempted`, `Pending`, `Accepted`, `Rejected`) and
  `TlsInfo::early_data` / `early_data_len`.
- **Replay protection** (always on with early data): a 10-second freshness window on the
  ticket age (RFC 8446 section 8.3) and a per-`ServerConfig` record of the PSK binders of
  accepted ClientHellos, kept for 20 seconds and bounded at 100,000 (section 8.2): a replayed
  ClientHello's early data is rejected, a full record rejects early data until entries expire.
  Not across processes or machines sharing tickets (documented).
- **`only-quic`**: 0-RTT (RFC 9001 section 4.6), `ServerConfig::zero_rtt` /
  `ClientConfig::zero_rtt` (default off). Resuming clients start from the remembered transport
  parameters (RFC 9000 section 7.4.1), open streams right after `dial` and send them in 0-RTT
  packets (v1 and v2), coalesced behind the Initial. Servers accept 0-RTT only under the limits
  the ticket was issued with, answer in 0.5-RTT, and the client resends rejected or lost 0-RTT
  data (in 0-RTT after a Retry, else in 1-RTT). New `Connection::early_data` and
  `Connection::is_early(stream)`.
- **HTTP**: only-h3 marks requests that arrived in 0-RTT with `Early-Data: 1` (RFC 8470), and
  `H3Client` sends its requests in 0-RTT when its QUIC config enables it; only-http over TLS
  marks HTTP/1.1 requests that arrived as early data (and every HTTP/2 request of a connection
  that began with early data). Handlers answer `425 Too Early` to what is not safe to repeat.
- Tests: TLS state machine (accept, reject, HelloRetryRequest, replay, stale ticket age,
  ALPN/SNI binding, `max_early_data` limits), QUIC on the simulated network (accept, reject,
  lost 0-RTT packets, Retry, a replayed first flight, v2), loopback QUIC, HTTP/3 and HTTP/1.1
  over TLS. Interop: 0-RTT with quic-go both ways in v1 and v2 (`tools/interop/quic/run.sh`),
  early data with OpenSSL `s_client` / `s_server -early_data` both ways, accepted and rejected
  (`tools/interop/tls/run.sh`). Fuzz seeds for 0-RTT packets and early-data handshakes.
- Also: packets processed after waiting for their keys, and 0-RTT / 0.5-RTT packets, no longer
  give RTT samples; 0-RTT in flight does not hold back the handshake probe timer.
- Security: early data and 0-RTT are not forward secret and can be replayed beyond what one
  server's record sees; the READMEs and the guide say when (not) to enable them.

### Added: ECN, BBR, client migration, preferred_address and QUIC v2 in `only-quic`

- **ECN** (RFC 9000 section 13.4, RFC 9002 section 7.1), `TransportConfig::ecn` (on by
  default): on Linux packets go out ECT(0) and received codepoints are reported in ACK_ECN
  frames; the path is validated with a ten-packet testing period and the peer's counts, CE marks
  are congestion events, and a path that bleaches, re-marks or drops marked packets falls back to
  unmarked ones. New `ConnectionStats::ecn_capable` / `ecn_ce_events`. The UDP layer carries the
  codepoint per datagram: `IP_RECVTOS` / `IPV6_RECVTCLASS` on receive, an `IP_TOS` /
  `IPV6_TCLASS` control message per `sendmmsg` message (`only_sys::enable_ecn`,
  `ecn_available`, `RecvBatch::ecn`, `Batch::push_ecn`; `ONLY_UDP_ECN=0` turns it off).
- **BBR**: `Congestion::Bbr` no longer runs CUBIC. It is BBRv1's model and state machine on
  delivery-rate samples, with BBRv2/v3's bound on rounds that lose or CE-mark more than 2%.
  Through netem in network namespaces on the bench host (100 Mbit/s, 40 ms RTT, a 40 MB echo
  each way): 73 against CUBIC's 5 Mbit/s with 1% loss, 75 against 36 Mbit/s with a 60-packet
  buffer, both 84 Mbit/s on a clean deep buffer. Experimental.
- **Client migration**: `Connection::migrate(&engine)` moves a client connection to a new
  local UDP socket, or to the server's preferred address, after probing the new path under a
  connection ID not used before; it stays on the old path when the probe goes unanswered.
  `Connection::preferred_address()`, `Error::Migration`.
- **preferred_address**: `ServerConfig::preferred_address(addr)` offers it (connection ID
  sequence number 1 and its reset token); `QuicServer` is now `Clone`, so the same server serves
  that address on a second listener.
- **QUIC version 2** (RFC 9369): `Version`, `ClientConfig::version`, `ServerConfig::versions`,
  `Connection::version()`. Servers accept 1 and 2; a client answered with Version Negotiation
  starts over once in a common version, guarded by RFC 9368's version_information parameter.
  Compatible version negotiation (switching inside a handshake) is not implemented.
- Interop (`tools/interop/quic/run.sh`): quic-go both ways in version 2 (below quic-go's first
  key update: quic-go v0.62 derives version 2 key update secrets with the version 1 label,
  against RFC 9369 section 3.3.2), client migration both ways, our side with BBR, and on Linux
  ECN validated against quic-go.
- Answers to path probes from another address now use a connection ID of their own (RFC 9000
  section 9.5); quic-go's migrating clients need that.
- Not done: 0-RTT.

Cost on the loopback benchmarks (`quic-bench`, bench host, CPUs 2–5, median of five alternating
rounds against the merge base): bulk 18,704 → 18,288 Mbit/s (−2.2%; −1.5% with
`ONLY_UDP_ECN=0`), HTTP/3 839,148 → 824,949 req/s (−1.7%; −1.0%), full handshakes 9,725 →
9,615/s (−1.1%; −0.8%). ECN's share is the per-datagram control messages and ACK_ECN counts.

### Evaluated: kernel TLS offload (not adopted, experimental feature)

- Handing only-tls's record keys to the Linux kernel after the handshake (kTLS) was measured on
  Linux 7.0 / Ryzen 7 7800X3D with HTTP/1.1 over TLS (`tools/bench/ktls.sh`): the kernel's
  software TLS reached 0.83x of only-tls's own record layer at 1 KiB responses, 0.65x at 16 KiB,
  0.40x at 256 KiB, and 0.48x when it sent a 10 MB file with `sendfile` against only-tls's
  `pread` plus sealing, with 1.3x to 2.5x the server CPU per byte (docs/BENCHMARKS.md, "Kernel TLS
  (kTLS) evaluation"). It is not wired into `Tls` or the engine.
- The offload stays for re-measuring behind a new **experimental** `only-tls` feature,
  `experimental-ktls` (off by default, outside the semver promise, no public API): the blocking
  test stream (`only_tls::stream`, hidden) can offload after the handshake (TLS 1.3 and 1.2,
  AES-128/256-GCM and ChaCha20-Poly1305, alerts, close_notify, NewSessionTicket and KeyUpdate in
  both directions on Linux 6.14+, fallback to user space), with the `ktls-bench` example,
  `tls-interop --ktls` / `ONLY_INTEROP_KTLS=require tools/interop/tls/run.sh` (107/107 against
  OpenSSL and Go) and `crates/only-tls/tests/ktls.rs` (skipped without the `tls` kernel module).
  `only-sys` gained the hidden `ktls` module (`TCP_ULP`, `SOL_TLS`, record-type cmsgs) with the
  `linux/tls.h` structures checked against `libc` in the layout tests.
- Docs: the stale "rustls underneath" wording in the README, the book's crate list and the fib
  migration guide, and the ROADMAP's TLS row, now say what is true (own TLS 1.3 / 1.2).

### Performance: AES-GCM on VAES-AVX2 and masked tails in the AVX-512 kernel (`only-crypto`)

No public API change (a new `#[doc(hidden)]` `AesGcm::with_cipher_avx2` and `AesGcm::kernel`
for tests and benchmarks).

- x86_64 with VAES, VPCLMULQDQ and AVX-512: the whole message runs in one call of the 512-bit
  kernel. An AAD of up to 256 bytes is hashed in the kernel, the last partial group (1 to 255
  bytes) is loaded and stored under AVX-512 byte masks instead of going through the 128-bit path,
  and the length block and `E(J0)` give the tag in the same call; messages under 256 bytes hash
  their AAD, data and length block under one reduction. AES-128-GCM seal 1 KiB 7,902 → 10,433
  MB/s (1.00× → 1.32× ring), 1400 B 8,356 → 10,632 (1.10× → 1.46×), 64 B 1,204 → 1,383
  (1.11× → 1.29×); open 1 KiB 1.04× → 1.22×; 16–64 KiB unchanged (1.16–1.18×).
- x86_64 with VAES and VPCLMULQDQ but no AVX-512 (Zen 3, Alder Lake / Raptor Lake): a new
  VAES-AVX2 kernel, sixteen blocks per iteration in eight 256-bit registers with one GHASH
  reduction per group, for whole 256-byte groups (the rest on the 128-bit path). Measured on
  Zen 4 with the AVX-512 kernel switched off (no Zen 3 available): 1.55–2.35× the 128-bit kernel
  those CPUs used before (AES-128 seal 16 KiB 6,310 → 12,671 MB/s).
- TLS 1.3 records in `only-tls` follow: AES-128-GCM 1 KiB 1.51× → 1.58× rustls + ring, 16 KiB
  1.56× → 1.60×. The record layer still zero-fills its output before the AEAD writes it: copying
  the plaintext in and sealing in place measured 6% slower at 16 KiB, a reused buffer would trade
  the memset for a copy, and skipping the fill (+10% at 16 KiB) needs `unsafe` in a
  `#![forbid(unsafe_code)]` crate, so it was not done (docs/BENCHMARKS.md).
- Tests: every kernel (AVX-512, AVX2, 128-bit, portable) against the others at every length
  0..=600, large sizes, every AAD length 0..=300 and past 512, misaligned, in place and out of
  place, and on the CAVP and Wycheproof vectors; the `crypto_aead` fuzz target compares the AVX2
  kernel too. Run natively on Zen 4, also with `ONLY_CRYPTO_PORTABLE=1`.
- `unsafe`: +5 blocks and +1 `unsafe fn` in `gcm::hw` / `gcm::hw::vaes` (the AVX2 kernel's two
  `asm!` blocks, the whole-message calls), documented in docs/unsafe-review.md. Miri never
  reaches the `asm!`.

### Fixed: io_uring kept calling `on_data` after reads paused

- `only-uring`: once a connection's output queue reached `Config::write_high_watermark`, or the
  handler called `hold_reads(true)`, the backend cancelled its multishot recv, but completions
  that arrived before the cancel took effect (on a fast machine with a flooding peer, a dozen or
  more 16 KiB reads) were still handed to `on_data`. An echo-style handler then queued past the
  watermark up to `max_queued_bytes` and got `Error::Overloaded`, and held reads were not held.
  It made `chaos_engine` fail every run on io_uring on a 16-thread Linux 7.0 machine
  ("echo send failed: overloaded"). That input now waits in the connection, in order (an EOF
  behind it too), and is delivered when reads resume, as epoll and kqueue stop reading instead.
  No API change.

### Fixed: SOCKS and HTTP CONNECT tunnels could hang under backpressure

- `only-socks`: a tunnel (SOCKS5/4/4a or HTTP `CONNECT`) could stop for good while relaying a
  large transfer. The engine's write backpressure (`Config::write_high_watermark`) paused reading
  the upstream connection whenever client data was queued for it, but those reads feed the
  client, not that queue. An upstream that does not read while its own writes are blocked (an
  echo server, most request/response servers) then waited on the proxy while the proxy waited on
  it. It showed up as a rare 10-second hang of `socks5_ipv4_domain_and_backpressure` on a loaded
  machine (kqueue, epoll and io_uring alike); an upstream that sends before it reads hung every
  time. Both ends of a tunnel are now paced only by the relay's own pause/resume. Backends honour
  a new hidden `ConnInner::set_relayed` (epoll, kqueue, io_uring, DPDK). No public API change.

### Performance: HTTP/3 request handling in `only-h3`, keyed fast hashing in `only-quic`

HTTP/3 GET with 64 requests in flight on one connection went from 429,038 to 838,721 req/s
(1.95×, median of seven alternating rounds; AMD Ryzen 7 7800X3D, loopback, CPUs 2–5); QUIC bulk
+5%, handshakes flat. In the profile the allocator fell from 31.8% to 11.2% of the samples and
SipHash from 7.3% to 0.1%. No API change; interop with quic-go and fib passes both ways.

- only-h3: request and response frames are read in place from the received stream data (only a
  trailing partial frame is buffered); a field section is decoded into one reused flat buffer,
  checked as UTF-8 in one pass and copied once into the request's or response's `Headers`, where
  it used to cost two `Vec`s per field, a `String` per name and value and a second header list.
- only-h3: HEADERS frames are QPACK-encoded straight into the outgoing buffer, with `:status`,
  `date` (formatted once a second per thread) and `content-length` written there instead of being
  added to the response's headers; static-table references are found by name length instead of
  two SipHash maps; a response's HEADERS, a body up to 16 KiB and its trailers go to QUIC in one
  write (larger bodies follow without a copy).
- only-h3: a request that arrives whole is read without entering the stream table; the stream
  tables are hashed with a multiply-fold (they are bounded by the stream limits we grant).
- only-quic: the endpoint's connection-ID tables and the tables of connections and client
  sockets (by peer address) use a hasher keyed with fresh random words per table (folded
  64×64→128-bit multiplies) instead of SipHash; a client chooses the connection ID of its first
  Initial, so the key keeps colliding IDs from being computed in advance. Connection IDs hash
  only their used bytes. On its own this is +3% bulk (a lookup per datagram); HTTP/3 with many
  requests per datagram does not notice it.
- only-quic: in-order stream acknowledgments move the send buffer's front directly instead of
  through the acknowledged-range tree (a node allocated and freed per acknowledgment), and the
  first chunk of a stream's send buffer is held inline, so a stream written once costs no queue
  allocation.
- only-http: `Response::text` and `Response::with_body` size the header storage once instead of
  growing it field by field.

### Performance: ChaCha20-Poly1305 on AVX-512 and IFMA in `only-crypto`, out-of-place TLS records

On x86_64 ChaCha20-Poly1305 seals 16 KiB at 4,597 MB/s (1,752 before, 1.30× ring), 1400 B at
2,541 (1,070, 0.96× ring) and 64 B at 412 (283, 0.83×); TLS 1.3 records with
TLS_CHACHA20_POLY1305_SHA256 went from 0.55× to 1.42× rustls + ring at 16 KiB and from 0.64× to
1.02× at 1 KiB (AMD Ryzen 7 7800X3D; docs/BENCHMARKS.md). No API change.

- ChaCha20 sixteen blocks per iteration in zmm registers with `vprold` rotations, the rest of a
  message in one group of sixteen, eight (ymm) or four (xmm) blocks, as `asm!` kernels
  (`chacha::hw::avx512`; the AVX-512 intrinsics are not stable at the MSRV). AVX2 stays the
  path for CPUs without AVX-512.
- Poly1305 eight blocks per step on AVX-512 IFMA (`chacha::hw::ifma`, `vpmadd52luq` /
  `vpmadd52huq` on 44-bit limbs) for runs of 256 bytes and more, detected through
  `Feature::Ifma`; elsewhere, and everywhere on other CPUs and on aarch64, a radix-2⁶⁴ scalar
  loop replaces the 44-bit two-block one (1.3× at 16 KiB on the AVX2 path).
- `ChaCha20Poly1305::encrypt_detached_from` / `decrypt_detached_from` (`#[doc(hidden)]`, like the
  AES-GCM ones): only-tls seals and opens ChaCha20-Poly1305 records out of place instead of
  copying first. `new_avx2` / `new_portable` (`#[doc(hidden)]`) pin a key to a narrower path
  for tests, the `crypto_aead` fuzz target and `examples/chacha-sizes.rs` (sizes against ring).
- Correctness: every length 0..=600 and large sizes through the AVX-512 / IFMA, AVX2 and
  portable paths, misaligned, in place and out of place, forged tags, counters near the wrap,
  Poly1305 on all-ones blocks and extreme `r` / `s`, run natively on Zen 4 with and without
  `ONLY_CRYPTO_PORTABLE=1`. `unsafe`: +6 blocks, +2 `unsafe fn` (docs/unsafe-review.md).

### Added: aarch64 assembly for P-256 and X25519 in `only-crypto` (not benchmarked yet)

On aarch64 the P-256 field and group-order arithmetic and the X25519 ladder's field now run in
inline assembly (`ec::hw_aarch64`, `curve25519::hw_aarch64`), the counterparts of the x86_64
BMI2 + ADX code; no API change.

- P-256: Montgomery multiplication and squaring modulo `p` and `n`, addition, subtraction,
  `2ᵏ·a` and `3·a` on four 64-bit limbs with `MUL`/`UMULH` products, `ADDS`/`ADCS`/`SUBS`/`SBCS`
  carry chains and `CSEL` corrections; the reduction modulo `p` needs shifts and subtractions
  only (as OpenSSL's `ecp_nistz256-armv8`), modulo `n` two of the four limb products are shifts.
  `P256` dispatches to a twin curve on this field, as on x86_64; inversions are safegcd (portable
  divsteps) with the final multiplication in assembly, and the twin keeps the portable defaults of
  the `Curve::jac_*` hooks (point formulas, table scans, 4-bit comb) over the assembly field.
- X25519: the ladder's field on four 64-bit limbs (16 `MUL` + 16 `UMULH` per product instead of
  the 25 128-bit products of radix 2⁵¹), folds by `2²⁵⁶ ≡ 38` with `CSEL`, masked swaps.
- Every ARMv8.0 CPU has these instructions: `hardware_features()` reports `umulh` on aarch64;
  `ONLY_CRYPTO_PORTABLE=1` / `set_portable(true)` switch back to the portable code, and Miri
  never runs the assembly.
- Correctness: differential tests against the portable field code on random and edge values and
  on chains of 20,000–50,000 dependent operations, the twin curve against the portable curve
  (key generation, ECDH, signing, verification), the RFC 7748 vectors (including the
  1,000,000-iteration one, `--ignored`), Wycheproof, all on macOS (Apple silicon) and arm64
  Linux. The release code of the secret paths was disassembled: no conditional branch in the
  assembly, and around it only loop counters, public bounds, CPU-feature checks and the final
  identity test.
- **Not benchmarked yet**: the design follows the instruction counts; no aarch64 speed-up is
  claimed until it is measured.

### Performance: HTTP/2 and pipelined HTTP/1 hot paths in `only-http`

Re-profiled after the in-house replacements (DEV-PLAN "Performance pass"); no API change.

- HTTP/2: frames are parsed in place from the read buffer (no copy per frame, the leftover moved
  once per read); decoded header fields go into one reused buffer instead of two `Vec`s per
  field; header blocks are HPACK-encoded straight into the output, with `:status`, `date` and
  `content-length` written there; a body that fits one DATA frame and the flow-control windows
  skips the stream queue; the stream table uses a multiply-fold hasher instead of SipHash.
- HTTP/2: everything one read produces, including the responses the service sends on the I/O
  thread, is handed to the connection in a single write at the end of the read (one TLS record
  for the batch instead of one per response); responses sent from other threads join the batch
  while a read is being handled and go out immediately otherwise.
- HTTP/2 flow control: the connection and stream receive windows are given back once a quarter
  of them is owed, instead of two WINDOW_UPDATE frames per DATA frame.
- HTTP/1: request heads are parsed with room for 32 fields first (100 only when needed), and the
  fields framing needs (`Host`, `Connection`, `Content-Length`, `Transfer-Encoding`, `Expect`)
  are found in one pass.
- Ryzen 7 7800X3D, 4 server threads (epoll): h2c 64 connections x 16 streams 2.28M → 4.05M
  req/s (1.78x, now 1.25x fib), h2c 16 x 128 2.37M → 4.71M, HTTP/2 over TLS 1.58M → 4.03M (2.5x,
  1.33x fib), pipelined HTTP/1.1 x16 3.99M → 4.26M (+7%, 1.14x fib). h2spec: 147/147. Tables
  in docs/BENCHMARKS.md; the harness (`tools/bench`, now with a README) drives HTTP/1.1 with
  `h2load --h1` when wrk is missing and gained h2-over-TLS and many-streams cases.

### Performance: CPU acceleration in `only-crypto`

`only-crypto` now uses CPU instructions where the CPU has them, detected at run time, each with
the constant-time portable code as fallback (DEV-PLAN "Performance pass"); no API change.

- x86_64: SHA-NI for SHA-1 / SHA-256, AES-NI CTR eight blocks at a time, AES-GCM with PCLMULQDQ
  GHASH (eight blocks per reduction) fused into the CTR pass, PCLMULQDQ folding for CRC-32 and
  CRC-32C plus the SSE4.2 `crc32` instruction, AVX2 ChaCha20 (eight blocks).
- aarch64: ARMv8 SHA1/SHA2, ARMv8 AES CTR, PMULL GHASH fused with CTR, ARMv8 CRC32 instructions;
  ChaCha20 in a 4-block lane layout the compiler vectorizes (also the portable path elsewhere).
- Safe Rust: Poly1305 in 44-bit limbs (two blocks per step); P-256 with a dedicated Montgomery
  reduction, an addition-chain inversion, a signed comb of affine points for `[k]G` and Jacobian
  wNAF verification without inversion; Ed25519 verification by interleaved wNAF; squaring
  routines for Curve25519, the NIST fields and RSA; fixed-size RSA Montgomery multiplication;
  windowed exponentiation for the remaining inversions.
- `unsafe` stays confined to the instruction modules (`aes::hw`, `gcm::hw`, `hash::hw`,
  `crc::hw`, `chacha::hw`), every call behind detection (docs/unsafe-review.md).
  `ONLY_CRYPTO_PORTABLE=1` forces the portable code (tests, benchmarks); Miri runs it.
- Ryzen 7 7800X3D, one core: SHA-1 3.6x and SHA-256 6.5x (equal to the RustCrypto crates),
  AES-128-GCM 364 → 6 484 MB/s, CRC-32 2.7 → 20 GB/s, ChaCha20-Poly1305 3x, P-256 verify 1.67x /
  sign 1.46x, Ed25519 verify 1.49x, RSA-2048 sign 1.38x; TLS 1.3 handshakes 1.5x and 16 KiB
  AES-GCM records 15x (0.60x and 0.64x rustls + ring). Tables in docs/BENCHMARKS.md.

### Performance: faster TLS 1.3 handshakes (P-256 and X25519 in `only-crypto`)

The handshake profile was >98% curve arithmetic; no API change (`tools/api/public-api.sh`
unchanged). Measured in memory on one core of the bench host, against rustls 0.23 + ring:
full handshakes 3,055 → 5,027/s with X25519 (0.61× → 1.00× rustls) and 2,306 → 4,552/s with
secp256r1 (0.45× → 0.89×).

- P-256 on x86_64 with BMI2 + ADX (run-time detection, new `cpu` feature `adx`): Montgomery
  multiplication and squaring modulo `p` and modulo the group order, addition, subtraction and
  small multiples in inline assembly (`mulx`, `adcx`/`adox`, `cmov`; new hardware module
  `ec::hw`). The operations run on a twin curve type that shares the Montgomery form and the
  base point tables, so the dispatch happens once per operation.
- Constant-time scalar multiplication in Jacobian coordinates with the `a = -3` formulas:
  Booth-recoded signed 5-bit windows for the variable base (ECDH) and the signed comb with mixed
  additions for the fixed base (key generation, signing). The identity cases are masked selects;
  equal operands cannot occur for scalars in `[1, n)` (proof in the code, `n mod 32 ≥ 17` checked
  by a test). Doublings are 4M + 4S with fused `2ᵏ·a`/`3·a`.
- The P-256 scalar inversion uses a dedicated chain (255 squarings, 40 multiplications); ECDSA
  verification inverts `s` (public) with a binary extended Euclidean algorithm and builds its
  table from projective keys without an inversion. Public keys from `SecretKey::public_key` stay
  projective until encoded (one constant-time inversion then).
- X25519: public keys are `[k]B` on edwards25519 mapped to `u = (1 + y)/(1 - y)` (the Ed25519
  base table, now affine Niels entries with signed digits: 7M per digit), and on x86_64 with
  BMI2 + ADX the ladder runs on four 64-bit limbs in inline assembly (`curve25519::hw`); the
  radix-2⁵¹ ladder stays the portable path.
- Micro-benchmarks against ring (`--example pk_bench`, op/s, before → after): P-256 sign
  34,152 → 59,837 (0.45× → 0.79×), verify 13,404 → 25,138 (0.51× → 0.96×), ECDH 10,380 → 27,288
  (0.35× → 0.91×), key generation 54,581 → 108,263 (0.49× → 0.96×); X25519 30,696 → 36,488
  (0.84× → 1.00×); Ed25519 sign 1.15× → 1.53× ring; P-384 sign, verify, ECDH and key generation
  1.13–1.47× faster than before. RSA is unchanged.
- Constant-time evidence: the disassembly of the secret-scalar paths (x86_64 with the assembly,
  aarch64 portable) has conditional branches only on loop counters, public indices, the public
  exponent bits of the inversion chains, CPU-feature checks and the "result is the identity"
  test (`ct.rs`). Every assembly routine is compared with the portable code on random and edge
  values, and all known-answer tests run with and without `ONLY_CRYPTO_PORTABLE=1`.
- `unsafe`: +13 `asm!` blocks in `only-crypto` (8 in `ec::hw`, 5 in `curve25519::hw`; see
  docs/unsafe-review.md).

### Performance: wide AES-GCM and CRC in `only-crypto`, out-of-place TLS records

No public API change (new `#[doc(hidden)]` helpers only).

- x86_64 with VAES, VPCLMULQDQ and AVX-512 (Zen 4, Ice Lake and later; detected with CPUID and
  XCR0): AES-GCM seal and open run as one 512-bit pass, sixteen blocks per loop iteration with
  the AES rounds interleaved with the GHASH of the previous group and one reduction per sixteen
  blocks (the BoringSSL / Linux `aes-gcm-avx10` design, written as `asm!` because those
  intrinsics are newer than the MSRV). The 512-bit kernel was faster than the same kernel on
  256-bit registers at every size on Zen 4, so only it ships; other CPUs keep the AES-NI +
  PCLMULQDQ kernel. CRC-32 / CRC-32C fold 256 bytes per step on 512-bit registers from 512 bytes.
- Every CPU with AES and carry-less multiplication: the last bytes of a message and `J0` go
  through AES in one call, and a short AAD, the tail ciphertext and the length block through one
  GHASH call (64-byte messages 1.8–2.1x).
- `only-tls` seals and opens records out of place: the AEAD reads the caller's plaintext or the
  received record and writes its output once, instead of copying first and working in place
  (the copy was 30% of a 16 KiB record).
- Ryzen 7 7800X3D, one core: AES-128-GCM seal 16 KiB 6,455 → 15,048 MB/s (0.51x → 1.19x ring),
  1400 B 4,249 → 8,163, 64 B 611 → 1,185; TLS 1.3 records seal + open 16 KiB 2,739 → 6,603 MB/s
  (0.69x → 1.65x rustls + ring); CRC-32 16 KiB 20.0 → 74.9 GB/s (0.27x → 1.02x crc32fast). Tables
  in docs/BENCHMARKS.md.
- `unsafe`: the new `gcm::hw::vaes` kernel, the `asm!` CRC fold and CPUID / XGETBV (`cpu::hw`),
  each documented in docs/unsafe-review.md. Miri never reaches the `asm!` (nothing is detected).

### Performance: P-256 whole-point assembly, wide comb and safegcd in `only-crypto`

No API change (`tools/api/public-api.sh` unchanged). Measured on one core of the bench host
against ring 0.17 / rustls 0.23 in the same run (median of five alternating rounds; the host was
loaded by another benchmark, so absolute rates are 20–30% low, see docs/BENCHMARKS.md): P-256
sign 0.77× → 1.25× ring, key generation 0.94× → 1.33×, verify 0.98× → 1.04×, ECDH 0.94× → 0.96×;
TLS 1.3 secp256r1 handshakes 0.94× → 1.12× rustls.

- x86_64 with BMI2 + ADX: the Jacobian doubling (`a = -3`), addition and mixed addition of the
  P-256 twin are each one `asm!` block over a small stack frame, the products and reductions
  fused with the modular additions, subtractions and doublings around them (the accumulator stays
  in registers; the low half of each product is reduced on its own and the high half added
  after). Consecutive doublings (five per ECDH window, runs between additions in verification)
  share one frame. A doubling costs ~355 cycles instead of ~480. The curve trait gained hooks
  for these routines and the table scans, so an aarch64 twin can plug in the same way.
- Fixed base (key generation, signing) on the twin with AVX2: Booth-recoded signed 6-bit digits
  over a 43-row comb of 32 affine points each (88 KiB, built on first use), 43 mixed additions
  instead of 65; every row is scanned with 256-bit loads and `vpcmpeqq` masks. 6- and 7-bit combs
  measured equal, 5 and 8 bits slower. The ECDH window table is scanned the same way. Without
  AVX2 the 4-bit comb stays.
- Inversion modulo the P-256 prime and order by safegcd (Bernstein–Yang divsteps in
  libsecp256k1's form, new module `safegcd`), constant time, with the divsteps in assembly on
  x86_64 and masked Rust elsewhere: the scalar inversion of signing 20.9k → 7.0k cycles, the
  field inversion ~12.7k → ~7–9k. It replaces the Fermat chains on every path, portable included.
- Correctness: the whole-point routines are compared limb for limb with the portable formulas
  on random points with random `Z`, every valid Wycheproof ECDH point, `P + P`, `P + (-P)` and
  the identity; safegcd against Fermat on random and edge inputs for both moduli; the wide comb
  against the complete-formula reference on random and edge scalars (every top digit); the
  equal-operand argument for the wide comb is in `ec/hw.rs`.
- Constant-time evidence (Zen 4 release disassembly): no conditional branch in the point
  routines, the AVX2 scans and `Fe::invert`; one (the loop counter) in each `divsteps_59`; in
  `ecdh_x_impl`, `sign_impl` and `hw::mul_base` only CPU-feature and `OnceLock` checks, loop
  counters, public digit positions and bounds, the output length and the final identity test.
- `unsafe`: +6 blocks and +2 `unsafe fn` in `ec::hw` (the point blocks share one, the divsteps
  block, two AVX2 scans and their two calls; docs/unsafe-review.md).

### Performance: cheaper P-256 point formulas on x86_64 in `only-crypto`

No API change (`tools/api/public-api.sh` unchanged). Measured on a quiet bench host (Zen 4, CPU 2,
median of five alternating rounds, ring 0.17 in the same run): P-256 ECDH 1.08× → 1.12× ring
(32,351 → 33,904 op/s), sign 1.36× → 1.38×, verify 1.08× → 1.10×, key generation 1.36× →
1.40×. The 0.96× of the previous entry was measured on a loaded host; quiet, the code before this
change already did 1.08×. TLS 1.3 handshakes did not move (secp256r1 1.07×, X25519 1.08× rustls):
one ECDH is about 1% of a handshake.

- The whole-point assembly of the P-256 twin uses the formulas of OpenSSL's `ecp_nistz256`: the
  addition is 12M + 4S with seven modular additions and subtractions instead of add-2007-bl's
  11M + 5S with thirteen (the products cost the same as the squares here, the linear operations
  do not), the mixed addition 8M + 3S instead of 7M + 4S (seven against fourteen), and the
  doubling computes `2Y` first, so `Z₃ = 2Y·Z`, `4β = X·(2Y)²` and `8γ² = ((2Y)²)²/2` (a new
  modular halving) need ten linear operations instead of fourteen. The additions return another
  representative of the same point (`(X, Y, Z)` instead of `(4X, 8Y, 2Z)`); the doubling the same
  limbs.
- The Montgomery reduction inside the point routines keeps `p₃` in `rdx` for its four steps and
  splits `m·2⁹⁶` with `shlx`/`shrx` (the compiler-reserved `rbx` holds the count 32, saved and
  restored in the frame): ten instructions per step become seven.
- Cycles (`perf stat`, Zen 4): addition 745 → 721, mixed addition 537 → 508, doubling 355 → 348,
  variable-base multiplication 148.1k → 140.6k, fixed-base (comb) 29.8k → 28.9k. The doubling
  measures as a fixed ~44 cycles per product: reordering it (independent products first, or the
  `Y` chain first) made it 8–10% slower, an OpenSSL-style reduction interleaved with the product
  rows was neutral, and replacing the `cmov` selections by `xor`/`and` masks was 10% slower, so
  none of them is in.
- Correctness: `points_match_portable` compares the doublings limb for limb and the additions as
  points (cross-multiplied, `Z = 0` exactly where the portable formulas give it), now also with
  the all-zero identity on either side; the halving is checked on random and edge values.
- Constant time: the release disassembly on Zen 4 has the same conditional branches as before in
  `ecdh_x_impl` (17: loop counters, public digit positions and bounds, CPU-feature checks, the
  output length and the final identity test), `hw::mul_base`, `divsteps_59` and `safegcd::inv_with`,
  and none in the point routines.
- `unsafe`: no new block; the point block saves and restores `rbx` (docs/unsafe-review.md).

### Performance: RSA on BMI2 + ADX and AVX-512 IFMA in `only-crypto`

No API change (`tools/api/public-api.sh` unchanged). Measured on a quiet bench host (Zen 4,
CPU 2, three alternating rounds of the old and new binaries, ring 0.17 in the same run, op/s):
RSA-2048 PKCS#1 v1.5 sign 1,192 → 3,910 (0.49× → 1.61× ring), RSA-3072 371 → 1,455 (0.47× →
1.85×), RSA-4096 156 → 755 (0.45× → 2.19×); verify 39,250 → 79,970 (0.60× → 1.22×), 18,300 →
33,440 (1.10×), 10,110 → 19,090 (1.09×); verify including the public-key parse (one
certificate signature; ring parses on every call) 5,850 → 67,090 (0.09× → 1.02×), 0.95× and
0.95× at 3072 and 4096 bits. only-tls full handshakes with an RSA-2048 certificate (new
`tls-bench` row): 775 → 2,586/s, 0.43× → 1.44× rustls + ring.

- On x86_64 with AVX-512 IFMA (new `cpu` feature `ifma`: CPUID leaf 7 with the AVX-512 state)
  the CRT exponentiations of 2048-, 3072- and 4096-bit keys run in radix 2⁵² (`bignum::ifma`):
  almost Montgomery multiplication over 20, 32 or 40 digits, one `asm!` block per product with
  the operands in registers (`ymm` for 20 and 32 digits, `zmm` for 40), two accumulators at 20
  digits so each register takes two dependent multiply-adds per step, the low digit and the next
  `yᵢ` computed in general-purpose registers so that chain bypasses the vector unit, the carries
  normalized with a generate / propagate mask word. Results stay below `2p` through the whole
  exponentiation; one masked subtraction at the end. A 1024-bit multiplication takes 416 cycles.
- Without IFMA, with BMI2 + ADX: Montgomery multiplication and squaring for 16 to 64 limbs in
  `asm!` (`bignum::hw`; operand scanning with `mulx` and the two carry chains, rows unrolled with
  the assembler's `.rept`, the next reduction factor taken from a register, a dedicated squaring
  up to 32 limbs, the final subtraction by `cmovnz`): a 1024-bit multiplication 1,240 → 805
  cycles, squaring 1,490 → 681; RSA-2048 signing on this path alone measured 0.99× ring,
  verification 1.20×.
- Exponentiation: fixed 5-bit windows (were 4) over a flat table built with squarings for the
  even entries, every lookup one pass over all 32 entries with AVX2 `vpcmpeqq` masks (the
  constant-time `ct` masks without AVX2).
- `R² mod m`: `64 + k` doublings and six Montgomery squarings instead of `128k` doublings for the
  secret primes (constant time), one long division for public moduli; key parsing is no longer
  the cost of a certificate check. The private operation keeps the blinding (now squared with
  the dedicated squaring), drops four 2048-bit conversions and reduces the blinded input into
  each prime field with three multiplications.
- Karatsuba was not tried: at these sizes the assembly row loops leave little to save.
- Correctness: `asm_matches_generic` (the BMI2 + ADX code at every size against the generic CIOS
  on random values and 0, 1, m - 1, m - 2, R - 1, R - m, full and short top limbs, a 200-step
  chain), `ifma_pow_matches` (the IFMA exponentiation against square-and-multiply, edge bases and
  exponents), `r2_constructions`; `rsa_vs_ring` now signs with 2048-, 3072- (new) and 4096-bit
  (new) keys and requires byte-identical PKCS#1 v1.5 signatures, also with the portable code
  forced; the Wycheproof RSA vectors are unchanged and pass on both paths.
- Constant time: the release disassembly on Zen 4 lists only loop counters, the public limb- and
  digit-count dispatch, CPU-feature, slice and allocation checks, public window offsets, the
  blinding cache and the final fault check in `Mont::mul_into` / `sqr_into`, `ifma::amm`,
  `ifma::pow`, `Mont::pow`, the table scans, `Mont::new`, `crt_combine` and `private_op`
  (counts in `src/ct.rs`).
- `unsafe`: +7 blocks and +1 `unsafe fn` in `only-crypto` (`bignum::hw`: the two Montgomery
  blocks and the AVX2 scan; `bignum::ifma`: the IFMA blocks); see docs/unsafe-review.md.

### Added: statistical timing test for `only-crypto` (`tools/ct-dudect`)

A dudect-style test (Welch's t-test of fixed vs random secrets, random interleaving, `rdtsc` /
`cntvct_el0`, percentile cropping and a second-order test, `|t| > 4.5` a leak) of the
secret-dependent paths on the hardware and the portable code: P-256 ECDH, key generation and
signing, X25519 and its key generation, Ed25519 signing, RSA-2048 signing, AES-GCM and
ChaCha20-Poly1305 tag checks, HMAC verification, `ct_eq` and the `ct.rs` primitives, with an A/A
test and two deliberately leaky functions as sanity checks. A new workspace-internal tool (not
published, no new dependency); runs in CI as the informational job `ct-dudect` (not part of
`ci-ok`, t-values kept as an artifact). On Zen 4 nothing leaks beyond two small, intermittent
differences under investigation (the degenerate all-zero X25519 scalar, P-256 portable signing
at the threshold); method and results in [docs/constant-time.md](docs/constant-time.md).

### Performance: stored blocks copied once in `only-deflate`

No API change; compressed output is byte-identical. Measured on the bench host (Zen 4, CPU 2,
five alternating rounds of the old and new `bench` binaries, zlib-rs in the same run):
inflating random data at level 6 (stored blocks) 15,456 → 34,278 MB/s (0.43× → 0.94×
zlib-rs), level 9 15,357 → 34,003 MB/s. Text and JSON (literals and matches) are unchanged.

- Stored blocks are copied straight from the input to the caller's output instead of through
  the window, and only the last window's worth of a run of stored data (up to 32 KiB, once per
  call, before a compressed block or the trailer needs it) enters the history afterwards.
- `Inflater::decompress_vec` appends stored data with `extend_from_slice` (no zero-filled room
  to copy into); block headers are decoded with no output space. `decompress` reserves room for
  twice the input (at most the limit) up front.
- Tested with stored blocks split at every input byte and every output size in the three
  formats, through `decompress` and `decompress_vec`, and stored blocks longer than the window
  (up to 65,535 bytes) followed by matches at the largest distance, for 512-byte, 4 KiB and
  32 KiB windows.
- Tried and dropped: decoding up to five literals per refill instead of three on the
  literal-heavy path made no measurable difference.

### Performance: QUIC datapath (GRO by default, per-batch ACKs, pooled receive buffers)

No API change (`tools/api/public-api.sh` unchanged: the new hook is `#[doc(hidden)]`). One
default changed: `Config::udp_gro` is now `true`. Measured on the bench host (Zen 4, loopback,
`quic-bench` client and server on CPUs 2–5, median of seven alternating old/new rounds, an
outside workload on the host during some of them): one-stream bulk 6,378 → 16,066 Mbit/s
(2.52×), HTTP/3 427,901 → 443,299 req/s (1.04×), full handshakes 9,294 → 9,542/s (flat). The
quinn-proto build of the same program did 4,613 Mbit/s and 56,934 req/s in the same run as
15,999 Mbit/s and 430,098 req/s for this one (3.5× and 7.6×).

- `only-core`: `Handler::on_batch_end` (`#[doc(hidden)]`, default no-op, outside the stability
  promise) tells a UDP handler that the receive batch that called its `on_data` is over. The UDP
  loop of only-epoll, which also serves UDP on the io_uring backend and on macOS, calls it once
  per connection and batch (one `recvmmsg`; up to 32 `recv_from`/`recv` calls on macOS), before
  the batch's replies are flushed; dialed connections that fill a whole batch now flush after
  each one instead of after up to eight. Other backends (only-dpdk) never call it.
- `Config::udp_gro` defaults to `true` (Linux, where the kernel supports `UDP_GRO`; probed once,
  `ONLY_UDP_GRO=0` still turns it off, `read_buffer` must stay at least 64 KiB). Coalesced
  receives are split by the `UDP_GRO` segment size on server, bound and dialed sockets as before,
  so `on_data` still sees one datagram per call (only-kcp, only-turn, only-webrtc and DNS tests
  pass unchanged). Bulk QUIC 6.4 → 9.8 Gbit/s on its own: a GSO batch from the sender reaches the
  receiving socket whole instead of being segmented. 64-byte UDP echo with GRO on and off, 15
  alternating rounds each: no difference beyond the noise of the case.
- The UDP loop reads the clock once per receive call and chains the end of each timed callback
  into the start of the next (as the TCP loops do): three clock reads per datagram become one.
- only-quic acknowledges once per receive batch: after each datagram the handler runs and data
  that is ready goes out right away, but an ACK-only packet waits for `on_batch_end` (one per
  batch instead of one per two packets); the QUIC timer is armed once per batch too. A variant
  that also deferred handler events and data to the batch end measured 1.45× on bulk but cost
  28% on HTTP/3 (64 requests in flight became one lock-step batch per round trip), so it is not
  in. Until a socket's first `on_batch_end` (and on backends without it) every datagram is
  driven on its own, as before.
- Received datagrams are copied once into a per-thread pool of buffers (`Arc<Vec<u8>>`) and
  decrypted in place; stream data and datagrams are `Bytes` slices of them, and a buffer is reused
  once all its slices are dropped (on any thread). This replaces two allocations per packet (the
  copy and the `Arc` around it). A copy remains: the handler gets the `recvmmsg` slot by
  reference, and decrypting in place needs a buffer this side owns alone.
- Sent packets are kept in a ring indexed by packet number (`proto/conn/sent.rs`) instead of a
  `BTreeMap`, and the frame lists of acknowledged or lost packets are reused for new packets.
- Profile notes not acted on: SipHash on the peer address and connection ID maps (~2% of the
  receiver), and allocations and header hashing in only-h3/only-http (`encode_fields`,
  `Headers`), which dominate the HTTP/3 profile.

### Changed (breaking, before 1.0.0): pre-1.0 dependencies wrapped

rustls 0.23, quinn-proto 0.11, str0m 0.24 and prost 0.13 no longer appear in the covered API, so
upgrading them (or replacing them with in-house code) is not a breaking change after 1.0.0.
Raw access moved behind new `unstable` cargo features (`only`, `only-tls`, `only-quic`,
`only-webrtc`), outside the semver promise like the `prost` feature of `only-grpc`
(docs/api-stability.md, "Public dependencies").

| Before | After |
|---|---|
| `only::tls::rustls` (re-export) | `unstable` feature only |
| `rustls::ServerConfig::builder()...with_single_cert(chain, key)` + `alpn_protocols` | `only::tls::ServerConfig::builder(chain, key).alpn([..]).build()?` (also `sni_cert`, `client_auth_required` / `_optional`, `session_cache`, `session_tickets`, `tls13_only`) |
| `rustls::ClientConfig::builder().with_root_certificates(roots)...` | `only::tls::ClientConfig::builder().roots(roots).alpn([..]).build()?` (also `client_cert`, `sni`, `resumption`, `tls13_only`, `insecure_skip_verify`) |
| `CertificateDer`, `PrivateKeyDer`, `RootCertStore` | `only::tls::{Certificate, PrivateKey, RootCerts}` (`from_pem`, `from_der`, `from_pkcs8_der`) |
| `Tls::server(Arc<rustls::ServerConfig>, a)`, `Tls::client(Arc<rustls::ClientConfig>, ..)` | `Tls::server(ServerConfig, a)`, `Tls::client(ClientConfig, ..)` |
| `Client::with_tls(Arc<rustls::ClientConfig>)`, `H2Client::dial(.., Some((Arc<..>, name)), ..)`, `DialOptions::tls: Option<Arc<..>>` | the same with `only::tls::ClientConfig` |
| `only_quic::{proto, rustls}` re-exports, `VarInt` | `unstable` feature only (`proto`); `VarInt` removed |
| `only_quic::{StreamId, Dir, ConnectionError, TransportConfig}` (quinn's) | `only`'s own types (plus `Side`, `Congestion`, `UdpStats`); `ConnectionError` variants are struct-like (`ApplicationClosed { code, reason }`, `TransportError { code, reason }`) |
| `Connection::stats() -> quinn_proto::ConnectionStats` | `ConnectionStats` (`udp_tx`, `udp_rx`, `rtt`, `cwnd`, `lost_packets` ...) |
| `server_config(Vec<CertificateDer>, PrivateKeyDer, alpn) -> quinn_proto::ServerConfig` | `server_config(Vec<Certificate>, PrivateKey, alpn) -> only_quic::ServerConfig` (`.transport(&TransportConfig)`, `.migration(bool)`) |
| `server_config_from(rustls::ServerConfig)`, `client_config(RootCertStore, ..)`, `client_config_from(rustls::ClientConfig)` | `server_config_from(&only::tls::ServerConfig)`, `client_config(RootCerts, ..)`, `client_config_from(&only::tls::ClientConfig)` |
| `Error::Connect(quinn_proto::ConnectError)` | `Error::Connect(String)` |
| `only_h3::server_config(Vec<CertificateDer>, PrivateKeyDer)`, `serve(quinn_proto::ServerConfig, ..)`, `H3Client::dial(.., quinn_proto::ClientConfig)` | `Certificate` / `PrivateKey`, `only_quic::ServerConfig`, `only_quic::ClientConfig` |
| `only_grpc::codec::{encode, decode}` bound on `prost::Message` | bound on `only_grpc::codec::Message` (`encode_to`, `decode_from`); the `prost` feature implements it for prost messages |
| `only_webrtc::str0m` re-export, `Peer::with_rtc`, `crypto_provider`, `generate_certificate` | `unstable` feature only (`str0m`, `with_rtc`, `crypto_provider_str0m`); `generate_certificate` is internal |
| str0m's `ChannelId`, `ChannelConfig`, `Reliability`, `Mid`, `Pt`, `MediaKind`, `Direction`, `Frequency`, `MediaTime`, `MediaData`, `MediaAdded`, `KeyframeRequest(Kind)`, `RtpPacket`, `Candidate`, `IceConnectionState`, `RtcConfig`, `Event` | `only`'s own types of the same names (`ChannelConfig` is `#[non_exhaustive]`: `ChannelConfig::new(label)` then set fields; `MediaData::data` / `RtpPacket::payload` are `Arc<[u8]>`) |
| `create_offer(h, \|api: &mut SdpApi\| ..)`, `renegotiate(..)`; `api.add_channel(label.into())`, `api.add_media(kind, dir, None, None, None)` | `SdpChanges`: `add_channel(label)`, `add_channel_with_config(&cfg)`, `add_media(kind, dir, None, None)`, `set_direction`, `stop_media`, `ice_restart` |
| `Peer::open_channel(ChannelConfig)`, `payload_type(mid, str0m::format::Codec)` | `open_channel(&ChannelConfig)`, `payload_type(mid, only_webrtc::Codec)` |
| `PeerHandler::on_event(&str0m::Event)` | `on_event(&Event)`: `Event::ChannelBufferedAmountLow(id)` or `Event::Other(OtherEvent)` |
| `Error::Rtc(str0m::RtcError)`, `impl From<str0m::RtcError> for Error` | `Error::Rtc(only_webrtc::RtcError)`; new `Error::InvalidCandidate` |
| `Endpoint::add_candidate(str0m::Candidate)` | `Candidate::host(addr)` / `server_reflexive(addr, base)` / `relayed(addr, base)` / `parse(sdp)` |

### Changed (breaking, before 1.0.0): own logging facade `only-log` replaces `log`

DEV-PLAN wave B. `only` no longer depends on the `log` crate; it logs through the new public
crate `only-log` (no dependencies, re-exported as `only::log`): levels, targets, structured
key-values with `log`'s macro syntax, a global maximum level in an atomic (a disabled statement
costs one relaxed load: 0.25-0.29 ns against `log`'s 0.36 ns), a `Logger` trait with
`set_logger` / `set_boxed_logger`, and built-in loggers (`only::log::init(level)` for formatted
lines on stderr, `StderrLogger`). Targets, messages and key names are unchanged; without a
logger, errors and slow-callback warnings still go to stderr. The new `log` cargo feature
(`only`, `only-core`, `only-log`; outside the semver promise) bridges to the `log` crate: records
go to `log`'s logger while no only-log logger is installed (and `Config::log_level` also sets
`log::max_level`, as before), and `only::log::bridge::route_log_to_only()` sends `log` records
(str0m, rustls ...) to the only-log logger.

Migration:

| Before | After |
|---|---|
| `env_logger::init()` (or any `log` logger) | unchanged, with `features = ["log"]` on `only`; or drop it for `only::log::init(only::log::LevelFilter::Info)` |
| `cfg.log_level = Some(log::LevelFilter::Info)` | `Some(only::log::LevelFilter::Info)` (with the `log` feature, `Some(log::LevelFilter::Info.into())` also works) |
| `Telemetry::set_log_level(log::LevelFilter)` | `set_log_level(only::log::LevelFilter)` |
| `impl log::Log for MyLogger` | `impl only::log::Logger for MyLogger` (`enabled` and `flush` have defaults); install with `only::log::set_logger` |
| `record.key_values().visit(&mut visitor)` | `record.key_values().iter()` / `.get("conn_id")`; values implement `Display` |
| `log::max_level()` | `only::log::max_level()` |

### Changed: in-house cryptography (`only-crypto`, DEV-PLAN wave A)

- New internal crate `only-crypto` (std only, `#![deny(unsafe_code)]` except its AES-NI / ARMv8
  AES module): SHA-1, SHA-224/256, SHA-384/512, MD5, HMAC, HKDF, PBKDF2, CRC-32 / CRC-32C,
  AES-128/192/256 (CPU instructions when detected, else constant-time fixsliced software) with CTR, AES-GCM with a constant-time GHASH, ChaCha20-Poly1305, base64 (strict decoding), OS
  randomness and a ChaCha20 generator. Tested against NIST CAVP, RFC and Wycheproof vectors and
  cross-checked (tests and fuzz targets) against the crates it replaces.
- `only-kcp`, `only-turn`, `only-ws`, `only-http`, `only-media`, `only-bittorrent` and
  `only-webrtc` use it instead of sha1, sha2, md-5, hmac, pbkdf2, aes, aes-gcm, ctr, crc32fast,
  base64 and getrandom (those remain dev-/fuzz-only references, and transitively under
  str0m/dimpl until wave D). Public APIs and wire formats are unchanged (KCP crypt incl. golden
  datagrams sealed by the old code, TURN MESSAGE-INTEGRITY/FINGERPRINT, WebSocket accept keys,
  BitTorrent info hashes and MSE, SRT key wrap and AES-CTR, RTMP digest handshake, SRTP).
- `only-sys` (internal, `#[doc(hidden)]`): `fill_random` over `getrandom(2)` / `getentropy(2)`
  with a `/dev/urandom` fallback.
### Added: public-key cryptography and X.509 (`only-crypto`, new `only-x509`, DEV-PLAN wave B)

Groundwork for the own TLS 1.2/1.3, DTLS, QUIC and WebRTC stacks (waves C and D); nothing uses
it in the protocol crates yet, so no behaviour changes.

- `only-crypto` (internal tier; additive API): X25519 (RFC 7748), Ed25519 (RFC 8032, strict
  verification: canonical `S`, encoded-`R` comparison), ECDH and ECDSA on P-256 and P-384
  (RFC 6979 deterministic nonces, DER and fixed-width signatures, SEC1 points with validation),
  RSA PKCS#1 v1.5 and PSS sign/verify with SHA-256/384/512 (SHA-1 verify only) for 2048–8192-bit
  moduli (CRT, blinding, result check), strict DER reader/writer, PEM, and key encodings
  (PKCS#8 v1/v2, SEC1, PKCS#1, SubjectPublicKeyInfo) behind `pkey::{PrivateKey, PublicKey,
  SignatureAlgorithm}`. New `Error` variants `InvalidKey`, `Encoding`, `Unsupported`, `Random`,
  `ZeroSharedSecret`. Constant-time field arithmetic (Montgomery for P-256/P-384 and scalars,
  radix 2⁵¹ for Curve25519), complete addition formulas, table lookups that read every entry.
- New internal crate `only-x509` (`#![forbid(unsafe_code)]`): certificate parsing (strict DER;
  subjectAltName, basicConstraints, keyUsage, extKeyUsage, nameConstraints, key identifiers),
  chain building and validation against a `RootStore` (validity, CA/pathLen, key usage, EKU,
  DNS/IP/directoryName name constraints, unknown critical extensions, a signature-check budget),
  RFC 6125 server-name matching (leftmost-label wildcards, IP SANs), and generation of
  self-signed and CA-signed certificates (`CertificateParams`, `generate_simple_self_signed`).
- Tests: Wycheproof (X25519, Ed25519, ECDSA P-256/P-384 DER and P1363, ECDH P-256/P-384, RSA
  PKCS#1 v1.5 and PSS verification, RSA signature generation), RFC 7748 / 8032 / 6979 vectors,
  identical signatures and mutual verification with ring and RustCrypto p256/p384, real-world
  chains (Google Trust Services, Let's Encrypt ECDSA and RSA), OpenSSL-made chains and keys
  (RSA-PSS, P-384, Ed25519), rcgen and rustls-webpki interop, constructed negative chains; fuzz
  targets `x509_parse` and `crypto_sig_verify` (differential against ring) with corpus replays.

### Added: own DTLS 1.2 (new `only-dtls`, DEV-PLAN wave C)

The DTLS layer of the in-house WebRTC stack (wave D will replace str0m's `dimpl` with it);
nothing uses it yet, so no behaviour changes.

- New internal crate `only-dtls` (`#![forbid(unsafe_code)]`, depends only on `only-crypto` and
  `only-x509`): a sans-io DTLS 1.2 (RFC 6347) `Connection` for either role, driven by
  `handle_datagram`, `poll_transmit`, `poll_event`, `poll_timeout` / `handle_timeout` and
  `send_application_data`. Record layer with epochs, 48-bit sequence numbers and a 64-record
  anti-replay window; handshake fragmentation to the configured MTU and out-of-order
  reassembly; flight retransmission with exponential backoff (RFC 6347 §4.2.4) and on a
  repeated peer flight; stateless HMAC-SHA-256 HelloVerifyRequest cookies (`HelloVerifier` for
  listeners that allocate nothing before return routability is proven).
- Cipher suites `TLS_ECDHE_{ECDSA,RSA}_WITH_{AES_128_GCM_SHA256, AES_256_GCM_SHA384,
  CHACHA20_POLY1305_SHA256}`, groups X25519 / P-256 / P-384, ECDSA, Ed25519, RSA-PSS and
  RSA PKCS#1 signatures; extended master secret (RFC 7627, required by default); renegotiation
  refused (RFC 5746).
- WebRTC: `Config::webrtc`, mutual authentication with self-signed certificates checked by
  `PeerVerifier::Fingerprints` (SDP `a=fingerprint`), a callback, or deferred to the caller;
  `Identity::generate_self_signed`, `Fingerprint` (SDP form), `use_srtp` (RFC 5764) with
  `SRTP_AEAD_AES_128_GCM`, `SRTP_AEAD_AES_256_GCM`, `SRTP_AES128_CM_HMAC_SHA1_80/32`, SRTP master
  keys in `Event::Connected`, and the RFC 5705 exporter (`export_keying_material`).
- Tests: handshakes over a simulated link with 25 % loss, duplication and reordering at MTU 256,
  every suite with ECDSA P-256/P-384, Ed25519 and RSA certificates, negative cases (wrong
  fingerprints, replays, tampered records, bad cookies, timeouts, missing client certificates,
  no shared suite); interop both directions with OpenSSL `s_client`/`s_server -dtls1_2`
  (3.5 in Docker, 4.1; `-use_srtp` and `-keymatexport` keys identical) and pion/dtls v3
  (`tools/interop/dtls/run.sh`), and in memory with `dimpl` (`tests/dimpl.rs`); fuzz targets
  `dtls_record` and `dtls_handshake` with corpus replays. Not implemented: DTLS 1.3 (RFC 9147),
  connection IDs, session resumption, PSK.
### Changed: own TLS 1.3 and 1.2 in `only-tls` (DEV-PLAN wave C; no more rustls, ring)

`only-tls` now implements TLS itself, from the RFCs, on `only-crypto` and `only-x509`
(`#![forbid(unsafe_code)]`, no third-party dependencies). The covered API is unchanged
(`api/only-tls.txt` is identical): `ServerConfig` / `ClientConfig` builders, `Certificate`,
`PrivateKey`, `RootCerts`, `Error`, `Tls`, `TlsInfo`, `tls_info`; only-http (HTTP/1.1, HTTP/2 by
ALPN), only-ws (`wss://`), only-socks, only-grpc and only-mux run on it unchanged.

- TLS 1.3 (RFC 8446): full handshake both sides, HelloRetryRequest (with cookie echo), key
  schedule, KeyUpdate (answered, and sent proactively before the AES-GCM record limit),
  NewSessionTicket and PSK resumption (`psk_dhe_ke`; stateless tickets with
  `session_tickets(true)`, single-use cached tickets with the session cache), client
  certificates, middlebox compatibility mode, 0-RTT rejected (skipped as RFC 8446 4.2.10 says).
- TLS 1.2 (RFC 5246 + RFC 7627 extended master secret + RFC 5746 renegotiation indication,
  renegotiation refused with a `no_renegotiation` warning): ECDHE with ECDSA, Ed25519 or RSA
  certificates and AEAD suites only, resumption by session ID and by RFC 5077 tickets, client
  certificates; the RFC 8446 downgrade sentinel is set and checked.
- Suites: TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256 and the six
  ECDHE-ECDSA/RSA AES-GCM / ChaCha20-Poly1305 TLS 1.2 suites. Groups X25519, secp256r1,
  secp384r1. Signatures ECDSA P-256/P-384, Ed25519, RSA-PSS (rsae) and RSA PKCS#1 v1.5 (TLS 1.2
  and certificates). Extensions: SNI, ALPN, supported_versions, key_share, signature_algorithms,
  psk_key_exchange_modes, pre_shared_key, early_data, cookie, extended_master_secret,
  renegotiation_info, session_ticket, ec_point_formats; unknown ones ignored.
- Record layer: 16 KiB fragments, TLS 1.3 inner content types and padding, strict state
  machines, handshake messages reassembled across records (and refused across key changes),
  close_notify, alerts, bounded warning alerts; certificates verified with `only-x509`
  (chain, validity, EKU, DNS names and IP addresses); `insecure_skip_verify` unchanged.
- QUIC-facing core (`only_tls::quic`, `#[doc(hidden)]`, internal): the same TLS 1.3 machines
  without records, driven per encryption level (handshake bytes in and out, traffic secrets per
  level, quic_transport_parameters, ALPN required, no compatibility mode, RFC 9001 key
  derivation helpers with its Appendix A vectors), ready for the in-house QUIC of wave D. Until
  then only-quic keeps quinn-proto, whose rustls configuration it now builds itself from the
  only-tls configs (rustls stays a dependency of only-quic only).
- Tests: RFC 8448 traces (simple 1-RTT, resumption binder, HelloRetryRequest: key schedule,
  transcript, Finished, records byte for byte), in-memory handshakes over every suite, group,
  key type and version, resumption, client authentication, fragmentation down to one byte,
  KeyUpdate, downgrade detection and negative cases; interop matrix
  (`tools/interop/tls/run.sh`, 107 cases: OpenSSL `s_server`/`s_client`, Go `crypto/tls` both
  ways, curl with HTTP/1.1 and HTTP/2), a TLS leg in `tools/interop/grpc/run.sh`, rustls clients
  in `only`'s TLS tests; tlsfuzzer against the server (`tools/interop/tls/tlsfuzzer.sh`: 33
  applicable TLS 1.3 / 1.2 scripts, 985 probes, 5 known and documented failures); fuzz targets
  `tls_server`, `tls_client`, `tls_record` with corpus replays.
- Performance (Apple M4 Pro, 2 server threads, rustls client): full handshakes about 0.7x
  rustls+ring (P-256 ECDSA and X25519 in `only-crypto` are slower than ring's assembly), small
  records on par, bulk throughput about 0.45x (`only-crypto`'s GHASH is portable; PMULL /
  PCLMULQDQ is a wave A follow-up).

Migration: the `unstable` feature of only-tls (and `only/unstable` for TLS) no longer exposes
anything: `only::tls::rustls`, `ServerConfig::from_rustls` / `as_rustls` and
`ClientConfig::from_rustls` / `as_rustls` are removed (they were outside the semver promise).
`ServerConfigBuilder::build` now also fails when the private key does not belong to the
certificate. rcgen and rustls left the dev-dependencies of only-tls, only-http, only-ws,
only-mux, only-h3, only-quic and only-grpc (test certificates come from `only-x509`); `only`
keeps a rustls client in its TLS tests as an interop peer.

### Changed: own QUIC v1 in `only-quic` (DEV-PLAN wave D; no more quinn-proto, rustls, bytes)

`only-quic` now implements QUIC itself, from RFC 9000, 9001 and 9002 plus RFC 9221 datagrams, as
a sans-io core on `only-tls` (its record-free TLS 1.3, `only_tls::quic`) and `only-crypto`
(`#![forbid(unsafe_code)]`, no third-party dependencies). quinn-proto, the rustls inside it
(with ring) and the `bytes` crate left only-quic and only-h3; no library of the workspace
depends on rustls any more. The API is the same apart from the payload type (migration below):
`QuicServer`, `dial`, `Connection`, `QuicHandler`, `ServerConfig` / `ClientConfig` /
`TransportConfig`, `StreamId`, `ConnectionError`, `ConnectionStats`; only-h3's API is unchanged
(`api/only-h3.txt` is identical).

- Packets: long and short headers, the three packet number spaces, packet number encoding,
  header protection (AES, ChaCha20), AES-128/256-GCM and ChaCha20-Poly1305 packet protection,
  coalesced packets, Initial and path-validation padding, Version Negotiation, Retry with the
  integrity tag, stateless resets (sent for unknown connection IDs, detected by token), 1-RTT
  key updates (started every few million packets, followed when the peer starts one).
- Frames: every RFC 9000 frame and DATAGRAM, with the per-packet-type rules; streams with stream
  and connection flow control, stream limits (MAX_STREAMS in batches), BLOCKED frames, final
  size checks, RESET_STREAM in answer to STOP_SENDING.
- Recovery (RFC 9002): RTT estimation, packet and time threshold loss detection, probe timeouts
  and handshake anti-deadlock probes, persistent congestion, NewReno and CUBIC (RFC 9438),
  pacing, the 3x anti-amplification limit, ACK delay rules, idle timeout, keep-alive, path MTU
  discovery up to 1452 bytes.
- Endpoint: routing by connection ID (8-byte IDs issued with NEW_CONNECTION_ID, retired and
  replaced), Retry under handshake load, NEW_TOKEN address validation (tokens kept per server
  name in `ClientConfig`), migration with path validation (`ServerConfig::migration(false)`
  refuses it), transport parameter and connection ID checks, session resumption by ticket
  (`server_config` enables tickets).
- I/O: full-size datagrams leave in GSO batches (`Conn::send_segments`, up to 10); writes made
  from a connection's own callbacks are corked and leave with the acknowledgments once the
  callback returns, so an HTTP/3 response's headers, body and FIN usually share one packet.
- Tests: RFC 9001 Appendix A vectors, unit tests per component and a simulated network (loss,
  reordering, duplication, MTU, blackouts, virtual clock) for handshakes, bulk transfers, many
  streams, migration, key updates, Retry, resumption, resets and timeouts; interop with quic-go
  in both directions as raw QUIC (`tools/interop/quic/run.sh`, new: streams and datagrams, then
  Retry, key updates and a 150 MB stream) and as HTTP/3 with quic-go and fib
  (`tools/interop/h3/run.sh`); in Docker, ngtcp2 1.11 (through libcurl-gnutls) and OpenSSL 3.5's
  QUIC (curl, libcurl, `openssl s_client -quic`) as clients of our servers
  (`tools/interop/quic/docker.sh`, new); fuzz targets `quic_packet`, `quic_frame`, `quic_conn` with corpus
  replays.
- Performance against the quinn-proto version, same loopback benchmark
  (`crates/only-h3/examples/quic-bench.rs`): on an AMD Ryzen 7 7800X3D (Linux, loopback, 3 alternating rounds) full handshakes 6705-6785/s against 6536-6674/s (about 1.0x), bulk throughput on one stream 3.1-3.6 Gbit/s against 4.6-4.7 Gbit/s (about 0.72x; packet protection uses `only-crypto`'s hardware AES-GCM), and HTTP/3 requests on one connection with 64 in flight 171k/s against 58k/s (about 2.9x, since responses, FINs and acknowledgments share packets).

Migration: stream and datagram payloads are `only_quic::Bytes` instead of `bytes::Bytes`, the
only signature change (`QuicHandler::on_stream_data`, `QuicHandler::on_datagram`,
`Connection::send` and `Connection::send_datagram` take `impl Into<only_quic::Bytes>`). It has
the same shape (reference counted; `new`, `from_static`, `copy_from_slice`, `slice`,
`split_to`, `split_off`, `truncate`, `advance`, `Deref<Target = [u8]>`, `From<Vec<u8>>`,
`From<&'static [u8]>`, `From<&'static str>`, `From<String>`, `Vec<u8>: From<Bytes>`), so code
usually only changes its import: `use bytes::Bytes;` becomes `use only_quic::Bytes;`. The
`unstable` feature of only-quic is reserved and empty: `only_quic::proto`,
`ServerConfig::from_quinn` / `as_quinn_mut` and `ClientConfig::from_quinn` / `as_quinn_mut` are
removed (they were outside the semver promise). `Congestion::Bbr` (experimental) runs CUBIC.
`Connection::queued_bytes` counts bytes not sent yet. A dialed connection's UDP socket is now closed once the connection is gone (it used to stay open until the engine stopped), and `open_bi` / `open_uni` never run handler callbacks, so they may be called while holding locks the handler takes. Not implemented: 0-RTT, sending ECN marks,
client-initiated migration, preferred_address, QUIC v2.

### Changed: own WebRTC stack in `only-webrtc` (DEV-PLAN wave D; no more str0m, dimpl, p256)

`only-webrtc` runs on an in-house, sans-io WebRTC stack with no third-party dependencies, behind
the unchanged API (`RtcServer`, `Endpoint`, `Peer`, `PeerHandler` and its ordering guarantees,
`ChannelConfig`, `Codec`, `SdpChanges`, `Event`, `RtcError` ...). Four new internal crates, all
`#![forbid(unsafe_code)]` on `only-crypto`:

- `only-ice`: ICE (RFC 8445) full agent and ICE-lite: candidate priorities and foundations,
  checklists with pacing and retransmission, peer-reflexive candidates, regular nomination, role
  conflicts (487), checks before the remote credentials, consent freshness (RFC 7675), trickle
  (RFC 8838) and restarts; STUN through `only-turn`'s codec. RFC 5769 vectors; pion/ice interop.
- `only-srtp`: SRTP/SRTCP (RFC 3711, RFC 7714) with AES-CM-HMAC-SHA1-80/32 and
  AEAD-AES-128/256-GCM, ROC estimation, replay windows; RFC 3711 and RFC 7714 vectors and
  byte-exact cross-checks with pion/srtp.
- `only-rtp`: RTP header extensions (one- and two-byte), RTCP (SR, RR, SDES, BYE, generic NACK,
  PLI, FIR, REMB, transport-wide CC feedback), send/receive streams with NACK + RTX (RFC 4588),
  reports and RTT, TWCC and a delay- and loss-based bandwidth estimator; payload formats for
  Opus, G.711, G.722, VP8, VP9, H.264 (RFC 6184), H.265 (RFC 7798) and AV1 with a jitter-free
  frame assembler. Byte-exact cross-checks with pion/rtp, pion/rtcp and pion/interceptor.
- `only-sctp`: SCTP over DTLS (RFC 8261; RFC 9260 essentials) with congestion control, fast
  retransmit, PR-SCTP FORWARD-TSN (RFC 3758), stream reset (RFC 6525), DCEP data channels
  (RFC 8831/8832); interop with pion/sctp 1.8 and 1.12 over UDP.

`only-webrtc` itself gained the SDP offer/answer (BUNDLE, rtcp-mux, codec / RTX / rtcp-fb /
extmap negotiation, ssrc and FID groups, setup roles and fingerprints, ICE-lite, candidates,
sctp-port / max-message-size, renegotiation and ICE restarts) and the sans-io peer that glues
the layers together. Tested on a simulated lossy link (ICE + DTLS + SCTP + media) and against
pion (data channels, Opus/VP8 echo, PLI, a TURN relay, both offer directions), fib's Go WebRTC
(both directions) and headless Chrome (`tools/interop/media/browser.sh`: data channels, Chrome's
camera and microphone echoed back and decoded, both offer directions). New fuzz targets
`ice_stun`, `srtp_unprotect`, `rtp_rtcp`, `rtp_codec`, `sctp_packet`; `webrtc_sdp` now drives the
new SDP code.

Migration notes:

- The `unstable` feature of `only-webrtc` is now reserved and empty: `only_webrtc::str0m`,
  `crypto_provider_str0m`, `Peer::with_rtc`, `RtcConfig::with_str0m` and
  `OtherEvent::as_str0m` are gone (they were outside the semver promise).
- The covered API is unchanged except that `Event`, `OtherEvent`, `RtcConfig`, `RtcError` and
  `SdpChanges` are now `RefUnwindSafe` (and `RtcError` `UnwindSafe`): auto traits gained, nothing
  lost.
- Behaviour: H.265 is no longer offered by default (`RtcConfig::enable_h265(true)` turns it on),
  DTLS is 1.2 only (browsers and pion negotiate 1.2), the answerer takes the DTLS client role
  (`a=setup:active`), `OtherEvent`'s `Debug` output changed (it was never stable), and
  `Endpoint` still has no TURN client (relayed candidates must come from elsewhere, as before).
- Dependencies: str0m, dimpl, p256 / ecdsa / elliptic-curve, the RustCrypto crates they pulled
  and rand 0.9 left the library graph; only-dtls's in-memory interop test against dimpl was
  removed. p256/p384 0.13 remain dev-dependencies of only-crypto's cross-checks, so the
  RUSTSEC-2026-0387 (crypto-bigint) ignore in `deny.toml` now only covers them.

### Changed: in-house HTTP codecs (no more httparse, loona-hpack, regex)

DEV-PLAN "no third-party dependencies", wave A. The public API is unchanged.

- HTTP/1 head parsing (only-http requests, chunked trailers and client responses, only-ws client
  handshake responses) uses an in-house parser, `only_ws::http1` (`#[doc(hidden)]`): zero-copy,
  incremental (a head arriving in many reads is scanned once instead of re-parsed from the start
  on every read; the session also stops copying the buffered bytes on every read) and strict per
  RFC 9110/9112: token methods and field names, visible-ASCII request targets (non-ASCII bytes,
  which httparse let through, are now 400), exactly one SP between request-line elements, a bare
  CR, whitespace before a colon or the first field and obsolete line folding are rejected (also
  in responses), CRLF or bare LF line ends. Header values are no longer `str::trim`med (only
  SP/HTAB around them are removed, as RFC 9110 says). Speed is on par with httparse (SIMD) using
  word-at-a-time scanning in safe code (`tools/codec-bench`).
- HPACK is in-house (`only_http::hpack`, `#[doc(hidden)]`): encoder with dynamic table, Huffman
  coding when not longer, never-indexed literals for `authorization` / `proxy-authorization` /
  short `cookie`s and the table size updates RFC 7541 §4.2 requires after the peer changes
  `SETTINGS_HEADER_TABLE_SIZE` (loona-hpack sent none); decoder with dynamic table, size updates
  only at the start of a block and within our setting, 32-bit integers, and a header list limit
  applied while decoding (the whole block is still processed so the table stays in step); the
  Huffman decoder walks 4 bits at a time. RFC 7541 Appendix C vectors pass both ways; h2spec
  147/147.
- Route constraints (`{id:[0-9]+}`) use an in-house linear-time engine (`only_http::re`): literals,
  `.`, classes with ranges/negation/escapes, ASCII `\d \w \s` (and negations), groups (named
  ones too, nothing is captured), `|`, `* + ? {m} {m,} {m,n}` with lazy variants, `^`/`$`;
  unsupported syntax (flags, `\b`, `\p{..}`, backreferences, POSIX classes, class set
  operations, counts above 1000) panics at registration naming the problem. Regexp parameters are
  always available; the `regex` cargo feature of only-http is kept as a no-op for compatibility.
- Fuzzing: `http1_request` / `http1_client` compare the head parser with httparse, `hpack` with
  loona-hpack (both directions of encode/decode too), new `regex_match` with the `regex` crate;
  those crates remain only as dependencies of `fuzz/` and of the `tools/codec-bench` micro
  benchmarks (both outside the library workspace).
### Changed (internal): own syscall and io_uring bindings (no more `libc`, `io-uring`)

DEV-PLAN "no third-party dependencies", wave B. No public API changes; behaviour, errno and
`EINTR` handling are unchanged.

- `only-sys` declares its own OS bindings in `only_sys::ffi` (`#[doc(hidden)]`, internal): C
  types, constants, `#[repr(C)]` structs (`sockaddr_in`/`in6`/`storage`/`ll`, `msghdr`,
  `mmsghdr`, `cmsghdr` with the `CMSG_*` helpers, `iovec`, `epoll_event` (packed on x86_64),
  `kevent`, `timespec`, `pollfd`, `cpu_set_t`, `sigaction`, `utsname`) and `extern "C"`
  declarations of the C library (Linux, glibc or musl) and libSystem (macOS). System calls
  without a C wrapper (`bpf`, `io_uring_*`) use `syscall(2)` with per-architecture numbers.
  Linux x86_64 and aarch64 (riscv64 / loongarch64 share the generic layouts) and macOS
  aarch64 / x86_64; other Linux architectures fail to compile with a clear message instead of
  silently using wrong layouts.
- Every layout and constant is compared with the `libc` crate in a test-only module (`libc` is
  now a dev-dependency only), verified on macOS aarch64, Linux aarch64 and Linux x86_64.
- `only-uring` has its own io_uring binding (`ring`): `io_uring_setup` / `io_uring_enter` /
  `io_uring_register`, the mmap'd SQ/CQ rings and SQE array with the kernel's memory ordering,
  the submission entries the reactor uses (multishot accept, multishot recv with buffer
  selection, poll add, async cancel and cancel-any, read), CQE flags, opcode probing and
  `IORING_FEAT_*` checks (the probe now also requires `IORING_FEAT_EXT_ARG`), SQPOLL and the
  cooperative / single-issuer / deferred task-run setup. The buffer-ring, `KernelBuf`,
  in-flight cancel and graveyard logic is unchanged.
- `only-ebpf` and `only-dpdk` (TAP, AF_PACKET) use `only_sys::ffi`.

### Changed (experimental tier): only-dpdk runs its own TCP/IP stack

`only-dpdk` no longer depends on smoltcp (DEV-PLAN "no third-party dependencies", wave A): the
userspace stack is now `only`'s own, in `crates/only-dpdk/src/net` (safe Rust,
`#![forbid(unsafe_code)]`, no dependencies), with the same `Device` kinds, `DpdkConfig` and
`Backend::Dpdk` integration.

- Ethernet II; ARP with a 60 s cache and a queue of packets awaiting resolution (the first SYN to
  a new neighbour is no longer dropped, which cost the smoltcp version a 1 s SYN retransmission);
  IPv4 with fragmentation on send and bounded reassembly (UDP datagrams larger than the MTU now
  work); ICMP echo replies, port / protocol unreachable, and received unreachables delivered to
  dialed UDP connections (closed with `ConnectionRefused`, as on the kernel backends).
- TCP per RFC 9293: RTT / RTO per RFC 6298, SACK (RFC 2018) with RFC 6675-style recovery,
  NewReno fast recovery (RFC 6582), CUBIC (RFC 9438, the default) or NewReno, window scaling and
  timestamps with PAWS (RFC 7323), delayed ACKs, keepalive, TIME-WAIT with reuse, RFC 5961
  challenge ACKs, a listen backlog with SYN cookies.
- The I/O loop is event-driven with a per-connection timer heap (the smoltcp version re-examined
  every connection on each busy iteration); ACKs are coalesced per receive burst; a memory-wire
  end wakes its peer's thread when it sends.
- Dialing works on multi-queue DPDK ports (was `Unsupported`): local ports name their queue and
  replies RSS puts elsewhere are handed over.
- New `DpdkConfig` fields: `syn_cookies` (default `true`), `congestion`
  (new `only::dpdk::Congestion`, default `Cubic`), `tcp_keepalive` (default `None`).
  `udp_buffer` now bounds the datagrams queued per UDP port.
- TAP and AF_PACKET devices use `libc` directly (`src/sys.rs`); the AF_PACKET socket gets an 8 MiB
  receive buffer and skips the host's outgoing frames.
- Tests: per-layer unit tests, a simulated lossy / reordering link in virtual time, the kernel
  peer suite extended with `tc netem` loss, a 4 MiB window over 20 ms, 500 concurrent
  connections, dials to the kernel and ping; fuzz targets `dpdk_ethernet`, `dpdk_arp`,
  `dpdk_ipv4`, `dpdk_tcp`, `dpdk_udp`, `dpdk_icmp`, `dpdk_stack`. Benchmark example
  `stack-bench`; A/B against the smoltcp version in docs/BENCHMARKS.md.
- `deny.toml`: the 0BSD license and the `bitflags@1` duplicate (both smoltcp's) are gone.

### Changed (performance): QUIC and TLS hot paths (DEV-PLAN performance pass)

No API change. Ryzen 7 7800X3D, loopback, three alternating rounds (docs/BENCHMARKS.md):

- `only-quic`: single-stream bulk 3.4-3.7 → 5.7-5.8 Gbit/s (1.25x the quinn-proto version, was
  0.72x), HTTP/3 requests on one connection with 64 in flight 171k → 415-426k/s, handshakes +2%.
  The pacer floored the RTT at 1 ms and, once empty, woke the sender for every packet through the
  timer thread; it now uses the measured RTT and waits for a whole burst to refill (as
  quinn-proto does), so paced data leaves in GSO batches from the I/O thread (per GiB: futex calls
  423k → 5.6k, context switches 182k → 9.5k). Also cheaper per-packet bookkeeping (stream maps
  without SipHash, in-order range inserts with one lookup, no per-datagram allocations for the
  batch buffer and space selection).
- `only-tls`: received records are copied once, straight into the caller's plaintext buffer, and
  decrypted there (they used to go through the receive buffer and be copied out); large writes
  reserve room for all their records at once. Seal + open +5-7% for 16-64 KiB records. Handshakes
  were profiled: over 98% is curve arithmetic and hashing, so they are unchanged. New
  `crates/only-tls/examples/tls-bench.rs` compares against rustls 0.23 + ring (dev-dependency
  only).

### Changed (performance): only-deflate at zlib-rs speed (DEV-PLAN performance pass)

`only-deflate` (still `#![forbid(unsafe_code)]`, no dependencies, no SIMD) now compresses at
0.94-1.48x the speed of flate2 with the zlib-rs backend (was 0.25-0.9x) with output at most 0.5%
larger (identical in 36 of 45 level × corpus cases), and decompresses at 0.82-1.23x (was
0.7-0.85x); measured on x86-64, tables in docs/BENCHMARKS.md. The streams are as valid as before
for every window size (8 laid out as 9); no API change.

- Compression uses zlib-ng's / zlib-rs's level table and match finders: a hash of four bytes
  (three at level 9), `quick` at level 1 (one probe per position, fixed-code blocks written
  directly, replaced by stored blocks when those are smaller), `fast` at level 2, `medium` at
  levels 3-6 (greedy, from level 5 looking one match ahead), lazy `slow` at 7-9 with zlib-ng's
  chain-jumping search at level 9. Candidates are compared 8 bytes at a time with a cheap
  rejection first. **Level 1 output is now up to 40% larger than before** (like zlib-ng's and
  zlib-rs's level 1) and 1.7-2.9x faster; levels 2-9 are 1.03-4x faster, with output between
  12% smaller and 3.4% larger than before.
- `Deflater::reset` (permessage-deflate without context takeover) clears only the hash slots a
  short stream used instead of the whole table; stored blocks are written straight from the
  window; Huffman code construction counts lengths without store-forwarding stalls.
- Decompression: a fast path refills 64 bits without branches and decodes up to three literals
  or a length/distance pair per refill; matches are copied 8 or 16 bytes at a time (also for
  overlapping matches); decoding tables of complete codes are no longer cleared first.
- permessage-deflate echo (`pmd_echo`, level 6, context takeover) against zlib-rs: 1.84x for 64 B
  messages, 1.04x for 512 B, 1.00x for 4 KiB, 0.98x for 64 KiB (was 1.36x / 0.62x / 0.75x /
  0.54x), with the same bytes on the wire as zlib-rs.
- The `bench` example covers levels 1..=9 (`BENCH_LEVELS`), generated corpora plus files and a
  profiling mode (`BENCH_PROFILE`); a new streaming test covers every level, window size and
  flush kind.

### Added

- `only-protobuf` and `only-protobuf-build` (DEV-PLAN "no third-party dependencies", wave A):
  an in-house protobuf runtime and code generator replacing prost, with no dependencies.
  - `only-protobuf`: the wire format, `Message` (encode, decode, merge, length-delimited),
    open enums (`Enumeration`), unknown-field preservation (`UnknownFields`), `Name`, bounded
    decoding (100 nesting levels, checked lengths, UTF-8; a field with an unexpected wire type
    is kept as an unknown field, as in C++ and Go), and `well_known` (`Empty`, `Timestamp`,
    `Duration`, `Any`, wrappers, `FieldMask`, `Struct` / `Value` / `ListValue`, with `std`
    conversions and `Any::pack` / `unpack`). Encodes byte for byte as protoc's C++ runtime.
  - `only-protobuf-build`: a `.proto` parser (proto3 and proto2: messages, nested types, enums,
    `optional`, `required`, `repeated`, `map`, `oneof`, defaults, packages, imports, built-in
    well-known types) and Rust generator for `build.rs` (`compile(&["x.proto"], out_dir)`,
    `Config`), no `protoc`. Services become `only-grpc` stubs: a `<service>_server` trait with
    `register`, and a typed `<service>_client`; messages then implement
    `only_grpc::codec::Message`.
  - Checked against golden encodings from protoc, differentially against prost (tests and the
    `protobuf_diff` fuzz target), and with grpc-go's generated route_guide / helloworld code in
    both directions (`tools/interop/grpc/run.sh`, new `tools/protobuf-test`).
- `only-grpc`: `Sink::send_message` and `ClientSink::send_message` (encode a `codec::Message`
  and send it), and the re-export `only_grpc::Headers`.

- `only-prefork` (M6, optional): serve one program from several worker processes. A supervisor
  re-executes the current binary as N workers (no fork after threads), each running its own
  `Engine`; listeners are shared with `SO_REUSEPORT` (Linux default) or inherited from the
  supervisor (`ListenMode::Inherit`, the macOS default; no connection is refused across restarts
  and reloads); crashed workers are restarted with exponential backoff; SIGTERM/SIGINT drain the
  workers, SIGHUP (or `Supervisor::reload`) starts a new generation and stops each old worker once
  its replacement is ready; optional CPU pinning (Linux); `Worker` gives the index, worker count
  and generation. Example `prefork-http`, book chapter "Multi-process serving (prefork)".
- `only::Listener::tcp_from_std`: serve an already bound and listening socket (inherited from a
  supervisor, systemd socket activation); internal `EpollGroup::bind_listener` /
  `UringGroup::bind_listener`.
- `only-sys` (internal): `process` module (child fd inheritance, CPU affinity and parent-death
  signal in `pre_exec`, `take_inherited_fd`, `reserve_reuseport`, a self-pipe `signal_pipe`, `kill`).
- `only-deflate` (internal, DEV-PLAN "no third-party dependencies", wave A): DEFLATE, zlib and
  gzip in pure safe Rust without dependencies, replacing `flate2`/`zlib-rs` in `only-ws`
  (permessage-deflate), `only-http` (compression middleware) and `only-grpc` (gzip messages).
  Streaming `Inflater` (any input split, bounded output, windows 2^8..2^15, zlib's code checks)
  and `Deflater` (hash chains, lazy matching, zlib levels 0..=9, length-limited dynamic Huffman,
  fixed or stored blocks, sync/full flush, windows 2^8..2^15), Adler-32 and CRC-32. Interop both
  ways with zlib-rs and `gzip(1)`; fuzz targets `deflate_inflate` (differential against zlib-rs)
  and `deflate_roundtrip`; Miri runs its tests, and the Miri job runs the only-grpc gzip test
  again (the zlib-rs aliasing report in docs/unsafe-review.md no longer applies). Public APIs of
  the other crates are unchanged.
- `only-ws`: permessage-deflate with a window of 8 bits. A server accepts
  `server_max_window_bits=8` (it used to decline such an offer) and a client told
  `client_max_window_bits=8` compresses (it used to send uncompressed); the compressor keeps
  distances within 250 bytes there. `deflate::Deflater`, `deflate::Inflater` and
  `protocol::Decoder` are now `UnwindSafe` (they no longer hold zlib-rs state).

### Deprecated

- The `prost` feature of `only-grpc` (outside the semver promise): it still works; use
  `only-protobuf` / `only-protobuf-build` instead. It may be removed in a minor release.

### Fixed

- `only-ws`: every WebSocket connection carried ~2 KB of inline permessage-deflate state (the
  only-deflate inflater and deflater inside `Option`s), even when compression was not negotiated;
  the state is now boxed. An idle connection after upgrade + one echo: 3,486 → 1,426 bytes.
- io_uring: during a graceful shutdown, connections the multishot accept completed before its
  cancellation took effect were reset; they are now served (`on_shutdown` after their first data),
  and the drain ends only once the accept has ended, so the listening socket is really closed.
- `only-dpdk` (experimental, M6): a kernel-bypass backend. A userspace TCP/IP stack (smoltcp,
  IPv4) runs on `only` I/O threads over a DPDK port (EAL init from `EalConfig`, one rx/tx queue
  pair and one thread per queue, mbuf rx/tx bursts, RSS with ARP fanned out between queues), a
  Linux TAP interface, an AF_PACKET socket or an in-process `MemoryWire`. UDP listeners deliver one
  datagram per `on_data` and TCP listeners a byte stream, with `dial` / `dial_udp`, backpressure,
  idle timeouts, telemetry and graceful shutdown, so protocol crates (only-kcp, ...) run
  unchanged. Listeners on the same device share its stack and threads.
- `only`: cargo features `dpdk` (`Backend::Dpdk(DpdkConfig)`, re-export `only::dpdk`) and
  `dpdk-pmd` (also DPDK ports; links libdpdk found with pkg-config). Experimental: outside the
  semver promise (docs/api-stability.md).
- `only-core` (backend-facing, `#[doc(hidden)]`): `ConnInner::new_virtual` and
  `ConnInner::drain_output` for connections whose bytes a userspace stack moves.
- `tools/dpdk/` (Dockerfile + `test.sh`) and the heavy CI job `dpdk`: builds against the
  distribution's DPDK and runs UDP/TCP echo against the kernel stack over DPDK's `net_tap` PMD
  (one and two queues), over smoltcp's TAP device and over AF_PACKET on a veth pair.
- `Engine::bind_udp` and `UdpBinding` (`only`, only-core): an unconnected UDP socket bound
  while the engine runs, served like a UDP listener (one connection per peer address), that
  sends to any address with `UdpBinding::send_to`. What ICE agents and TURN relays need.
- `only-turn` (new crate): the STUN codec (RFC 8489, with the TURN and ICE attributes,
  `MESSAGE-INTEGRITY`, `FINGERPRINT`), `StunServer`, and `TurnServer`, a TURN relay over UDP
  (RFC 8656): allocations with long-term credentials (`static_auth`, `ephemeral_auth` for the
  TURN REST API), permissions, channels, Send/Data indications, refresh, `EVEN-PORT` and
  `RESERVATION-TOKEN`, stateless nonces, quotas, and a peer policy refusing private and
  loopback peers by default; `TurnCore` is the same server as a sans-io state machine. Interop:
  pion/turn client and coturn's `turnutils_uclient`.
- `only-webrtc` (new crate): WebRTC on the sans-io `str0m` 0.24 over `only` UDP. `RtcServer`
  serves a UDP listener (ICE-lite by default, peers demultiplexed by ICE username and source
  address); `Endpoint` runs a full ICE agent on a `bind_udp` socket, with server-reflexive
  candidates from a STUN server. `Peer` (any thread) sends on data channels, writes media,
  requests keyframes, renegotiates; `PeerHandler` callbacks run one at a time per peer. DTLS
  1.2/1.3 with fingerprint verification, SRTP (AES-CM, AES-GCM), SCTP data channels (reliable or
  not, ordered or not), RTP/RTCP with NACK, PLI/FIR, TWCC. A pure-Rust crypto provider
  (RustCrypto and `dimpl`, no C toolchain). Interop with pion (data channels and media in both
  offer directions, through a `only` TURN relay) and with fib's Go WebRTC (data channels);
  `tools/interop/webrtc/run.sh`.
- Fuzz targets `stun_message`, `turn_server` and `webrtc_sdp`.
- `only-media` (M7 streaming media), a new crate: one stream hub with RTMP, RTSP, SRT,
  HTTP-FLV, WS-FLV, HLS and WHIP/WHEP signalling around it.
  - `hub`: streams by path, one publisher and many subscribers, GOP cache for fast start,
    `Dropper` (slow players drop to the next keyframe), publish / play auth hooks, reserve
    before the tracks are known, waiting for (re)publishers, `Timeline` timestamp
    normalization, per-stream statistics.
  - RTMP server: simple and Flash digest handshake, chunk stream, publish / play, Enhanced RTMP
    (H.265 `hvc1`, Opus); AMF0 / AMF3; FLV mux / demux (legacy and enhanced tags).
  - HTTP-FLV and WS-FLV playback (`HttpFlv`), HLS with MPEG-TS segments, LL-HLS parts,
    preload hints and blocking reload (`Hls`), `MediaHttp` dispatching both; MPEG-TS muxer.
  - RTSP 1.0 server (ANNOUNCE/RECORD, DESCRIBE/SETUP/PLAY over TCP-interleaved and UDP,
    Digest/Basic auth), RTP packetization for H.264/H.265/AAC/Opus/G.711 with decode times
    derived for B-frame video, SDP, and WHIP/WHEP HTTP signalling with a `WebRtcEngine`
    integration trait.
  - SRT live mode (HSv5 caller/listener, ARQ, TSBPD, AES-CTR encryption with passphrase,
    stream ID access control) with a hub-backed `SrtServer` and `srt::dial` / `push` / `pull`;
    incremental MPEG-TS demuxer (`mpegts::demux`).
  - Interop-tested with ffmpeg / ffprobe as publisher and player (SRT with libsrt in Docker);
    fuzz targets `rtmp_server`, `flv_demux`, `amf_decode`, `rtsp_server`, `sdp_parse`,
    `rtp_depacketize`, `mpegts_demux`, `srt_listener`, `srt_conn`.
- `only_ws::WsSender::queued_bytes`, for pacing a producer that streams to a slow peer.
- `only-bittorrent` (M7): bencode; .torrent v1 files (path safety, `Builder`) and magnet links;
  HTTP and UDP trackers as codecs, a `TrackerClient` (only-http, `dial_udp`) and a
  `TrackerServer` (a only-http service and a UDP acceptor on one store); the peer wire protocol
  with the Fast extension, the extension protocol, ut_metadata and ut_pex; MSE/PE (DH-768, RC4);
  uTP with LEDBAT; the mainline DHT; `port::UdpPort`, uTP and the DHT on one `only` UDP listener;
  and a `client::Client` (magnets, rarest-first picker with endgame, pipelining, choking with
  optimistic unchoke, storage and SHA-1 on a logical pool, PEX, DHT, trackers, events). Interop
  with libtorrent 2.0 and aria2 1.37 (`tools/interop/bittorrent/run.sh`); fuzz targets
  `bt_bencode`, `bt_peer_wire`, `bt_krpc`, `bt_utp`, `bt_tracker`, `bt_mse`.
- `Engine::dial_udp_from`: a peer connection on a UDP listener's own socket, so datagrams to a
  new address leave from the listener's port (DHT nodes, uTP).

### Fixed

- `Engine::dial` no longer picks a UDP group (and fails) when the engine has both TCP listeners
  and UDP listeners or UDP client threads, but no `client_threads`.

## [1.0.0-rc.1] - 2026-11-14

First release candidate of 1.0: the API is frozen for review. The public API of every crate is
recorded in `api/<crate>.txt` and checked in CI.

### Added

**Core engine (M0–M1)**
- Thread-per-core event loops: each I/O thread owns its reactor, connections, buffers and timer
  wheel; callbacks run inline on the owning thread, so per-connection handler state needs no lock
  (ADR-001..004).
- `Handler` / `Acceptor` / `fn_acceptor`, and `Conn`: a cloneable `Send + Sync` handle with
  `send`, `send_owned`, `send_shared` (`SharedBuf`), `send_segments`, `cork`/`flush`,
  `close`/`close_after_send`, `hold_reads`, `on_drain`; using a closed handle returns
  `Error::Closed`.
- Backends: epoll (Linux) and kqueue (macOS) in `only-epoll`; `SO_REUSEPORT` accept distribution;
  asynchronous `Engine::dial`.
- Backpressure (write high watermark, `max_queued_bytes`), idle and write timeouts, connection
  limit, graceful shutdown with a timeout.
- `loom` models for the connection send path, stress tests with 5,000 simultaneous and 100,000
  idle connections.

**Logical pool, io_uring, UDP, TLS (M2)**
- `only-pool` adaptive bounded pool; `Conn::spawn_blocking` with the completion back on the
  connection's I/O thread; ordered response slots (`Conn::reserve_response`, `ResponseSlot`,
  `ResponseStream`).
- Slow-callback detection (`Config::slow_callback_threshold`, `slow_hook`).
- `only-uring`: io_uring backend (multishot accept/recv, provided-buffer rings, kernel probe with
  fallback to epoll); per-listener backend choice (`Listener::backend`).
- UDP: `Listener::udp` (one `Conn` per peer), `Engine::dial_udp`, `recvmmsg`/`sendmmsg`, UDP
  GSO/GRO, `udp_max_peers`.
- `only-tls`: rustls as a sans-io transport layer under `Conn` (`Tls::server`, `Tls::client`,
  `tls_info`).

**HTTP and WebSocket (M3)**
- `only-http`: HTTP/1.1 server with pipelining, chunked bodies and trailers, streaming request
  and response bodies, `Router` (static > `:param` > `*wildcard`, regex parameters, nesting,
  layers), middleware (recover, request id, CORS, logger, response time, compress, etag, csrf,
  limiter), static files (`files::Files`: ranges, precompressed twins, cache, `sendfile`), HTTP/1
  client (`client::Client`, `ResponseFuture`).
- `only-ws`: RFC 6455 with permessage-deflate, `PreparedMessage` broadcast, subprotocols, origin
  check; server upgrade (`Context::upgrade_websocket`) and client (`only_ws::client`); Autobahn
  suite clean.

**HTTP/2 and more protocols (M4)**
- HTTP/2 server on the same `Service` (h2c prior knowledge and upgrade, ALPN `h2`, flow control,
  HPACK, push) and `h2client::H2Client`; h2spec clean.
- `only-mux` (several protocols on one port), `only-arpc` (lesismal/arpc wire format),
  `only-grpc` (unary and streaming gRPC on only-http, gzip, deadlines, interceptors, optional
  prost helpers), `only-socks` (SOCKS5/4/4a and HTTP CONNECT).

**QUIC, HTTP/3, KCP, eBPF (M5)**
- `only-quic` (quinn-proto over `only` UDP) and `only-h3` (HTTP/3 with QPACK, client and server).
- `only-kcp`: KCP compatible with skywind3000/kcp and kcp-go (crypts, Reed–Solomon FEC).
- `only-ebpf`: `SO_REUSEPORT` steering by CPU or consistent hash (classic BPF unprivileged, eBPF
  when privileged) via `Accel::Ebpf`, and an in-kernel sockmap `Relay`.

**Production readiness (M6)**
- Telemetry: per-thread counters, `Engine::metrics` (Prometheus and JSON), connection table,
  slow-callback ring, live reload of settings (`Engine::reload`), `only_http::observe` endpoints
  and HTTP metrics.
- Seeded chaos test suites (engine, fd exhaustion, TLS, HTTP/WebSocket).

**1.0 stabilization**
- 21 fuzz targets with corpora and coverage reporting; `cargo-deny`/`cargo-audit` gate; unsafe
  review (docs/unsafe-review.md), Miri and sanitizer jobs; strict lint set; mdBook guide in English
  and Chinese with migration guides; benchmark report.
- API freeze: `docs/api-stability.md` (semver, MSRV and platform policy), `docs/deprecation.md`,
  this changelog, public API snapshots (`api/*.txt`, `tools/api/public-api.sh`) checked by the CI
  job `public-api`, and a `semver-checks` job that activates once 1.0.0 is published.
- New API from the review: `AnyAcceptor` and `Listener::serve_any` (type-erased acceptors, used
  by `only-mux`); `Request::new`, `ClientRequest::new`/`body`, `FileBody::new`; re-exports of
  `Part`, `ResponseStream`, `Transport` and `SharedBuf` from `only` (and `SharedBuf` from
  `only-core`); `only_h3::H3Error`; `Display`/`Error` for `InflateError`, `ProtocolError`
  (ws), `FrameError` (arpc) and `QpackError`; `only_core::Error::source` returns the I/O error.
- Every public type implements `Debug`; builder methods are `#[must_use]`.

### Changed (breaking, with migration)

Config and report structs and the enums that may grow are now `#[non_exhaustive]`: struct
literals no longer compile outside `only`. Start from `Default` (or a preset) and assign fields:

```rust
// before
let cfg = Config { idle_timeout: Some(d), ..Config::default() };
// after
let mut cfg = Config::default();
cfg.idle_timeout = Some(d);
```

Affected structs: `only`: `Config`, `UringConfig`, `EbpfConfig`, `PoolConfig`, `PoolStats`,
`SlowCallback`, `UdpStats`, `ConnInfo`, `LoopMeta`, `LoopCounters`, `LoopMetrics`, `Metrics`,
`ReloadReport`, `SlowRecord`; `only-tls`: `TlsInfo`; `only-http`: `HttpConfig`, `H2Config`,
`H2Options`, `WsOptions`, `Request`, `Response`, `FileBody`, `ClientRequest`, `ClientResponse`,
`Cors`, `Compress`, `LogRecord`, `HttpSnapshot`; `only-ws`: `WsConfig`, `DialOptions`, `PmdOffer`,
`PmdParams`, `ProtocolError`; `only-grpc`: `CallOptions`, `Status`, `Metadata`; `only-kcp`:
`KcpConfig`, `Stats`; `only-h3`: `H3Config`; `only-ebpf`: `AttachOptions`, `SteerInfo`, `Probe`;
`only-arpc`: `proto::Message`. Enums (add a wildcard arm to `match`): `only::Error`, `Part`,
`Backend`, `Accel`, `AccelStatus`, `only_http::Method`, `Version`, `BodyMode`, `ClientError`,
`only_ws::client::WsClientError`, `deflate::InflateError`, `only_mux::Rule`,
`only_arpc::CallError`, `proto::Cmd`, `only_quic::Error`, `only_h3::qpack::QpackError`,
`only_kcp::KcpError`, `CloseReason`, `only_ebpf::Steering`, `HashKey`, `Tier`.

Renames and signature changes:

| Crate | Before | After |
|---|---|---|
| `only` | `Listener::serve_dyn(Arc<dyn DynAcceptor>)` (hidden) | `Listener::serve_any(impl Into<AnyAcceptor>)` |
| only-mux | `Mux::into_dyn() -> Arc<dyn DynAcceptor>` | `Mux::into_any() -> AnyAcceptor` (also `From<Mux> for AnyAcceptor`; pass the `Mux` to `serve_any` directly) |
| only-mux | `Mux::route_dyn(rule, Arc<dyn DynAcceptor>)` | `Mux::route_any(rule, impl Into<AnyAcceptor>)` |
| only-mux | `Mux::max_sniff(n)` | `Mux::max_sniff_bytes(n)` |
| only-http | `H2Client::connect(..)` | `H2Client::dial(..)` |
| only-http | `H2Client::connect_blocking(..)` | `H2Client::dial_blocking(..)` |
| only-ws | `client::connect(..)` (blocking) | `client::dial_blocking(..)` |
| only-ws | `INTERNAL_ERROR` | `protocol::close::INTERNAL` |
| only-arpc | `dial(..)` (blocking) | `dial_blocking(..)` |
| only-arpc | `Routes::max_body(n)` | `Routes::max_body_bytes(n)` |
| only-grpc | `GrpcClient::gzip(bool)` | `GrpcClient::compress(bool)` (same name as `GrpcServer::compress`) |
| only-grpc | `GrpcServer::max_message(n)` | `GrpcServer::max_message_bytes(n)` |
| only-h3 | `H3Client::connect(..)` | `H3Client::dial(..)` |
| only-h3 | `server(quic, service)` | `serve(quic, service)` |
| only-h3 | `server_with(quic, service, cfg)` | `serve_with(quic, cfg, service)` (config before service, as in `only_http::serve_with`) |
| only-h3 | `H3Config::max_body`, `max_field_section` | `max_body_bytes`, `max_field_section_bytes` |
| only-h3 | `Result<Response, String>` from `request`, `request_blocking`, `get` | `Result<Response, H3Error>` (`Closed`, `Reset(code)`, `Protocol`, `Timeout`) |
| only-kcp | `Config` | `KcpConfig` |
| only-kcp | `KcpServer::new`, `dial`, `dial_conv`, `Crypt::new` returning `Result<_, String>` | `std::io::Result<_>` (`InvalidInput` for bad settings) |
| only-kcp | `Kcp::stats: [u64; 4]` (public field) | private; use `Session::stats()` |
| only-ebpf | `Relay::new_unchecked(pairs)` | `Relay::new_any_kernel(pairs)` |
| only-ebpf | `Relay::splice_conns(&Arc<ConnInner>, &Arc<ConnInner>)` | `Relay::splice_conns(&Conn<A>, &Conn<B>)` |

Moved out of the covered API (now `#[doc(hidden)]`; backend-facing or test helpers that may change
in any release): `only_core::{LoopLink, Task, Pool, LoopStats, telemetry::Counter,
telemetry::json_str, telemetry::prometheus_header}` and backend-only `Telemetry` methods,
`only::{DynAcceptor, DynHandler}` re-exports, `only_http::transport`, `only_ws::WsSession`,
`only_ebpf::{cbpf, SLOTS, slot_table, expected_index}`.

Versioning: all crates are at `1.0.0-rc.1` and depend on each other with exact (`=`) versions;
`only-sys`, `only-buf`, `only-timer`, `only-pool`, `only-epoll` and `only-uring` are internal
crates without a semver promise of their own (see docs/api-stability.md).

[Unreleased]: https://github.com/lesismal/only/compare/v1.0.0-rc.1...HEAD
[1.0.0-rc.1]: https://github.com/lesismal/only/releases/tag/v1.0.0-rc.1
