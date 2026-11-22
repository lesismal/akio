# ADR-061: A complete QPACK encoder and streamed responses on the HTTP/3 client

English | [简体中文](061-qpack-encoder-h3-streamed-responses.zh-CN.md)

Status: accepted (2026-11-20)

## Context

ADR-011 gave akio-h3 a QPACK dynamic table on both sides, but this side's encoder stayed a
subset of RFC 9204: it inserted with static name references or literal names only, never used
the Duplicate instruction, never referenced a name in its own table, and referenced only entries
the peer had acknowledged, so the blocked-streams budget the peer grants
(`SETTINGS_QPACK_BLOCKED_STREAMS`) went unused and a field was compressed only from the message
after the acknowledgement of the one that inserted it. The client buffered every response
(`H3Client::request`, bounded by `max_body_bytes`), while the HTTP/2 client already streamed
them (`H2Client::open`, `H2Event`). Server push was the last ADR-011 gap and is left out
(below).

## Decision

### 1. The encoder (akio-h3, `qtable::Encoder`)

- **Inserts** are written with a static name reference, a dynamic name reference (the newest
  entry with that name, if it is not about to be evicted) or a literal name.
- **Conservative insertion.** A field is inserted the second time the encoder sees it (a
  256-slot direct-mapped filter of fingerprints remembers the first time), never for fields that
  change per message or are sensitive (`:path`, `date`, `content-length`, validators, ranges,
  `age`, `expires`, credentials, cookies; RFC 9204 §7.1), and an entry may take at most a quarter
  of the table. One-off values therefore cost nothing on the encoder stream.
- **References.** A section's Base is the Insert Count when it starts; entries inserted while
  it is encoded get post-base indices (indexed lines and literal lines with a name reference,
  RFC 9204 §4.5.3, §4.5.5), so the second sighting of a field is already a one-byte reference.
  Literal lines use a dynamic name reference when the name is in the table.
- **Blocking within the peer's budget.** A section may reference an entry the peer has not
  acknowledged (Known Received Count) only if its stream already has such a section in flight,
  or fewer streams than the peer's `SETTINGS_QPACK_BLOCKED_STREAMS` (at most 64 whatever the
  peer says) have one; otherwise it uses acknowledged entries, static references and literals.
  With a budget of 0 the encoder behaves as ADR-011's (never blocks). The decision is made once
  per section, lazily, at the first reference that needs it.
- **Duplicate.** A referenced entry in the oldest quarter of a full table ("draining") is
  duplicated (RFC 9204 §4.3.4) when the copy fits without evicting anything still needed; the
  section then references the copy (if it may block) or still the old entry, and later sections
  find the copy, so the old one can be evicted.
- **Eviction** takes only entries below the Known Received Count that no unacknowledged section
  (nor the one being encoded) references, and never the entry an insert or a Duplicate names.
- **Acknowledgements.** Section Acknowledgement takes the stream's oldest unacknowledged section
  and raises the Known Received Count to its Required Insert Count; Stream Cancellation drops the
  stream's sections (freeing its share of the blocked budget); Insert Count Increment raises the
  count, refusing 0 and counts beyond what was inserted (`QPACK_DECODER_STREAM_ERROR`). At most
  1024 unacknowledged sections are tracked; past that sections use no dynamic references, so a
  peer that never acknowledges cannot grow the encoder.
- **Configuration is unchanged**: `qpack_encoder_capacity` in `H3Config` / `H3ClientOptions`,
  the peer's `SETTINGS_QPACK_MAX_TABLE_CAPACITY` and `SETTINGS_QPACK_BLOCKED_STREAMS` (now read
  from its SETTINGS).
- **Default: still off** (0), decided by the benchmark below: with the encoder on, every
  message takes the encoder's mutex and every section that uses the table must be acknowledged on
  the decoder stream; `quic-bench h3` (tiny messages, few repeated fields) pays for that and saves
  little, and the peers in our interop matrix (quic-go, curl's nghttp3, fib) advertise a decoder
  table of 0, so the encoder would mostly be per-connection state no one uses. It is one setting
  for deployments whose peers decode with a table and whose messages repeat fields.

### 2. Streamed responses on the client

- `H3Client::open(method, path, headers, on_event) -> H3Upload`, the counterpart of
  `H2Client::open`: the request body is written through the returned `H3Upload` (`write`,
  `finish` at once when there is none, `queued_bytes`), and the response is reported to
  `on_event` on the connection's I/O thread as `H3Event::Head { status, headers }`,
  `Data(&[u8])` for each piece as it arrives (never buffered, not limited by `max_body_bytes`),
  `Trailers(&Headers)`, then `End`, or `Error(H3Error)`. `H3Event` is `#[non_exhaustive]`.
  Upload and download may run at once (full duplex on one request).
- **Backpressure**: `H3Upload::hold_reads(bool)` pauses and resumes reading the response; while
  held, QUIC flow control stops the server once the stream's receive window is used, so a slow
  consumer bounds what a response takes (the window, plus bytes already received). This needs a
  new akio-quic call, `Connection::hold_reads(id, bool)`: a held stream's data stays in its
  receive buffer and its `MAX_STREAM_DATA` is not raised until it is resumed; `stop` drops what
  is held. Callable from any thread, the event callback included.
- **Cancellation**: `H3Upload::cancel()` resets the stream and sends `STOP_SENDING`
  (`H3_REQUEST_CANCELLED`); nothing more is reported.
- **Timeouts**: `request_timeout` applies until the head arrives (as for a WebSocket), then not
  (a download may last as long as the consumer wants; `cancel` ends it).
- **Inside**: a streamed request is a request kind of its own. Until its head it goes through
  the same reader as buffered responses (QPACK blocking included); at the head it moves to a
  per-connection map owned by the I/O thread and is read with the streaming frame reader that
  never holds DATA payloads. Trailers that wait for QPACK inserts hold the stream's reads
  (`hold_reads`), so what arrives behind them is bounded by the window. The buffered path's fast
  path (a response arriving whole) and per-request costs are unchanged: plain requests have no
  new state and one more `is_empty` check per stream chunk.

### 3. No server push

HTTP/3 server push (`PUSH_PROMISE`, push streams, `MAX_PUSH_ID`) stays unimplemented: Chrome
removed push for HTTP/2 and never shipped it for HTTP/3, Firefox disabled it, and 103 Early Hints
replaced its one use (preloading). The client never sends `MAX_PUSH_ID`, so a server may not
push (RFC 9114 §4.6); as before, a push stream reaching the client is refused with
`STOP_SENDING`, and a client's push stream or `PUSH_PROMISE` reaching the server is a connection
error. `Context::push` stays HTTP/2 only. Nothing in the API anticipates push.

## Consequences

- Public API, additions only: `H3Client::open`, `H3Event`, `H3Upload::hold_reads`,
  `H3Upload::cancel` (akio-h3); `Connection::hold_reads` (akio-quic). `api/akio-h3.txt` and
  `api/akio-quic.txt` gain only these lines.
- Benchmarks (gpu51, `quic-bench h3 5 64`, CPUs 2-5, two same-run A/Bs of 7 alternating rounds
  against main b22519ae, through `quiet.sh`): default configuration (encoder off) at parity, 0.997x and 1.001x in two runs (0.999x over all 14 rounds, 863.9k vs 864.8k req/s; the client's request path only gained a check for streamed responses); with both encoders on, 0.991x of the previous encoder with both on (722.1k vs 728.9k), which is 0.833x of the default (the previous encoder: 0.839x), hence the encoder stays off by default.
- Verification: unit tests for each encoder instruction and rule (post-base references and the
  blocked budget, Duplicate and eviction, dynamic names, the eviction floor); a randomized
  encoder-against-decoder harness (`qpack_encoder`, also a new fuzz target) that delays and splits
  the encoder stream, delays acknowledgements and increments and cancels streams, and checks that
  every section decodes to its fields, that the peer never has more blocked streams than it
  allows and that the tables stay within capacity (1.08 M runs in 5 minutes, clean); `tools/interop/h3/nghttp3-qpack.py` drives
  libnghttp3's QPACK decoder (the one curl uses) with our encoder through the `qpack-pipe`
  example in several table/budget configurations, feeding its decoder stream back (third-party
  peers on the wire advertise no decoder table, so this is how a third-party decoder checks the
  encoder); end-to-end tests for streamed responses (pieces, trailers, backpressure with a held
  stream, cancellation, the head timeout, duplex with both encoders on); a sim test for
  `hold_reads` in akio-quic. Network interop is unchanged (quic-go, fib, curl/ngtcp2 and OpenSSL
  QUIC in Docker, with the server's encoder on and off).
- The client's per-connection state grows by two empty maps; a streamed request costs a boxed
  callback and its `H3Upload` state.
