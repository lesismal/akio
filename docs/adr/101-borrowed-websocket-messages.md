# ADR-101: Borrowed WebSocket messages and a lock-free send path

English | [简体中文](101-borrowed-websocket-messages.zh-CN.md)

Status: accepted (2026-11-23)

## Context

HttpArena's WebSocket profiles (gpu51, gcannon `--ws`, small text messages) put akio behind
Proa, a hyper/tokio entry whose echo loop parses frames in its read buffer, unmasks in place,
appends each reply to one output buffer and writes once per read:

| Profile | Proa | akio (`main`) |
|---|---:|---:|
| echo-ws 512 / 4096 / 16384 conns | 1.32 M / 1.29 M / 1.05 M | 1.24 M / 1.21 M / 999 k |
| echo-ws-pipeline (16 in flight) | 20.4 M / 19.5 M / 15.9 M | 15.7 M / 15.2 M / 12.8 M |

akio already writes once per read (the loop corks the connection around `on_data`), so the gap
is per-message CPU. Per message, `main`:

1. allocated the message (`Vec::with_capacity` in the decoder, then `String::from_utf8`), moved
   it through an `events` `Vec`, and handed it to `on_message` by value;
2. checked text for UTF-8 twice: incrementally as it arrived, then again in `String::from_utf8`;
3. took the `WsSender`'s `Tx` mutex, swapped two thread-local buffers in and out, encoded the
   frame into one of them and copied it again into the connection's queue under the
   connection's write lock.

Proa does none of this (it also checks no UTF-8 and reassembles no fragments; akio must keep
both, RFC 6455 and Autobahn require them).

## Decision

1. **Borrowed decoding.** `Decoder::decode_ref(input, |EventRef| -> bool)` hands out each
   message and control frame borrowed from the decoder's buffers (or from `input` when it is
   unmasked), valid for the call. A message buffer is kept between messages (dropped past
   64 KiB, as the compressed one is). When `input` holds a whole unfragmented, uncompressed data
   frame within the limit, it is unmasked once into that buffer and checked for UTF-8 once;
   everything else (fragments, compression, frames split across reads, control frames, every
   error) takes the general path, which reports the same events and errors.
   `Decoder::decode` keeps its API on top of it.
2. **`WsHandler::on_message_ref(&WsSender, MessageRef<'_>)`**, `MessageRef::Text(&str)` |
   `Binary(&[u8])`. Its default copies the message (`MessageRef::to_message`) and calls
   `on_message`, which now has an empty default: a handler implements either, existing
   handlers are unchanged (owned messages cost what they did). Echoes, relays and parsers that
   keep only what they extract use the borrowed form (rule 5: copy what is kept).
3. **A lock-free send path for "plain" senders.** A server sender over TCP whose connection
   negotiated no compression sends unfragmented messages without the `Tx` mutex: nothing in
   `Tx` is needed to encode them. The frame header (on the stack) and the payload go to the
   connection through `ConnInner::send_parts`, which appends both to the queue under the
   connection's write lock when the bytes are not written at once (inside a callback, or behind
   queued data) and otherwise joins them and sends as `send_owned` does. Frames from different
   threads still never interleave: the connection's write lock orders them.
4. **The close frame cannot be overtaken.** Without the `Tx` mutex, a plain sender racing a
   `close` could put a data frame behind the close frame. For plain senders the close frame
   goes through `ConnInner::send_then_close`, which queues it and sets `close_after_send` in one
   critical section; any later send fails with `Closed`. `closed` became an atomic read without
   the mutex. Compressed connections, clients (which mask with keys from `Tx`) and transports
   other than TCP (HTTP/2, HTTP/3) keep the locked path unchanged.

`send_parts` and `send_then_close` are on the `#[doc(hidden)]` `ConnInner`, outside the semver
promise. The public additions (`MessageRef`, `on_message_ref`, `EventRef`, `decode_ref`,
`EventRef::to_event`) are additive; `on_message` gaining a default is not a breaking change.

## Consequences

- Per message on the echo path: no allocation, one copy in (unmasking), one copy out (into the
  queue), one UTF-8 pass, one lock (the connection's). Measurements: see
  docs/BENCHMARKS.md, "WebSocket echo hot path (ADR-101)".
- Autobahn|Testsuite: server 298 OK + 3 informational, permessage-deflate 216/216, client 514 OK
  + 3 informational and 216/216 without context takeover, as before.
- The `ws_frames` fuzz target already checks that events and errors do not depend on read
  boundaries, which compares the whole-frame path against the general one: 4.7 M runs in ten
  minutes (libFuzzer, macOS arm64), no failures.
- A handler that implements neither `on_message` nor `on_message_ref` now compiles and drops
  messages; the docs say to implement one.
- Not done: zero-copy unmasking in the read buffer (the loop's buffer is shared and read-only
  to handlers), and a lock-free path for compressed connections (the compressor's state needs
  the order the mutex gives).
