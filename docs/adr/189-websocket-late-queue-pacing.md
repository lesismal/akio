# ADR-189: A WebSocket's late queue is counted by pacing and bounded by its connection

English | [简体中文](189-websocket-late-queue-pacing.zh-CN.md)

Status: accepted (2026-11-28). akit's A305.

## Context

A server-side WebSocket over TCP or TLS without compression is "plain" in akio-ws (`session.rs`,
since `26b811df`): while its I/O thread is inside `on_data`, what the handler sends collects in a
thread-local batch sent once when the read ends, and what other threads send meanwhile goes to a
late queue (`TxShared::late`) sent right after the batch, so that a message another thread sends
because of one the handler sent cannot overtake it.

That queue was invisible to pacing and had a bound of its own:

- `WsSender::queued_bytes` and `on_drain` reported the connection's send queue alone, which does
  not move while the I/O thread is inside the handler and is often empty. A producer paced on
  `queued_bytes` (rule 8: akit's console socket holds a console connection's reads past 256 KiB)
  never held.
- Past `LATE_MAX` (4 MiB) a late send failed with `Overloaded` while `queued_bytes` read 0, far
  below the connection's `max_queued_bytes` (64 MiB by default).
- `end_batch` sent the late bytes with `let _ = conn.send(..)`: if the connection refused them
  (past `max_queued_bytes`, which `LATE_MAX` did not consider), messages whose sends had returned
  `Ok` were dropped without a word. A close from inside the read also put the close frame before
  them, and the connection then refused them as closed.

akit-tunnel's sealed console WebSocket (each message's number is its AES-GCM nonce, so one lost
message ends the channel) failed `large_transfers_both_ways` 3 to 5 times in 50 with "could not
be sent (overloaded)", always with `queued_bytes()` 0.

## Decision

1. **The late queue counts as queued.** On a plain session `queued_bytes` is the connection's
   queue, plus the late bytes (kept in an atomic beside the queue, read without its lock), plus,
   asked from inside the read on the I/O thread, what the handler's batch holds.
2. **`on_drain` waits for the late bytes.** A waiter set while late bytes are held is kept with
   them and handed to the connection (`ConnInner::on_drain`) when they join its queue at the end
   of the read; it runs once that queue is written. A waiter set while nothing is late goes to the
   connection as before (the connection's queue does not drain while the I/O thread is inside the
   handler, so late bytes added later are joined before it can run). The last waiter set still
   wins; an abort runs a held waiter at once.
3. **One bound: the connection's.** `LATE_MAX` is gone. The late bytes, the batch's reservation
   and the connection's queue stay within the connection's `max_queued_bytes`: a late send is
   refused with `Overloaded` when `late + reserved + len > send_room()`. The batch reserves at
   most 64 KiB (`BATCH_MAX`) of the room left beyond the late bytes when the read begins and each
   time it is sent mid-read; whatever the batch's owner sends past the batch while it is open (a
   message larger than the batch, a control frame, a fragmented or prepared message, a close)
   goes through the late lock and is refused past the room the late bytes leave. A sender paced
   on `queued_bytes` far below `max_queued_bytes` therefore never meets a refusal.
4. **What was accepted is sent.** The batch and the late bytes go to the connection with
   `ConnInner::send_admitted` (hidden): bytes already counted against the bound when they were
   accepted, refused only by a connection that is closed or closing, never with `Overloaded`. A
   transport's framing (TLS records) may take the queue a few bytes per record past the bound
   rather than refuse what senders were told was sent. A close from inside the read sends the
   batch and the late bytes before the close frame, under the late lock, so nothing is accepted
   behind it. A refusal can only come from a connection already ending, whose end the session
   reports (`on_close`).

The other session kinds have no late queue: a compressed or client session sends under the
sender's lock straight to the connection, and WebSocket over HTTP/2 and HTTP/3 sends to its
stream (`WsLink`), so their `queued_bytes` already covers everything a send accepted.

## Consequences

- akit's pacing gate (`akit-tunnel/src/pace.rs`) holds the console's reads while the late queue
  fills, and `large_transfers_both_ways` no longer meets a refused send; akit changes nothing.
- A refusal now happens where the connection's own would (default 64 MiB), not at 4 MiB.
- Cost: a late send takes the connection's write lock to read `send_room` (only while a read is
  in progress); `begin_batch` and `end_batch` take the same locks as before; the handler's
  per-message path inside the read is unchanged (a comparison against its reservation).
- `on_drain` set from inside the read no longer runs at once when nothing is queued but other
  threads' bytes are late; it runs once they are written.

## Verification

`crates/akio-http/tests/ws.rs`: `late_sends_count_in_queued_bytes_and_are_bounded_by_the_connections_queue`
(the I/O thread held inside a read; another thread's sends count in `queued_bytes`, `on_drain`
does not run until they are written, the refusal comes within one message and the batch's
reservation of an 8 MiB `max_queued_bytes`, past 4 MiB, and every accepted message arrives in
order), `late_sends_go_before_a_close_from_inside_the_read`, and
`a_sender_paced_on_queued_bytes_is_never_refused_while_the_handler_reads` (2000 × 16 KiB paced
at 256 KiB under a 1 MiB bound while the client keeps the handler busy). `tests/tls.rs`:
`late_sends_over_tls_fill_the_connections_queue_and_all_arrive` (filled to the bound over TLS,
everything accepted arrives). All four fail without this change. akit-tunnel's
`large_transfers_both_ways` (akit `efd37874`) on gpu51, six copies at once as akit measured it,
240 runs per backend: against akio `5893a0ed` 16 failed on epoll and 24 on io_uring, each with the
hub's "could not be sent (overloaded)"; against this change none failed on either backend, and no
send was refused (also 50 of 50 run alone per backend).
