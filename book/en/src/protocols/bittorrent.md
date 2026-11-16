# BitTorrent

`only-bittorrent` is BitTorrent on `only`: bencoding, .torrent files and magnet links, HTTP and
UDP trackers (client and server), the peer wire protocol with its extensions and Message Stream
Encryption, uTP and the mainline DHT, and a client that downloads and seeds with all of them.
It is a port of fib's `bittorrent` packages and is wire compatible with mainstream clients:
`tools/interop/bittorrent/run.sh` checks it against **libtorrent 2.0** (uTP with RC4, TCP,
magnet links both ways, the DHT both ways) and **aria2 1.37** (both directions, MSE, magnet,
HTTP and UDP trackers).

## A tracker, a seeder and a leecher

```rust,ignore
{{#include ../../../../crates/only-bittorrent/examples/guide-bittorrent.rs:tracker}}
```

A `TrackerServer` serves both protocols from one in-memory store: `http()` is a only-http
service (paths ending in `announce` and `scrape`, compact and dictionary peer lists, `peers6`),
`udp()` the acceptor of a UDP listener (BEP 15; connection IDs are an HMAC of a secret, the
minute and the client address, so nothing is kept per client).

The store is bounded: `TrackerConfig::max_swarms` (100 000) torrents at once, beyond which an
announce for a new one gets the failure reason `tracker full`, and `max_peers_per_swarm`
(1000) peers per torrent, beyond which a newcomer still gets a peer list but is not recorded.
A swarm is dropped when its last peer leaves or expires (`peer_ttl`, 1 h); expiry costs O(1)
per announce instead of a scan of the swarm, and the store is split into 16 locked shards.

```rust,ignore
{{#include ../../../../crates/only-bittorrent/examples/guide-bittorrent.rs:torrent}}
```

`metainfo::Builder` hashes bytes, in-memory files or a path (streaming) into a v1 torrent with
trackers (BEP 12 tiers), DHT nodes, web seeds and the private flag. `MetaInfo::parse` refuses
what a client must not trust: paths that could escape the download directory, clashing paths,
piece hashes that do not match the length. v2-only torrents are refused; hybrid ones are read
as their v1 part.

```rust,ignore
{{#include ../../../../crates/only-bittorrent/examples/guide-bittorrent.rs:seeder}}
```

```rust,ignore
{{#include ../../../../crates/only-bittorrent/examples/guide-bittorrent.rs:leecher}}
```

## The client

A `Client` is one `only` engine and **one port number**: a TCP listener for peers, and a UDP
listener shared by uTP and the DHT through a `port::UdpPort`. Trackers go through a
`tracker::TrackerClient` on the same engine (only-http for HTTP(S), `dial_udp` sockets for
UDP). Storage reads and writes and every SHA-1 check run on a logical pool (`only-pool`), never
on an I/O thread.
Tracker host names are resolved off the calling thread (`only::dns`, for UDP trackers and,
through only-http's client, HTTP ones), never on the I/O thread that triggered an announce.

- **Torrents** come from a `MetaInfo` (`add_torrent`) or a magnet link (`add_magnet`, the info
  dictionary fetched from peers with ut_metadata, BEP 9/10). `AddOptions` give a storage of the
  torrent's own (`MemoryStorage`, or anything implementing `Storage`; the default is a
  `FileStorage` below `ClientConfig::data_dir`), extra peers and trackers, `paused`, and `seed`
  (take every piece as had, for a torrent just made from its data). Data already in storage is
  hash-checked when a torrent starts, so an interrupted download resumes.
- **A `Torrent`** has `stats()`, `peers()` (address, client, uTP or TCP, encrypted, pieces,
  bytes each way, choke state), `info()`, `metainfo()`, `add_peers`, `pause`/`resume`,
  `wait_metadata` and `wait_complete`. `ClientConfig::on_event` hears metadata, checked, piece
  verified, hash failed, completed, peer connected and disconnected, state changes, tracker
  errors and errors, in order, after the torrent's lock is released.
- **Picking**: rarest first with random ties (the first 4 pieces at random), pieces in progress
  before new ones, 16 KiB blocks pipelined up to the peer's `reqq` (at most 64), refilled once
  half are answered; endgame asks for the last blocks twice and cancels the slower request.
  Requests time out after 30 s; a peer that sends nothing for 60 s is snubbed.
- **Choking**: `upload_slots` (4) for the peers it downloads most from (that take most, when
  seeding), an optimistic unchoke rotated every 30 s, re-evaluated every 10 s, and an interested
  peer unchoked at once while slots are free. With the Fast extension (BEP 6): have-all and
  have-none, 10 allowed-fast pieces, and a choked peer's requests rejected.
- **Connections** dial uTP first (`ClientConfig::utp`) and fall back to TCP when uTP gets no
  answer; MSE first with `Policy::Prefer` (the default) and plaintext after a refusal,
  `Policy::Require` for RC4 only, `Policy::Disabled` for plaintext. Incoming connections are
  told apart by their first bytes (plaintext handshake or MSE). Of two connections to one peer
  ID, the second is refused; a connection to ourselves is detected by peer ID.
- **Peers** come from trackers (`started`, `completed`, `stopped`, intervals honoured, retries
  with backoff), the DHT (`get_peers` and `announce_peer` every 15 minutes, every minute while
  there are few peers; `port` messages both ways), PEX (BEP 11, a message a minute per peer), a
  magnet's `x.pe` and `add_peers`. A private torrent (BEP 27) uses its trackers alone.

## One UDP port: `UdpPort`

```text
datagram ─┬─ uTP header (version 1, type ≤ 4) ──► uTP connection ──► peer session
          └─ anything else ('d…' = DHT)       ──► on_datagram ──► dht::Node
```

`UdpPort` is the acceptor of a `only` UDP listener. It sorts datagrams by their first byte, runs
uTP connections on a 10 ms timer, and **sends from the listener's own port**: to reach an
address that has not written first it opens a peer on the listener socket with
`Engine::dial_udp_from`, so a DHT node is reachable at the port it announces and uTP peers see
the port they were told. `port.connect(addr, handler)` dials uTP; `on_accept` takes incoming
streams; `send_to` and `on_datagram` carry the rest.
At most `set_max_inbound(n)` (1024) incoming uTP connections exist at once; a SYN beyond it is
dropped unanswered (SYNs cost nothing to send and may be spoofed).

## The protocol layers

Each protocol is usable alone, without I/O:

- `bencode`: `Value`, `decode` (strict: no leading zeros, no `-0`, depth limit 256),
  `decode_prefix` (a ut_metadata message's dictionary followed by data), `encode` (sorted keys),
  `raw_value` (the info dictionary's exact bytes, for the info hash).
- `wire`: `Handshake` (reserved bits for BEP 10, the DHT and the Fast extension), `Message` (BEP
  3, `port`, BEP 6), an incremental `Parser`, `Bitfield`, `ExtendedHandshake`, `MetadataMsg`,
  `Pex`, `allowed_fast_set` (BEP 6's algorithm, checked against its test vector).
- `mse`: `Initiator` and `Receiver` take bytes and return bytes to write until `Established`
  (768-bit Diffie-Hellman in Montgomery arithmetic, RC4 with 1024 bytes dropped,
  crypto_provide/select, padding, the SKEY lookup by `HASH('req2', info_hash)`).
- `utp`: `Header` and `Connection`: SYN/DATA/STATE/FIN/RESET, libutp's connection-ID rule,
  16-bit wrapping sequence numbers, selective ACKs both ways, fast retransmit on three duplicate
  ACKs or a SACK past a hole, RTO from the smoothed RTT (500 ms minimum, backoff), LEDBAT (100 ms
  target) with a slow start, keepalives, FIN and idle timeouts.
- `dht`: `Node` takes datagrams and the clock, and queues datagrams and `DhtEvent`s: a routing
  table of K = 8 buckets (only nodes that answered enter; new queriers are pinged first),
  ping/find_node/get_peers/announce_peer with `implied_port`, tokens bound to the asker's IP
  and rotated every 5 minutes, iterative lookups with 3 queries in flight, BEP 43 read-only.
- `tracker`: `http` and `udp` codecs, `TrackerClient`, `TrackerServer`.

## Testing and interop

- Unit tests per layer (the uTP connection over a lossy, reordering simulated network; a 40-node
  in-memory DHT; MSE both roles; BEP 6 vectors), and local swarms over real sockets
  (`tests/swarm.rs`): a seeder and leechers over TCP and uTP, with and without MSE, peers found
  through HTTP and UDP trackers, magnet links, files on disk with resume, the DHT and PEX.
- `tools/interop/bittorrent/run.sh` runs everything in a Debian container on 127.0.0.1:
  aria2 leeching from `only` (plaintext, MSE required, magnet) and seeding to it (UDP tracker,
  plaintext and MSE); libtorrent leeching from `only` over uTP with RC4 and over TCP, and by
  magnet, seeding to `only` the same three ways, and the DHT both ways (a `only` node bootstraps
  libtorrent; each finds the other's seed by magnet alone).
- Fuzz targets: `bt_bencode` (bencode, metainfo, magnet), `bt_peer_wire`, `bt_krpc`, `bt_utp`,
  `bt_tracker`, `bt_mse`, with their seed corpora replayed by `cargo test`.

Not done yet: BitTorrent v2 and hybrid torrents (BEP 52), web seeds (BEP 19, parsed but not
used), local service discovery (BEP 14), BEP 44 DHT items, IPv6 DHT (BEP 32), fast resume
files, seed ratio limits, rate limits.
