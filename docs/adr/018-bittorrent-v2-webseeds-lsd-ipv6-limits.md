# ADR-018: BitTorrent v2 and hybrid torrents, web seeds, LSD, IPv6 DHT, rate and seed limits

English | [简体中文](018-bittorrent-v2-webseeds-lsd-ipv6-limits.zh-CN.md)

Status: accepted (2026-11-17)

## Context

`only-bittorrent` shipped v1 torrents only. `docs/DEV-PLAN.md` (M7) listed what was left: BEP 52
(v2 and hybrid torrents), web seeds (BEP 19), Local Service Discovery (BEP 14), BEP 44, the IPv6
DHT (BEP 32), and rate and seed limits. v2-only torrents were refused with
`MetaError::Unsupported`; hybrid torrents were read as their v1 part. The client had one
`InfoHash` per torrent, listened on one address family, and moved data as fast as peers let it.

All of these change the public API of `metainfo`, `magnet`, `wire`, `dht` and `client`, and add
modules.

## Decision

1. **v2 hashes and trees (BEP 52).**
   - New module `merkle`: SHA-256 trees over 16 KiB blocks, padded to a power of two with zero
     leaves (`pad_hash`, `subtree_root`, `piece_root`, `file_root`, `root_from_piece_layer`),
     `MerkleTree` (a file's tree from its piece layer up, answering hash requests: `hashes`,
     `uncles`), `verify_hashes` and `uncle_count`. The uncle hashes follow libtorrent: one per
     layer from `log2(length)` to `proof layers`, leaf to root (BEP 52's "omitted layers still
     count").
   - `metainfo`: `InfoHashV2` (32 bytes, `truncated()`), `TorrentVersion { V1, V2, Hybrid }`
     (`Info::version`), `FileEntry::pieces_root`, `PieceLayers` (validated per file root),
     `MetaInfo::{info_hash_v2, piece_layers, verify_piece}`, `Info::{info_hash_v1, info_hash_v2,
     has_v1, has_v2, piece_file, file_pieces, needs_piece_layer, file_of_root,
     check_piece_layer, verify_piece_with, can_verify}`, `Builder::version`. `MetaError::
     Unsupported` now means `meta version` above 2.
   - **One piece space for all three kinds.** v2 starts every non-empty file on a piece
     boundary. A hybrid torrent's v1 file list already holds BEP 47 padding files; for a
     v2-only torrent the parser synthesizes them (`.pad/<size>`, `padding: true`). So piece `i`
     covers the same bytes in every view, storage (which never writes padding) and the piece
     picker stay as they were, and v1 and v2 checks apply to the same buffer.
   - **`MetaInfo::info_hash` is the hash peers use**: the SHA-1 for v1 and hybrid torrents,
     the truncated SHA-256 for v2-only ones. Code that keys torrents by `info_hash` keeps working.
   - Parsing refuses: a v2 piece length that is not a power of two of at least 16 KiB, unsafe or
     clashing names in the file tree, a file node with children, a missing or mismatching piece
     layer, and a hybrid torrent whose v1 and v2 parts describe different files or offsets.
   - `Builder` for v2 and hybrid torrents sorts files by path (the file tree is a dictionary)
     and pads hybrid files with BEP 47 padding files.
2. **Magnets**: `urn:btmh:1220<hex>` (`Magnet::info_hash_v2`, `is_v2_only`); a v2-only link's
   `info_hash` is the truncated hash.
3. **Peer wire**: `Handshake::new` sets the v2 bit (reserved byte 7, `0x10`), `Handshake::v2`;
   `Message::{HashRequest, Hashes, HashReject}` with `HashRequest`.
4. **Client and v2.** A hybrid torrent is one torrent under two hashes: trackers and the DHT get
   both, incoming handshakes and MSE are accepted under either, and a peer that answers our v1
   handshake with the v2 hash (BEP 52's upgrade) is kept. Pieces are checked with SHA-1 and the
   merkle tree where each applies. A torrent from a magnet link fetches missing piece layers
   from v2 peers, 512 hashes per request with a proof to the root, at most 4 requests in flight
   per peer, 10 s timeout, peers that reject or time out three times are not asked again; until
   a v2-only file's layer is known its pieces are not picked. The client answers hash requests
   for piece layers it has, and for block hashes of pieces it has (read on the logical pool,
   at most 8 per peer); everything else gets a hash reject. Merkle trees kept to answer are
   capped (64).
5. **IPv6.** No second socket pair: listening on `[::]:port` makes the engine's sockets dual-stack
   (as `only-sys` already binds IPv6 sockets with `IPV6_V6ONLY` off), and the `UdpPort` and the
   TCP acceptor report IPv4 peers by their plain address (not `::ffff:a.b.c.d`) and map them back
   when sending. The DHT `Node` keeps an IPv6 routing table beside the IPv4 one (BEP 32):
   `compact_nodes6`, `parse_compact_nodes6`, `Node::{set_ipv6, table6_len}`, `nodes6` and
   `want` in answers, values of the asker's family; the client turns it on when it listens
   dual-stack (`Client::dht_nodes6`). PEX and trackers already carried IPv6 peers.
6. **Web seeds (BEP 19)** through only-http's client (redirects up to 5, 60 s per request, range
   requests of at most 4 MiB, bodies capped at that): one piece in flight per web seed, at most
   16 web seeds per torrent, a piece no connected peer has preferred, padding never fetched,
   `206` required (or `200` for a whole file), backoff from 10 s doubling to 10 min after a
   failure or a hash failure, `TorrentEvent::WebSeedError`. `ClientConfig::web_seeds` (default
   on), `AddOptions::web_seeds`, `Torrent::add_web_seed`.
7. **LSD (BEP 14)**: module `lsd` (`Announce`, the multicast groups, `MAX_MESSAGE` 1400,
   `MAX_INFO_HASHES` 16) and `ClientConfig::lsd` (default on, never for private torrents). The
   client runs it on a thread of its own with a `SO_REUSEADDR`/`SO_REUSEPORT` socket on 6771
   (IPv4, plus IPv6 when dual-stack), announces a torrent when added and every 5 minutes (at
   most once a minute), recognises its own announcements by a cookie and reads at most 50
   announcements a second. If the port or the group is unavailable the client runs without
   LSD. A thread rather than an engine listener: the engine has no multicast membership API,
   and LSD is a few datagrams a minute.
8. **Rate limits**: `RateLimits { upload, download }` (bytes per second, `None` unlimited) for
   the client (`ClientConfig::rate_limits`, `Client::set_rate_limits`) and per torrent
   (`AddOptions::rate_limits`, `Torrent::set_rate_limits`). Token buckets refilled from the
   clock, holding at most 200 ms worth (at least one block); requests to peers and web seeds
   take download tokens before they are sent, uploads wait in a queue (bounded by the per-peer
   request cap) for upload tokens before storage is read. Unlimited costs one relaxed atomic
   load per block.
9. **Seed limits**: `SeedLimits { ratio, time }` (`ClientConfig::seed_limits`,
   `AddOptions::seed_limits`, `Torrent::set_seed_limits`); a complete torrent that reaches
   either is paused with `TorrentEvent::SeedLimitReached`. Ratio: uploaded over downloaded in
   this session (over the torrent's size if nothing was downloaded). `TorrentStats` gains
   `seeding_time` and `web_seeds_active`.
10. **BEP 44 (DHT arbitrary data) is not implemented.** It stores mutable and immutable items
    for other applications; downloading and seeding torrents never need it, and libtorrent,
    the one client with a full implementation, uses it for nothing in the torrent path. It
    would add per-item storage keyed by remote input, Ed25519 signature checks per `put` and a
    salt/sequence-number state machine to the DHT's attack surface. `dht::Node` is
    `#[non_exhaustive]`-friendly (new methods only), so it can be added later without breaking
    the API.

## Consequences

- v2-only torrents and magnets now load instead of failing with `Unsupported`; hybrid torrents
  are checked as both. A torrent whose piece layers are missing or wrong is refused, as BEP 52
  says.
- `Handshake::new` advertises v2 support; v1-only peers ignore the bit.
- `ClientConfig::lsd` and `web_seeds` default to on, as in libtorrent; tests that run many
  clients on one host turn LSD off.
- Interop (`tools/interop/bittorrent/run.sh`, suites `v2`, `webseed`, `lsd`): v2 and hybrid
  torrents made by either side, by .torrent and by magnet, both directions with libtorrent 2.0;
  aria2 1.37 (no v2) with hybrid torrents both ways; web seeds from nginx; LSD between two
  containers on a Docker network.
- New fuzz targets `bt_lsd` and `bt_merkle`; `bt_bencode`, `bt_peer_wire` and `bt_krpc` cover
  v2 metainfo, the hash messages and BEP 32.
