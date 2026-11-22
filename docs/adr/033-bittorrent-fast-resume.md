# ADR-033: BitTorrent fast resume

English | [简体中文](033-bittorrent-fast-resume.zh-CN.md)

Status: accepted (2026-11-18)

## Context

ADR-018 left one item of the `akio-bittorrent` client undone: fast-resume files. A torrent added
again, after a restart or a crash, hash-checked all of its data before it did anything else: for
a large torrent minutes of disk reads and SHA-1/SHA-256 work, and for a v2 torrent from a magnet
link a fresh round of hash requests, because the piece layers fetched from peers were only held
in memory. Peers, totals and limits were lost as well.

A resume file has to answer one question safely: which pieces on disk can be trusted without
reading them? The bitfield saved with them is only true as long as the files have not changed
since, and the client cannot see every change: another program may edit a file, and the client
itself keeps writing after a save while it downloads, so after a crash the files are newer than
the last save for reasons that are harmless.

## Decision

1. **Format**: a bencoded dictionary, `file` = `akio-bittorrent resume`, `version` = 1, closed by
   `checksum`, the SHA-256 of the canonical encoding of the dictionary without that key. It holds
   the key info hash (and the v2 hash), the name, the info dictionary as raw bytes (so a magnet
   link restarts without metadata exchange), the have-bitfield, the v2 piece layers (root to
   concatenated hashes: the merkle state worth keeping; trees are rebuilt from them, and
   per-block hashes are not kept, as pieces are checked whole), one `[size, mtime ns]` per file
   (`[]` for a missing or padding file), `clean` and `paused` flags, up to 200 peers (compact,
   `peers` and `peers6`), trackers and web seeds, upload/download totals and seeding time across
   sessions, and the torrent's rate and seed limits (the ratio in thousandths). A later version
   is refused (`ResumeError::Version`); unknown keys are ignored, so a version 1 reader takes
   additions that do not change the meaning of these keys.
2. **Decoding trusts nothing.** Bencode is decoded strictly (depth limit, no trailing data); the
   magic, version and checksum are checked first, then every field's type and length (20/32-byte
   hashes, a bitfield of exactly the info dictionary's piece count with spare bits clear, layers
   in whole hashes, peers in whole entries, one stamp per file); the info dictionary must hash
   to the info hash; piece layers are kept only if they match their file's root. Data of another
   torrent, or whose info dictionary differs from the torrent's, is a `Mismatch`. Truncated or
   damaged data never panics (fuzz target `bt_resume`, which also reseals fuzzed dictionaries
   with a correct checksum so mutations reach the fields), and is never used: the torrent is
   checked in full and reports `TorrentEvent::ResumeRejected`.
3. **Validation against the disk.** `Storage::file_stamps` (new, default `None`) gives each
   file's size and modification time; `FileStorage` stats its files. For every file whose stamp
   differs from the saved one, all pieces touching the file are checked again, claimed or not,
   and only the claims in unchanged files are trusted — with one exception that makes a crash
   cheap: a save taken while the torrent ran (`clean` = 0) of a file that was still being
   downloaded (some of its pieces missing) cannot tell the client's own later writes from
   anyone else's, so such a file is checked again only if it is gone, shorter than its last
   claimed piece needs, or longer than the file should be. Pieces downloaded between that save
   and the crash are downloaded again (at most one save interval's worth). A save is `clean`
   when the torrent is paused or stopped and no verified piece is still being written; then
   every changed file is checked again. Storage without stamps (memory, an embedder's own) is
   trusted if `may_have_data()` and dropped otherwise. Hash checks run on the disk pool as before;
   `TorrentEvent::ResumeAccepted { pieces, rechecking }` reports the outcome before `Checked`, and
   `TorrentStats::pieces_checked` counts the pieces read back.
4. **Saving.** `ClientConfig::resume_dir` (default none: nothing saved or loaded) holds
   `<key info hash hex>.resume`. The maintenance thread queues a save on the disk pool every
   `ClientConfig::resume_interval` (default 30 s) when anything recorded changed (pieces, layers,
   metadata, limits, state, totals), soon after a pause or a finished check (once no write is in
   flight, at most 5 s later), and `Client::close` saves every torrent after the pool has drained,
   recording whether each was paused before the close. A save never runs during a check (the
   bitfield is not known yet), takes the state under the torrent's lock, stamps the files after
   it (so every claimed piece is already written), and writes atomically: a temporary file,
   `fsync`, `rename`, then `fsync` of the directory. `Client::remove` deletes the file.
5. **Loading.** `add_torrent` and `add_magnet` take `AddOptions::resume_data` or else the file
   under any of the torrent's hashes. Resume data adds its peers, trackers and web seeds, starts
   the torrent paused if it was saved paused, and sets its limits unless the options set some;
   for a magnet link it brings the info dictionary and piece layers. `AddOptions::seed` still
   wins (every piece taken as had).
6. **API** (additive): `client::{ResumeError, FileStamp}`, `Storage::file_stamps`,
   `ClientConfig::{resume_dir, resume_interval}`, `AddOptions::resume_data`,
   `Client::add_resume` (a torrent from resume data alone), `AddError::Resume`,
   `Torrent::{resume_data, save_resume_data}`, `TorrentEvent::{ResumeAccepted, ResumeRejected}`,
   `TorrentStats::{pieces_checked, total_uploaded, total_downloaded}`.
7. **Totals across sessions.** `TorrentStats::seeding_time` now includes the seeding time
   recorded in resume data, and seed limits (ADR-018) use the totals across sessions, so a
   ratio or time limit is not reset by a restart. Without resume data nothing changes.

Not done: blocks of unfinished pieces are not saved (libtorrent's `unfinished`); a crash loses
the pieces in progress, which a fast connection refetches in well under a second. Resume data is
not shared between clients of other implementations (libtorrent's format differs in keys and
semantics).

## Consequences

- A restarted client seeds or continues at once; a crash costs at most the pieces of the last
  save interval. Tests (`tests/resume.rs`, v1, v2 and hybrid each): restart after `close` with
  no peer at all and `pieces_checked == 0`; a child process `SIGKILL`ed mid-download, restarted,
  finishing with no piece hashed again; a changed file (one byte, same size) checked again
  alone, its bad piece the only one downloaded again; truncated, flipped, empty and foreign
  resume files refused with a full check; export and import of paused state, limits and web
  seeds; a v2 magnet's fetched piece layers restored from the file and from bytes alone.
- The cost is on the maintenance thread and the disk pool, never on the I/O path: one more
  increment of a counter per verified piece, and nothing at all without a resume directory.
  bt-bench (512 MiB, loopback TCP, gpu51, same-run A/B, 5 alternating pairs, medians):
  2169 MiB/s before, 2199 after (1.01x, noise); uTP pairs at parity.
- Fuzz: `bt_resume` ran 661 s (13.5M inputs) without a failure.
- Trusting files written after an unclean save on their size alone means a file edited by
  another program while the client was killed mid-download can go unnoticed until a peer
  complains about a bad piece; a clean shutdown closes that gap.
- `MemoryStorage::new` holds nothing after a restart, so resume data claiming pieces in it is
  dropped (`may_have_data` is false).
