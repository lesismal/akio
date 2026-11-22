# ADR-066: Change notifications for the static file cache (inotify / kqueue)

English | [简体中文](066-static-files-change-notifications.zh-CN.md)

Status: accepted (2026-11-20)

## Context

`akio_http::files::Files` caches small files in memory and keeps an open handle for large
ones. An entry is trusted for `check_interval` (default 5 s); after that the disk pool runs `stat`
again on the file and its `.br` / `.zst` / `.gz` twins. That has two costs. A change can take up
to one interval to show. Every hot file is `stat`ed again every interval, and because only a
fresh hit is answered on the I/O thread, one request per interval detours through the disk pool.
The DEV-PLAN listed "inotify-based change tracking" as not done.

Constraints: the default behaviour stays as it is; no third-party dependency; the hit path on
the I/O thread does not get slower; whatever notifications cannot vouch for falls back to the
interval rule and never serves stale content.

## Decision

### 1. akio-sys: `FsWatcher`

New `akio_sys::{FsWatcher, FsEvent, WatchId}`:

- Linux: inotify (`IN_NONBLOCK | IN_CLOEXEC`). The directory mask is writes, attributes,
  `CLOSE_WRITE`, moves in and out, creation, deletion, and deletion or move of the directory itself
  (`IN_ONLYDIR`); the file mask is the subset about the file itself. `wait` uses `ppoll` on the
  inotify descriptor and an eventfd (`wake`). Events are parsed byte by byte, without unsafe
  pointer casts.
- macOS: kqueue `EVFILT_VNODE` (`EV_CLEAR`), one `O_EVTONLY` descriptor per watch; closing the
  descriptor deletes its kevent. The watch id rides in `udata` (`ptr::without_provenance_mut`,
  never dereferenced). `wake` uses `EVFILT_USER` / `NOTE_TRIGGER`.
- Events: `Changed { id, name, is_dir }`, `Gone { id }` (deleted, moved, revoked or unmounted)
  and `Overflow`. On Linux a directory event names the changed entry. On macOS a directory event
  names nothing, and a file's contents need a watch of the file itself (see
  `FsWatcher::DIR_EVENTS_NAME_ENTRIES`).
- The new constants and declarations are added to the `ffi::layout` comparison with `libc`.

### 2. akio-http: `Files::watch(true)`

Off by default. When it is on, the first request that reaches the disk creates the watcher and
one thread named `akio-files-watch` per `Files`. The thread holds only a `Weak<Inner>`; when the
`Files` is dropped, `Drop` wakes it and it exits.

- **What is watched.** Before the `stat`, every directory from the root down to the one holding
  the file gets a watch (for a directory request, that directory too). On macOS each file and
  each compressed twin also gets a file watch before it is read (`FileWatch`). The cache entry
  holds it, and it ends when the last holder drops it. The code checks that the watch follows the
  file the `stat` described (size, modification time, device and inode).
- **Vouching.** An entry is marked `watched` only when all of these hold:
  - every directory on the path is watched;
  - the file and each twin are trackable (Linux: a regular file with one hard link; macOS: a file
    watch was taken);
  - no batch of notifications was applied between the start of the disk lookup and the moment the
    entry was in place (see below).

  A `watched` entry is no longer bound by `check_interval` until a notification drops it; the
  rest are re-checked by interval as before. The hit path on the I/O thread reads one more relaxed
  atomic.
- **Races.** Each batch of notifications increments an epoch before it drops anything. A request
  records the epoch after its watches are up and before it consults the disk, and compares it once
  the entry is in the cache. If a batch was applied in between, the entry is not marked `watched`:
  that batch may concern what was just read, and it was applied before the entry was in place to be
  dropped. A change after that point produces a notification that drops the entry, which is now in
  the cache. This is conservative: a busy directory only degrades to the interval rule.
- **What is dropped.**
  - A change to a file or its directory drops the file. On Linux the event names the entry
    exactly; on macOS the directory's direct entries are dropped.
  - A change to a twin also drops the original.
  - A directory (or a symlink to one) moved, removed or replaced drops every entry below it and
    ends the watches of every directory below it; they are set up again on the next request. On
    macOS, where directory events name nothing, the watched subdirectories are compared by device
    and inode to catch a replacement through a symlink.
  - `Overflow` drops the whole cache.
  - A failure to read notifications drops the whole cache and goes back to the interval rule for
    good.
- **Limit.** `Files::max_watches(n)` (default 1024) counts directory watches, plus file watches on
  macOS (each one a file descriptor). Past it, new entries follow the interval rule. On Linux the
  watches also count against `fs.inotify.max_user_watches`.
- **Lock order.** The watch-state lock is taken either without the ring or shard locks held, or
  by `FileWatch::drop` while they are held. The ring and shard locks are never taken while the
  watch-state lock is held. The notification thread collects the paths to drop under the
  watch-state lock and drops them after releasing it.

### 3. Deliberately not done

- **On by default.** On network and FUSE file systems (NFS, SMB, sshfs…), changes made by other
  machines produce no notification, so entries would never be renewed. The documentation says so.
- **Per-file watches on Linux.** They would cover writes through other hard links or to a
  symlink's target, but each file would use an inotify watch that must be removed on eviction.
  Such files follow the interval rule instead.
- **fanotify, macOS FSEvents.** fanotify needs privileges. FSEvents needs CoreServices linked and
  its delayed, coalesced stream handled, and macOS is a development platform.

## Consequences

- With `watch` on, a change shows as soon as its notification arrives (milliseconds in the
  tests). Unchanged hot files are no longer `stat`ed, nor detoured through the disk pool, every
  interval.
- Cost with `watch` off: a cache hit (`fresh`, 50 M lookups, best of 5) took 96.1–96.9 ns on
  this branch and 98.7–99.1 ns on main `b22519ae`. The runs alternated 5 times each in one
  `quiet.sh` session on gpu51 (Ryzen 7 7800X3D, core 2), so there is no regression.
- The public API only grows: `Files::watch`, `Files::max_watches`; `FsWatcher`, `FsEvent` and
  `WatchId` in akio-sys.
- Tests:
  - akio-sys: writes, creation, atomic replacement, directory removal, wake-up and error paths;
    on Linux, parsing of inotify records.
  - akio-http: a write; a new or changed twin; renaming a directory on the path and re-creating
    it; a directory index; `max_watches`; `Overflow`; a notification applied mid-request; thread
    exit once the `Files` is dropped; on Linux, the fallback for hard links and symlinks.

  They pass on macOS and x86_64 Linux (gpu51).
