//! Change notification for directories and files: inotify on Linux, kqueue `EVFILT_VNODE` on
//! macOS. One thread blocks in [`FsWatcher::wait`]; any thread adds and removes watches and
//! [`wake`](FsWatcher::wake)s it.

use std::{ffi::OsString, io, path::Path, time::Duration};

#[cfg(target_os = "linux")]
use linux as imp;
#[cfg(target_os = "macos")]
use macos as imp;

/// Identifies one watch of a [`FsWatcher`]. On Linux two watches of the same inode (a directory
/// reached by two paths) share an id.
pub type WatchId = u64;

/// What [`FsWatcher::wait`] reports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FsEvent {
    /// Something in the watched object changed. For a directory on Linux, `name` is the entry
    /// that was created, deleted, moved, written or had its attributes changed, and `is_dir`
    /// whether that entry is a directory. On macOS a directory event names nothing: entries were
    /// added, removed or renamed (the contents of files need their own watches).
    Changed {
        /// The watch.
        id: WatchId,
        /// The entry of a watched directory that changed (Linux).
        name: Option<OsString>,
        /// Whether `name` is a directory.
        is_dir: bool,
    },
    /// The watched object was deleted, moved, revoked or unmounted. The watch no longer tracks
    /// the path it was made for; [`unwatch`](FsWatcher::unwatch) it.
    Gone {
        /// The watch.
        id: WatchId,
    },
    /// The kernel's queue overflowed: events were lost, anything may have changed.
    Overflow,
}

/// A set of watches and the descriptor their events arrive on.
pub struct FsWatcher {
    imp: imp::Watcher,
}

impl std::fmt::Debug for FsWatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FsWatcher").finish_non_exhaustive()
    }
}

impl FsWatcher {
    /// Whether a directory's events name the changed entry and cover writes to the files in it
    /// (Linux). When false (macOS), a file's contents need a watch of the file itself
    /// ([`watch_file`](FsWatcher::watch_file)).
    pub const DIR_EVENTS_NAME_ENTRIES: bool = cfg!(target_os = "linux");

    /// Creates an empty watcher (an inotify instance, or a kqueue).
    pub fn new() -> io::Result<FsWatcher> {
        Ok(FsWatcher {
            imp: imp::Watcher::new()?,
        })
    }

    /// Watches the directory at `path` (following a symlink to it).
    pub fn watch_dir(&self, path: &Path) -> io::Result<WatchId> {
        self.imp.watch(path, true)
    }

    /// Watches the file at `path` (following a symlink to it): writes, attribute changes,
    /// deletion and renames. On macOS this holds a descriptor (`O_EVTONLY`) until
    /// [`unwatch`](FsWatcher::unwatch).
    pub fn watch_file(&self, path: &Path) -> io::Result<WatchId> {
        self.imp.watch(path, false)
    }

    /// Ends a watch. Unknown or already ended ids are ignored. Events of the watch already
    /// read from the kernel may still be reported once.
    pub fn unwatch(&self, id: WatchId) {
        self.imp.unwatch(id);
    }

    /// Waits up to `timeout` (forever with `None`) for events or a [`wake`](FsWatcher::wake),
    /// and appends the events to `out`. It may return with nothing appended (a wake, a signal).
    pub fn wait(&self, timeout: Option<Duration>, out: &mut Vec<FsEvent>) -> io::Result<()> {
        self.imp.wait(timeout, out)
    }

    /// Makes a pending or the next [`wait`](FsWatcher::wait) return.
    pub fn wake(&self) {
        self.imp.wake();
    }
}

fn timespec(t: Duration) -> crate::ffi::timespec {
    crate::ffi::timespec {
        tv_sec: i64::try_from(t.as_secs()).unwrap_or(i64::MAX),
        tv_nsec: t.subsec_nanos().into(),
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::{
        ffi::{CString, OsString},
        io,
        os::{
            fd::{AsRawFd, FromRawFd, OwnedFd},
            unix::ffi::{OsStrExt, OsStringExt},
        },
        path::Path,
        ptr,
        time::Duration,
    };

    use super::{FsEvent, WatchId};
    use crate::{EventFd, ffi};

    /// The watched changes of a file, and of a directory (which also reports them for its
    /// entries).
    const FILE_MASK: u32 = ffi::IN_MODIFY
        | ffi::IN_ATTRIB
        | ffi::IN_CLOSE_WRITE
        | ffi::IN_DELETE_SELF
        | ffi::IN_MOVE_SELF;
    const DIR_MASK: u32 = FILE_MASK
        | ffi::IN_MOVED_FROM
        | ffi::IN_MOVED_TO
        | ffi::IN_CREATE
        | ffi::IN_DELETE
        | ffi::IN_ONLYDIR;
    /// `struct inotify_event` without its name: `wd`, `mask`, `cookie`, `len`.
    const HEADER: usize = 16;

    pub(super) struct Watcher {
        fd: OwnedFd,
        wake: EventFd,
    }

    impl Watcher {
        pub(super) fn new() -> io::Result<Watcher> {
            // SAFETY: plain syscall; the fd is owned below.
            let fd = unsafe { ffi::inotify_init1(ffi::IN_NONBLOCK | ffi::IN_CLOEXEC) };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: fd was just created and is owned by nobody else.
            let fd = unsafe { OwnedFd::from_raw_fd(fd) };
            Ok(Watcher {
                fd,
                wake: EventFd::new()?,
            })
        }

        pub(super) fn watch(&self, path: &Path, dir: bool) -> io::Result<WatchId> {
            let c = CString::new(path.as_os_str().as_bytes())
                .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
            let mask = if dir { DIR_MASK } else { FILE_MASK };
            // SAFETY: `c` is a NUL-terminated string that outlives the call.
            let wd = unsafe { ffi::inotify_add_watch(self.fd.as_raw_fd(), c.as_ptr(), mask) };
            if wd < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(u64::from(wd.unsigned_abs()))
        }

        pub(super) fn unwatch(&self, id: WatchId) {
            if let Ok(wd) = i32::try_from(id) {
                // SAFETY: plain syscall; an unknown wd fails with EINVAL.
                unsafe { ffi::inotify_rm_watch(self.fd.as_raw_fd(), wd) };
            }
        }

        pub(super) fn wait(
            &self,
            timeout: Option<Duration>,
            out: &mut Vec<FsEvent>,
        ) -> io::Result<()> {
            let mut fds = [
                ffi::pollfd {
                    fd: self.fd.as_raw_fd(),
                    events: ffi::POLLIN,
                    revents: 0,
                },
                ffi::pollfd {
                    fd: self.wake.as_raw_fd(),
                    events: ffi::POLLIN,
                    revents: 0,
                },
            ];
            let ts = timeout.map(super::timespec);
            let tsp = ts.as_ref().map_or(ptr::null(), ptr::from_ref);
            // SAFETY: `fds` is a live array of 2 pollfds; `tsp` is null or a live timespec; no
            // signal mask.
            let n = unsafe { ffi::ppoll(fds.as_mut_ptr(), 2, tsp, ptr::null()) };
            if n < 0 {
                let e = io::Error::last_os_error();
                return if e.kind() == io::ErrorKind::Interrupted {
                    Ok(())
                } else {
                    Err(e)
                };
            }
            if fds[1].revents != 0 {
                let mut v = 0u64;
                // SAFETY: reads 8 bytes into a live u64 (EAGAIN when already drained is fine).
                unsafe { ffi::read(self.wake.as_raw_fd(), (&raw mut v).cast(), 8) };
            }
            if fds[0].revents != 0 {
                self.drain(out)?;
            }
            Ok(())
        }

        /// Reads every queued event.
        fn drain(&self, out: &mut Vec<FsEvent>) -> io::Result<()> {
            let mut buf = [0u8; 16 << 10];
            loop {
                // SAFETY: reads at most `buf.len()` bytes into `buf`.
                let n =
                    unsafe { ffi::read(self.fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
                if n < 0 {
                    let e = io::Error::last_os_error();
                    return match e.kind() {
                        io::ErrorKind::WouldBlock => Ok(()),
                        io::ErrorKind::Interrupted => continue,
                        _ => Err(e),
                    };
                }
                let n = n.unsigned_abs();
                if n == 0 {
                    return Ok(());
                }
                parse(&buf[..n], out);
            }
        }

        pub(super) fn wake(&self) {
            self.wake.wake();
        }
    }

    fn u32_at(b: &[u8], at: usize) -> u32 {
        let mut w = [0u8; 4];
        w.copy_from_slice(&b[at..at + 4]);
        u32::from_ne_bytes(w)
    }

    /// The events in one `read` of an inotify descriptor (whole events only, as the kernel
    /// returns them).
    pub(super) fn parse(mut b: &[u8], out: &mut Vec<FsEvent>) {
        while b.len() >= HEADER {
            let wd = u32_at(b, 0);
            let mask = u32_at(b, 4);
            let len = u32_at(b, 12) as usize;
            let Some(name) = b.get(HEADER..HEADER + len) else {
                return;
            };
            let name = &name[..name.iter().position(|&c| c == 0).unwrap_or(len)];
            b = &b[HEADER + len..];
            let id = u64::from(wd);
            if mask & ffi::IN_Q_OVERFLOW != 0 {
                out.push(FsEvent::Overflow);
            } else if mask
                & (ffi::IN_IGNORED | ffi::IN_DELETE_SELF | ffi::IN_MOVE_SELF | ffi::IN_UNMOUNT)
                != 0
            {
                out.push(FsEvent::Gone { id });
            } else {
                out.push(FsEvent::Changed {
                    id,
                    name: (!name.is_empty()).then(|| OsString::from_vec(name.to_vec())),
                    is_dir: mask & ffi::IN_ISDIR != 0,
                });
            }
        }
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use std::{
        collections::HashMap,
        fs::OpenOptions,
        io,
        os::{
            fd::{AsRawFd, FromRawFd, OwnedFd},
            unix::fs::OpenOptionsExt,
        },
        path::Path,
        ptr,
        sync::{
            Mutex,
            atomic::{AtomicU64, Ordering},
        },
        time::Duration,
    };

    use super::{FsEvent, WatchId};
    use crate::ffi;

    const NOTES: u32 = ffi::NOTE_DELETE
        | ffi::NOTE_WRITE
        | ffi::NOTE_EXTEND
        | ffi::NOTE_ATTRIB
        | ffi::NOTE_LINK
        | ffi::NOTE_RENAME
        | ffi::NOTE_REVOKE;
    /// The notes after which the descriptor no longer tracks its path.
    const GONE: u32 = ffi::NOTE_DELETE | ffi::NOTE_RENAME | ffi::NOTE_REVOKE;

    pub(super) struct Watcher {
        kq: OwnedFd,
        /// The `O_EVTONLY` descriptor of every watch: closing one removes its kevent.
        fds: Mutex<HashMap<WatchId, OwnedFd>>,
        next: AtomicU64,
    }

    fn change(kq: &OwnedFd, ev: &ffi::kevent) -> io::Result<()> {
        // SAFETY: one live change, no event list, no timeout (does not block).
        let r = unsafe { ffi::kevent(kq.as_raw_fd(), ev, 1, ptr::null_mut(), 0, ptr::null()) };
        if r < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn user_event(flags: u16, fflags: u32) -> ffi::kevent {
        ffi::kevent {
            ident: 0,
            filter: ffi::EVFILT_USER,
            flags,
            fflags,
            data: 0,
            udata: ptr::null_mut(),
        }
    }

    impl Watcher {
        pub(super) fn new() -> io::Result<Watcher> {
            // SAFETY: plain syscall; the fd is owned below.
            let fd = unsafe { ffi::kqueue() };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: fd was just created and is owned by nobody else.
            let kq = unsafe { OwnedFd::from_raw_fd(fd) };
            // SAFETY: fcntl on a valid fd with valid commands.
            if unsafe { ffi::fcntl(kq.as_raw_fd(), ffi::F_SETFD, ffi::FD_CLOEXEC) } < 0 {
                return Err(io::Error::last_os_error());
            }
            change(&kq, &user_event(ffi::EV_ADD | ffi::EV_CLEAR, 0))?;
            Ok(Watcher {
                kq,
                fds: Mutex::default(),
                next: AtomicU64::new(1),
            })
        }

        pub(super) fn watch(&self, path: &Path, dir: bool) -> io::Result<WatchId> {
            let f = OpenOptions::new()
                .read(true)
                .custom_flags(ffi::O_EVTONLY)
                .open(path)?;
            if f.metadata()?.is_dir() != dir {
                return Err(io::Error::from(io::ErrorKind::InvalidInput));
            }
            let fd = OwnedFd::from(f);
            let id = self.next.fetch_add(1, Ordering::Relaxed);
            let ev = ffi::kevent {
                ident: fd.as_raw_fd().unsigned_abs() as usize,
                filter: ffi::EVFILT_VNODE,
                flags: ffi::EV_ADD | ffi::EV_CLEAR,
                fflags: NOTES,
                data: 0,
                // The id rides in `udata`; it is never dereferenced.
                udata: ptr::without_provenance_mut(id as usize),
            };
            change(&self.kq, &ev)?;
            self.fds
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .insert(id, fd);
            Ok(id)
        }

        pub(super) fn unwatch(&self, id: WatchId) {
            let fd = self
                .fds
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(&id);
            drop(fd); // closing the descriptor deletes its kevent
        }

        pub(super) fn wait(
            &self,
            timeout: Option<Duration>,
            out: &mut Vec<FsEvent>,
        ) -> io::Result<()> {
            let mut evs = [user_event(0, 0); 64];
            let ts = timeout.map(super::timespec);
            let tsp = ts.as_ref().map_or(ptr::null(), ptr::from_ref);
            // SAFETY: `evs` is a live array of 64 kevents; `tsp` is null or a live timespec.
            let n = unsafe {
                ffi::kevent(
                    self.kq.as_raw_fd(),
                    ptr::null(),
                    0,
                    evs.as_mut_ptr(),
                    64,
                    tsp,
                )
            };
            if n < 0 {
                let e = io::Error::last_os_error();
                return if e.kind() == io::ErrorKind::Interrupted {
                    Ok(())
                } else {
                    Err(e)
                };
            }
            for ev in &evs[..n.unsigned_abs() as usize] {
                let (filter, flags, fflags, udata) = (ev.filter, ev.flags, ev.fflags, ev.udata);
                if filter != ffi::EVFILT_VNODE || flags & ffi::EV_ERROR != 0 {
                    continue;
                }
                let id = udata.addr() as u64;
                out.push(if fflags & GONE != 0 {
                    FsEvent::Gone { id }
                } else {
                    FsEvent::Changed {
                        id,
                        name: None,
                        is_dir: false,
                    }
                });
            }
            Ok(())
        }

        pub(super) fn wake(&self) {
            let _ = change(&self.kq, &user_event(0, ffi::NOTE_TRIGGER));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, path::PathBuf, time::Instant};

    fn scratch(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("only-fswatch-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).expect("scratch dir");
        d
    }

    /// Waits until `pred` holds for an event (up to 5 s).
    fn expect(w: &FsWatcher, what: &str, pred: impl Fn(&FsEvent) -> bool) {
        expect_all(w, what, |seen| seen.iter().any(&pred));
    }

    /// Waits until `pred` holds for the events seen so far (up to 5 s).
    fn expect_all(w: &FsWatcher, what: &str, pred: impl Fn(&[FsEvent]) -> bool) {
        let end = Instant::now() + Duration::from_secs(5);
        let mut seen = Vec::new();
        while Instant::now() < end {
            w.wait(Some(Duration::from_millis(100)), &mut seen)
                .expect("wait");
            if pred(&seen) {
                return;
            }
        }
        panic!("no event for {what}; saw {seen:?}");
    }

    fn drain(w: &FsWatcher) {
        let mut evs = Vec::new();
        while {
            evs.clear();
            w.wait(Some(Duration::from_millis(50)), &mut evs)
                .expect("wait");
            !evs.is_empty()
        } {}
    }

    #[test]
    fn reports_writes_creations_and_removals() {
        let d = scratch("basic");
        let f = d.join("a.txt");
        fs::write(&f, "one").expect("write");
        let w = FsWatcher::new().expect("watcher");
        let dir = w.watch_dir(&d).expect("watch dir");
        let file = w.watch_file(&f).expect("watch file");
        let named = |n: &str, ev: &FsEvent| {
            matches!(ev, FsEvent::Changed { id, name, .. } if *id == dir
                && (name.is_none() || name.as_deref() == Some(std::ffi::OsStr::new(n))))
        };

        fs::write(&f, "two").expect("write");
        expect(
            &w,
            "a write",
            |ev| matches!(ev, FsEvent::Changed { id, .. } if *id == file),
        );
        drain(&w);

        fs::write(d.join("b.txt"), "new").expect("write");
        expect(&w, "a creation", |ev| named("b.txt", ev));
        drain(&w);

        // Atomic replacement: the old file is gone for its watch, the directory changed.
        fs::write(d.join("c.tmp"), "three").expect("write");
        drain(&w);
        fs::rename(d.join("c.tmp"), &f).expect("rename");
        expect_all(&w, "a rename over the file", |seen| {
            seen.iter().any(|ev| named("a.txt", ev))
                && (FsWatcher::DIR_EVENTS_NAME_ENTRIES
                    || seen.contains(&FsEvent::Gone { id: file }))
        });
        w.unwatch(file);
        drain(&w);

        let sub = d.join("sub");
        fs::create_dir(&sub).expect("mkdir");
        let subw = w.watch_dir(&sub).expect("watch sub");
        drain(&w);
        fs::remove_dir(&sub).expect("rmdir");
        expect(&w, "a removed directory", |ev| {
            *ev == FsEvent::Gone { id: subw }
        });

        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn wake_interrupts_wait() {
        let w = std::sync::Arc::new(FsWatcher::new().expect("watcher"));
        let w2 = w.clone();
        let t = std::thread::spawn(move || {
            let start = Instant::now();
            let mut evs = Vec::new();
            w2.wait(None, &mut evs).expect("wait");
            start.elapsed()
        });
        std::thread::sleep(Duration::from_millis(50));
        w.wake();
        let took = t.join().expect("join");
        assert!(took < Duration::from_secs(5), "wait was not woken");
    }

    #[test]
    fn rejects_the_wrong_kind_and_missing_paths() {
        let d = scratch("kinds");
        let f = d.join("x");
        fs::write(&f, "x").expect("write");
        let w = FsWatcher::new().expect("watcher");
        assert!(w.watch_dir(&f).is_err());
        assert!(w.watch_file(&d.join("missing")).is_err());
        w.unwatch(12_345); // unknown: ignored
        let _ = fs::remove_dir_all(&d);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parses_inotify_records() {
        let mut b = Vec::new();
        let mut rec = |wd: u32, mask: u32, name: &[u8], len: u32| {
            for v in [wd, mask, 0, len] {
                b.extend_from_slice(&v.to_ne_bytes());
            }
            let mut n = name.to_vec();
            n.resize(len as usize, 0);
            b.extend_from_slice(&n);
        };
        rec(3, crate::ffi::IN_MODIFY, b"index.html", 16);
        rec(4, crate::ffi::IN_DELETE | crate::ffi::IN_ISDIR, b"sub", 16);
        rec(4, crate::ffi::IN_IGNORED, b"", 0);
        rec(u32::MAX, crate::ffi::IN_Q_OVERFLOW, b"", 0);
        let mut out = Vec::new();
        linux::parse(&b, &mut out);
        assert_eq!(
            out,
            [
                FsEvent::Changed {
                    id: 3,
                    name: Some("index.html".into()),
                    is_dir: false
                },
                FsEvent::Changed {
                    id: 4,
                    name: Some("sub".into()),
                    is_dir: true
                },
                FsEvent::Gone { id: 4 },
                FsEvent::Overflow,
            ]
        );
        // A truncated record is ignored.
        out.clear();
        linux::parse(&b[..20], &mut out);
        assert!(out.is_empty());
    }
}
