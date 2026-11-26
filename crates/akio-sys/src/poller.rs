use crate::ffi;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::Arc;
use std::time::Duration;

/// A readiness event. Interest is level-triggered.
#[derive(Clone, Copy, Debug, Default)]
pub struct Event {
    /// The token given at registration.
    pub token: u64,
    /// Readable (or the peer hung up / errored: a read will report it).
    pub readable: bool,
    /// Writable (or errored: a write will report it).
    pub writable: bool,
    /// The peer hung up or the socket errored (`EPOLLRDHUP`/`EPOLLHUP`/`EPOLLERR`, `EV_EOF`):
    /// with edge-triggered interest, a reader must read until end of stream or `WouldBlock`
    /// rather than stop at a short read, as no further edge announces the end.
    pub hup: bool,
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn set_nonblock_cloexec(fd: RawFd) -> io::Result<()> {
    // SAFETY: fcntl on a valid fd with valid commands.
    unsafe {
        let fl = ffi::fcntl(fd, ffi::F_GETFL);
        if fl < 0 || ffi::fcntl(fd, ffi::F_SETFL, fl | ffi::O_NONBLOCK) < 0 {
            return Err(io::Error::last_os_error());
        }
        let fl = ffi::fcntl(fd, ffi::F_GETFD);
        if fl < 0 || ffi::fcntl(fd, ffi::F_SETFD, fl | ffi::FD_CLOEXEC) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn timeout_ms(t: Option<Duration>) -> ffi::c_int {
    match t {
        None => -1,
        // round up so a 100µs timeout does not spin
        Some(d) => d.as_micros().div_ceil(1000).min(i32::MAX as u128) as ffi::c_int,
    }
}

/// Level-triggered readiness poller: epoll on Linux, kqueue on macOS.
#[derive(Debug)]
pub struct Poller {
    fd: Arc<OwnedFd>,
    #[cfg(target_os = "linux")]
    buf: Vec<ffi::epoll_event>,
    #[cfg(target_os = "macos")]
    buf: Vec<ffi::kevent>,
}

const BATCH: usize = 1024;

// SAFETY: the only non-Send content is the kevent scratch buffer, whose `udata` pointers are
// opaque integers (tokens), never dereferenced. The fd is an owned integer.
unsafe impl Send for Poller {}

#[cfg(target_os = "linux")]
impl Poller {
    /// Creates a poller.
    pub fn new() -> io::Result<Poller> {
        // SAFETY: plain syscall; the fd is owned by the OwnedFd.
        let fd = unsafe { ffi::epoll_create1(ffi::EPOLL_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Poller {
            // SAFETY: fd was just created and is owned by nobody else.
            fd: Arc::new(unsafe { OwnedFd::from_raw_fd(fd) }),
            buf: vec![ffi::epoll_event { events: 0, u64: 0 }; BATCH],
        })
    }

    /// Registers `fd`.
    pub fn add(&self, fd: RawFd, token: u64, read: bool, write: bool) -> io::Result<()> {
        epoll_ctl(
            &self.fd,
            ffi::EPOLL_CTL_ADD,
            fd,
            token,
            interest(read, write),
        )
    }

    /// Changes the interest of a registered `fd`.
    pub fn modify(&self, fd: RawFd, token: u64, read: bool, write: bool) -> io::Result<()> {
        epoll_ctl(
            &self.fd,
            ffi::EPOLL_CTL_MOD,
            fd,
            token,
            interest(read, write),
        )
    }

    /// Deregisters `fd` (errors ignored: closing the fd deregisters it anyway).
    pub fn delete(&self, fd: RawFd) {
        let _ = epoll_ctl(&self.fd, ffi::EPOLL_CTL_DEL, fd, 0, 0);
    }

    /// Waits for events, appending them to `out`. `None` waits forever.
    pub fn wait(&mut self, out: &mut Vec<Event>, timeout: Option<Duration>) -> io::Result<()> {
        // SAFETY: `buf` has BATCH initialised entries; the kernel writes at most BATCH.
        let n = unsafe {
            ffi::epoll_wait(
                self.fd.as_raw_fd(),
                self.buf.as_mut_ptr(),
                BATCH as i32,
                timeout_ms(timeout),
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
        for ev in &self.buf[..n as usize] {
            let (events, token) = (ev.events, ev.u64); // by-value reads: the struct is packed
            let bad = events & (ffi::EPOLLERR | ffi::EPOLLHUP) as u32 != 0;
            out.push(Event {
                token,
                readable: bad || events & (ffi::EPOLLIN | ffi::EPOLLRDHUP) as u32 != 0,
                writable: bad || events & ffi::EPOLLOUT as u32 != 0,
                hup: bad || events & ffi::EPOLLRDHUP as u32 != 0,
            });
        }
        Ok(())
    }
}

#[cfg(target_os = "macos")]
impl Poller {
    /// Creates a poller.
    pub fn new() -> io::Result<Poller> {
        // SAFETY: plain syscall; the fd is owned by the OwnedFd.
        let fd = unsafe { ffi::kqueue() };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fd was just created and is owned by nobody else (owned first, so that a
        // failing fcntl below closes it).
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        // kqueue descriptors reject O_NONBLOCK (ENOTTY); close-on-exec is all they need.
        // SAFETY: fcntl on a valid fd with valid commands.
        if unsafe { ffi::fcntl(fd.as_raw_fd(), ffi::F_SETFD, ffi::FD_CLOEXEC) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Poller {
            fd: Arc::new(fd),
            // SAFETY: kevent is plain-old-data; all-zero is valid.
            buf: vec![unsafe { std::mem::zeroed() }; BATCH],
        })
    }

    /// Registers `fd`.
    pub fn add(&self, fd: RawFd, token: u64, read: bool, write: bool) -> io::Result<()> {
        kq_change(&self.fd, fd, token, read, write, KqOp::Level)
    }

    /// Changes the interest of a registered `fd`.
    pub fn modify(&self, fd: RawFd, token: u64, read: bool, write: bool) -> io::Result<()> {
        kq_change(&self.fd, fd, token, read, write, KqOp::Level)
    }

    /// Deregisters `fd` (errors ignored: closing the fd deregisters it anyway).
    pub fn delete(&self, fd: RawFd) {
        let _ = kq_change(&self.fd, fd, 0, false, false, KqOp::Delete);
    }

    /// Waits for events, appending them to `out`. `None` waits forever.
    pub fn wait(&mut self, out: &mut Vec<Event>, timeout: Option<Duration>) -> io::Result<()> {
        let ts = timeout.map(|d| ffi::timespec {
            tv_sec: d.as_secs() as ffi::time_t,
            tv_nsec: d.subsec_nanos().into(),
        });
        let tsp = ts.as_ref().map_or(std::ptr::null(), std::ptr::from_ref);
        // SAFETY: `buf` has BATCH initialised entries; `tsp` is null or points to a live timespec.
        let n = unsafe {
            ffi::kevent(
                self.fd.as_raw_fd(),
                std::ptr::null(),
                0,
                self.buf.as_mut_ptr(),
                BATCH as i32,
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
        for k in &self.buf[..n as usize] {
            let bad = k.flags & (ffi::EV_ERROR | ffi::EV_EOF) != 0;
            out.push(Event {
                token: k.udata as usize as u64,
                readable: k.filter == ffi::EVFILT_READ || bad,
                writable: k.filter == ffi::EVFILT_WRITE || (bad && k.filter != ffi::EVFILT_READ),
                hup: bad,
            });
        }
        Ok(())
    }
}

impl Poller {
    /// A handle that registers and deregisters descriptors on this poller from any thread
    /// (work-stealing scheduling, ADR-104: workers deregister the connections they close).
    pub fn registry(&self) -> Registry {
        Registry {
            fd: self.fd.clone(),
        }
    }
}

/// Registers descriptors on a [`Poller`] from any thread: `epoll_ctl` and `kevent` changes are
/// safe to make while another thread waits on the same instance.
#[derive(Clone, Debug)]
pub struct Registry {
    fd: Arc<OwnedFd>,
}

impl Registry {
    /// Registers `fd` edge-triggered for both reads and writes (`EPOLLET`, `EV_CLEAR`): an event
    /// is reported when the socket becomes readable or writable, not while it stays so. The
    /// reader must drain the socket (read until `WouldBlock`) or remember that it did not.
    pub fn add_edge(&self, fd: RawFd, token: u64) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            let ev = interest(true, true) | (ffi::EPOLLRDHUP | ffi::EPOLLET) as u32;
            epoll_ctl(&self.fd, ffi::EPOLL_CTL_ADD, fd, token, ev)
        }
        #[cfg(target_os = "macos")]
        {
            kq_change(&self.fd, fd, token, true, true, KqOp::Edge)
        }
    }

    /// Registers `fd` level-triggered (as [`Poller::add`]).
    pub fn add(&self, fd: RawFd, token: u64, read: bool, write: bool) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            epoll_ctl(
                &self.fd,
                ffi::EPOLL_CTL_ADD,
                fd,
                token,
                interest(read, write),
            )
        }
        #[cfg(target_os = "macos")]
        {
            kq_change(&self.fd, fd, token, read, write, KqOp::Level)
        }
    }

    /// Deregisters `fd` (errors ignored: closing the fd deregisters it anyway).
    pub fn delete(&self, fd: RawFd) {
        #[cfg(target_os = "linux")]
        {
            let _ = epoll_ctl(&self.fd, ffi::EPOLL_CTL_DEL, fd, 0, 0);
        }
        #[cfg(target_os = "macos")]
        {
            let _ = kq_change(&self.fd, fd, 0, false, false, KqOp::Delete);
        }
    }
}

#[cfg(target_os = "linux")]
fn interest(read: bool, write: bool) -> u32 {
    (if read { ffi::EPOLLIN } else { 0 } | if write { ffi::EPOLLOUT } else { 0 }) as u32
}

#[cfg(target_os = "linux")]
fn epoll_ctl(ep: &OwnedFd, op: ffi::c_int, fd: RawFd, token: u64, events: u32) -> io::Result<()> {
    let mut ev = ffi::epoll_event { events, u64: token };
    // SAFETY: `ev` is a valid epoll_event for the duration of the call.
    if unsafe { ffi::epoll_ctl(ep.as_raw_fd(), op, fd, &raw mut ev) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "macos")]
#[derive(Clone, Copy, PartialEq, Eq)]
enum KqOp {
    Level,
    Edge,
    Delete,
}

#[cfg(target_os = "macos")]
fn kq_change(
    kq: &OwnedFd,
    fd: RawFd,
    token: u64,
    read: bool,
    write: bool,
    op: KqOp,
) -> io::Result<()> {
    let mk = |filter: i16, on: bool| {
        // SAFETY: kevent is plain-old-data; all-zero is valid.
        let mut k: ffi::kevent = unsafe { std::mem::zeroed() };
        k.ident = fd as usize;
        k.filter = filter;
        k.flags = match op {
            KqOp::Delete => ffi::EV_DELETE,
            KqOp::Level => ffi::EV_ADD | if on { ffi::EV_ENABLE } else { ffi::EV_DISABLE },
            KqOp::Edge => ffi::EV_ADD | ffi::EV_ENABLE | ffi::EV_CLEAR,
        };
        k.udata = token as usize as *mut ffi::c_void;
        k
    };
    let changes = [mk(ffi::EVFILT_READ, read), mk(ffi::EVFILT_WRITE, write)];
    // SAFETY: `changes` is a valid array of 2 kevents; no event list is requested.
    let r = unsafe {
        ffi::kevent(
            kq.as_raw_fd(),
            changes.as_ptr(),
            2,
            std::ptr::null_mut(),
            0,
            std::ptr::null(),
        )
    };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
