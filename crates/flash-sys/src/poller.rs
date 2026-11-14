use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
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
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn set_nonblock_cloexec(fd: RawFd) -> io::Result<()> {
    // SAFETY: fcntl on a valid fd with valid commands.
    unsafe {
        let fl = libc::fcntl(fd, libc::F_GETFL);
        if fl < 0 || libc::fcntl(fd, libc::F_SETFL, fl | libc::O_NONBLOCK) < 0 {
            return Err(io::Error::last_os_error());
        }
        let fl = libc::fcntl(fd, libc::F_GETFD);
        if fl < 0 || libc::fcntl(fd, libc::F_SETFD, fl | libc::FD_CLOEXEC) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn timeout_ms(t: Option<Duration>) -> libc::c_int {
    match t {
        None => -1,
        // round up so a 100µs timeout does not spin
        Some(d) => d.as_micros().div_ceil(1000).min(i32::MAX as u128) as libc::c_int,
    }
}

/// Level-triggered readiness poller: epoll on Linux, kqueue on macOS.
pub struct Poller {
    fd: OwnedFd,
    #[cfg(target_os = "linux")]
    buf: Vec<libc::epoll_event>,
    #[cfg(target_os = "macos")]
    buf: Vec<libc::kevent>,
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
        let fd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Poller {
            // SAFETY: fd was just created and is owned by nobody else.
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
            buf: vec![libc::epoll_event { events: 0, u64: 0 }; BATCH],
        })
    }

    fn ctl(
        &self,
        op: libc::c_int,
        fd: RawFd,
        token: u64,
        read: bool,
        write: bool,
    ) -> io::Result<()> {
        let mut ev = libc::epoll_event {
            events: (if read { libc::EPOLLIN } else { 0 } | if write { libc::EPOLLOUT } else { 0 })
                as u32,
            u64: token,
        };
        // SAFETY: `ev` is a valid epoll_event for the duration of the call.
        if unsafe { libc::epoll_ctl(self.fd.as_raw_fd(), op, fd, &mut ev) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Registers `fd`.
    pub fn add(&self, fd: RawFd, token: u64, read: bool, write: bool) -> io::Result<()> {
        self.ctl(libc::EPOLL_CTL_ADD, fd, token, read, write)
    }

    /// Changes the interest of a registered `fd`.
    pub fn modify(&self, fd: RawFd, token: u64, read: bool, write: bool) -> io::Result<()> {
        self.ctl(libc::EPOLL_CTL_MOD, fd, token, read, write)
    }

    /// Deregisters `fd` (errors ignored: closing the fd deregisters it anyway).
    pub fn delete(&self, fd: RawFd) {
        let _ = self.ctl(libc::EPOLL_CTL_DEL, fd, 0, false, false);
    }

    /// Waits for events, appending them to `out`. `None` waits forever.
    pub fn wait(&mut self, out: &mut Vec<Event>, timeout: Option<Duration>) -> io::Result<()> {
        // SAFETY: `buf` has BATCH initialised entries; the kernel writes at most BATCH.
        let n = unsafe {
            libc::epoll_wait(
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
            let bad = events & (libc::EPOLLERR | libc::EPOLLHUP) as u32 != 0;
            out.push(Event {
                token,
                readable: bad || events & (libc::EPOLLIN | libc::EPOLLRDHUP) as u32 != 0,
                writable: bad || events & libc::EPOLLOUT as u32 != 0,
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
        let fd = unsafe { libc::kqueue() };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fd was just created and is owned by nobody else (owned first, so that a
        // failing fcntl below closes it).
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        // kqueue descriptors reject O_NONBLOCK (ENOTTY); close-on-exec is all they need.
        // SAFETY: fcntl on a valid fd with valid commands.
        if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Poller {
            fd,
            // SAFETY: kevent is plain-old-data; all-zero is valid.
            buf: vec![unsafe { std::mem::zeroed() }; BATCH],
        })
    }

    fn change(
        &self,
        fd: RawFd,
        token: u64,
        read: bool,
        write: bool,
        delete: bool,
    ) -> io::Result<()> {
        let mk = |filter: i16, on: bool| {
            // SAFETY: kevent is plain-old-data; all-zero is valid.
            let mut k: libc::kevent = unsafe { std::mem::zeroed() };
            k.ident = fd as libc::uintptr_t;
            k.filter = filter;
            k.flags = if delete {
                libc::EV_DELETE
            } else {
                libc::EV_ADD
                    | if on {
                        libc::EV_ENABLE
                    } else {
                        libc::EV_DISABLE
                    }
            };
            k.udata = token as usize as *mut libc::c_void;
            k
        };
        let changes = [mk(libc::EVFILT_READ, read), mk(libc::EVFILT_WRITE, write)];
        // SAFETY: `changes` is a valid array of 2 kevents; no event list is requested.
        let r = unsafe {
            libc::kevent(
                self.fd.as_raw_fd(),
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

    /// Registers `fd`.
    pub fn add(&self, fd: RawFd, token: u64, read: bool, write: bool) -> io::Result<()> {
        self.change(fd, token, read, write, false)
    }

    /// Changes the interest of a registered `fd`.
    pub fn modify(&self, fd: RawFd, token: u64, read: bool, write: bool) -> io::Result<()> {
        self.change(fd, token, read, write, false)
    }

    /// Deregisters `fd` (errors ignored: closing the fd deregisters it anyway).
    pub fn delete(&self, fd: RawFd) {
        let _ = self.change(fd, 0, false, false, true);
    }

    /// Waits for events, appending them to `out`. `None` waits forever.
    pub fn wait(&mut self, out: &mut Vec<Event>, timeout: Option<Duration>) -> io::Result<()> {
        let ts = timeout.map(|d| libc::timespec {
            tv_sec: d.as_secs() as libc::time_t,
            tv_nsec: d.subsec_nanos() as _,
        });
        let tsp = ts.as_ref().map_or(std::ptr::null(), |t| t as *const _);
        // SAFETY: `buf` has BATCH initialised entries; `tsp` is null or points to a live timespec.
        let n = unsafe {
            libc::kevent(
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
            let bad = k.flags & (libc::EV_ERROR | libc::EV_EOF) != 0;
            out.push(Event {
                token: k.udata as usize as u64,
                readable: k.filter == libc::EVFILT_READ || bad,
                writable: k.filter == libc::EVFILT_WRITE || (bad && k.filter != libc::EVFILT_READ),
            });
        }
        Ok(())
    }
}
