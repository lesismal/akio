use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use crate::Poller;

/// Wakes a [`Poller`] blocked in `wait` from any thread (eventfd on Linux, a pipe elsewhere).
pub struct Waker {
    read: OwnedFd,
    #[cfg(not(target_os = "linux"))]
    write: OwnedFd,
}

impl Waker {
    /// Creates a waker and registers it with `poller` under `token` (read interest).
    pub fn new(poller: &Poller, token: u64) -> io::Result<Waker> {
        #[cfg(target_os = "linux")]
        let w = {
            // SAFETY: plain syscall; the fd is owned by the returned OwnedFd.
            let fd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: fd was just created and is owned by nobody else.
            let read = unsafe { OwnedFd::from_raw_fd(fd) };
            Waker { read }
        };
        #[cfg(not(target_os = "linux"))]
        let w = {
            let mut fds = [0 as libc::c_int; 2];
            // SAFETY: `fds` has room for the two descriptors pipe(2) writes.
            if unsafe { libc::pipe(fds.as_mut_ptr()) } < 0 {
                return Err(io::Error::last_os_error());
            }
            crate::poller::set_nonblock_cloexec(fds[0])?;
            crate::poller::set_nonblock_cloexec(fds[1])?;
            // SAFETY: both fds were just created and are owned by nobody else.
            let read = unsafe { OwnedFd::from_raw_fd(fds[0]) };
            // SAFETY: as above.
            let write = unsafe { OwnedFd::from_raw_fd(fds[1]) };
            Waker { read, write }
        };
        poller.add(w.read.as_raw_fd(), token, true, false)?;
        Ok(w)
    }

    fn write_fd(&self) -> RawFd {
        #[cfg(target_os = "linux")]
        return self.read.as_raw_fd();
        #[cfg(not(target_os = "linux"))]
        return self.write.as_raw_fd();
    }

    /// Makes the poller's next (or current) `wait` return a readable event for the token.
    pub fn wake(&self) {
        let one: u64 = 1;
        #[cfg(target_os = "linux")]
        let len = 8;
        #[cfg(not(target_os = "linux"))]
        let len = 1;
        // SAFETY: writes `len` bytes from a live u64. EAGAIN (already signalled) is fine.
        unsafe {
            libc::write(
                self.write_fd(),
                &one as *const _ as *const libc::c_void,
                len,
            )
        };
    }

    /// Clears the signalled state; call after the poller reported the waker's token.
    pub fn drain(&self) {
        let mut buf = [0u8; 64];
        loop {
            // SAFETY: reads at most `buf.len()` bytes into a live buffer.
            let n = unsafe {
                libc::read(
                    self.read.as_raw_fd(),
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                )
            };
            // An eventfd read resets the counter in one call; a pipe may need several.
            if n <= 0 || cfg!(target_os = "linux") {
                break;
            }
        }
    }
}

/// A bare Linux eventfd for backends that wait on it with their own mechanism (io_uring reads it
/// with a submitted `Read`). `wake` may be called from any thread.
#[cfg(target_os = "linux")]
pub struct EventFd {
    fd: OwnedFd,
}

#[cfg(target_os = "linux")]
impl EventFd {
    /// Creates a non-blocking, close-on-exec eventfd.
    pub fn new() -> io::Result<EventFd> {
        // SAFETY: plain syscall; the fd is owned by the returned OwnedFd.
        let fd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fd was just created and is owned by nobody else.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        Ok(EventFd { fd })
    }

    /// The raw descriptor (for `Read` submissions).
    pub fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    /// Increments the counter, completing a pending read of the eventfd.
    pub fn wake(&self) {
        let one: u64 = 1;
        // SAFETY: writes 8 bytes from a live u64. EAGAIN (counter saturated) is fine.
        unsafe { libc::write(self.fd.as_raw_fd(), (&raw const one).cast(), 8) };
    }
}
