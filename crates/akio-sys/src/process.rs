//! Process plumbing: the CPUs a thread may run on and pinning it to some of them, turning
//! signals into bytes on a pipe (the self-pipe trick), and sending a signal to a process.

use crate::ffi;
use std::io;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Mutex, OnceLock};

/// `SIGHUP`.
pub const SIGHUP: i32 = ffi::SIGHUP;
/// `SIGINT`.
pub const SIGINT: i32 = ffi::SIGINT;
/// `SIGTERM`.
pub const SIGTERM: i32 = ffi::SIGTERM;
/// `SIGUSR2`.
pub const SIGUSR2: i32 = ffi::SIGUSR2;

#[cfg(target_os = "linux")]
fn cpu_set(cpus: &[usize]) -> Option<ffi::cpu_set_t> {
    if cpus.is_empty() {
        return None;
    }
    let mut set = ffi::cpu_set_t::new();
    for &c in cpus.iter().filter(|&&c| c < ffi::cpu_set_t::CAPACITY) {
        set.set(c);
    }
    Some(set)
}

/// The CPUs the calling thread may run on (`sched_getaffinity`), ascending. Linux only;
/// `Unsupported` elsewhere (macOS has no CPU affinity API).
pub fn allowed_cpus() -> io::Result<Vec<usize>> {
    #[cfg(target_os = "linux")]
    {
        let mut set = ffi::cpu_set_t::new();
        // SAFETY: `set` is a valid, writable cpu_set_t of the size passed.
        let r = unsafe {
            ffi::sched_getaffinity(0, size_of::<ffi::cpu_set_t>(), std::ptr::from_mut(&mut set))
        };
        if r < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((0..ffi::cpu_set_t::CAPACITY)
            .filter(|&c| set.is_set(c))
            .collect())
    }
    #[cfg(not(target_os = "linux"))]
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "CPU affinity is Linux-only",
    ))
}

/// Restricts the calling thread to `cpus` (`sched_setaffinity` on the thread). Linux only;
/// `Unsupported` elsewhere, `InvalidInput` when `cpus` names no CPU below 1024.
pub fn pin_current_thread(cpus: &[usize]) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        let Some(set) =
            cpu_set(cpus).filter(|s| (0..ffi::cpu_set_t::CAPACITY).any(|c| s.is_set(c)))
        else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "no CPU to pin to",
            ));
        };
        // SAFETY: `set` is a fully initialised cpu_set_t of the size passed; pid 0 is the
        // calling thread.
        let r = unsafe {
            ffi::sched_setaffinity(0, size_of::<ffi::cpu_set_t>(), std::ptr::from_ref(&set))
        };
        if r < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = cpus;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "CPU affinity is Linux-only",
        ))
    }
}

/// Write end of the signal pipe, read by the handler (-1 until set up).
static SIGNAL_WRITE: AtomicI32 = AtomicI32::new(-1);
/// Read end of the signal pipe.
static SIGNAL_READ: OnceLock<std::os::unix::net::UnixStream> = OnceLock::new();
/// Serialises [`signal_pipe`] calls.
static SIGNAL_SETUP: Mutex<()> = Mutex::new(());

extern "C" fn on_signal(sig: ffi::c_int) {
    let fd = SIGNAL_WRITE.load(Ordering::Relaxed);
    if fd < 0 {
        return;
    }
    let b = sig as u8;
    // SAFETY: write(2) is async-signal-safe; `b` outlives the call. errno is saved and restored
    // so the interrupted code does not see the handler's errno.
    unsafe {
        let errno = ffi::errno_location();
        let saved = *errno;
        ffi::write(fd, (&raw const b).cast::<ffi::c_void>(), 1);
        *errno = saved;
    }
}

/// Installs handlers for `signals` (e.g. [`SIGTERM`]) that write each delivered signal's number,
/// as one byte, to a process-wide pipe, and returns a blocking reader of that pipe. Later calls
/// add their signals to the same pipe and return another reader of it, so one thread should
/// read and dispatch. The handlers stay installed for the life of the process.
pub fn signal_pipe(signals: &[i32]) -> io::Result<std::os::unix::net::UnixStream> {
    let _g = SIGNAL_SETUP.lock().unwrap_or_else(|p| p.into_inner());
    if SIGNAL_READ.get().is_none() {
        // A socket pair rather than a pipe: std creates it close-on-exec and can make the
        // write end non-blocking (a full buffer drops a signal instead of blocking the handler).
        let (r, w) = std::os::unix::net::UnixStream::pair()?;
        w.set_nonblocking(true)?;
        // The write end lives for the rest of the process: the handlers may run at any time.
        SIGNAL_WRITE.store(std::os::fd::IntoRawFd::into_raw_fd(w), Ordering::Relaxed);
        let _ = SIGNAL_READ.set(r);
    }
    for &sig in signals {
        // SAFETY: sigaction is plain-old-data; all-zero is a valid starting value.
        let mut sa: ffi::sigaction = unsafe { std::mem::zeroed() };
        // sigaction takes the handler as an integer (`sighandler_t`).
        #[allow(clippy::fn_to_numeric_cast_any)]
        {
            sa.sa_sigaction = on_signal as extern "C" fn(ffi::c_int) as ffi::sighandler_t;
        }
        sa.sa_flags = ffi::SA_RESTART;
        // SAFETY: `sa` is initialised (empty mask, our handler); the old action is not wanted.
        let r = unsafe {
            ffi::sigemptyset(&raw mut sa.sa_mask);
            ffi::sigaction(sig, &raw const sa, std::ptr::null_mut())
        };
        if r < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    let read = SIGNAL_READ
        .get()
        .ok_or_else(|| io::Error::other("signal pipe missing"))?;
    read.try_clone()
}

/// Sends `sig` to process `pid` (`kill(2)`). `pid` must be positive: process groups and
/// "every process" are refused.
pub fn kill(pid: u32, sig: i32) -> io::Result<()> {
    let pid = ffi::pid_t::try_from(pid)
        .ok()
        .filter(|&p| p > 0)
        .ok_or_else(|| io::Error::from_raw_os_error(ffi::EINVAL))?;
    // SAFETY: plain syscall with integer arguments.
    if unsafe { ffi::kill(pid, sig) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signal_to_pipe() {
        use std::io::Read;
        let mut r = signal_pipe(&[SIGUSR2]).unwrap();
        // Directed at this thread, not the process: a process-directed signal may land on the
        // test harness's main thread, and under ThreadSanitizer a handler is deferred until its
        // thread enters an intercepted call. The main thread waits in a raw futex syscall,
        // which TSan does not intercept, so the byte never arrived and the test hung
        // (tools/sanitizers/README.md). `raise` targets the reading thread, whose `read`
        // is intercepted and runs the handler.
        // SAFETY: raise(3) with a signal whose handler was just installed by `signal_pipe`.
        assert_eq!(unsafe { libc::raise(SIGUSR2) }, 0);
        let mut b = [0u8; 1];
        r.read_exact(&mut b).unwrap();
        assert_eq!(i32::from(b[0]), SIGUSR2);
        // kill(2) itself: signal 0 checks the target without delivering anything.
        kill(std::process::id(), 0).unwrap();
        assert!(kill(0, SIGUSR2).is_err());
    }
}
