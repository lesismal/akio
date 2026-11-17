//! Process plumbing for multi-process serving (`only-prefork`): handing file descriptors to a
//! re-executed child, pinning it to CPUs, tying its life to the parent, reserving a
//! `SO_REUSEPORT` port, and turning signals into bytes on a pipe (the self-pipe trick).

use crate::ffi;
use std::collections::HashSet;
use std::io;
use std::net::{SocketAddr, TcpListener};
use std::os::fd::{FromRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Mutex, OnceLock};

/// `SIGHUP`.
pub const SIGHUP: i32 = ffi::SIGHUP;
/// `SIGINT`.
pub const SIGINT: i32 = ffi::SIGINT;
/// `SIGTERM`.
pub const SIGTERM: i32 = ffi::SIGTERM;
/// `SIGQUIT`.
pub const SIGQUIT: i32 = ffi::SIGQUIT;
/// `SIGUSR1`.
pub const SIGUSR1: i32 = ffi::SIGUSR1;
/// `SIGUSR2`.
pub const SIGUSR2: i32 = ffi::SIGUSR2;

/// What [`configure_child`] does in the child between `fork` and `exec`.
#[derive(Clone, Debug, Default)]
pub struct ChildSetup {
    /// File descriptors the child inherits at the same numbers (their close-on-exec flag is
    /// cleared in the child only; the parent's copies keep it).
    pub inherit: Vec<RawFd>,
    /// Linux: CPUs the child (and every thread it starts) may run on; empty = no pinning.
    /// Ignored elsewhere (macOS has no CPU affinity API).
    pub cpus: Vec<usize>,
    /// Linux: the child receives this signal when the thread that spawned it exits
    /// (`PR_SET_PDEATHSIG`); `None` = nothing. Ignored elsewhere.
    pub parent_death_signal: Option<i32>,
}

/// Installs `setup` as a `pre_exec` hook of `cmd`. Everything the hook does is a plain,
/// async-signal-safe system call; all memory it touches is prepared here, before `fork`.
pub fn configure_child(cmd: &mut Command, setup: &ChildSetup) {
    let inherit = setup.inherit.clone();
    #[cfg(target_os = "linux")]
    let cpus = cpu_set(&setup.cpus);
    #[cfg(target_os = "linux")]
    let pdeathsig = setup.parent_death_signal;
    #[cfg(target_os = "linux")]
    // SAFETY: getpid has no preconditions. Read in the parent before fork: the child compares
    // its getppid() against it.
    let parent = unsafe { ffi::getpid() };
    let hook = move || -> io::Result<()> {
        for &fd in &inherit {
            // SAFETY: fcntl on an fd number with valid commands; an invalid fd fails with EBADF,
            // which is reported. No memory is passed.
            let r = unsafe {
                let fl = ffi::fcntl(fd, ffi::F_GETFD);
                if fl < 0 {
                    -1
                } else {
                    ffi::fcntl(fd, ffi::F_SETFD, fl & !ffi::FD_CLOEXEC)
                }
            };
            if r < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        #[cfg(target_os = "linux")]
        {
            if let Some(sig) = pdeathsig {
                // SAFETY: prctl(PR_SET_PDEATHSIG) takes a signal number by value.
                if unsafe { ffi::prctl(ffi::PR_SET_PDEATHSIG, sig as ffi::c_ulong) } < 0 {
                    return Err(io::Error::last_os_error());
                }
                // The parent may have died between fork and prctl: then nobody would signal us.
                // SAFETY: getppid has no preconditions.
                if unsafe { ffi::getppid() } != parent {
                    return Err(io::Error::from_raw_os_error(ffi::ESRCH));
                }
            }
            if let Some(set) = &cpus {
                // SAFETY: `set` is a fully initialised cpu_set_t of the size passed.
                let r = unsafe {
                    ffi::sched_setaffinity(0, size_of::<ffi::cpu_set_t>(), std::ptr::from_ref(set))
                };
                if r < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
        }
        Ok(())
    };
    // SAFETY: the hook only makes async-signal-safe system calls (fcntl, prctl, getppid,
    // sched_setaffinity) and allocates nothing: `inherit` and `cpus` were built before fork, and
    // the error paths build `io::Error`s from an errno or a static string without allocating.
    unsafe {
        cmd.pre_exec(hook);
    }
}

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

/// Fds already taken by [`take_inherited_fd`] in this process.
static TAKEN: Mutex<Option<HashSet<RawFd>>> = Mutex::new(None);

/// Takes ownership of the descriptor `fd` that this process inherited from its parent (named,
/// say, in an environment variable the parent set): checks that it is open, marks it
/// close-on-exec so it does not leak further, and returns it owned.
///
/// Each fd number can be taken once per process (`AlreadyExists` afterwards), which is what
/// makes owning it sound: an inherited descriptor that nothing in this process opened has no
/// other owner, and this function never hands it out twice. Only pass fd numbers your parent
/// promised to pass you.
pub fn take_inherited_fd(fd: RawFd) -> io::Result<OwnedFd> {
    if fd < 0 {
        return Err(io::Error::from_raw_os_error(ffi::EBADF));
    }
    let mut taken = TAKEN.lock().unwrap_or_else(|p| p.into_inner());
    let set = taken.get_or_insert_with(HashSet::new);
    if set.contains(&fd) {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("inherited fd {fd} was already taken"),
        ));
    }
    // SAFETY: fcntl on an fd number with valid commands; EBADF for a closed one is reported.
    let r = unsafe {
        let fl = ffi::fcntl(fd, ffi::F_GETFD);
        if fl < 0 {
            -1
        } else {
            ffi::fcntl(fd, ffi::F_SETFD, fl | ffi::FD_CLOEXEC)
        }
    };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    set.insert(fd);
    // SAFETY: `fd` is open (checked above) and was inherited across exec; the `TAKEN` set
    // guarantees this is the only owner this function ever creates for it (see the docs).
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Binds `addr` with `SO_REUSEADDR` and `SO_REUSEPORT` **without listening**: it reserves the
/// port (and resolves port 0) for processes that then bind and listen on the same address with
/// `SO_REUSEPORT`, without receiving any connection itself (only listening sockets join the
/// kernel's reuseport group). The returned socket is not listening; use it for `local_addr`.
pub fn reserve_reuseport(addr: SocketAddr) -> io::Result<TcpListener> {
    crate::net::bind_reuseport(addr)
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
    fn reserve_then_listen() {
        let r = reserve_reuseport("127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = r.local_addr().unwrap();
        let l = crate::listen(addr, true, 16).unwrap();
        assert_eq!(l.local_addr().unwrap(), addr);
        drop(std::net::TcpStream::connect(addr).unwrap());
    }

    #[test]
    fn take_inherited_twice() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let fd = std::os::fd::IntoRawFd::into_raw_fd(l);
        let owned = take_inherited_fd(fd).unwrap();
        assert_eq!(
            take_inherited_fd(fd).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        drop(owned);
        assert!(take_inherited_fd(-1).is_err());
    }

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
