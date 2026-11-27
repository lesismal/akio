//! Process plumbing: the CPUs a thread may run on and pinning it to some of them, turning
//! signals into bytes on a pipe (the self-pipe trick), sending a signal to a process or a
//! process group, and the process's effective user.

use crate::ffi;
use std::io;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Mutex, OnceLock};

/// `SIGHUP`.
pub const SIGHUP: i32 = ffi::SIGHUP;
/// `SIGINT`.
pub const SIGINT: i32 = ffi::SIGINT;
/// `SIGKILL`.
pub const SIGKILL: i32 = ffi::SIGKILL;
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

/// Sends `sig` to every process in process group `pgid` (`killpg(2)`): a child spawned in a
/// group of its own (`std::os::unix::process::CommandExt::process_group(0)`, whose group id is
/// then its pid) together with whatever it started that stayed in its group, as Go's
/// `syscall.Kill(-pid, sig)`. Signal `0` checks that the group has a process the caller may
/// signal, delivering nothing.
///
/// `0` (the caller's own group) and `1` (which `killpg` turns into "every process the caller
/// may signal") are refused, as is a `pgid` past `i32::MAX`, with `EINVAL`. `ESRCH` when no
/// process is in the group, `EPERM` when the caller may signal none of them. A group the caller
/// is in is not refused: the caller gets the signal too.
pub fn kill_group(pgid: u32, sig: i32) -> io::Result<()> {
    let pgid = ffi::pid_t::try_from(pgid)
        .ok()
        .filter(|&p| p > 1)
        .ok_or_else(|| io::Error::from_raw_os_error(ffi::EINVAL))?;
    // SAFETY: plain syscall with integer arguments; `pgid` > 1, so neither the caller's group
    // nor every process.
    if unsafe { ffi::killpg(pgid, sig) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// The process's effective user id (`geteuid(2)`, which cannot fail): `0` when it runs as root.
/// The user it acts as when it opens files or signals other processes, which differs from the
/// real user under a set-user-ID program.
pub fn euid() -> u32 {
    // SAFETY: geteuid takes no arguments and always succeeds.
    unsafe { ffi::geteuid() }
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

    #[test]
    fn euid_owns_the_files_it_creates() {
        // A new file belongs to the effective user (Linux: the file system user, which follows
        // it unless set apart with setfsuid).
        use std::os::unix::fs::MetadataExt;
        let path = std::env::temp_dir().join(format!("akio-sys-euid-{}", std::process::id()));
        let file = std::fs::File::create(&path).unwrap();
        let uid = file.metadata().unwrap().uid();
        drop(file);
        std::fs::remove_file(&path).unwrap();
        assert_eq!(euid(), uid);
    }

    #[test]
    fn kill_group_reaches_the_whole_group() {
        use std::io::{BufRead, BufReader, Read};
        use std::os::unix::process::{CommandExt, ExitStatusExt};
        use std::process::{Command, Stdio};
        use std::time::Duration;

        for refused in [0, 1, u32::MAX] {
            let e = kill_group(refused, 0).unwrap_err();
            assert_eq!(e.raw_os_error(), Some(ffi::EINVAL), "pgid {refused}");
        }
        // A shell in a group of its own starts a child in the background (in its group: a
        // shell that is not interactive has no job control), prints the child's pid and
        // becomes another process of the group. Both hold the pipe's write end, so the pipe
        // reads to its end only once both are gone.
        let mut leader = Command::new("sh")
            .args(["-c", "sleep 1000 & echo $!; exec sleep 1000"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .process_group(0)
            .spawn()
            .unwrap();
        let mut out = BufReader::new(leader.stdout.take().unwrap());
        let mut line = String::new();
        out.read_line(&mut line).unwrap();
        let member: u32 = line.trim().parse().unwrap();
        let pgid = leader.id();
        kill_group(pgid, 0).unwrap();
        kill_group(pgid, SIGKILL).unwrap();
        assert_eq!(leader.wait().unwrap().signal(), Some(SIGKILL));
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut rest = Vec::new();
            let _ = tx.send(out.read_to_end(&mut rest).map(|_| rest));
        });
        // A deadline for the test, not a retry: the member is killed with the leader or not
        // at all.
        let Ok(rest) = rx.recv_timeout(Duration::from_secs(30)) else {
            let _ = kill(member, SIGKILL);
            panic!("process {member} of group {pgid} outlived SIGKILL to the group");
        };
        assert!(rest.unwrap().is_empty());
    }
}
