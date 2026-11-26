//! WASI preview 1 (`wasi_snapshot_preview1`), the subset a plugin needs: arguments and
//! environment, clocks, random bytes, standard output and error to a sink, sleeping, exiting. No
//! file system and no sockets (ADR-125, section 3).

use std::{
    fmt,
    sync::{Arc, OnceLock},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use crate::{
    linker::{LinkError, Linker},
    store::{Caller, HostFn},
    trap::Trap,
    types::{FuncType, ValType},
    value::Value,
};

/// The module name WASI preview 1's functions are imported from.
pub const MODULE: &str = "wasi_snapshot_preview1";

/// Where a guest's output goes: its standard output or standard error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OutputStream {
    /// File descriptor 1.
    Stdout,
    /// File descriptor 2.
    Stderr,
}

type Sink = Arc<dyn Fn(OutputStream, &[u8]) + Send + Sync>;

/// What WASI shows a guest: its arguments and environment (none by default), and where its
/// standard output and error go (nowhere by default). Standard input is empty.
///
/// ```
/// use std::sync::{Arc, Mutex};
/// use akio_wasm::{Linker, WasiConfig};
///
/// let log = Arc::new(Mutex::new(Vec::new()));
/// let sink = Arc::clone(&log);
/// let wasi = WasiConfig::new()
///     .arg("plugin")
///     .env("MODE", "test")
///     .output(move |_stream, bytes| sink.lock().unwrap().extend_from_slice(bytes));
/// let mut linker = Linker::<()>::new();
/// linker.wasi_preview1(wasi).unwrap();
/// ```
#[derive(Clone, Default)]
pub struct WasiConfig {
    args: Vec<Box<[u8]>>,
    env: Vec<Box<[u8]>>,
    output: Option<Sink>,
}

impl fmt::Debug for WasiConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WasiConfig")
            .field("args", &self.args.len())
            .field("env", &self.env.len())
            .field("output", &self.output.is_some())
            .finish()
    }
}

impl WasiConfig {
    /// No arguments, no environment, output discarded.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds an argument (the first is the program's name, by convention). A NUL in it ends it
    /// for the guest.
    #[must_use]
    pub fn arg(mut self, arg: &str) -> Self {
        self.args.push(Box::from(arg.as_bytes()));
        self
    }

    /// Adds an environment variable, `key=value`.
    #[must_use]
    pub fn env(mut self, key: &str, value: &str) -> Self {
        self.env
            .push(format!("{key}={value}").into_bytes().into_boxed_slice());
        self
    }

    /// Sends what the guest writes to its standard output and error to `sink`, a write at a
    /// time (one call per buffer of each `fd_write`). It runs on the thread running the guest,
    /// within the guest's call: it should be quick, and bound what it keeps (akit sends it to
    /// its log, rate limited).
    #[must_use]
    pub fn output(mut self, sink: impl Fn(OutputStream, &[u8]) + Send + Sync + 'static) -> Self {
        self.output = Some(Arc::new(sink));
        self
    }
}

// The errno values preview 1 defines that these functions return.
const SUCCESS: i32 = 0;
const EBADF: i32 = 8;
const EFAULT: i32 = 21;
const EINVAL: i32 = 28;
const EIO: i32 = 29;
const ENOSYS: i32 = 52;
const ESPIPE: i32 = 70;

// Clocks.
const CLOCK_REALTIME: u32 = 0;
const CLOCK_MONOTONIC: u32 = 1;

// File types, flags and rights for the standard streams.
const FILETYPE_CHARACTER_DEVICE: u8 = 2;
const RIGHT_FD_READ: u64 = 1 << 1;
const RIGHT_FD_WRITE: u64 = 1 << 6;
const RIGHT_POLL_FD_READWRITE: u64 = 1 << 27;

// poll_oneoff's subscriptions and events.
const EVENTTYPE_CLOCK: u8 = 0;
const EVENTTYPE_FD_READ: u8 = 1;
const EVENTTYPE_FD_WRITE: u8 = 2;
const SUBCLOCKFLAG_ABSTIME: u16 = 1;
const EVENTRWFLAG_HANGUP: u16 = 1;
const SUBSCRIPTION_SIZE: u32 = 48;
const EVENT_SIZE: u32 = 32;

/// The longest a sleep goes without looking at the call's interrupt.
const SLEEP_SLICE: Duration = Duration::from_millis(5);

/// What a function's body returns: an errno for the guest, or a trap.
type Errno = Result<i32, Trap>;

/// The fuel for copying `n` bytes: one unit per 64, as bulk memory instructions pay.
const fn fuel_for(n: usize) -> u64 {
    (n as u64).div_ceil(64)
}

fn arg_u32(args: &[Value], i: usize) -> u32 {
    args.get(i).and_then(Value::i32).unwrap_or(0) as u32
}

/// Nanoseconds on `clock`, `None` for a clock this does not have.
fn now(clock: u32) -> Option<u64> {
    static START: OnceLock<Instant> = OnceLock::new();
    match clock {
        CLOCK_REALTIME => Some(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX)),
        ),
        CLOCK_MONOTONIC => {
            let start = *START.get_or_init(Instant::now);
            // From 1, so that a guest never reads a zero monotonic clock.
            Some(u64::try_from(start.elapsed().as_nanos()).map_or(u64::MAX, |n| n + 1))
        }
        _ => None,
    }
}

/// Writes the strings `items`, each NUL-terminated, at `buf`, and a pointer to each at `ptrs`
/// (`args_get`, `environ_get`).
fn write_strings<S>(c: &mut Caller<'_, S>, items: &[Box<[u8]>], ptrs: u32, buf: u32) -> Errno {
    let mut at = buf;
    for (k, item) in items.iter().enumerate() {
        let item = item.split(|&b| b == 0).next().unwrap_or(&[]);
        c.consume_fuel(fuel_for(item.len()) + 1)?;
        c.write_u32(ptrs.wrapping_add(k as u32 * 4), at)?;
        c.write(at, item)?;
        at = at.wrapping_add(item.len() as u32);
        c.write(at, &[0])?;
        at = at.wrapping_add(1);
    }
    Ok(SUCCESS)
}

/// Writes how many `items` there are, and the bytes they take NUL-terminated (`*_sizes_get`).
fn write_sizes<S>(c: &mut Caller<'_, S>, items: &[Box<[u8]>], count: u32, size: u32) -> Errno {
    let bytes: usize = items
        .iter()
        .map(|i| i.split(|&b| b == 0).next().map_or(0, <[u8]>::len) + 1)
        .sum();
    c.write_u32(count, items.len() as u32)?;
    c.write_u32(size, u32::try_from(bytes).unwrap_or(u32::MAX))?;
    Ok(SUCCESS)
}

/// The buffers of an iovec array: `(ptr, len)` pairs.
fn iovecs<S>(c: &mut Caller<'_, S>, iovs: u32, n: u32) -> Result<Vec<(u32, u32)>, Trap> {
    // Each takes 8 bytes of memory, so n is bounded by the memory's size; it is checked as a
    // whole before anything is allocated for it.
    c.read(iovs, n.checked_mul(8).ok_or(Trap::MemoryOutOfBounds)?)?;
    c.consume_fuel(u64::from(n))?;
    (0..n)
        .map(|k| {
            let at = iovs + k * 8;
            Ok((c.read_u32(at)?, c.read_u32(at + 4)?))
        })
        .collect()
}

fn fd_write<S>(c: &mut Caller<'_, S>, sink: Option<&Sink>, a: &[Value]) -> Errno {
    let (fd, iovs, n, nwritten) = (arg_u32(a, 0), arg_u32(a, 1), arg_u32(a, 2), arg_u32(a, 3));
    let stream = match fd {
        1 => OutputStream::Stdout,
        2 => OutputStream::Stderr,
        _ => return Ok(EBADF),
    };
    let mut total: u32 = 0;
    for (ptr, len) in iovecs(c, iovs, n)? {
        c.consume_fuel(fuel_for(len as usize))?;
        let bytes = c.read(ptr, len)?;
        if let Some(sink) = sink {
            if !bytes.is_empty() {
                sink(stream, bytes);
            }
        }
        total = total.saturating_add(len);
    }
    c.write_u32(nwritten, total)?;
    Ok(SUCCESS)
}

fn fd_read<S>(c: &mut Caller<'_, S>, a: &[Value]) -> Errno {
    if arg_u32(a, 0) != 0 {
        return Ok(EBADF);
    }
    // Standard input is empty: at its end at once.
    c.write_u32(arg_u32(a, 3), 0)?;
    Ok(SUCCESS)
}

fn fd_fdstat_get<S>(c: &mut Caller<'_, S>, a: &[Value]) -> Errno {
    let rights = match arg_u32(a, 0) {
        0 => RIGHT_FD_READ | RIGHT_POLL_FD_READWRITE,
        1 | 2 => RIGHT_FD_WRITE | RIGHT_POLL_FD_READWRITE,
        _ => return Ok(EBADF),
    };
    // fdstat: filetype u8, flags u16 at 2, rights_base u64 at 8, rights_inheriting at 16.
    let mut st = [0u8; 24];
    st[0] = FILETYPE_CHARACTER_DEVICE;
    st[8..16].copy_from_slice(&rights.to_le_bytes());
    c.write(arg_u32(a, 1), &st)?;
    Ok(SUCCESS)
}

fn fd_filestat_get<S>(c: &mut Caller<'_, S>, a: &[Value]) -> Errno {
    if arg_u32(a, 0) > 2 {
        return Ok(EBADF);
    }
    // filestat: dev, ino u64, filetype u8 at 16, nlink at 24, size, atim, mtim, ctim.
    let mut st = [0u8; 64];
    st[16] = FILETYPE_CHARACTER_DEVICE;
    st[24..32].copy_from_slice(&1u64.to_le_bytes());
    c.write(arg_u32(a, 1), &st)?;
    Ok(SUCCESS)
}

fn clock_time_get<S>(c: &mut Caller<'_, S>, a: &[Value]) -> Errno {
    let Some(t) = now(arg_u32(a, 0)) else {
        return Ok(EINVAL);
    };
    c.write_u64(arg_u32(a, 2), t)?;
    Ok(SUCCESS)
}

fn clock_res_get<S>(c: &mut Caller<'_, S>, a: &[Value]) -> Errno {
    if now(arg_u32(a, 0)).is_none() {
        return Ok(EINVAL);
    }
    c.write_u64(arg_u32(a, 1), 1)?;
    Ok(SUCCESS)
}

fn random_get<S>(c: &mut Caller<'_, S>, a: &[Value]) -> Errno {
    let (ptr, len) = (arg_u32(a, 0), arg_u32(a, 1));
    c.consume_fuel(fuel_for(len as usize))?;
    let buf = c.read_mut(ptr, len)?;
    if akio_crypto::rand::fill_random(buf).is_err() {
        return Ok(EIO);
    }
    Ok(SUCCESS)
}

/// One subscription of `poll_oneoff`.
struct Sub {
    userdata: u64,
    kind: u8,
    /// For a clock: nanoseconds from now; `None` for a clock this does not have.
    wait: Option<u64>,
    fd: u32,
}

fn poll_oneoff<S>(c: &mut Caller<'_, S>, a: &[Value]) -> Errno {
    let (subs_at, events_at, n, nevents) =
        (arg_u32(a, 0), arg_u32(a, 1), arg_u32(a, 2), arg_u32(a, 3));
    if n == 0 {
        return Ok(EINVAL);
    }
    // Checked as a whole before anything is allocated: n is bounded by the memory's size.
    c.read(
        subs_at,
        n.checked_mul(SUBSCRIPTION_SIZE)
            .ok_or(Trap::MemoryOutOfBounds)?,
    )?;
    c.read(
        events_at,
        n.checked_mul(EVENT_SIZE).ok_or(Trap::MemoryOutOfBounds)?,
    )?;
    c.consume_fuel(u64::from(n))?;
    let mut subs = Vec::with_capacity(n as usize);
    for k in 0..n {
        let s = c.read(subs_at + k * SUBSCRIPTION_SIZE, SUBSCRIPTION_SIZE)?;
        let u64_at = |i: usize| {
            let mut b = [0; 8];
            b.copy_from_slice(&s[i..i + 8]);
            u64::from_le_bytes(b)
        };
        let u32_at = |i: usize| u32::from_le_bytes([s[i], s[i + 1], s[i + 2], s[i + 3]]);
        let kind = s[8];
        let (mut wait, mut fd) = (None, 0);
        match kind {
            EVENTTYPE_CLOCK => {
                let (clock, timeout) = (u32_at(16), u64_at(24));
                let flags = u16::from_le_bytes([s[40], s[41]]);
                wait = now(clock).map(|t| {
                    if flags & SUBCLOCKFLAG_ABSTIME != 0 {
                        timeout.saturating_sub(t)
                    } else {
                        timeout
                    }
                });
            }
            EVENTTYPE_FD_READ | EVENTTYPE_FD_WRITE => fd = u32_at(16),
            _ => return Ok(EINVAL),
        }
        subs.push(Sub {
            userdata: u64_at(0),
            kind,
            wait,
            fd,
        });
    }
    // Ready at once: a standard stream, any file descriptor (it has none other, so its
    // subscription reports EBADF), a clock it does not have (EINVAL), a timeout of zero. Else
    // it sleeps until the first timeout, waking early at the call's deadline or interrupt.
    let ready_now = |s: &Sub| s.kind != EVENTTYPE_CLOCK || s.wait.is_none_or(|w| w == 0);
    let fired = if subs.iter().any(ready_now) {
        0
    } else {
        let first = subs.iter().filter_map(|s| s.wait).min().unwrap_or(0);
        sleep(c, first);
        first
    };
    let mut count = 0u32;
    for s in &subs {
        let (error, nbytes, flags) = match (s.kind, s.wait) {
            (EVENTTYPE_CLOCK, Some(w)) if w <= fired => (SUCCESS, 0u64, 0),
            (EVENTTYPE_CLOCK, Some(_)) => continue,
            (EVENTTYPE_CLOCK, None) => (EINVAL, 0, 0),
            (EVENTTYPE_FD_READ, _) if s.fd == 0 => (SUCCESS, 0, EVENTRWFLAG_HANGUP),
            (EVENTTYPE_FD_WRITE, _) if s.fd == 1 || s.fd == 2 => (SUCCESS, 0, 0),
            _ => (EBADF, 0, 0),
        };
        // event: userdata u64, error u16 at 8, type u8 at 10, nbytes u64 at 16, flags u16 at 24.
        let mut ev = [0u8; EVENT_SIZE as usize];
        ev[0..8].copy_from_slice(&s.userdata.to_le_bytes());
        ev[8..10].copy_from_slice(&(error as u16).to_le_bytes());
        ev[10] = s.kind;
        ev[16..24].copy_from_slice(&nbytes.to_le_bytes());
        ev[24..26].copy_from_slice(&flags.to_le_bytes());
        c.write(events_at + count * EVENT_SIZE, &ev)?;
        count += 1;
    }
    c.write_u32(nevents, count)?;
    Ok(SUCCESS)
}

/// Sleeps `ns` nanoseconds, or until the call's deadline or interrupt if sooner. The guest
/// stops at its next check after either.
fn sleep<S>(c: &Caller<'_, S>, ns: u64) {
    let start = Instant::now();
    let mut until = start.checked_add(Duration::from_nanos(ns));
    if let Some(d) = c.deadline() {
        until = Some(until.map_or(d, |u| u.min(d)));
    }
    loop {
        if c.is_interrupted() {
            return;
        }
        let now = Instant::now();
        let left = until.map_or(SLEEP_SLICE, |u| u.saturating_duration_since(now));
        if left.is_zero() {
            return;
        }
        std::thread::sleep(left.min(SLEEP_SLICE));
    }
}

/// The functions that are stubs, by name, parameter types and the errno they return.
const STUBS: &[(&str, &[ValType], i32)] = {
    use ValType::{I32 as A, I64 as B};
    &[
        ("fd_advise", &[A, B, B, A], EBADF),
        ("fd_allocate", &[A, B, B], EBADF),
        ("fd_datasync", &[A], EBADF),
        ("fd_fdstat_set_rights", &[A, B, B], EBADF),
        ("fd_filestat_set_size", &[A, B], EBADF),
        ("fd_filestat_set_times", &[A, B, B, A], EBADF),
        ("fd_pread", &[A, A, A, B, A], EBADF),
        ("fd_prestat_get", &[A, A], EBADF),
        ("fd_prestat_dir_name", &[A, A, A], EBADF),
        ("fd_pwrite", &[A, A, A, B, A], EBADF),
        ("fd_readdir", &[A, A, A, B, A], EBADF),
        ("fd_renumber", &[A, A], EBADF),
        ("fd_sync", &[A], EBADF),
        ("path_create_directory", &[A, A, A], EBADF),
        ("path_filestat_get", &[A, A, A, A, A], EBADF),
        ("path_filestat_set_times", &[A, A, A, A, B, B, A], EBADF),
        ("path_link", &[A, A, A, A, A, A, A], EBADF),
        ("path_open", &[A, A, A, A, A, B, B, A, A], EBADF),
        ("path_readlink", &[A, A, A, A, A, A], EBADF),
        ("path_remove_directory", &[A, A, A], EBADF),
        ("path_rename", &[A, A, A, A, A, A], EBADF),
        ("path_symlink", &[A, A, A, A, A], EBADF),
        ("path_unlink_file", &[A, A, A], EBADF),
        ("proc_raise", &[A], ENOSYS),
        ("sock_accept", &[A, A, A], ENOSYS),
        ("sock_recv", &[A, A, A, A, A, A], ENOSYS),
        ("sock_send", &[A, A, A, A, A], ENOSYS),
        ("sock_shutdown", &[A, A], ENOSYS),
    ]
};

/// A function's body: the guest's arguments to an errno.
type Body<S> = fn(&mut Caller<'_, S>, &WasiConfig, &[Value]) -> Errno;

fn args_get<S>(c: &mut Caller<'_, S>, w: &WasiConfig, a: &[Value]) -> Errno {
    write_strings(c, &w.args, arg_u32(a, 0), arg_u32(a, 1))
}

fn args_sizes_get<S>(c: &mut Caller<'_, S>, w: &WasiConfig, a: &[Value]) -> Errno {
    write_sizes(c, &w.args, arg_u32(a, 0), arg_u32(a, 1))
}

fn environ_get<S>(c: &mut Caller<'_, S>, w: &WasiConfig, a: &[Value]) -> Errno {
    write_strings(c, &w.env, arg_u32(a, 0), arg_u32(a, 1))
}

fn environ_sizes_get<S>(c: &mut Caller<'_, S>, w: &WasiConfig, a: &[Value]) -> Errno {
    write_sizes(c, &w.env, arg_u32(a, 0), arg_u32(a, 1))
}

/// For the standard streams `ok`, for any other file descriptor `EBADF`.
const fn stdio(a: &[Value], ok: i32) -> Errno {
    match a.first() {
        Some(Value::I32(0..=2)) => Ok(ok),
        _ => Ok(EBADF),
    }
}

impl<S> Linker<S> {
    /// Defines WASI preview 1 (module `wasi_snapshot_preview1`, all 46 of its functions) as
    /// `config` says, the subset of ADR-125's section 3:
    ///
    /// - `args_*` and `environ_*`: [`WasiConfig::arg`] and [`WasiConfig::env`], none by default;
    /// - `clock_time_get` and `clock_res_get`: the realtime and monotonic clocks (others
    ///   `EINVAL`), to the nanosecond;
    /// - `random_get`: the operating system's generator (akio-crypto's `fill_random`);
    /// - `fd_write` on 1 and 2: to [`WasiConfig::output`]'s sink; `fd_read` on 0: empty;
    ///   `fd_fdstat_get`, `fd_filestat_get`, `fd_fdstat_set_flags` and `fd_close` on 0 to 2: a
    ///   character device that does nothing; `fd_seek` and `fd_tell` on them `ESPIPE`;
    /// - `poll_oneoff`: clock subscriptions sleep until the first timeout, but no later than the
    ///   call's deadline, nor past its interrupt (the guest then stops at its next check);
    ///   standard streams are ready at once;
    /// - `sched_yield`: nothing; `proc_exit`: [`Trap::Exit`] with its code;
    /// - no file system and no sockets: there are no preopened directories, every other `fd_*`
    ///   and `path_*` function returns `EBADF`, `sock_*` and `proc_raise` `ENOSYS`.
    ///
    /// A pointer from the guest outside its memory is `EFAULT`, not a trap. Copies are charged
    /// to the call's fuel, a unit per 64 bytes, as bulk memory instructions are.
    ///
    /// # Errors
    ///
    /// [`LinkError::Duplicate`] if one of its functions is defined already.
    pub fn wasi_preview1(&mut self, config: WasiConfig) -> Result<&mut Self, LinkError>
    where
        S: 'static,
    {
        use ValType::{I32 as A, I64 as B};
        let cfg = Arc::new(config);
        let funcs: [(&str, &[ValType], Body<S>); 17] = [
            ("args_get", &[A, A], args_get),
            ("args_sizes_get", &[A, A], args_sizes_get),
            ("environ_get", &[A, A], environ_get),
            ("environ_sizes_get", &[A, A], environ_sizes_get),
            ("clock_time_get", &[A, B, A], |c, _, a| clock_time_get(c, a)),
            ("clock_res_get", &[A, A], |c, _, a| clock_res_get(c, a)),
            ("random_get", &[A, A], |c, _, a| random_get(c, a)),
            ("poll_oneoff", &[A, A, A, A], |c, _, a| poll_oneoff(c, a)),
            ("sched_yield", &[], |_, _, _| Ok(SUCCESS)),
            ("fd_write", &[A, A, A, A], |c, w, a| {
                fd_write(c, w.output.as_ref(), a)
            }),
            ("fd_read", &[A, A, A, A], |c, _, a| fd_read(c, a)),
            ("fd_fdstat_get", &[A, A], |c, _, a| fd_fdstat_get(c, a)),
            ("fd_filestat_get", &[A, A], |c, _, a| fd_filestat_get(c, a)),
            ("fd_fdstat_set_flags", &[A, A], |_, _, a| stdio(a, SUCCESS)),
            ("fd_close", &[A], |_, _, a| stdio(a, SUCCESS)),
            ("fd_seek", &[A, B, A, A], |_, _, a| stdio(a, ESPIPE)),
            ("fd_tell", &[A, A], |_, _, a| stdio(a, ESPIPE)),
        ];
        for (name, params, body) in funcs {
            let cfg = Arc::clone(&cfg);
            self.define(
                MODULE,
                name,
                FuncType::new(params, &[A]),
                HostFn::Values(Arc::new(
                    move |c: &mut Caller<'_, S>, a: &[Value], r: &mut [Value]| {
                        // A fault in the guest's memory is its error, not a trap.
                        r[0] = Value::I32(match body(c, &cfg, a) {
                            Ok(e) => e,
                            Err(Trap::MemoryOutOfBounds) => EFAULT,
                            Err(t) => return Err(t),
                        });
                        Ok(())
                    },
                )),
            )?;
        }
        self.define(
            MODULE,
            "proc_exit",
            FuncType::new(&[A], &[]),
            HostFn::Values(Arc::new(
                |_: &mut Caller<'_, S>, a: &[Value], _: &mut [Value]| {
                    Err(Trap::Exit(a.first().and_then(Value::i32).unwrap_or(0)))
                },
            )),
        )?;
        for &(name, params, errno) in STUBS {
            self.define(
                MODULE,
                name,
                FuncType::new(params, &[A]),
                HostFn::Values(Arc::new(
                    move |_: &mut Caller<'_, S>, _: &[Value], r: &mut [Value]| {
                        r[0] = Value::I32(errno);
                        Ok(())
                    },
                )),
            )?;
        }
        Ok(self)
    }
}
