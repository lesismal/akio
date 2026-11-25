//! WASI preview 1's subset (ADR-125, section 3), a function at a time: each test calls one
//! through a module that imports it and passes its arguments on.

use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use akio_wasm::{
    Budget, Caller, Instance, InstanceLimits, InterruptHandle, Linker, Memory, OutputStream, Store,
    Trap, ValType, Value, WasiConfig, wasi,
};

mod common;
use common::*;

const EBADF: i32 = 8;
const EFAULT: i32 = 21;
const EINVAL: i32 = 28;
const ENOSYS: i32 = 52;
const ESPIPE: i32 = 70;

struct Wasi {
    s: Store<()>,
    inst: Instance,
    mem: Memory,
}

/// An instance of a module that imports `name` (of `params` to `results`) from WASI and exports
/// `run`, which calls it with its arguments, and its memory of one page.
fn wasi(name: &str, params: &[u8], results: &[u8], config: WasiConfig) -> Wasi {
    let mut b = Builder::default();
    let t = b.ty(params, results);
    let f = b.import_func(wasi::MODULE, name, t);
    let mut code = Code::default();
    for i in 0..params.len() as u32 {
        code = code.get(i);
    }
    let run = b.func(t, &[], code.call(f).end());
    b.export("run", run);
    b.memory(1, None);
    b.export_memory("memory");
    let m = b.load();
    let mut l = Linker::new();
    l.wasi_preview1(config).unwrap();
    let mut s = Store::new((), InstanceLimits::default());
    let inst = l.instantiate(&mut s, &m, &Budget::unlimited()).unwrap();
    let mem = s.export(inst, "memory").unwrap().memory().unwrap();
    Wasi { s, inst, mem }
}

impl Wasi {
    fn call(&mut self, args: &[Value], budget: &Budget) -> Result<Vec<Value>, Trap> {
        let f = self.s.export_func(self.inst, "run").unwrap();
        let mut out: Vec<Value> = self
            .s
            .func_type(f)
            .results()
            .iter()
            .map(|&t| Value::default_of(t))
            .collect();
        self.s.call(f, args, &mut out, budget)?;
        Ok(out)
    }

    /// Calls it with i32 arguments, for its errno.
    fn errno(&mut self, args: &[i32]) -> i32 {
        let args: Vec<Value> = args.iter().map(|&a| Value::I32(a)).collect();
        self.call(&args, &Budget::fuel(1_000_000)).unwrap()[0]
            .i32()
            .unwrap()
    }

    fn mem(&self) -> &[u8] {
        self.s.memory_data(self.mem)
    }

    fn mem_mut(&mut self) -> &mut [u8] {
        self.s.memory_data_mut(self.mem)
    }

    fn u32_at(&self, at: usize) -> u32 {
        u32::from_le_bytes(self.mem()[at..at + 4].try_into().unwrap())
    }

    fn u64_at(&self, at: usize) -> u64 {
        u64::from_le_bytes(self.mem()[at..at + 8].try_into().unwrap())
    }
}

#[test]
fn every_function_of_preview_1_is_defined() {
    let mut l = Linker::<()>::new();
    l.wasi_preview1(WasiConfig::new()).unwrap();
    let names = [
        "args_get",
        "args_sizes_get",
        "environ_get",
        "environ_sizes_get",
        "clock_res_get",
        "clock_time_get",
        "fd_advise",
        "fd_allocate",
        "fd_close",
        "fd_datasync",
        "fd_fdstat_get",
        "fd_fdstat_set_flags",
        "fd_fdstat_set_rights",
        "fd_filestat_get",
        "fd_filestat_set_size",
        "fd_filestat_set_times",
        "fd_pread",
        "fd_prestat_get",
        "fd_prestat_dir_name",
        "fd_pwrite",
        "fd_read",
        "fd_readdir",
        "fd_renumber",
        "fd_seek",
        "fd_sync",
        "fd_tell",
        "fd_write",
        "path_create_directory",
        "path_filestat_get",
        "path_filestat_set_times",
        "path_link",
        "path_open",
        "path_readlink",
        "path_remove_directory",
        "path_rename",
        "path_symlink",
        "path_unlink_file",
        "poll_oneoff",
        "proc_exit",
        "proc_raise",
        "sched_yield",
        "random_get",
        "sock_accept",
        "sock_recv",
        "sock_send",
        "sock_shutdown",
    ];
    assert_eq!(names.len(), 46);
    for n in names {
        let ty = l
            .func_type(wasi::MODULE, n)
            .unwrap_or_else(|| panic!("{n}"));
        let want: &[ValType] = if n == "proc_exit" {
            &[]
        } else {
            &[ValType::I32]
        };
        assert_eq!(ty.results(), want, "{n}");
    }
    assert_eq!(
        l.func_type(wasi::MODULE, "clock_time_get")
            .unwrap()
            .params(),
        [ValType::I32, ValType::I64, ValType::I32]
    );
    // Defining it twice is refused.
    assert!(l.wasi_preview1(WasiConfig::new()).is_err());
}

#[test]
fn arguments_and_environment() {
    let cfg = || {
        WasiConfig::new()
            .arg("plugin")
            .arg("-v")
            .env("A", "1")
            .env("LONG", "xyz")
    };
    let mut w = wasi("args_sizes_get", &[I32, I32], &[I32], cfg());
    assert_eq!(w.errno(&[0, 4]), 0);
    assert_eq!((w.u32_at(0), w.u32_at(4)), (2, 7 + 3));
    let mut w = wasi("args_get", &[I32, I32], &[I32], cfg());
    assert_eq!(w.errno(&[0, 100]), 0);
    assert_eq!((w.u32_at(0), w.u32_at(4)), (100, 107));
    assert_eq!(&w.mem()[100..110], b"plugin\0-v\0");
    let mut w = wasi("environ_sizes_get", &[I32, I32], &[I32], cfg());
    assert_eq!(w.errno(&[0, 4]), 0);
    assert_eq!((w.u32_at(0), w.u32_at(4)), (2, 4 + 9));
    let mut w = wasi("environ_get", &[I32, I32], &[I32], cfg());
    assert_eq!(w.errno(&[0, 100]), 0);
    assert_eq!(&w.mem()[100..113], b"A=1\0LONG=xyz\0");
    // None by default.
    let mut w = wasi("args_sizes_get", &[I32, I32], &[I32], WasiConfig::new());
    w.mem_mut()[..8].fill(0xff);
    assert_eq!(w.errno(&[0, 4]), 0);
    assert_eq!((w.u32_at(0), w.u32_at(4)), (0, 0));
    // A pointer outside the memory is the guest's error, not a trap.
    let mut w = wasi("args_get", &[I32, I32], &[I32], cfg());
    assert_eq!(w.errno(&[0, 65_536 - 5]), EFAULT);
    assert_eq!(w.errno(&[-1, 100]), EFAULT);
    assert!(!w.s.ended());
}

#[test]
fn clocks() {
    let mut w = wasi(
        "clock_time_get",
        &[I32, I64, I32],
        &[I32],
        WasiConfig::new(),
    );
    let mut call = |clock: i32| {
        let r = w.call(
            &[Value::I32(clock), Value::I64(1), Value::I32(8)],
            &Budget::unlimited(),
        );
        (r.unwrap()[0].i32().unwrap(), w.u64_at(8))
    };
    let (e, t) = call(0);
    assert_eq!(e, 0);
    let wall = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    assert!(wall.as_nanos() as u64 - t < 5_000_000_000, "{t}");
    let (e, t1) = call(1);
    assert_eq!(e, 0);
    assert!(t1 > 0);
    std::thread::sleep(Duration::from_millis(2));
    let (_, t2) = call(1);
    assert!(t2 >= t1 + 2_000_000, "{t1} {t2}");
    // Process and thread CPU time, and anything else, are not there.
    assert_eq!(call(2).0, EINVAL);
    assert_eq!(call(3).0, EINVAL);
    assert_eq!(call(99).0, EINVAL);

    let mut w = wasi("clock_res_get", &[I32, I32], &[I32], WasiConfig::new());
    assert_eq!(w.errno(&[1, 16]), 0);
    assert_eq!(w.u64_at(16), 1);
    assert_eq!(w.errno(&[7, 16]), EINVAL);
    assert_eq!(w.errno(&[0, 65_535]), EFAULT);
}

#[test]
fn random_bytes() {
    let mut w = wasi("random_get", &[I32, I32], &[I32], WasiConfig::new());
    assert_eq!(w.errno(&[1000, 4096]), 0);
    let a = w.mem()[1000..5096].to_vec();
    assert!(a.iter().filter(|&&b| b == 0).count() < 100);
    assert_eq!(w.errno(&[1000, 4096]), 0);
    assert_ne!(a, w.mem()[1000..5096]);
    assert!(w.s.fuel_used() >= 64, "charged by the byte");
    assert_eq!(w.errno(&[65_000, 1000]), EFAULT);
    assert_eq!(w.errno(&[0, 0]), 0);
}

#[test]
fn standard_output_and_error_go_to_the_sink() {
    let out = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&out);
    let cfg = WasiConfig::new().output(move |s, b| sink.lock().unwrap().push((s, b.to_vec())));
    let mut w = wasi("fd_write", &[I32, I32, I32, I32], &[I32], cfg);
    // Two buffers, "hello " at 100 and "world" at 200; an empty one between.
    w.mem_mut()[100..106].copy_from_slice(b"hello ");
    w.mem_mut()[200..205].copy_from_slice(b"world");
    for (k, (p, n)) in [(100u32, 6u32), (300, 0), (200, 5)].into_iter().enumerate() {
        w.mem_mut()[16 + k * 8..20 + k * 8].copy_from_slice(&p.to_le_bytes());
        w.mem_mut()[20 + k * 8..24 + k * 8].copy_from_slice(&n.to_le_bytes());
    }
    assert_eq!(w.errno(&[1, 16, 3, 8]), 0);
    assert_eq!(w.u32_at(8), 11);
    assert_eq!(w.errno(&[2, 32, 1, 8]), 0);
    assert_eq!(w.u32_at(8), 5);
    assert_eq!(
        *out.lock().unwrap(),
        [
            (OutputStream::Stdout, b"hello ".to_vec()),
            (OutputStream::Stdout, b"world".to_vec()),
            (OutputStream::Stderr, b"world".to_vec()),
        ]
    );
    // No other file descriptor; a buffer outside the memory, or an iovec array, is EFAULT.
    assert_eq!(w.errno(&[0, 16, 1, 8]), EBADF);
    assert_eq!(w.errno(&[3, 16, 1, 8]), EBADF);
    w.mem_mut()[16..20].copy_from_slice(&65_533u32.to_le_bytes()); // 6 bytes from there pass the end
    assert_eq!(w.errno(&[1, 16, 1, 8]), EFAULT);
    assert_eq!(w.errno(&[1, 65_532, 1, 8]), EFAULT);
    assert_eq!(w.errno(&[1, 16, 1 << 30, 8]), EFAULT);
    assert_eq!(out.lock().unwrap().len(), 3);
    // Discarded by default.
    let mut w = wasi("fd_write", &[I32, I32, I32, I32], &[I32], WasiConfig::new());
    w.mem_mut()[20..24].copy_from_slice(&5u32.to_le_bytes());
    assert_eq!(w.errno(&[1, 16, 1, 8]), 0);
    assert_eq!(w.u32_at(8), 5);
}

#[test]
fn standard_streams_and_no_files() {
    let mut w = wasi("fd_read", &[I32, I32, I32, I32], &[I32], WasiConfig::new());
    w.mem_mut()[8..12].fill(0xff);
    assert_eq!(w.errno(&[0, 16, 1, 8]), 0);
    assert_eq!(w.u32_at(8), 0, "standard input is empty");
    assert_eq!(w.errno(&[1, 16, 1, 8]), EBADF);
    assert_eq!(w.errno(&[5, 16, 1, 8]), EBADF);

    let mut w = wasi("fd_fdstat_get", &[I32, I32], &[I32], WasiConfig::new());
    assert_eq!(w.errno(&[1, 16]), 0);
    assert_eq!(w.mem()[16], 2, "a character device");
    assert_eq!(w.u64_at(24), (1 << 6) | (1 << 27), "write and poll");
    assert_eq!(w.errno(&[0, 16]), 0);
    assert_eq!(w.u64_at(24), (1 << 1) | (1 << 27), "read and poll");
    assert_eq!(w.errno(&[3, 16]), EBADF);

    let mut w = wasi("fd_filestat_get", &[I32, I32], &[I32], WasiConfig::new());
    assert_eq!(w.errno(&[2, 64]), 0);
    assert_eq!(w.mem()[64 + 16], 2);
    assert_eq!(w.errno(&[3, 64]), EBADF);

    for (name, params, args, want) in [
        ("fd_close", &[I32][..], &[1][..], 0),
        ("fd_close", &[I32], &[3], EBADF),
        ("fd_fdstat_set_flags", &[I32, I32], &[1, 4], 0),
        ("fd_fdstat_set_flags", &[I32, I32], &[9, 4], EBADF),
        ("fd_tell", &[I32, I32], &[1, 8], ESPIPE),
        ("fd_tell", &[I32, I32], &[4, 8], EBADF),
        // No preopened directory: what WASI's libc looks for at start, and so no path works.
        ("fd_prestat_get", &[I32, I32], &[3, 8], EBADF),
        ("fd_prestat_dir_name", &[I32, I32, I32], &[3, 8, 8], EBADF),
        ("path_create_directory", &[I32, I32, I32], &[3, 8, 1], EBADF),
        ("fd_sync", &[I32], &[1], EBADF),
        ("sock_shutdown", &[I32, I32], &[3, 0], ENOSYS),
        ("proc_raise", &[I32], &[9], ENOSYS),
        ("sched_yield", &[], &[], 0),
    ] {
        let mut w = wasi(name, params, &[I32], WasiConfig::new());
        assert_eq!(w.errno(args), want, "{name}");
    }

    // With i64 parameters.
    let mut w = wasi("fd_seek", &[I32, I64, I32, I32], &[I32], WasiConfig::new());
    let seek = |w: &mut Wasi, fd| {
        let args = [Value::I32(fd), Value::I64(0), Value::I32(0), Value::I32(8)];
        w.call(&args, &Budget::unlimited()).unwrap()[0]
    };
    assert_eq!(seek(&mut w, 1), Value::I32(ESPIPE));
    assert_eq!(seek(&mut w, 3), Value::I32(EBADF));
    let mut w = wasi(
        "path_open",
        &[I32, I32, I32, I32, I32, I64, I64, I32, I32],
        &[I32],
        WasiConfig::new(),
    );
    let args = [3, 0, 100, 5, 0]
        .map(Value::I32)
        .into_iter()
        .chain([Value::I64(-1), Value::I64(-1), Value::I32(0), Value::I32(8)])
        .collect::<Vec<_>>();
    assert_eq!(
        w.call(&args, &Budget::unlimited()).unwrap(),
        [Value::I32(EBADF)]
    );
}

#[test]
fn proc_exit_ends_the_store_with_its_code() {
    let mut w = wasi("proc_exit", &[I32], &[], WasiConfig::new());
    assert_eq!(
        w.call(&[Value::I32(3)], &Budget::unlimited()),
        Err(Trap::Exit(3))
    );
    assert!(w.s.ended());
    assert_eq!(Trap::Exit(3).to_string(), "wasm exited with code 3");
}

/// Writes a clock subscription at `at`: userdata, clock, timeout, flags.
fn clock_sub(w: &mut Wasi, at: usize, userdata: u64, clock: u32, timeout: u64, flags: u16) {
    let s = &mut w.mem_mut()[at..at + 48];
    s.fill(0);
    s[0..8].copy_from_slice(&userdata.to_le_bytes());
    s[8] = 0;
    s[16..20].copy_from_slice(&clock.to_le_bytes());
    s[24..32].copy_from_slice(&timeout.to_le_bytes());
    s[40..42].copy_from_slice(&flags.to_le_bytes());
}

fn fd_sub(w: &mut Wasi, at: usize, userdata: u64, kind: u8, fd: u32) {
    let s = &mut w.mem_mut()[at..at + 48];
    s.fill(0);
    s[0..8].copy_from_slice(&userdata.to_le_bytes());
    s[8] = kind;
    s[16..20].copy_from_slice(&fd.to_le_bytes());
}

/// The events at 1024: (userdata, error, type).
fn events(w: &Wasi) -> Vec<(u64, u16, u8)> {
    (0..w.u32_at(8) as usize)
        .map(|k| {
            let e = 1024 + k * 32;
            (
                w.u64_at(e),
                u16::from_le_bytes([w.mem()[e + 8], w.mem()[e + 9]]),
                w.mem()[e + 10],
            )
        })
        .collect()
}

fn poll(w: &mut Wasi, n: i32, budget: &Budget) -> Result<i32, Trap> {
    let args = [64, 1024, n, 8].map(Value::I32);
    Ok(w.call(&args, budget)?[0].i32().unwrap())
}

#[test]
fn poll_oneoff_sleeps_on_clocks() {
    let mut w = wasi(
        "poll_oneoff",
        &[I32, I32, I32, I32],
        &[I32],
        WasiConfig::new(),
    );
    // Two relative timeouts: 20 ms and 1 s; the first fires.
    clock_sub(&mut w, 64, 7, 1, 20_000_000, 0);
    clock_sub(&mut w, 112, 8, 1, 1_000_000_000, 0);
    let start = Instant::now();
    assert_eq!(poll(&mut w, 2, &Budget::unlimited()), Ok(0));
    let took = start.elapsed();
    assert!(took >= Duration::from_millis(20), "{took:?}");
    assert!(took < Duration::from_millis(900), "{took:?}");
    assert_eq!(events(&w), [(7, 0, 0)]);

    // An absolute timeout on the realtime clock, already past: at once.
    clock_sub(&mut w, 64, 9, 0, 1, 1);
    assert_eq!(poll(&mut w, 1, &Budget::unlimited()), Ok(0));
    assert_eq!(events(&w), [(9, 0, 0)]);

    // A standard stream is ready at once, beside a clock that is not waited for.
    clock_sub(&mut w, 64, 1, 1, 10_000_000_000, 0);
    fd_sub(&mut w, 112, 2, 2, 1);
    fd_sub(&mut w, 160, 3, 1, 0);
    fd_sub(&mut w, 208, 4, 1, 5);
    let start = Instant::now();
    assert_eq!(poll(&mut w, 4, &Budget::unlimited()), Ok(0));
    assert!(start.elapsed() < Duration::from_secs(1));
    assert_eq!(events(&w), [(2, 0, 2), (3, 0, 1), (4, EBADF as u16, 1)]);

    // An unknown clock is that subscription's error; no subscription, or an unknown kind,
    // the call's.
    clock_sub(&mut w, 64, 5, 42, 10, 0);
    assert_eq!(poll(&mut w, 1, &Budget::unlimited()), Ok(0));
    assert_eq!(events(&w), [(5, EINVAL as u16, 0)]);
    assert_eq!(poll(&mut w, 0, &Budget::unlimited()), Ok(EINVAL));
    fd_sub(&mut w, 64, 5, 9, 0);
    assert_eq!(poll(&mut w, 1, &Budget::unlimited()), Ok(EINVAL));
    // Subscriptions or events past the memory's end.
    assert_eq!(poll(&mut w, 1400, &Budget::unlimited()), Ok(EFAULT));
}

#[test]
fn poll_oneoff_wakes_at_the_deadline_and_the_interrupt() {
    let mut w = wasi(
        "poll_oneoff",
        &[I32, I32, I32, I32],
        &[I32],
        WasiConfig::new(),
    );
    // A 60 s sleep, under a 30 ms deadline: it wakes then, and the call stops after it.
    clock_sub(&mut w, 64, 7, 1, 60_000_000_000, 0);
    let start = Instant::now();
    let r = poll(
        &mut w,
        1,
        &Budget::deadline(start + Duration::from_millis(30)),
    );
    let took = start.elapsed();
    assert!(took >= Duration::from_millis(30), "{took:?}");
    assert!(took < Duration::from_secs(5), "{took:?}");
    // The host function returns at the deadline; the guest's next check stops it.
    assert!(matches!(r, Ok(0) | Err(Trap::Deadline)), "{r:?}");

    let mut w = wasi(
        "poll_oneoff",
        &[I32, I32, I32, I32],
        &[I32],
        WasiConfig::new(),
    );
    clock_sub(&mut w, 64, 7, 1, 60_000_000_000, 0);
    let stop = InterruptHandle::new();
    let raise = stop.clone();
    let t = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(30));
        raise.interrupt();
    });
    let start = Instant::now();
    let r = poll(&mut w, 1, &Budget::unlimited().with_interrupt(&stop));
    assert!(start.elapsed() < Duration::from_secs(5));
    assert!(matches!(r, Ok(0) | Err(Trap::Interrupted)), "{r:?}");
    t.join().unwrap();
}

#[test]
fn a_go_style_sleep_loop_stops_at_the_deadline() {
    // A guest that sleeps 1 ms at a time, forever: the call stops at its deadline.
    let mut b = Builder::default();
    let t = b.ty(&[I32, I32, I32, I32], &[I32]);
    let poll = b.import_func(wasi::MODULE, "poll_oneoff", t);
    let run_t = b.ty(&[], &[]);
    let run = b.func(
        run_t,
        &[],
        Code::default()
            .op(&[0x03, 0x40]) // loop
            .i32c(64)
            .i32c(1024)
            .i32c(1)
            .i32c(8)
            .call(poll)
            .op(&[0x1a]) // drop
            .op(&[0x0c, 0, 0x0b]) // br 0 end
            .end(),
    );
    b.export("run", run);
    b.memory(1, None);
    b.export_memory("memory");
    let m = b.load();
    let mut l = Linker::new();
    l.wasi_preview1(WasiConfig::new()).unwrap();
    let mut s = Store::new((), InstanceLimits::default());
    let inst = l.instantiate(&mut s, &m, &Budget::unlimited()).unwrap();
    let mem = s.export(inst, "memory").unwrap().memory().unwrap();
    let mut w = Wasi { s, inst, mem };
    clock_sub(&mut w, 64, 1, 1, 1_000_000, 0);
    let start = Instant::now();
    let r = w.call(&[], &Budget::deadline(start + Duration::from_millis(50)));
    assert_eq!(r, Err(Trap::Deadline));
    assert!(start.elapsed() < Duration::from_secs(5));
}

#[test]
fn wasi_functions_are_charged_to_the_call() {
    let mut w = wasi("random_get", &[I32, I32], &[I32], WasiConfig::new());
    let r = w.call(&[Value::I32(0), Value::I32(65_536)], &Budget::fuel(500));
    assert_eq!(r, Err(Trap::OutOfFuel));
}

#[test]
fn wasi_coexists_with_the_hosts_functions() {
    let mut l = Linker::<()>::new();
    l.wasi_preview1(WasiConfig::new())
        .unwrap()
        .func_wrap("env", "f", |_: &mut Caller<'_, ()>, (): ()| Ok(()))
        .unwrap();
    assert!(l.func_type("env", "f").is_some());
    assert!(l.func_type(wasi::MODULE, "fd_write").is_some());
}
