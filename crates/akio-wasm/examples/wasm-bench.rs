//! What a guest call costs (ADR-125, W5; akit's A180): a call on a warm instance, split into its
//! parts, and the pool's hand-off.
//!
//! ```text
//! cargo run --release -p akio-wasm --example wasm-bench -- [scenario ...] [--secs S]
//! ```
//!
//! Scenarios (all by default):
//!
//! - `headers`: fit's `headers` plugin (a Go `wasip1` guest, `tests/guests/headers-go.wasm.gz`)
//!   called on one warm instance with fit's ABI, as akit calls it: `fit_on_request` for `/a`,
//!   which sets and deletes request fields and adds three response fields. The same call as fit's
//!   `BenchmarkGuestCall` (wazero), without the pool.
//! - `entry`: an export that returns a constant: entering and leaving the guest.
//! - `host`: a guest loop calling an imported `(i32, i32) -> i32` host function 1,000 times a
//!   call: a host call's cost, its loop subtracted (`loop`).
//! - `loop`: a guest loop of 1,000 iterations of six instructions: the interpreter's dispatch,
//!   per WebAssembly instruction.
//! - `pool`: `headers` through an [`InstancePool`] of one instance, one job at a time, from
//!   `submit` to its completion: the call plus the hand-off and the wake-up.
//!
//! Each scenario runs for `--secs` (1 s) after a warm-up, and prints the mean time a call and,
//! for the guests, the WebAssembly instructions a call.

#[path = "../tests/common/mod.rs"]
mod common;

use std::{
    path::Path,
    sync::{Arc, mpsc},
    time::{Duration, Instant},
};

use akio_wasm::{
    Budget, Caller, InstanceLimits, InstancePool, InterruptHandle, Linker, Module, ModuleLimits,
    PoolConfig, Store, Trap, TypedFunc, WasiConfig,
};
use common::{Builder, Code, I32};

/// One request, as fit's ABI sees it.
#[derive(Default)]
struct Host {
    method: String,
    path: String,
    config: Vec<u8>,
    request: Vec<(String, String)>,
    /// (op, name, value): op 0 set, 1 add, 2 del.
    response: Vec<(u32, String, String)>,
    status: u32,
    body: Vec<u8>,
}

impl Host {
    fn reset(&mut self) {
        self.request.clear();
        self.request.push(("X-Secret".into(), "s3cret".into()));
        self.request.push(("User-Agent".into(), "bench".into()));
        self.response.clear();
        self.status = 0;
        self.body.clear();
    }
}

fn new_host() -> Host {
    let mut h = Host {
        method: "GET".into(),
        path: "/a".into(),
        config: b"c".to_vec(),
        ..Host::default()
    };
    h.reset();
    h
}

fn field(c: &Caller<'_, Host>, ptr: u32, len: u32) -> Result<String, Trap> {
    Ok(String::from_utf8_lossy(c.read(ptr, len)?).into_owned())
}

fn give(c: &mut Caller<'_, Host>, buf: u32, cap: u32, v: &[u8]) -> Result<i32, Trap> {
    let n = v.len().min(cap as usize);
    c.write(buf, &v[..n])?;
    Ok(v.len() as i32)
}

/// WASI, and fit's ABI as the tests' linker has it (`tests/guests.rs`).
fn linker() -> Linker<Host> {
    type C<'a, 'b> = &'a mut Caller<'b, Host>;
    let mut l = Linker::new();
    l.wasi_preview1(WasiConfig::new().output(|_, _| {}))
        .unwrap()
        .trap_unresolved(true);
    l.func_wrap(
        "fit",
        "header_get",
        |c: C<'_, '_>, (kind, np, nl, buf, cap): (u32, u32, u32, u32, u32)| {
            let name = field(c, np, nl)?;
            let v = if kind == 0 {
                c.state()
                    .request
                    .iter()
                    .find(|(n, _)| n.eq_ignore_ascii_case(&name))
                    .map(|(_, v)| v.clone())
            } else {
                None
            };
            match v {
                Some(v) => give(c, buf, cap, v.as_bytes()),
                None => Ok(-1),
            }
        },
    )
    .unwrap();
    for (name, op) in [("header_set", 0), ("header_add", 1)] {
        l.func_wrap(
            "fit",
            name,
            move |c: C<'_, '_>, (kind, np, nl, vp, vl): (u32, u32, u32, u32, u32)| {
                let (n, v) = (field(c, np, nl)?, field(c, vp, vl)?);
                let h = c.state_mut();
                if kind == 0 {
                    if op == 0 {
                        h.request.retain(|(x, _)| !x.eq_ignore_ascii_case(&n));
                    }
                    h.request.push((n, v));
                } else {
                    h.response.push((op, n, v));
                }
                Ok(())
            },
        )
        .unwrap();
    }
    l.func_wrap(
        "fit",
        "header_del",
        |c: C<'_, '_>, (kind, np, nl): (u32, u32, u32)| {
            let n = field(c, np, nl)?;
            let h = c.state_mut();
            if kind == 0 {
                h.request.retain(|(x, _)| !x.eq_ignore_ascii_case(&n));
            } else {
                h.response.push((2, n, String::new()));
            }
            Ok(())
        },
    )
    .unwrap();
    l.func_wrap(
        "fit",
        "request_get",
        |c: C<'_, '_>, (f, buf, cap): (u32, u32, u32)| {
            let h = c.state();
            let v: &[u8] = match f {
                0 => h.method.as_bytes(),
                1 => h.path.as_bytes(),
                5 => &h.config,
                2..=4 => &[],
                _ => return Ok(-1),
            };
            let v = v.to_vec();
            give(c, buf, cap, &v)
        },
    )
    .unwrap();
    l.func_wrap(
        "fit",
        "respond",
        |c: C<'_, '_>, (status, p, n): (u32, u32, u32)| {
            let body = c.read(p, n)?.to_vec();
            let h = c.state_mut();
            h.status = status;
            h.body = body;
            Ok(())
        },
    )
    .unwrap();
    l.func_wrap(
        "fit",
        "log",
        |c: C<'_, '_>, (_level, p, n): (i32, u32, u32)| {
            c.read(p, n)?;
            Ok(())
        },
    )
    .unwrap();
    l
}

fn headers_module() -> Arc<Module> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/guests/headers-go.wasm.gz");
    let gz = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let bytes = akio_deflate::decompress(akio_deflate::Format::Gzip, &gz, 64 << 20).unwrap();
    Arc::new(Module::new(&bytes, &ModuleLimits::default()).unwrap())
}

/// The pool's budget for one job: a deadline and an interrupt.
fn job_budget(stop: &InterruptHandle) -> Budget {
    Budget::deadline(Instant::now() + Duration::from_millis(100)).with_interrupt(stop)
}

/// Runs `f` for `secs` after a warm-up of a tenth of it; the mean time a run, and the runs.
fn time(secs: f64, mut f: impl FnMut()) -> (Duration, u64) {
    let warm = Instant::now();
    while warm.elapsed().as_secs_f64() < secs / 10.0 {
        f();
    }
    let mut n = 0u64;
    let start = Instant::now();
    let mut batch = 1u64;
    loop {
        for _ in 0..batch {
            f();
        }
        n += batch;
        let e = start.elapsed();
        if e.as_secs_f64() >= secs {
            return (e / u32::try_from(n).unwrap_or(u32::MAX), n);
        }
        batch = (batch * 2).min(1 << 14);
    }
}

fn report(name: &str, per: Duration, runs: u64, extra: &str) {
    println!(
        "{name:<10} {:>10.1} ns a call  ({runs} calls){extra}",
        per.as_nanos() as f64
    );
}

fn headers(secs: f64) {
    let m = headers_module();
    let mut s = Store::new(new_host(), InstanceLimits::default());
    let inst = linker()
        .instantiate(&mut s, &m, &Budget::unlimited())
        .unwrap();
    s.initialize_reactor(inst, &Budget::unlimited()).unwrap();
    let f: TypedFunc<(), i32> = s
        .typed_func(s.export_func(inst, "fit_on_request").unwrap())
        .unwrap();
    let stop = InterruptHandle::new();
    let (per, runs) = time(secs, || {
        s.state_mut().reset();
        assert_eq!(f.call(&mut s, (), &job_budget(&stop)), Ok(0));
    });
    assert_eq!(s.state().response.len(), 3);
    let fuel = s.fuel_used();
    report(
        "headers",
        per,
        runs,
        &format!(
            ", {fuel} instructions, {:.2} ns an instruction",
            per.as_nanos() as f64 / fuel as f64
        ),
    );
}

fn tiny(secs: f64) {
    // entry: () -> i32 { 7 }
    // loop: (n) -> i32 { i = n; acc = 0; do { acc += i; i -= 1 } while i != 0; acc }
    // host: (n) -> i32 { i = n; do { acc = h(acc, i); i -= 1 } while i != 0; acc }
    let mut b = Builder::default();
    let t2 = b.ty(&[I32, I32], &[I32]);
    let h = b.import_func("bench", "h", t2);
    let t0 = b.ty(&[], &[I32]);
    let t1 = b.ty(&[I32], &[I32]);
    let entry = b.func(t0, &[], Code::default().i32c(7).end());
    b.export("entry", entry);
    let body = |host: bool| {
        let c = Code::default().op(&[0x03, 0x40]); // loop
        let c = if host {
            c.get(1).get(0).call(h).set(1)
        } else {
            c.get(1).get(0).op(&[0x6a]).set(1) // acc = acc + i
        };
        c.get(0)
            .i32c(1)
            .op(&[0x6b]) // i - 1
            .tee(0)
            .op(&[0x0d, 0x00]) // br_if 0
            .op(&[0x0b]) // end loop
            .get(1)
            .end()
    };
    let lp = b.func(t1, &[(1, I32)], body(false));
    b.export("loop", lp);
    let hp = b.func(t1, &[(1, I32)], body(true));
    b.export("host", hp);
    let m = b.load();

    let mut l: Linker<()> = Linker::new();
    l.func_wrap(
        "bench",
        "h",
        |_: &mut Caller<'_, ()>, (a, b): (i32, i32)| Ok(a.wrapping_add(b)),
    )
    .unwrap();
    let mut s = Store::new((), InstanceLimits::default());
    let inst = l.instantiate(&mut s, &m, &Budget::unlimited()).unwrap();
    let stop = InterruptHandle::new();
    let entry: TypedFunc<(), i32> = s.typed_func(s.export_func(inst, "entry").unwrap()).unwrap();
    let (per, runs) = time(secs, || {
        assert_eq!(entry.call(&mut s, (), &job_budget(&stop)), Ok(7));
    });
    report("entry", per, runs, "");

    const N: i32 = 1000;
    let lp: TypedFunc<i32, i32> = s.typed_func(s.export_func(inst, "loop").unwrap()).unwrap();
    let (loop_per, runs) = time(secs, || {
        lp.call(&mut s, N, &job_budget(&stop)).unwrap();
    });
    let fuel = s.fuel_used();
    report(
        "loop",
        loop_per,
        runs,
        &format!(
            ", {fuel} instructions, {:.2} ns an instruction",
            loop_per.saturating_sub(per).as_nanos() as f64 / fuel as f64
        ),
    );

    let hp: TypedFunc<i32, i32> = s.typed_func(s.export_func(inst, "host").unwrap()).unwrap();
    let (host_per, runs) = time(secs, || {
        hp.call(&mut s, N, &job_budget(&stop)).unwrap();
    });
    report(
        "host",
        host_per,
        runs,
        &format!(
            ", {:.1} ns a host call (the loop's cost taken off)",
            host_per.saturating_sub(loop_per).as_nanos() as f64 / f64::from(N)
        ),
    );
}

fn pool(secs: f64) {
    let m = headers_module();
    let mut config = PoolConfig::default();
    config.instances = 1;
    let pool = InstancePool::builder(m, linker(), |_| new_host())
        .config(config)
        .build()
        .unwrap();
    let (tx, rx) = mpsc::channel::<i32>();
    let f = Arc::new(std::sync::OnceLock::<TypedFunc<(), i32>>::new());
    let (per, runs) = time(secs, || {
        let tx = tx.clone();
        let f = Arc::clone(&f);
        let job = move |p: &mut akio_wasm::Pooled<Host>| {
            let f = *f.get_or_init(|| p.typed_func("fit_on_request").unwrap());
            p.state_mut().reset();
            p.call_typed(f, ()).unwrap()
        };
        let done = move |r: Result<i32, akio_wasm::JobError>| {
            tx.send(r.unwrap()).unwrap();
        };
        assert!(pool.submit(job, done).is_ok());
        assert_eq!(rx.recv().unwrap(), 0);
    });
    report("pool", per, runs, ", submit to completion, one at a time");
}

fn main() {
    let mut secs = 1.0;
    let mut which = Vec::new();
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        if a == "--secs" {
            secs = args.next().and_then(|s| s.parse().ok()).expect("--secs S");
        } else {
            which.push(a);
        }
    }
    let all = which.is_empty();
    let want = |n: &str| all || which.iter().any(|w| w == n);
    if want("headers") {
        headers(secs);
    }
    if want("entry") || want("loop") || want("host") {
        tiny(secs);
    }
    if want("pool") {
        pool(secs);
    }
}
