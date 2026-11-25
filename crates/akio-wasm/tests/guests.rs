//! fit's guests (ADR-125, section 7): plugins built with Go and Rust (tests/guests, rebuilt by
//! tests/guests/build.sh) load, initialize and run on a test linker that has fit's ABI, its
//! sync modules' ABI and Proxy-Wasm's, each as much as the guest needs; a guest that loops stops
//! at its deadline, one that grows past the memory limit or panics traps, and the instance is
//! made again after each.

use std::{
    path::Path,
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant},
};

use akio_wasm::{
    Budget, Caller, Instance, InstanceLimits, Linker, Module, ModuleLimits, Store, Trap, TypedFunc,
    Value, WasiConfig,
};

/// A guest, inflated and loaded once for all the tests.
fn guest(name: &'static str) -> Arc<Module> {
    static CACHE: [(&str, OnceLock<Arc<Module>>); 3] = [
        ("headers-go", OnceLock::new()),
        ("http_routing-go", OnceLock::new()),
        ("sync-rust", OnceLock::new()),
    ];
    let (_, cell) = CACHE.iter().find(|(n, _)| *n == name).expect(name);
    Arc::clone(cell.get_or_init(|| {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/guests")
            .join(format!("{name}.wasm.gz"));
        let gz = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        let bytes = akio_deflate::decompress(akio_deflate::Format::Gzip, &gz, 64 << 20).unwrap();
        let start = Instant::now();
        let m = Module::new(&bytes, &ModuleLimits::default()).unwrap();
        eprintln!(
            "{name}: {} bytes loaded in {:?}",
            bytes.len(),
            start.elapsed()
        );
        Arc::new(m)
    }))
}

/// What a test host keeps: one request, as fit's ABI sees it, the sync ABI's call, Proxy-Wasm's
/// configuration, and what the guest wrote to standard error and logged.
#[derive(Default)]
struct Host {
    method: String,
    path: String,
    config: Vec<u8>,
    request: Vec<(String, String)>,
    /// The changes to the response's fields: (op, name, value), op 0 set, 1 add, 2 del.
    response: Vec<(u32, String, String)>,
    status: Option<u32>,
    body: Vec<u8>,
    logs: Vec<(i32, String)>,
    // The sync ABI.
    input: Vec<u8>,
    emitted: Vec<(i32, String)>,
    output: Vec<u8>,
    fails: Vec<(i32, String)>,
}

/// A field's name in the canonical form fit gives it (`x-plugin` is `X-Plugin`).
fn canonical(name: &str) -> String {
    let mut up = true;
    name.chars()
        .map(|c| {
            let c = if up {
                c.to_ascii_uppercase()
            } else {
                c.to_ascii_lowercase()
            };
            up = c == '-';
            c
        })
        .collect()
}

const MAX_FIELD: u32 = 64 << 10;

fn field(c: &Caller<'_, Host>, ptr: u32, len: u32) -> Result<String, Trap> {
    if len > MAX_FIELD {
        return Err(Trap::Host("a field longer than 64 KiB".into()));
    }
    Ok(String::from_utf8_lossy(c.read(ptr, len)?).into_owned())
}

/// Writes up to `cap` bytes of `v` at `buf`, and returns `v`'s length, as fit's `write`.
fn give(c: &mut Caller<'_, Host>, buf: u32, cap: u32, v: &[u8]) -> Result<i32, Trap> {
    let n = v.len().min(cap as usize);
    c.write(buf, &v[..n])?;
    Ok(v.len() as i32)
}

/// A linker with WASI (standard error to `stderr`), and fit's, its sync ABI's and Proxy-Wasm's
/// host functions, as much as these guests use; the rest trap if called.
fn linker(stderr: &Arc<Mutex<Vec<u8>>>) -> Linker<Host> {
    let sink = Arc::clone(stderr);
    let mut l = Linker::new();
    l.wasi_preview1(WasiConfig::new().output(move |_, b| {
        let mut s = sink.lock().unwrap();
        if s.len() < 1 << 20 {
            s.extend_from_slice(b);
        }
    }))
    .unwrap()
    .trap_unresolved(true);
    fit_abi(&mut l);
    sync_abi(&mut l);
    proxy_wasm_abi(&mut l);
    l
}

/// fit's ABI (fit's `plugin/wasm/abi.go`).
fn fit_abi(l: &mut Linker<Host>) {
    type C<'a, 'b> = &'a mut Caller<'b, Host>;
    l.func_wrap(
        "fit",
        "header_get",
        |c: C<'_, '_>, (kind, np, nl, buf, cap): (u32, u32, u32, u32, u32)| {
            let name = canonical(&field(c, np, nl)?);
            let v = if kind == 0 {
                c.state()
                    .request
                    .iter()
                    .find(|(n, _)| *n == name)
                    .map(|(_, v)| v.clone())
            } else {
                let mut v = None;
                for (op, n, val) in &c.state().response {
                    if *n == name {
                        match op {
                            0 => v = Some(val.clone()),
                            1 => v = v.or_else(|| Some(val.clone())),
                            _ => v = None,
                        }
                    }
                }
                v
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
                let (n, v) = (canonical(&field(c, np, nl)?), field(c, vp, vl)?);
                let h = c.state_mut();
                if kind == 0 {
                    if op == 0 {
                        h.request.retain(|(x, _)| *x != n);
                    }
                    h.request.push((n, v));
                } else {
                    if h.response.len() == 256 {
                        return Err(Trap::Host("more than 256 changes".into()));
                    }
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
            let n = canonical(&field(c, np, nl)?);
            let h = c.state_mut();
            if kind == 0 {
                h.request.retain(|(x, _)| *x != n);
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
            let v = match f {
                0 => h.method.clone().into_bytes(),
                1 => h.path.clone().into_bytes(),
                5 => h.config.clone(),
                2..=4 => Vec::new(),
                _ => return Ok(-1),
            };
            give(c, buf, cap, &v)
        },
    )
    .unwrap();
    l.func_wrap(
        "fit",
        "respond",
        |c: C<'_, '_>, (status, p, n): (u32, u32, u32)| {
            if !(200..=599).contains(&status) || n > 1 << 20 {
                return Err(Trap::Host("a bad response".into()));
            }
            let body = c.read(p, n)?.to_vec();
            let h = c.state_mut();
            h.status = Some(status);
            h.body = body;
            Ok(())
        },
    )
    .unwrap();
    l.func_wrap(
        "fit",
        "log",
        |c: C<'_, '_>, (level, p, n): (i32, u32, u32)| {
            let msg = field(c, p, n)?;
            c.state_mut().logs.push((level, msg));
            Ok(())
        },
    )
    .unwrap();
}

/// The part of fit's sync ABI (fit's `plugin/wasm/sync.go`) a transform, a decode and an encode
/// use.
fn sync_abi(l: &mut Linker<Host>) {
    type C<'a, 'b> = &'a mut Caller<'b, Host>;
    l.func_wrap(
        "fit_sync",
        "input",
        |c: C<'_, '_>, (buf, cap): (u32, u32)| {
            let input = c.state().input.clone();
            give(c, buf, cap, &input)
        },
    )
    .unwrap();
    l.func_wrap(
        "fit_sync",
        "record_emit",
        |c: C<'_, '_>, (i, p, n): (i32, u32, u32)| {
            let r = String::from_utf8_lossy(c.read(p, n)?).into_owned();
            c.state_mut().emitted.push((i, r));
            Ok(())
        },
    )
    .unwrap();
    l.func_wrap("fit_sync", "output", |c: C<'_, '_>, (p, n): (u32, u32)| {
        let b = c.read(p, n)?.to_vec();
        c.state_mut().output.extend(b);
        Ok(())
    })
    .unwrap();
    l.func_wrap(
        "fit_sync",
        "fail",
        |c: C<'_, '_>, (i, p, n): (i32, u32, u32)| {
            let msg = field(c, p, n)?;
            c.state_mut().fails.push((i, msg));
            Ok(())
        },
    )
    .unwrap();
}

const PW_OK: i32 = 0;
const PW_NOT_FOUND: i32 = 1;

/// Hands `data` to a Proxy-Wasm guest: memory from its `proxy_on_memory_allocate`, called from
/// the host function, with the pointer and size written where it asked (fit's `give`).
fn pw_give(c: &mut Caller<'_, Host>, data: &[u8], ptr_at: u32, size_at: u32) -> Result<i32, Trap> {
    let mut p = 0;
    if !data.is_empty() {
        let alloc = c
            .export("proxy_on_memory_allocate")
            .and_then(|e| e.func())
            .ok_or_else(|| Trap::Host("no proxy_on_memory_allocate".into()))?;
        let mut out = [Value::I32(0)];
        c.call(alloc, &[Value::I32(data.len() as i32)], &mut out)?;
        p = out[0].i32().unwrap_or(0) as u32;
        c.write(p, data)?;
    }
    c.write_u32(ptr_at, p)?;
    c.write_u32(size_at, data.len() as u32)?;
    Ok(PW_OK)
}

/// The part of Proxy-Wasm's ABI (fit's `plugin/wasm/proxywasm.go`) `http_routing` uses.
fn proxy_wasm_abi(l: &mut Linker<Host>) {
    type C<'a, 'b> = &'a mut Caller<'b, Host>;
    l.func_wrap(
        "env",
        "proxy_log",
        |c: C<'_, '_>, (level, p, n): (i32, u32, u32)| {
            let msg = field(c, p, n)?;
            c.state_mut().logs.push((level, msg));
            Ok(PW_OK)
        },
    )
    .unwrap();
    l.func_wrap(
        "env",
        "proxy_set_effective_context",
        |_: C<'_, '_>, _: i32| Ok(PW_OK),
    )
    .unwrap();
    l.func_wrap(
        "env",
        "proxy_get_buffer_bytes",
        |c: C<'_, '_>, (kind, start, size, ptr_at, size_at): (u32, u32, u32, u32, u32)| {
            // 7: the plugin's configuration.
            if kind != 7 {
                return Ok(PW_NOT_FOUND);
            }
            let cfg = c.state().config.clone();
            let s = (start as usize).min(cfg.len());
            let e = s.saturating_add(size as usize).min(cfg.len());
            pw_give(c, &cfg[s..e], ptr_at, size_at)
        },
    )
    .unwrap();
    l.func_wrap(
        "env",
        "proxy_get_header_map_value",
        |c: C<'_, '_>, (map, kp, kn, ptr_at, size_at): (u32, u32, u32, u32, u32)| {
            let k = field(c, kp, kn)?;
            let v = c
                .state()
                .request
                .iter()
                .find(|(n, _)| map == 0 && n.eq_ignore_ascii_case(&k))
                .map(|(_, v)| v.clone());
            match v {
                Some(v) => pw_give(c, v.as_bytes(), ptr_at, size_at),
                None => Ok(PW_NOT_FOUND),
            }
        },
    )
    .unwrap();
    l.func_wrap(
        "env",
        "proxy_replace_header_map_value",
        |c: C<'_, '_>, (map, kp, kn, vp, vn): (u32, u32, u32, u32, u32)| {
            let (k, v) = (field(c, kp, kn)?, field(c, vp, vn)?);
            if map != 0 {
                return Ok(PW_NOT_FOUND);
            }
            let h = c.state_mut();
            h.request.retain(|(n, _)| !n.eq_ignore_ascii_case(&k));
            h.request.push((k, v));
            Ok(PW_OK)
        },
    )
    .unwrap();
}

/// An instance of `module` in a store of its own, initialized as a reactor.
struct Plugin {
    s: Store<Host>,
    inst: Instance,
    stderr: Arc<Mutex<Vec<u8>>>,
}

fn plugin(module: &Arc<Module>, limits: InstanceLimits, host: Host) -> Plugin {
    let stderr = Arc::new(Mutex::new(Vec::new()));
    let l = linker(&stderr);
    let mut s = Store::new(host, limits);
    let inst = l.instantiate(&mut s, module, &Budget::unlimited()).unwrap();
    // fit's init_timeout is 1 s; a debug build of the interpreter is slower.
    let start = Instant::now();
    s.initialize_reactor(inst, &Budget::deadline(start + Duration::from_secs(30)))
        .unwrap();
    eprintln!(
        "initialized in {:?}, {} instructions",
        start.elapsed(),
        s.fuel_used()
    );
    Plugin { s, inst, stderr }
}

impl Plugin {
    fn typed<P: akio_wasm::WasmParams, R: akio_wasm::WasmResults>(
        &self,
        name: &str,
    ) -> TypedFunc<P, R> {
        let f = self.s.export_func(self.inst, name).expect(name);
        self.s.typed_func(f).expect(name)
    }

    fn stderr(&self) -> String {
        String::from_utf8_lossy(&self.stderr.lock().unwrap()).into_owned()
    }
}

fn budget(ms: u64) -> Budget {
    Budget::deadline(Instant::now() + Duration::from_millis(ms))
}

// --- fit's headers plugin, Go. ---

fn request(path: &str) -> Host {
    Host {
        method: "GET".into(),
        path: path.into(),
        config: b"cfg-value".to_vec(),
        request: vec![
            ("X-Secret".into(), "s3cret".into()),
            ("X-Deny".into(), "please".into()),
        ],
        ..Host::default()
    }
}

/// Calls `fit_on_request` on a fresh instance with `host` as the request.
fn on_request(path: &str, limits: InstanceLimits, ms: u64) -> (Plugin, Result<i32, Trap>) {
    let mut p = plugin(&guest("headers-go"), limits, request(path));
    let f = p.typed::<(), i32>("fit_on_request");
    let r = f.call(&mut p.s, (), &budget(ms));
    (p, r)
}

#[test]
fn go_headers_edits_fields() {
    let mut p = plugin(
        &guest("headers-go"),
        InstanceLimits::default(),
        request("/x"),
    );
    let f = p.typed::<(), i32>("fit_on_request");
    // The same instance serves request after request.
    for path in ["/x", "/y"] {
        let h = p.s.state_mut();
        *h = request(path);
        let start = Instant::now();
        assert_eq!(f.call(&mut p.s, (), &budget(10_000)), Ok(0));
        eprintln!(
            "fit_on_request: {:?}, {} instructions",
            start.elapsed(),
            p.s.fuel_used()
        );
        let h = p.s.state();
        assert!(h.request.contains(&("X-Plugin".into(), "cfg-value".into())));
        assert!(!h.request.iter().any(|(n, _)| n == "X-Secret"));
        assert_eq!(
            h.response,
            [
                (0, "X-Served-By".into(), format!("wasm GET {path}")),
                (1, "X-Count".into(), "one".into()),
                (1, "X-Count".into(), "two".into()),
            ]
        );
        assert_eq!(h.status, None);
    }
}

#[test]
fn go_headers_answers_a_request() {
    let (p, r) = on_request("/deny", InstanceLimits::default(), 10_000);
    assert_eq!(r, Ok(1));
    let h = p.s.state();
    assert_eq!(h.status, Some(403));
    assert_eq!(h.body, b"denied: please");
    assert_eq!(h.response, [(0, "X-Denied-By".into(), "plugin".into())]);
}

#[test]
fn go_headers_loop_stops_at_the_deadline() {
    let start = Instant::now();
    let (p, r) = on_request("/loop", InstanceLimits::default(), 100);
    assert_eq!(r, Err(Trap::Deadline));
    assert!(p.s.ended());
    eprintln!("stopped {:?} after the call started", start.elapsed());
    // Made again, it serves the next request.
    let (_, r) = on_request("/x", InstanceLimits::default(), 10_000);
    assert_eq!(r, Ok(0));
}

#[test]
fn go_headers_grow_fails_at_the_memory_limit() {
    let mut limits = InstanceLimits::default();
    limits.max_memory = 32 << 20;
    let (p, r) = on_request("/grow", limits.clone(), 10_000);
    // Go's runtime reports it, then stops at an `unreachable` (a reactor does not exit).
    assert_eq!(r, Err(Trap::Unreachable));
    assert!(p.stderr().contains("out of memory"), "{}", p.stderr());
    assert!(p.s.ended());
    let (_, r) = on_request("/x", limits, 10_000);
    assert_eq!(r, Ok(0));
}

#[test]
fn go_headers_panic_traps() {
    let (p, r) = on_request("/panic", InstanceLimits::default(), 10_000);
    assert_eq!(r, Err(Trap::Unreachable));
    assert!(p.stderr().contains("panic: on purpose"), "{}", p.stderr());
    assert!(p.s.ended());
    let (_, r) = on_request("/x", InstanceLimits::default(), 10_000);
    assert_eq!(r, Ok(0));
}

#[test]
fn go_headers_loads_with_imports_it_does_not_call() {
    // The guest package imports fit's sync ABI too, which this plugin does not use; the test
    // linker leaves most of it out (trap_unresolved). A sync call the plugin registered nothing
    // for fails on its own, through fit_sync.fail.
    let mut p = plugin(
        &guest("headers-go"),
        InstanceLimits::default(),
        Host::default(),
    );
    p.s.state_mut().input = b"{}".to_vec();
    let poll = p.typed::<u32, i32>("fit_sync_poll");
    assert_eq!(poll.call(&mut p.s, 2, &budget(10_000)), Ok(2));
    assert_eq!(
        p.s.state().fails,
        [(-1, "the plugin registered nothing for this call".into())]
    );
}

// --- fit's sync plugin, Rust. ---

fn sync_rust(config: &str, input: &[u8]) -> (Plugin, u32) {
    let host = Host {
        config: config.as_bytes().to_vec(),
        input: input.to_vec(),
        ..Host::default()
    };
    let p = plugin(&guest("sync-rust"), InstanceLimits::default(), host);
    (p, input.len() as u32)
}

#[test]
fn rust_sync_decodes_and_encodes() {
    let (mut p, n) = sync_rust("{}", b"1|apple|2.50\n2|pear|1.00\n");
    let decode = p.typed::<u32, i32>("fit_sync_decode");
    let r = decode.call(&mut p.s, n, &budget(10_000));
    assert_eq!(
        r,
        Ok(0),
        "{:?} {:?} {}",
        p.s.state().fails,
        p.s.state().logs,
        p.stderr()
    );
    let e = &p.s.state().emitted;
    assert_eq!(e.len(), 2, "{e:?}");
    assert!(e[0].1.contains(r#""name":"apple""#), "{e:?}");
    assert!(e[1].1.contains(r#""name":"pear""#), "{e:?}");

    let batch = br#"[{"namespace":"lines","op":"insert","key":{"map":{"id":{"int":1}}},"after":{"map":{"id":{"int":1},"name":"apple","price":{"decimal":"2.50"}}}}]"#;
    let (mut p, n) = sync_rust("{}", batch);
    let encode = p.typed::<u32, i32>("fit_sync_encode");
    let r = encode.call(&mut p.s, n, &budget(10_000));
    assert_eq!(
        r,
        Ok(0),
        "{:?} {:?} {}",
        p.s.state().fails,
        p.s.state().logs,
        p.stderr()
    );
    assert_eq!(
        String::from_utf8_lossy(&p.s.state().output),
        "1|apple|2.50\n"
    );
}

/// Records 1, 2 and 5, in fit's canonical JSON.
const BATCH: &[u8] = br#"[{"namespace":"shop","op":"insert","key":{"map":{"id":{"int":1}}},"after":{"map":{"id":{"int":1}}}},{"namespace":"shop","op":"insert","key":{"map":{"id":{"int":2}}},"after":{"map":{"id":{"int":2}}}},{"namespace":"shop","op":"insert","key":{"map":{"id":{"int":5}}},"after":{"map":{"id":{"int":5}}}}]"#;

#[test]
fn rust_sync_transforms() {
    let (mut p, n) = sync_rust(r#"{"mode":"edit"}"#, BATCH);
    let transform = p.typed::<u32, i32>("fit_sync_transform");
    assert_eq!(transform.call(&mut p.s, n, &budget(10_000)), Ok(0));
    let e = &p.s.state().emitted;
    // id 1 split in two, id 2 changed, id 5 dropped.
    assert_eq!(
        e.iter().map(|x| x.0).collect::<Vec<_>>(),
        [0, 0, 1],
        "{e:?}"
    );
    assert!(e[1].1.contains("shop.copy"), "{e:?}");
    assert!(e[2].1.contains(r#""seen""#), "{e:?}");
}

#[test]
fn rust_sync_misbehaves_and_is_made_again() {
    // A loop stops at its deadline.
    let (mut p, n) = sync_rust(r#"{"mode":"loop","fail":2}"#, BATCH);
    let start = Instant::now();
    let r = p
        .typed::<u32, i32>("fit_sync_transform")
        .call(&mut p.s, n, &budget(100));
    assert_eq!(r, Err(Trap::Deadline));
    assert!(start.elapsed() < Duration::from_secs(5));
    // A panic (abort) traps, after its message.
    let (mut p, n) = sync_rust(r#"{"mode":"trap","fail":2}"#, BATCH);
    let r = p
        .typed::<u32, i32>("fit_sync_transform")
        .call(&mut p.s, n, &budget(10_000));
    assert_eq!(r, Err(Trap::Unreachable));
    assert!(p.stderr().contains("on purpose"), "{}", p.stderr());
    // Calling an import the linker does not define traps, naming it.
    let (mut p, n) = sync_rust(r#"{"mode":"http","fail":2}"#, BATCH);
    let r = p
        .typed::<u32, i32>("fit_sync_transform")
        .call(&mut p.s, n, &budget(10_000));
    assert_eq!(
        r,
        Err(Trap::Host(
            "called unresolved import fit_sync.http_request".into()
        ))
    );
    // Growing past the memory limit traps.
    let host = Host {
        config: br#"{"mode":"grow","fail":2}"#.to_vec(),
        input: BATCH.to_vec(),
        ..Host::default()
    };
    let mut limits = InstanceLimits::default();
    limits.max_memory = 32 << 20;
    let mut p = plugin(&guest("sync-rust"), limits, host);
    let r = p.typed::<u32, i32>("fit_sync_transform").call(
        &mut p.s,
        BATCH.len() as u32,
        &budget(10_000),
    );
    assert_eq!(r, Err(Trap::Unreachable), "{}", p.stderr());
    assert!(p.stderr().contains("memory allocation"), "{}", p.stderr());
    // Each store ended; a new one works.
    assert!(p.s.ended());
    let (mut p, n) = sync_rust(r#"{"mode":"edit"}"#, BATCH);
    let r = p
        .typed::<u32, i32>("fit_sync_transform")
        .call(&mut p.s, n, &budget(10_000));
    assert_eq!(r, Ok(0));
}

// --- A Proxy-Wasm filter, Go: http_routing from the Proxy-Wasm Go SDK. ---

/// Runs http_routing on a request for `example.com` with `config` (its first byte, when there
/// is one, overrides the dice), and returns the request's `:authority` after it.
fn http_routing(config: &[u8]) -> (Plugin, String) {
    let host = Host {
        config: config.to_vec(),
        request: vec![
            (":authority".into(), "example.com".into()),
            (":path".into(), "/".into()),
            (":method".into(), "GET".into()),
            (":scheme".into(), "http".into()),
        ],
        ..Host::default()
    };
    let mut p = plugin(&guest("http_routing-go"), InstanceLimits::default(), host);
    let b = budget(10_000);
    let create = p.typed::<(i32, i32), ()>("proxy_on_context_create");
    create.call(&mut p.s, (1, 0), &b).unwrap();
    let vm_start = p.typed::<(i32, i32), i32>("proxy_on_vm_start");
    assert_ne!(vm_start.call(&mut p.s, (1, 0), &b), Ok(0));
    let configure = p.typed::<(i32, i32), i32>("proxy_on_configure");
    assert_ne!(
        configure.call(&mut p.s, (1, config.len() as i32), &b),
        Ok(0)
    );
    // A request: its context, its headers, then done, log and delete.
    create.call(&mut p.s, (2, 1), &b).unwrap();
    let headers = p.typed::<(i32, i32, i32), i32>("proxy_on_request_headers");
    let start = Instant::now();
    assert_eq!(headers.call(&mut p.s, (2, 4, 1), &b), Ok(0), "continue");
    eprintln!(
        "proxy_on_request_headers: {:?}, {} instructions",
        start.elapsed(),
        p.s.fuel_used()
    );
    let done = p.typed::<i32, i32>("proxy_on_done");
    done.call(&mut p.s, 2, &b).unwrap();
    p.typed::<i32, ()>("proxy_on_log")
        .call(&mut p.s, 2, &b)
        .unwrap();
    p.typed::<i32, ()>("proxy_on_delete")
        .call(&mut p.s, 2, &b)
        .unwrap();
    let authority =
        p.s.state()
            .request
            .iter()
            .find(|(n, _)| n == ":authority")
            .map(|(_, v)| v.clone())
            .unwrap_or_default();
    (p, authority)
}

#[test]
fn proxy_wasm_http_routing_routes() {
    // An even dice: to the canary, the header read and replaced through memory the host
    // allocates by calling back into the guest.
    let (p, authority) = http_routing(&[2]);
    assert_eq!(authority, "example.com-canary");
    assert!(
        p.s.state().logs.iter().any(|(_, m)| m.contains("value: 2")),
        "{:?}",
        p.s.state().logs
    );
    // An odd one: left alone.
    let (_, authority) = http_routing(&[3]);
    assert_eq!(authority, "example.com");
    // No configuration: the dice is random (random_get), either way.
    let (_, authority) = http_routing(&[]);
    assert!(authority.starts_with("example.com"), "{authority}");
}
