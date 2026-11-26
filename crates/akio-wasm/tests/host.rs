//! The host API (ADR-125, section 3): the linker and its typed host functions, unresolved
//! imports that trap, the caller's bounds-checked views of memory, host functions calling back
//! into the guest under the same budget, and typed calls.

use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use akio_wasm::{
    Budget, Caller, FuncType, InstanceLimits, InstantiateError, LinkError, Linker, Module, Store,
    Trap, ValType, Value,
};

mod common;
use common::*;

/// A module that imports `host.f` of type `ty` and exports `run`, which passes its arguments
/// to it, and a memory of one page.
fn forwarder(params: &[u8], results: &[u8]) -> Arc<Module> {
    let mut b = Builder::default();
    let t = b.ty(params, results);
    let f = b.import_func("host", "f", t);
    let mut code = Code::default();
    for i in 0..params.len() as u32 {
        code = code.get(i);
    }
    let run = b.func(t, &[], code.call(f).end());
    b.export("run", run);
    b.memory(1, None);
    b.export_memory("memory");
    b.load()
}

fn call_run<S>(
    s: &mut Store<S>,
    inst: akio_wasm::Instance,
    args: &[Value],
) -> Result<Vec<Value>, Trap> {
    let f = s.export_func(inst, "run").expect("run");
    let mut out: Vec<Value> = s
        .func_type(f)
        .results()
        .iter()
        .map(|&t| Value::default_of(t))
        .collect();
    s.call(f, args, &mut out, &Budget::fuel(1_000_000))?;
    Ok(out)
}

#[test]
fn the_linker_resolves_typed_and_untyped_host_functions() {
    let m = forwarder(&[I32, I64], &[I64]);
    let mut l = Linker::<Vec<i64>>::new();
    l.func_wrap(
        "host",
        "f",
        |c: &mut Caller<'_, Vec<i64>>, (a, b): (u32, i64)| {
            c.state_mut().push(b);
            Ok(i64::from(a) + b)
        },
    )
    .unwrap();
    assert_eq!(
        l.func_type("host", "f"),
        Some(&FuncType::new(
            &[ValType::I32, ValType::I64],
            &[ValType::I64]
        ))
    );
    let mut s = Store::new(Vec::new(), InstanceLimits::default());
    let inst = l.instantiate(&mut s, &m, &Budget::unlimited()).unwrap();
    assert_eq!(
        call_run(&mut s, inst, &[Value::I32(-1), Value::I64(1)]).unwrap(),
        [Value::I64(i64::from(u32::MAX) + 1)]
    );
    assert_eq!(*s.state(), [1]);

    // The same, untyped.
    let mut l = Linker::<()>::new();
    l.func_new(
        "host",
        "f",
        FuncType::new(&[ValType::I32, ValType::I64], &[ValType::I64]),
        |_, args, out| {
            out[0] = Value::I64(i64::from(args[0].i32().unwrap()) * args[1].i64().unwrap());
            Ok(())
        },
    )
    .unwrap();
    let mut s = Store::new((), InstanceLimits::default());
    let inst = l.instantiate(&mut s, &m, &Budget::unlimited()).unwrap();
    assert_eq!(
        call_run(&mut s, inst, &[Value::I32(6), Value::I64(7)]).unwrap(),
        [Value::I64(42)]
    );

    // A second definition of a name is refused.
    assert_eq!(
        l.func_wrap("host", "f", |_: &mut Caller<'_, ()>, (): ()| Ok(()))
            .unwrap_err(),
        LinkError::Duplicate {
            module: "host".into(),
            name: "f".into()
        }
    );
}

#[test]
fn a_linker_is_shared_by_threads_and_stores() {
    fn shared<T: Send + Sync + Clone>(_: &T) {}
    let m = forwarder(&[I32], &[I32]);
    let mut l = Linker::<u32>::new();
    l.func_wrap("host", "f", |c: &mut Caller<'_, u32>, x: (i32,)| {
        *c.state_mut() += 1;
        Ok(x.0 + 1)
    })
    .unwrap();
    shared(&l);
    let l = Arc::new(l);
    let threads: Vec<_> = (0..4)
        .map(|k| {
            let (l, m) = (Arc::clone(&l), Arc::clone(&m));
            std::thread::spawn(move || {
                let mut s = Store::new(0, InstanceLimits::default());
                let inst = l.instantiate(&mut s, &m, &Budget::unlimited()).unwrap();
                for _ in 0..10 {
                    assert_eq!(
                        call_run(&mut s, inst, &[Value::I32(k)]).unwrap(),
                        [Value::I32(k + 1)]
                    );
                }
                s.into_state()
            })
        })
        .collect();
    for t in threads {
        assert_eq!(t.join().unwrap(), 10);
    }
}

#[test]
fn imports_nothing_defines_are_refused_or_trap_when_called() {
    // Imports host.f, which run calls, and host.g, which nothing calls.
    let mut b = Builder::default();
    let t = b.ty(&[], &[I32]);
    let f = b.import_func("host", "f", t);
    let _g = b.import_func("host", "g", t);
    let run = b.func(t, &[], Code::default().call(f).end());
    let quiet = b.func(t, &[], Code::default().i32c(7).end());
    b.export("run", run);
    b.export("quiet", quiet);
    let m = b.load();

    let mut l = Linker::<()>::new();
    l.func_wrap("host", "f", |_: &mut Caller<'_, ()>, (): ()| Ok(1i32))
        .unwrap();
    let mut s = Store::new((), InstanceLimits::default());
    assert_eq!(
        l.instantiate(&mut s, &m, &Budget::unlimited()).unwrap_err(),
        InstantiateError::UnknownImport {
            index: 1,
            module: "host".into(),
            name: "g".into()
        }
    );
    // Unresolved functions trap only if called.
    l.trap_unresolved(true);
    let inst = l.instantiate(&mut s, &m, &Budget::unlimited()).unwrap();
    let quiet = s.export_func(inst, "quiet").unwrap();
    let quiet = s.typed_func::<(), i32>(quiet).unwrap();
    assert_eq!(quiet.call(&mut s, (), &Budget::unlimited()), Ok(7));
    let run = s
        .typed_func::<(), i32>(s.export_func(inst, "run").unwrap())
        .unwrap();
    assert_eq!(run.call(&mut s, (), &Budget::unlimited()), Ok(1));

    // Now host.f is the missing one: calling it traps, naming it, and ends the store.
    let mut l = Linker::<()>::new();
    l.func_wrap("host", "g", |_: &mut Caller<'_, ()>, (): ()| Ok(2i32))
        .unwrap()
        .trap_unresolved(true);
    let mut s = Store::new((), InstanceLimits::default());
    let inst = l.instantiate(&mut s, &m, &Budget::unlimited()).unwrap();
    let run = s
        .typed_func::<(), i32>(s.export_func(inst, "run").unwrap())
        .unwrap();
    assert_eq!(
        run.call(&mut s, (), &Budget::unlimited()),
        Err(Trap::Host("called unresolved import host.f".into()))
    );
    assert!(s.ended());
    assert_eq!(
        l.instantiate(&mut s, &m, &Budget::unlimited()).unwrap_err(),
        InstantiateError::Trap(Trap::Ended)
    );

    // A function defined with another type is unlinkable.
    let mut l = Linker::<()>::new();
    l.func_wrap("host", "f", |_: &mut Caller<'_, ()>, (): ()| Ok(1i64))
        .unwrap()
        .trap_unresolved(true);
    let mut s = Store::new((), InstanceLimits::default());
    assert_eq!(
        l.instantiate(&mut s, &m, &Budget::unlimited()).unwrap_err(),
        InstantiateError::Unlinkable {
            index: 0,
            message: "incompatible import type"
        }
    );

    // A memory, table or global nothing defines is refused, trapping or not.
    let mut b = Builder::default();
    b.import_memory("host", "memory", 1);
    b.ty(&[], &[]);
    let m = b.load();
    let mut s = Store::new((), InstanceLimits::default());
    assert_eq!(
        l.instantiate(&mut s, &m, &Budget::unlimited()).unwrap_err(),
        InstantiateError::UnknownImport {
            index: 0,
            module: "host".into(),
            name: "memory".into()
        }
    );
}

#[test]
fn host_functions_see_memory_through_bounds_checked_views() {
    let m = forwarder(&[I32, I32], &[I32]);
    let mut l = Linker::<Vec<u8>>::new();
    // Copies len bytes at ptr to the state, writes their sum after them, returns it.
    l.func_wrap(
        "host",
        "f",
        |c: &mut Caller<'_, Vec<u8>>, (ptr, len): (u32, u32)| {
            let bytes = c.read(ptr, len)?.to_vec();
            let sum: u32 = bytes.iter().map(|&b| u32::from(b)).sum();
            c.write_u32(ptr + len, sum)?;
            assert_eq!(c.read_u32(ptr + len)?, sum);
            c.write_u64(ptr + len + 4, u64::from(sum) << 32)?;
            assert_eq!(c.read_u64(ptr + len + 4)?, u64::from(sum) << 32);
            *c.state_mut() = bytes;
            Ok(sum as i32)
        },
    )
    .unwrap();
    let mut s = Store::new(Vec::new(), InstanceLimits::default());
    let inst = l.instantiate(&mut s, &m, &Budget::unlimited()).unwrap();
    let mem = s.export(inst, "memory").unwrap().memory().unwrap();
    s.memory_data_mut(mem)[100..104].copy_from_slice(&[1, 2, 3, 4]);
    assert_eq!(
        call_run(&mut s, inst, &[Value::I32(100), Value::I32(4)]).unwrap(),
        [Value::I32(10)]
    );
    assert_eq!(*s.state(), [1, 2, 3, 4]);
    assert_eq!(s.memory_data(mem)[104..108], 10u32.to_le_bytes());

    // The last bytes of the memory are in it; one past is not, nor a length that wraps.
    let end = 65_536 - 12;
    assert_eq!(
        call_run(&mut s, inst, &[Value::I32(end), Value::I32(0)]).unwrap(),
        [Value::I32(0)]
    );
    for (ptr, len) in [(end + 1, 0), (65_536, 0), (1, -1), (-1, 2)] {
        let mut s = Store::new(Vec::new(), InstanceLimits::default());
        let inst = l.instantiate(&mut s, &m, &Budget::unlimited()).unwrap();
        assert_eq!(
            call_run(&mut s, inst, &[Value::I32(ptr), Value::I32(len)]),
            Err(Trap::MemoryOutOfBounds),
            "{ptr} {len}"
        );
        assert!(s.ended());
    }
}

#[test]
fn a_module_without_memory_has_none_to_read() {
    let mut b = Builder::default();
    let t = b.ty(&[], &[]);
    let f = b.import_func("host", "f", t);
    let run = b.func(t, &[], Code::default().call(f).end());
    b.export("run", run);
    let m = b.load();
    let mut l = Linker::<()>::new();
    l.func_wrap("host", "f", |c: &mut Caller<'_, ()>, (): ()| {
        assert!(c.memory().is_none());
        assert!(c.instance().is_some());
        assert!(c.export("run").is_some());
        c.read(0, 0).map(|_| ())
    })
    .unwrap();
    let mut s = Store::new((), InstanceLimits::default());
    let inst = l.instantiate(&mut s, &m, &Budget::unlimited()).unwrap();
    assert_eq!(call_run(&mut s, inst, &[]), Err(Trap::MemoryOutOfBounds));
}

/// A module whose `run(n)` calls `host.f(n)`, and that exports `alloc(size) -> ptr`, a bump
/// allocator from 1024, and `down(n)`, which calls `host.f(n - 1)` unless n is 0: a host
/// function calls back through it.
fn reentrant() -> Arc<Module> {
    let mut b = Builder::default();
    let t = b.ty(&[I32], &[I32]);
    let f = b.import_func("host", "f", t);
    let run = b.func(t, &[], Code::default().get(0).call(f).end());
    // alloc: global-free bump pointer kept at address 0.
    let alloc = b.func(
        t,
        &[(1, I32)],
        Code::default()
            .i32c(0)
            .op(&[0x28, 2, 0]) // i32.load: the next free address
            .tee(1)
            .op(&[0x45]) // i32.eqz: first use
            .op(&[0x04, 0x40]) // if
            .i32c(1024)
            .set(1)
            .op(&[0x0b])
            .i32c(0)
            .get(1)
            .get(0)
            .op(&[0x6a]) // i32.add
            .op(&[0x36, 2, 0]) // i32.store
            .get(1)
            .end(),
    );
    let down = b.func(
        t,
        &[],
        Code::default()
            .get(0)
            .op(&[0x45]) // i32.eqz
            .op(&[0x04, I32]) // if (result i32)
            .i32c(0)
            .op(&[0x05]) // else
            .get(0)
            .i32c(1)
            .op(&[0x6b]) // i32.sub
            .call(f)
            .i32c(1)
            .op(&[0x6a])
            .op(&[0x0b])
            .end(),
    );
    let spin = b.func(
        t,
        &[],
        Code::default()
            .op(&[0x03, 0x40, 0x0c, 0, 0x0b]) // loop br 0 end
            .i32c(0)
            .end(),
    );
    b.export("run", run);
    b.export("alloc", alloc);
    b.export("down", down);
    b.export("spin", spin);
    b.memory(1, None);
    b.export_memory("memory");
    b.load()
}

#[test]
fn host_functions_call_back_into_the_guest() {
    let m = reentrant();
    // host.f(n) allocates n bytes in the guest, fills them, and returns where: what a
    // Proxy-Wasm host does with proxy_on_memory_allocate.
    let mut l = Linker::<()>::new();
    l.func_wrap("host", "f", |c: &mut Caller<'_, ()>, (n,): (u32,)| {
        let alloc = c.export("alloc").and_then(|e| e.func()).unwrap();
        let mut out = [Value::I32(0)];
        c.call(alloc, &[Value::I32(n as i32)], &mut out)?;
        let p = out[0].i32().unwrap() as u32;
        c.write(p, &vec![0xab; n as usize])?;
        Ok(p as i32)
    })
    .unwrap();
    let mut s = Store::new((), InstanceLimits::default());
    let inst = l.instantiate(&mut s, &m, &Budget::unlimited()).unwrap();
    let run = s
        .typed_func::<i32, i32>(s.export_func(inst, "run").unwrap())
        .unwrap();
    assert_eq!(run.call(&mut s, 16, &Budget::fuel(10_000)), Ok(1024));
    assert_eq!(run.call(&mut s, 8, &Budget::fuel(10_000)), Ok(1040));
    let mem = s.export(inst, "memory").unwrap().memory().unwrap();
    assert_eq!(s.memory_data(mem)[1024..1048], [0xab; 24]);
    assert_eq!(s.memory_data(mem)[1048], 0);
    // The nested call's fuel is the call's.
    let used = s.fuel_used();
    assert!(used > 10, "{used}");
    assert_eq!(
        run.call(&mut s, 8, &Budget::fuel(used - 1)),
        Err(Trap::OutOfFuel)
    );
}

#[test]
fn calls_back_into_the_guest_nest_to_a_bound() {
    let m = reentrant();
    // host.f(n) calls down(n), which calls host.f(n - 1) ...: 2n + 1 frames deep.
    let mut l = Linker::<u32>::new();
    l.func_wrap("host", "f", |c: &mut Caller<'_, u32>, (n,): (i32,)| {
        *c.state_mut() = (*c.state()).max(n as u32);
        let down = c.export("down").and_then(|e| e.func()).unwrap();
        let mut out = [Value::I32(0)];
        c.call(down, &[Value::I32(n)], &mut out)?;
        Ok(out[0].i32().unwrap())
    })
    .unwrap();
    let mut s = Store::new(0, InstanceLimits::default());
    let inst = l.instantiate(&mut s, &m, &Budget::unlimited()).unwrap();
    // 63 nested calls: under the bound of 64.
    assert_eq!(
        call_run(&mut s, inst, &[Value::I32(62)]).unwrap(),
        [Value::I32(62)]
    );
    // One more is over it, wherever the host function then returns.
    let mut l2 = Linker::<u32>::new();
    l2.func_wrap("host", "f", |c: &mut Caller<'_, u32>, (n,): (i32,)| {
        let down = c.export("down").and_then(|e| e.func()).unwrap();
        let mut out = [Value::I32(0)];
        // Swallows the error: the trap still ends the outer call.
        if c.call(down, &[Value::I32(n)], &mut out).is_err() {
            return Ok(-1);
        }
        Ok(out[0].i32().unwrap())
    })
    .unwrap();
    for l in [&l, &l2] {
        let mut s = Store::new(0, InstanceLimits::default());
        let inst = l.instantiate(&mut s, &m, &Budget::unlimited()).unwrap();
        assert_eq!(
            call_run(&mut s, inst, &[Value::I32(64)]),
            Err(Trap::CallStackExhausted)
        );
        assert!(s.ended());
    }
    // The call depth counts the frames below a nested call too: run(n) takes n + 2.
    let mut s = Store::new(0, limits_depth(20));
    let inst = l.instantiate(&mut s, &m, &Budget::unlimited()).unwrap();
    assert_eq!(
        call_run(&mut s, inst, &[Value::I32(18)]).unwrap(),
        [Value::I32(18)]
    );
    let mut s = Store::new(0, limits_depth(20));
    let inst = l.instantiate(&mut s, &m, &Budget::unlimited()).unwrap();
    assert_eq!(
        call_run(&mut s, inst, &[Value::I32(19)]),
        Err(Trap::CallStackExhausted)
    );
}

fn limits_depth(d: u32) -> InstanceLimits {
    let mut l = InstanceLimits::default();
    l.max_call_depth = d;
    l
}

#[test]
fn a_trap_in_a_nested_call_ends_the_outer_one() {
    let m = reentrant();
    let mut l = Linker::<Vec<Trap>>::new();
    // host.f calls spin, which loops until the deadline; it then returns Ok as if nothing
    // happened.
    l.func_wrap(
        "host",
        "f",
        |c: &mut Caller<'_, Vec<Trap>>, (_,): (i32,)| {
            let spin = c.export("spin").and_then(|e| e.func()).unwrap();
            let mut out = [Value::I32(0)];
            let e = c.call(spin, &[Value::I32(0)], &mut out).unwrap_err();
            c.state_mut().push(e);
            Ok(0i32)
        },
    )
    .unwrap();
    let mut s = Store::new(Vec::new(), InstanceLimits::default());
    let inst = l.instantiate(&mut s, &m, &Budget::unlimited()).unwrap();
    let start = Instant::now();
    let budget = Budget::deadline(start + Duration::from_millis(20));
    let run = s
        .typed_func::<i32, i32>(s.export_func(inst, "run").unwrap())
        .unwrap();
    assert_eq!(run.call(&mut s, 0, &budget), Err(Trap::Deadline));
    assert!(start.elapsed() < Duration::from_secs(5));
    assert_eq!(*s.state(), [Trap::Deadline]);
    assert!(s.ended());
}

#[test]
fn host_functions_read_and_spend_the_calls_budget() {
    let m = forwarder(&[I32], &[I32]);
    let seen = Arc::new(Mutex::new(None));
    let seen2 = Arc::clone(&seen);
    let mut l = Linker::<()>::new();
    l.func_wrap("host", "f", move |c: &mut Caller<'_, ()>, (n,): (u32,)| {
        *seen2.lock().unwrap() = Some((c.deadline(), c.is_interrupted()));
        c.consume_fuel(u64::from(n))?;
        Ok(0i32)
    })
    .unwrap();
    let mut s = Store::new((), InstanceLimits::default());
    let inst = l.instantiate(&mut s, &m, &Budget::unlimited()).unwrap();
    let run = s
        .typed_func::<u32, i32>(s.export_func(inst, "run").unwrap())
        .unwrap();
    let at = Instant::now() + Duration::from_secs(60);
    run.call(&mut s, 1000, &Budget::deadline(at).with_fuel(2000))
        .unwrap();
    assert_eq!(*seen.lock().unwrap(), Some((Some(at), false)));
    assert!(s.fuel_used() >= 1000);
    assert_eq!(
        run.call(&mut s, 5000, &Budget::fuel(2000)),
        Err(Trap::OutOfFuel)
    );
}

#[test]
fn typed_functions_check_their_type_once() {
    let m = forwarder(&[I32, I64], &[I64]);
    let mut l = Linker::<()>::new();
    l.func_wrap("host", "f", |_: &mut Caller<'_, ()>, (a, b): (i32, i64)| {
        Ok(i64::from(a) - b)
    })
    .unwrap();
    let mut s = Store::new((), InstanceLimits::default());
    let inst = l.instantiate(&mut s, &m, &Budget::unlimited()).unwrap();
    let f = s.export_func(inst, "run").unwrap();
    assert!(s.typed_func::<(i32, i64), i32>(f).is_err());
    assert!(s.typed_func::<(i64, i64), i64>(f).is_err());
    assert!(s.typed_func::<(i32,), i64>(f).is_err());
    let g = s.typed_func::<(i32, i64), (i64,)>(f).unwrap();
    assert_eq!(g.call(&mut s, (1, 3), &Budget::unlimited()), Ok((-2,)));
    let g = s.typed_func::<(u32, u64), u64>(f).unwrap();
    assert_eq!(g.call(&mut s, (0, 1), &Budget::unlimited()), Ok(u64::MAX));
    assert_eq!(g.func(), f);
}

#[test]
fn a_host_function_called_by_the_host_has_no_memory() {
    let mut s = Store::new(0u32, InstanceLimits::default());
    let f = s.func_new(FuncType::new(&[], &[ValType::I32]), |c, _, out| {
        assert!(c.instance().is_none());
        assert!(c.memory().is_none());
        *c.state_mut() += 1;
        out[0] = Value::I32(c.read(0, 1).map_or(-1, |_| 1));
        Ok(())
    });
    let f = s.typed_func::<(), i32>(f).unwrap();
    assert_eq!(f.call(&mut s, (), &Budget::unlimited()), Ok(-1));
    assert_eq!(*s.state(), 1);
}

#[test]
fn typed_host_functions_pass_every_type_by_its_bits() {
    // run(a: i32, b: i64, c: f32, d: f64) -> (i64, i32, f32, f64, i64): the host function's
    // results, its `i32` one widened by the guest with `i64.extend_i32_u` (a slot holds an
    // `i32` zero-extended, so that the widening is free).
    let mut b = Builder::default();
    const F32: u8 = 0x7d;
    const F64: u8 = 0x7c;
    let th = b.ty(&[I32, I64, F32, F64], &[I32, I64, F32, F64]);
    let f = b.import_func("host", "f", th);
    let tr = b.ty(&[I32, I64, F32, F64], &[I64, I32, F32, F64, I64]);
    let run = b.func(
        tr,
        &[(1, I32), (1, I64), (1, F32), (1, F64)],
        Code::default()
            .get(0)
            .get(1)
            .get(2)
            .get(3)
            .call(f)
            .set(7)
            .set(6)
            .set(5)
            .set(4)
            .get(4)
            .op(&[0xad]) // i64.extend_i32_u
            .get(4)
            .get(6)
            .get(7)
            .get(5)
            .end(),
    );
    b.export("run", run);
    let m = b.load();
    let mut l = Linker::<()>::new();
    l.func_wrap(
        "host",
        "f",
        |_: &mut Caller<'_, ()>, (a, b, c, d): (i32, u64, f32, f64)| {
            Ok((a.wrapping_neg(), b.wrapping_neg(), -c, -d))
        },
    )
    .unwrap();
    let mut s = Store::new((), InstanceLimits::default());
    let inst = l.instantiate(&mut s, &m, &Budget::unlimited()).unwrap();
    let nan = f32::from_bits(0x7fa0_0001);
    let r = call_run(
        &mut s,
        inst,
        &[
            Value::I32(1),
            Value::I64(5),
            Value::F32(nan),
            Value::F64(2.5),
        ],
    )
    .unwrap();
    assert_eq!(r[0], Value::I64(0xffff_ffff));
    assert_eq!(r[1], Value::I32(-1));
    match r[2] {
        Value::F32(x) => assert_eq!(x.to_bits(), 0xffa0_0001),
        v => panic!("{v:?}"),
    }
    assert_eq!(r[3], Value::F64(-2.5));
    assert_eq!(r[4], Value::I64(-5));

    // A typed host function called by the host, not the guest.
    let mut l = Linker::<()>::new();
    l.func_wrap("host", "g", |_: &mut Caller<'_, ()>, (a, b): (u32, i32)| {
        Ok((b, a))
    })
    .unwrap();
    let mut s = Store::new((), InstanceLimits::default());
    let mut b = Builder::default();
    let t = b.ty(&[I32, I32], &[I32, I32]);
    let g = b.import_func("host", "g", t);
    b.export("g", g);
    let m = b.load();
    let inst = l.instantiate(&mut s, &m, &Budget::unlimited()).unwrap();
    let g = s.export_func(inst, "g").unwrap();
    let mut out = [Value::I32(0), Value::I32(0)];
    s.call(
        g,
        &[Value::I32(-7), Value::I32(3)],
        &mut out,
        &Budget::unlimited(),
    )
    .unwrap();
    assert_eq!(out, [Value::I32(3), Value::I32(-7)]);
}
