//! Running modules (ADR-125, sections 1 and 3): the translator's corner cases, budgets
//! (deadline, fuel, interrupt), the limits on running just under, at and over, traps ending the
//! store, host functions, and translation in time linear in the module's size.

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use akio_wasm::{
    Budget, Extern, FuncType, InstanceLimits, InstantiateError, InterruptHandle, Module,
    ModuleLimits, Store, Trap, ValType, Value,
};

mod common;
use common::*;

// --- The translator's corner cases. ---

#[test]
fn a_local_read_before_it_changes_keeps_its_old_value() {
    let mut b = Builder::default();
    let t = b.ty(&[I32, I32], &[I32, I32, I32]);
    // (a, b) -> (a, b, b + 5), with local 0 changing while its old value is on the stack.
    let f = b.func(
        t,
        &[],
        Code::default()
            .get(0) // old a
            .get(1)
            .set(0) // local 0 = b
            .get(0) // b
            .get(1)
            .i32c(5)
            .op(&[0x6a]) // b + 5
            .tee(1) // local 1 = b + 5 (the add's result moved into the local)
            .end(),
    );
    b.export("f", f);
    let m = b.load();
    let mut s = store(&m, InstanceLimits::default());
    let r = s
        .call("f", &[1.into(), 2.into()], &Budget::unlimited())
        .unwrap();
    assert_eq!(r, vec![Value::I32(1), Value::I32(2), Value::I32(7)]);

    // local.tee into a local still on the stack, then read both.
    let mut b = Builder::default();
    let t = b.ty(&[I32], &[I32, I32]);
    let f = b.func(
        t,
        &[],
        Code::default()
            .get(0)
            .get(0)
            .i32c(1)
            .op(&[0x6a])
            .set(0) // the add retargeted to local 0? Not while its old value is below.
            .get(0)
            .end(),
    );
    b.export("f", f);
    let m = b.load();
    let mut s = store(&m, InstanceLimits::default());
    let r = s
        .call("f", &[Value::I32(41)], &Budget::unlimited())
        .unwrap();
    assert_eq!(r, vec![Value::I32(41), Value::I32(42)]);
}

impl Code {
    fn drop_(self) -> Self {
        self.op(&[0x1a])
    }
}

#[test]
fn branches_carry_values_from_below_the_top() {
    let mut b = Builder::default();
    let t = b.ty(&[I32], &[I32]);
    // block (result i32) 7 (extra values) ... br_if 0 with the value not at the label's slot.
    let f = b.func(
        t,
        &[],
        Code::default()
            .op(&[0x02, I32]) // block (result i32)
            .i32c(1)
            .i32c(2)
            .op(&[0x1a]) // drop: the stack is [1]
            .op(&[0x02, I32]) // inner block (result i32)
            .i32c(10)
            .get(0) // the result if branching
            .get(0) // condition
            .op(&[0x0d, 1]) // br_if 1: carries local 0 past the 10
            .drop_()
            .drop_()
            .i32c(99)
            .end()
            .op(&[0x6a]) // 1 + 99
            .end()
            .end(),
    );
    b.export("f", f);
    let m = b.load();
    let mut s = store(&m, InstanceLimits::default());
    assert_eq!(
        s.call("f", &[Value::I32(5)], &Budget::unlimited()).unwrap(),
        vec![Value::I32(5)]
    );
    assert_eq!(
        s.call("f", &[Value::I32(0)], &Budget::unlimited()).unwrap(),
        vec![Value::I32(100)]
    );
}

#[test]
fn fused_comparisons_branch_both_ways() {
    // (n) -> 42 if n == 0 (an `if` on `i64.eqz`), else the sum of 0..n (a loop leaving on
    // `i64.ge_s` + `br_if`).
    let mut b = Builder::default();
    let t = b.ty(&[I64], &[I64]);
    let f = b.func(
        t,
        &[(2, I64)],
        Code::default()
            .get(0)
            .op(&[0x50]) // i64.eqz
            .op(&[0x04, 0x40]) // if
            .i64c(42)
            .op(&[0x0f]) // return
            .end()
            .op(&[0x02, 0x40]) // block
            .op(&[0x03, 0x40]) // loop
            .get(1)
            .get(0)
            .op(&[0x59]) // i64.ge_s
            .op(&[0x0d, 1]) // br_if 1
            .get(2)
            .get(1)
            .op(&[0x7c])
            .set(2)
            .get(1)
            .i64c(1)
            .op(&[0x7c])
            .set(1)
            .op(&[0x0c, 0]) // br 0
            .end()
            .end()
            .get(2)
            .end(),
    );
    b.export("sum", f);
    let m = b.load();
    let mut s = store(&m, InstanceLimits::default());
    for (n, want) in [(0, 42), (1, 0), (2, 1), (10, 45), (1000, 499_500), (-5, 0)] {
        let r = s.call("sum", &[Value::I64(n)], &Budget::unlimited());
        assert_eq!(r, Ok(vec![Value::I64(want)]), "sum({n})");
    }
}

// --- Budgets. ---

/// `loop: br 0` forever.
fn spin() -> Arc<Module> {
    let mut b = Builder::default();
    let t = b.ty(&[], &[]);
    let f = b.func(
        t,
        &[],
        Code::default().op(&[0x03, 0x40, 0x0c, 0x00, 0x0b]).end(),
    );
    b.export("spin", f);
    b.load()
}

/// `count(n)`: n iterations of a loop of a known size.
fn count() -> Arc<Module> {
    let mut b = Builder::default();
    let t = b.ty(&[I32], &[I32]);
    let f = b.func(
        t,
        &[],
        Code::default()
            .op(&[0x03, 0x40]) // loop: 1
            .get(0) // 2
            .i32c(-1) // 3
            .op(&[0x6a]) // 4
            .tee(0) // 5
            .op(&[0x0d, 0x00]) // br_if 0: 6
            .end()
            .get(0)
            .end(),
    );
    b.export("count", f);
    b.load()
}

#[test]
fn a_deadline_stops_a_loop_and_ends_the_store() {
    let m = spin();
    let mut s = store(&m, InstanceLimits::default());
    let start = Instant::now();
    let r = s.call(
        "spin",
        &[],
        &Budget::deadline(start + Duration::from_millis(50)),
    );
    let took = start.elapsed();
    assert_eq!(r, Err(Trap::Deadline));
    assert!(took >= Duration::from_millis(50), "{took:?}");
    assert!(took < Duration::from_secs(5), "{took:?}");
    assert!(s.s.ended());
    assert_eq!(s.call("spin", &[], &Budget::unlimited()), Err(Trap::Ended));
}

#[test]
fn a_call_past_its_deadline_does_not_start() {
    let m = count();
    let mut s = store(&m, InstanceLimits::default());
    let r = s.call("count", &[1.into()], &Budget::deadline(Instant::now()));
    assert_eq!(r, Err(Trap::Deadline));
}

#[test]
fn fuel_counts_instructions() {
    let m = count();
    // Entry block: the function's first instructions up to the loop (just `loop`).
    let mut s = store(&m, InstanceLimits::default());
    s.call("count", &[Value::I32(100)], &Budget::unlimited())
        .unwrap();
    let per_100 = s.s.fuel_used();
    s.call("count", &[Value::I32(200)], &Budget::unlimited())
        .unwrap();
    let per_200 = s.s.fuel_used();
    // Each iteration runs the loop's block: 6 instructions (get, const, add, tee, br_if, and
    // the `end`/`get`/`end` that follow are counted in the same block).
    let per_iter = (per_200 - per_100) / 100;
    assert!((5..=9).contains(&per_iter), "{per_100} {per_200}");
    // Exactly enough fuel runs; one less does not.
    let need = per_100;
    let mut s = store(&m, InstanceLimits::default());
    assert_eq!(
        s.call("count", &[Value::I32(100)], &Budget::fuel(need))
            .unwrap(),
        vec![Value::I32(0)]
    );
    assert_eq!(s.s.fuel_used(), need);
    let r = s.call("count", &[Value::I32(100)], &Budget::fuel(need - 1));
    assert_eq!(r, Err(Trap::OutOfFuel));
    assert!(s.s.fuel_used() < need);
}

#[test]
fn an_interrupt_from_another_thread_stops_a_loop() {
    let m = spin();
    let mut s = store(&m, InstanceLimits::default());
    let h = InterruptHandle::new();
    let h2 = h.clone();
    let t = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(30));
        h2.interrupt();
    });
    let start = Instant::now();
    let r = s.call("spin", &[], &Budget::unlimited().with_interrupt(&h));
    t.join().unwrap();
    assert_eq!(r, Err(Trap::Interrupted));
    assert!(start.elapsed() < Duration::from_secs(5));
}

/// `fill(n)`: `memory.fill` of the whole memory, `n` times.
#[test]
fn bulk_memory_is_metered_by_its_bytes() {
    let mut b = Builder::default();
    b.memory(256, None); // 16 MiB
    let t = b.ty(&[I32], &[]);
    let f = b.func(
        t,
        &[],
        Code::default()
            .op(&[0x03, 0x40])
            .i32c(0)
            .i32c(7)
            .i32c(16 << 20)
            .op(&[0xfc, 11, 0]) // memory.fill
            .get(0)
            .i32c(-1)
            .op(&[0x6a])
            .tee(0)
            .op(&[0x0d, 0])
            .end()
            .end(),
    );
    b.export("fill", f);
    let m = b.load();
    let mut s = store(&m, InstanceLimits::default());
    s.call("fill", &[Value::I32(1)], &Budget::unlimited())
        .unwrap();
    // 16 MiB at one unit per 64 bytes.
    assert!(s.s.fuel_used() >= (16 << 20) / 64, "{}", s.s.fuel_used());
    let r = s.call("fill", &[Value::I32(10)], &Budget::fuel(1 << 20));
    assert_eq!(r, Err(Trap::OutOfFuel));
}

// --- Limits on running. ---

/// `rec(n)`: recursion `n` deep, with `locals` declared locals in each frame.
fn recursion(locals: u32) -> Arc<Module> {
    let mut b = Builder::default();
    let t = b.ty(&[I32], &[I32]);
    let f = b.func(
        t,
        &[(locals, I64)],
        Code::default()
            .get(0)
            .op(&[0x45]) // i32.eqz
            .op(&[0x04, I32]) // if (result i32)
            .i32c(0)
            .op(&[0x05]) // else
            .get(0)
            .i32c(-1)
            .op(&[0x6a])
            .call(0)
            .i32c(1)
            .op(&[0x6a])
            .end()
            .end(),
    );
    b.export("rec", f);
    b.load()
}

#[test]
fn call_depth_just_under_at_and_over() {
    let m = recursion(0);
    let mut limits = InstanceLimits::default();
    limits.max_call_depth = 100;
    // `rec(n)` makes n + 1 frames.
    for n in [98, 99] {
        let mut s = store(&m, limits.clone());
        let r = s.call("rec", &[Value::I32(n)], &Budget::unlimited());
        assert_eq!(r, Ok(vec![Value::I32(n)]), "depth {n}");
    }
    let mut s = store(&m, limits);
    let r = s.call("rec", &[Value::I32(100)], &Budget::unlimited());
    assert_eq!(r, Err(Trap::CallStackExhausted));
    // The default: deep recursion is a trap, not a native stack overflow.
    let mut s = store(&m, InstanceLimits::default());
    let r = s.call("rec", &[Value::I32(1_000_000)], &Budget::unlimited());
    assert_eq!(r, Err(Trap::CallStackExhausted));
}

#[test]
fn value_stack_just_under_at_and_over() {
    let m = recursion(1000);
    // A frame: 1001 locals and the operand stack (at most 3).
    let frame = 1004;
    let mut limits = InstanceLimits::default();
    limits.max_value_stack = frame * 10;
    // Frames overlap by their arguments: n + 1 frames take n * (frame - 1) + frame slots.
    let mut s = store(&m, limits.clone());
    let r = s.call("rec", &[Value::I32(9)], &Budget::unlimited());
    assert_eq!(r, Ok(vec![Value::I32(9)]));
    let mut s = store(&m, limits);
    let r = s.call("rec", &[Value::I32(11)], &Budget::unlimited());
    assert_eq!(r, Err(Trap::ValueStackExhausted));
}

fn grow_module(min: u32, max: Option<u32>) -> Arc<Module> {
    let mut b = Builder::default();
    b.memory(min, max);
    let t = b.ty(&[I32], &[I32]);
    let f = b.func(
        t,
        &[],
        Code::default().get(0).op(&[0x40, 0]).end(), // memory.grow
    );
    b.export("grow", f);
    b.load()
}

#[test]
fn memory_grows_up_to_the_limit() {
    let m = grow_module(1, None);
    let mut limits = InstanceLimits::default();
    limits.max_memory = 4 << 16; // 4 pages
    let mut s = store(&m, limits.clone());
    let grow = |s: &mut Inst, n: i32| {
        s.call("grow", &[Value::I32(n)], &Budget::unlimited())
            .unwrap()[0]
    };
    assert_eq!(grow(&mut s, 2), Value::I32(1));
    assert_eq!(grow(&mut s, 2), Value::I32(-1)); // 5 > 4
    assert_eq!(grow(&mut s, 1), Value::I32(3)); // at 4
    assert_eq!(grow(&mut s, 1), Value::I32(-1));
    assert_eq!(grow(&mut s, 0), Value::I32(4));
    // The declared maximum is a limit too.
    let m = grow_module(1, Some(2));
    let mut s = store(&m, InstanceLimits::default());
    assert_eq!(
        s.call("grow", &[Value::I32(2)], &Budget::unlimited())
            .unwrap(),
        vec![Value::I32(-1)]
    );
    // An initial size over the limit cannot be made.
    let m = grow_module(5, None);
    let mut s = Store::new((), limits);
    assert_eq!(
        s.instantiate(&m, &[], &Budget::unlimited()),
        Err(InstantiateError::Limit("max_memory"))
    );
}

#[test]
fn tables_grow_up_to_the_limit() {
    let mut b = Builder::default();
    b.table(1, None);
    let t = b.ty(&[I32], &[I32]);
    let f = b.func(
        t,
        &[],
        Code::default()
            .op(&[0xd0, 0x70]) // ref.null func
            .get(0)
            .op(&[0xfc, 15, 0]) // table.grow 0
            .end(),
    );
    b.export("grow", f);
    let m = b.load();
    let mut limits = InstanceLimits::default();
    limits.max_table_elements = 10;
    let mut s = store(&m, limits.clone());
    let mut grow = |n: i32| {
        s.call("grow", &[Value::I32(n)], &Budget::unlimited())
            .unwrap()[0]
    };
    assert_eq!(grow(8), Value::I32(1));
    assert_eq!(grow(2), Value::I32(-1));
    assert_eq!(grow(1), Value::I32(9));
    assert_eq!(grow(1), Value::I32(-1));
    limits.max_table_elements = 0;
    let mut s = Store::new((), limits);
    assert_eq!(
        s.instantiate(&m, &[], &Budget::unlimited()),
        Err(InstantiateError::Limit("max_table_elements"))
    );
}

#[test]
fn out_of_bounds_accesses_trap() {
    let mut b = Builder::default();
    b.memory(1, None);
    let t = b.ty(&[I32], &[I64]);
    let f = b.func(t, &[], Code::default().get(0).op(&[0x29, 3, 0]).end()); // i64.load
    b.export("load", f);
    let m = b.load();
    let mut s = store(&m, InstanceLimits::default());
    s.s.set_trap_ends(false);
    for (addr, ok) in [(0, true), (65_528, true), (65_529, false), (-1, false)] {
        let r = s.call("load", &[Value::I32(addr)], &Budget::unlimited());
        assert_eq!(r.is_ok(), ok, "{addr}");
        if !ok {
            assert_eq!(r, Err(Trap::MemoryOutOfBounds));
        }
    }
    assert!(!s.s.ended());
}

// --- Calls, host functions, the store. ---

#[test]
fn a_bad_call_runs_nothing_and_does_not_end_the_store() {
    let m = count();
    let mut s = store(&m, InstanceLimits::default());
    let r = s.call("count", &[Value::I64(1)], &Budget::unlimited());
    assert!(matches!(r, Err(Trap::BadCall(_))), "{r:?}");
    let r = s.call("count", &[], &Budget::unlimited());
    assert!(matches!(r, Err(Trap::BadCall(_))), "{r:?}");
    assert!(!s.s.ended());
    assert_eq!(
        s.call("count", &[Value::I32(3)], &Budget::unlimited()),
        Ok(vec![Value::I32(0)])
    );
}

#[derive(Default)]
struct Host {
    seen: Vec<String>,
}

#[test]
fn host_functions_see_the_callers_memory_and_state() {
    let mut b = Builder::default();
    let log_t = b.ty(&[I32, I32], &[I32]);
    let log = b.import_func("env", "log", log_t);
    b.memory(1, None);
    let t = b.ty(&[I32], &[I32]);
    let f = b.func(
        t,
        &[],
        Code::default()
            // memory[0..2] = "hi"
            .i32c(0)
            .i32c(i32::from(u16::from_le_bytes(*b"hi")))
            .op(&[0x3b, 1, 0]) // i32.store16
            .i32c(0)
            .get(0)
            .call(log)
            .end(),
    );
    b.export("f", f);
    let m = b.load();
    let mut s = Store::new(Host::default(), InstanceLimits::default());
    let log = s.func_new(
        FuncType::new(&[ValType::I32, ValType::I32], &[ValType::I32]),
        |c, args, results| {
            let (p, n) = (
                args[0].i32().unwrap() as usize,
                args[1].i32().unwrap() as usize,
            );
            let mem = c.memory().ok_or_else(|| Trap::Host("no memory".into()))?;
            let text = mem
                .get(p..p + n)
                .ok_or_else(|| Trap::Host("out of bounds".into()))?;
            let text = String::from_utf8_lossy(text).into_owned();
            c.state_mut().seen.push(text);
            results[0] = Value::I32(n as i32);
            Ok(())
        },
    );
    let inst = s
        .instantiate(&m, &[Extern::Func(log)], &Budget::unlimited())
        .unwrap();
    let f = s.export_func(inst, "f").unwrap();
    let mut out = [Value::I32(0)];
    s.call(f, &[Value::I32(2)], &mut out, &Budget::unlimited())
        .unwrap();
    assert_eq!(out, [Value::I32(2)]);
    assert_eq!(s.state().seen, ["hi"]);
    // A host function's failure is a trap, which ends the store.
    let r = s.call(f, &[Value::I32(70_000)], &mut out, &Budget::unlimited());
    assert_eq!(r, Err(Trap::Host("out of bounds".into())));
    assert!(s.ended());
    // An import of the wrong type is refused.
    let mut s = Store::new(Host::default(), InstanceLimits::default());
    let wrong = s.func_new(FuncType::new(&[], &[]), |_, _, _| Ok(()));
    assert_eq!(
        s.instantiate(&m, &[Extern::Func(wrong)], &Budget::unlimited()),
        Err(InstantiateError::Unlinkable {
            index: 0,
            message: "incompatible import type"
        })
    );
}

#[test]
fn a_store_moves_between_threads() {
    fn send<T: Send>(_: &T) {}
    fn sync<T: Sync>(_: &T) {}
    let m = count();
    sync(&m);
    let mut s = store(&m, InstanceLimits::default());
    send(&s.s);
    let r = std::thread::spawn(move || s.call("count", &[Value::I32(5)], &Budget::unlimited()))
        .join()
        .unwrap();
    assert_eq!(r, Ok(vec![Value::I32(0)]));
}

// --- Translation stays linear. ---

/// Bodies built to defeat a careless translator: many values on the stack still read from
/// locals that then change, and `br_table`s whose every target moves values.
#[test]
fn translation_is_linear_in_the_code() {
    let n = 20_000u32;
    let mut b = Builder::default();
    let t = b.ty(&[], &[]);
    // n locals read onto the stack, n values above them, then each local set in turn.
    let mut c = Code::default();
    for i in 0..n {
        c = c.get(i);
    }
    for _ in 0..n {
        c = c.i32c(1);
    }
    for i in 0..n {
        c = c.i32c(2).set(i);
    }
    for _ in 0..2 * n {
        c = c.drop_();
    }
    let f = b.func(t, &[(n, I32)], c.end());
    b.export("f", f);
    // A br_table of n targets, each carrying two values to a label lower in the stack.
    let t2 = b.ty(&[], &[I32, I32]);
    let mut c = Code::default().op(&[0x02]).idx(t2); // block (result i32 i32)
    c = c.i32c(9).i32c(1).i32c(2).i32c(0).op(&[0x0e]).idx(n);
    for _ in 0..=n {
        c = c.idx(0);
    }
    c = c.end().drop_().drop_().end();
    let g = b.func(t, &[], c);
    b.export("g", g);
    let bytes = b.build();
    let start = Instant::now();
    let m = Arc::new(Module::new(&bytes, &ModuleLimits::default()).unwrap());
    let took = start.elapsed();
    assert!(
        took < Duration::from_secs(if cfg!(debug_assertions) { 20 } else { 2 }),
        "{took:?}"
    );
    let mut s = store(&m, InstanceLimits::default());
    s.call("f", &[], &Budget::unlimited()).unwrap();
    s.call("g", &[], &Budget::unlimited()).unwrap();
}
