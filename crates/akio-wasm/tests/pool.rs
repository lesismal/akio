//! The instance pool (ADR-125, sections 4 and 7): jobs on the pool's threads, a full queue
//! refused, a wait expiring, `submit_to` ahead of the shared queue, a hung guest stopped at its
//! deadline and its instance remade, a pool failed by an instance that will not start, and
//! closing with jobs queued.

use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
        mpsc::{self, Receiver, Sender},
    },
    thread,
    time::{Duration, Instant},
};

use akio_wasm::{
    InstanceId, InstancePool, InstantiateError, JobError, Linker, Module, PoolConfig, Pooled,
    Refusal, StartError, Trap,
};

mod common;
use common::*;

/// Long enough for anything that should happen to happen, on a loaded host.
const LONG: Duration = Duration::from_secs(20);

/// A module with a memory of one page and:
/// - `_initialize`, which stores 7 at address 4 (a reactor's initialization);
/// - `init_value`, which loads address 4;
/// - `bump`, which adds one to the `i32` at address 0 and returns it;
/// - `spin`, a loop that never ends;
/// - `trap`, `unreachable`.
fn guest(spin_in_init: bool) -> Arc<Module> {
    let mut b = Builder::default();
    let unit = b.ty(&[], &[]);
    let ret = b.ty(&[], &[I32]);
    let spin = Code::default().op(&[0x03, 0x40, 0x0c, 0x00, 0x0b]); // loop br 0 end
    let init = if spin_in_init {
        spin.clone().end()
    } else {
        Code::default()
            .i32c(4)
            .i32c(7)
            .op(&[0x36, 0x02, 0x00]) // i32.store
            .end()
    };
    let f = b.func(unit, &[], init);
    b.export("_initialize", f);
    let f = b.func(
        ret,
        &[],
        Code::default().i32c(4).op(&[0x28, 0x02, 0x00]).end(),
    );
    b.export("init_value", f);
    let bump = Code::default()
        .i32c(0)
        .i32c(0)
        .op(&[0x28, 0x02, 0x00]) // i32.load
        .i32c(1)
        .op(&[0x6a]) // i32.add
        .op(&[0x36, 0x02, 0x00]) // i32.store
        .i32c(0)
        .op(&[0x28, 0x02, 0x00])
        .end();
    let f = b.func(ret, &[], bump);
    b.export("bump", f);
    let f = b.func(unit, &[], spin.end());
    b.export("spin", f);
    let f = b.func(unit, &[], Code::default().op(&[0x00]).end());
    b.export("trap", f);
    b.memory(1, None);
    b.load()
}

fn config(instances: usize) -> PoolConfig {
    let mut c = PoolConfig::default();
    c.instances = instances;
    c.call_timeout = LONG;
    c.wait_timeout = LONG;
    c.init_timeout = LONG;
    c
}

fn pool(c: PoolConfig) -> InstancePool<()> {
    InstancePool::builder(guest(false), Linker::new(), |_| ())
        .config(c)
        .build()
        .expect("the pool starts")
}

fn call(inst: &mut Pooled<()>, name: &str) -> Result<i32, Trap> {
    let f = inst.typed_func::<(), i32>(name)?;
    inst.call_typed(f, ())
}

fn call_unit(inst: &mut Pooled<()>, name: &str) -> Result<(), Trap> {
    let f = inst.typed_func::<(), ()>(name)?;
    inst.call_typed(f, ())
}

/// A channel whose sending half is a job's completion.
fn completion<T: Send + 'static>() -> (impl FnOnce(T) + Send + 'static, Receiver<T>) {
    let (tx, rx) = mpsc::channel();
    (move |r| tx.send(r).expect("the test waits"), rx)
}

/// Submits a job that tells the test it started (with its instance's id), then waits until
/// the test lets it go, then runs `then`. The instance is busy until then.
fn block<R: Send + 'static>(
    pool: &InstancePool<()>,
    then: impl FnOnce(&mut Pooled<()>) -> R + Send + 'static,
) -> (InstanceId, Sender<()>, Receiver<Result<R, JobError>>) {
    let (started_tx, started_rx) = mpsc::channel();
    let (go_tx, go_rx) = mpsc::channel::<()>();
    let (done, rx) = completion();
    pool.submit(
        move |inst| {
            started_tx.send(inst.id()).expect("the test waits");
            let _ = go_rx.recv_timeout(LONG);
            then(inst)
        },
        done,
    )
    .expect("accepted");
    let id = started_rx.recv_timeout(LONG).expect("the job starts");
    (id, go_tx, rx)
}

fn wait_for(what: &str, mut f: impl FnMut() -> bool) {
    let end = Instant::now() + LONG;
    while !f() {
        assert!(Instant::now() < end, "timed out waiting for {what}");
        thread::sleep(Duration::from_millis(2));
    }
}

#[test]
fn jobs_run_on_the_pools_threads_and_complete_there() {
    let pool = pool(config(3));
    let mut rxs = Vec::new();
    for _ in 0..30 {
        let (done, rx) = completion();
        pool.submit(
            |inst| {
                (
                    call(inst, "init_value"),
                    thread::current().name().map(str::to_owned),
                )
            },
            move |r| done((r, thread::current().name().map(str::to_owned))),
        )
        .expect("accepted");
        rxs.push(rx);
    }
    for rx in rxs {
        let (r, done_on) = rx.recv_timeout(LONG).expect("completed");
        let (value, ran_on) = r.expect("ran");
        // The reactor was initialized before the first job.
        assert_eq!(value, Ok(7));
        let ran_on = ran_on.expect("named");
        assert!(ran_on.starts_with("akio-wasm-"), "{ran_on}");
        assert_eq!(done_on.as_deref(), Some(ran_on.as_str()));
    }
    let s = pool.stats();
    assert_eq!((s.calls, s.instances, s.queued, s.running), (30, 3, 0, 0));
    assert_eq!(s.traps.total(), 0);
}

#[test]
fn an_instance_keeps_its_memory_between_jobs() {
    let pool = pool(config(1));
    for want in 1..=3 {
        let (done, rx) = completion();
        pool.submit(|inst| call(inst, "bump"), done)
            .expect("accepted");
        assert_eq!(rx.recv_timeout(LONG).expect("completed"), Ok(Ok(want)));
    }
}

#[test]
fn a_hung_guest_stops_at_its_deadline_and_its_instance_is_remade() {
    let mut c = config(1);
    c.call_timeout = Duration::from_millis(50);
    let pool = pool(c);
    let (done, rx) = completion();
    pool.submit(|inst| call(inst, "bump"), done)
        .expect("accepted");
    assert_eq!(rx.recv_timeout(LONG).expect("completed"), Ok(Ok(1)));

    let started = Instant::now();
    let (done, rx) = completion();
    pool.submit(|inst| (inst.id(), call_unit(inst, "spin")), done)
        .expect("accepted");
    let (first, r) = rx.recv_timeout(LONG).expect("completed").expect("ran");
    assert_eq!(r, Err(Trap::Deadline));
    let took = started.elapsed();
    assert!(took >= Duration::from_millis(50), "{took:?}");
    assert!(took < LONG, "{took:?}");

    // The next job finds a new instance: its memory starts again, its id is the next making.
    let (done, rx) = completion();
    pool.submit(|inst| (inst.id(), call(inst, "bump")), done)
        .expect("accepted");
    let (second, r) = rx.recv_timeout(LONG).expect("completed").expect("ran");
    assert_eq!(r, Ok(1));
    assert_eq!(second.index(), first.index());
    assert_eq!(second.generation(), first.generation() + 1);
    let s = pool.stats();
    assert_eq!((s.traps.deadline, s.traps.total(), s.remade), (1, 1, 1));
    assert_eq!(s.calls, 3);
}

#[test]
fn a_full_queue_refuses_at_once() {
    let mut c = config(1);
    c.queue = 2;
    c.instance_queue = 1;
    let pool = pool(c);
    let (id, go, first) = block(&pool, |_| ());
    let mut queued = Vec::new();
    for _ in 0..2 {
        let (done, rx) = completion();
        pool.submit(|inst| call(inst, "bump"), done)
            .expect("accepted");
        queued.push(rx);
    }
    let started = Instant::now();
    let (done, rx) = completion();
    let refused = pool
        .submit(|inst| call(inst, "bump"), done)
        .expect_err("the queue is full");
    assert!(started.elapsed() < Duration::from_secs(1));
    assert_eq!(refused.reason, Refusal::Overloaded);
    // Handed back unrun: the caller answers through the completion itself.
    (refused.done)(Err(JobError::Closed));
    assert_eq!(
        rx.recv_timeout(LONG).expect("answered"),
        Err(JobError::Closed)
    );

    // The instance's own queue is bounded too.
    let (done, to_rx) = completion();
    pool.submit_to(id, |inst| call(inst, "bump"), done)
        .expect("accepted");
    let (done, _rx) = completion::<Result<Result<i32, Trap>, JobError>>();
    let refused = pool
        .submit_to(id, |inst| call(inst, "bump"), done)
        .expect_err("its queue is full");
    assert_eq!(refused.reason, Refusal::Overloaded);

    let s = pool.stats();
    assert_eq!(
        (s.queued, s.instance_queued.clone(), s.running),
        (2, vec![1], 1)
    );
    assert_eq!(s.refused, 2);

    go.send(()).expect("the job waits");
    first.recv_timeout(LONG).expect("completed").expect("ran");
    // The instance's own job first, then the shared ones, in order.
    assert_eq!(to_rx.recv_timeout(LONG).expect("completed"), Ok(Ok(1)));
    for (rx, want) in queued.into_iter().zip(2..) {
        assert_eq!(rx.recv_timeout(LONG).expect("completed"), Ok(Ok(want)));
    }
}

#[test]
fn a_job_that_waits_too_long_is_handed_back_while_the_instance_is_busy() {
    let mut c = config(1);
    c.wait_timeout = Duration::from_millis(500);
    let pool = pool(c);
    let (id, go, first) = block(&pool, |_| ());
    let started = Instant::now();
    let (done, rx) = completion();
    pool.submit(|inst| call(inst, "bump"), done)
        .expect("accepted");
    let (done, to_rx) = completion();
    pool.submit_to(id, |inst| call(inst, "bump"), done)
        .expect("accepted");
    // Both come back while the only instance is still busy.
    assert_eq!(
        rx.recv_timeout(LONG).expect("handed back"),
        Err(JobError::Expired)
    );
    assert_eq!(
        to_rx.recv_timeout(LONG).expect("handed back"),
        Err(JobError::Expired)
    );
    let took = started.elapsed();
    assert!(took >= Duration::from_millis(500), "{took:?}");
    let s = pool.stats();
    assert_eq!((s.expired, s.queued, s.running), (2, 0, 1));
    go.send(()).expect("the job waits");
    first.recv_timeout(LONG).expect("completed").expect("ran");
    // Nothing else ran.
    let (done, rx) = completion();
    pool.submit(|inst| call(inst, "bump"), done)
        .expect("accepted");
    assert_eq!(rx.recv_timeout(LONG).expect("completed"), Ok(Ok(1)));
}

#[test]
fn submit_to_goes_ahead_of_the_shared_queue() {
    let pool = pool(config(1));
    let (id, go, first) = block(&pool, |_| ());
    let order = Arc::new(std::sync::Mutex::new(Vec::new()));
    let mut rxs = Vec::new();
    for (name, to) in [("shared 1", false), ("own", true), ("shared 2", false)] {
        let o = Arc::clone(&order);
        let job = move |inst: &mut Pooled<()>| {
            assert_eq!(inst.id(), id);
            o.lock().expect("lock").push(name);
        };
        let (done, rx) = completion();
        if to {
            pool.submit_to(id, job, done).expect("accepted");
        } else {
            pool.submit(job, done).expect("accepted");
        }
        rxs.push(rx);
    }
    go.send(()).expect("the job waits");
    first.recv_timeout(LONG).expect("completed").expect("ran");
    for rx in rxs {
        rx.recv_timeout(LONG).expect("completed").expect("ran");
    }
    assert_eq!(
        *order.lock().expect("lock"),
        ["own", "shared 1", "shared 2"]
    );
}

#[test]
fn jobs_for_an_instance_that_trapped_are_told_it_was_remade() {
    let pool = pool(config(2));
    // The job traps after the test has queued another for its instance.
    let (id, go, first) = block(&pool, |inst| call_unit(inst, "trap"));
    let (done, rx) = completion();
    pool.submit_to(id, |inst| call(inst, "bump"), done)
        .expect("accepted");
    go.send(()).expect("the job waits");
    assert_eq!(
        first.recv_timeout(LONG).expect("completed"),
        Ok(Err(Trap::Unreachable))
    );
    assert_eq!(
        rx.recv_timeout(LONG).expect("handed back"),
        Err(JobError::Remade)
    );
    // The old id is refused at once, and the new instance takes jobs.
    wait_for("the remade instance", || pool.stats().instances == 2);
    let (done, _rx) = completion::<Result<(), JobError>>();
    let refused = pool.submit_to(id, |_| (), done).expect_err("remade");
    assert_eq!(refused.reason, Refusal::Remade);
    let s = pool.stats();
    assert_eq!((s.traps.unreachable, s.remade), (1, 1));
}

#[test]
fn a_panicking_job_is_reported_and_its_instance_remade() {
    let pool = pool(config(1));
    let (done, rx) = completion();
    pool.submit(
        |inst| {
            call(inst, "bump").expect("bumps");
            panic!("the job panics");
        },
        done,
    )
    .expect("accepted");
    assert_eq!(
        rx.recv_timeout(LONG).expect("completed"),
        Err::<(), _>(JobError::Panicked)
    );
    let (done, rx) = completion();
    pool.submit(|inst| call(inst, "bump"), done)
        .expect("accepted");
    assert_eq!(rx.recv_timeout(LONG).expect("completed"), Ok(Ok(1)));
    let s = pool.stats();
    assert_eq!((s.panics, s.remade, s.traps.total()), (1, 1, 0));
}

#[test]
fn discard_remakes_the_instance_without_a_trap() {
    let pool = pool(config(1));
    let (done, rx) = completion();
    pool.submit(
        |inst| {
            let r = call(inst, "bump");
            inst.discard();
            r
        },
        done,
    )
    .expect("accepted");
    assert_eq!(rx.recv_timeout(LONG).expect("completed"), Ok(Ok(1)));
    let (done, rx) = completion();
    pool.submit(|inst| call(inst, "bump"), done)
        .expect("accepted");
    assert_eq!(rx.recv_timeout(LONG).expect("completed"), Ok(Ok(1)));
    assert_eq!(pool.stats().remade, 1);
}

#[test]
fn a_module_that_cannot_be_instantiated_fails_the_build() {
    let mut b = Builder::default();
    let t = b.ty(&[], &[]);
    b.import_func("host", "missing", t);
    let m = b.load();
    let err = InstancePool::builder(m, Linker::<()>::new(), |_| ())
        .config(config(2))
        .build()
        .expect_err("an unknown import");
    assert!(
        matches!(&err, StartError::Instantiate(InstantiateError::UnknownImport { name, .. }) if &**name == "missing"),
        "{err}"
    );
}

#[test]
fn an_initialization_that_runs_past_its_deadline_fails_the_build() {
    let mut c = config(1);
    c.init_timeout = Duration::from_millis(30);
    c.start_attempts = 2;
    let started = Instant::now();
    let err = InstancePool::builder(guest(true), Linker::<()>::new(), |_| ())
        .config(c)
        .build()
        .expect_err("_initialize never returns");
    assert_eq!(err, StartError::Trap(Trap::Deadline));
    assert!(started.elapsed() >= Duration::from_millis(60));
}

#[test]
fn an_instance_that_will_not_be_remade_fails_the_pool() {
    let mut c = config(1);
    c.start_attempts = 2;
    let made = Arc::new(AtomicUsize::new(0));
    let m = Arc::clone(&made);
    let pool = InstancePool::builder(guest(false), Linker::new(), |_| ())
        .config(c)
        .on_start(move |_| {
            // The first making succeeds, every later one fails.
            if m.fetch_add(1, Ordering::SeqCst) == 0 {
                Ok(())
            } else {
                Err(Trap::Host("the plugin's configuration is refused".into()))
            }
        })
        .build()
        .expect("the first making succeeds");
    let (_, go, first) = block(&pool, |inst| call_unit(inst, "trap"));
    let (done, rx) = completion();
    pool.submit(|inst| call(inst, "bump"), done)
        .expect("accepted");
    go.send(()).expect("the job waits");
    assert_eq!(
        first.recv_timeout(LONG).expect("completed"),
        Ok(Err(Trap::Unreachable))
    );
    let want = StartError::Trap(Trap::Host("the plugin's configuration is refused".into()));
    match rx.recv_timeout(LONG).expect("handed back") {
        Err(JobError::Failed(e)) => assert_eq!(*e, want),
        other => panic!("{other:?}"),
    }
    let (done, _rx) = completion::<Result<(), JobError>>();
    let refused = pool.submit(|_| (), done).expect_err("failed");
    assert!(matches!(&refused.reason, Refusal::Failed(e) if **e == want));
    let s = pool.stats();
    assert!(s.failed);
    assert_eq!((s.start_failures, made.load(Ordering::SeqCst)), (2, 3));
}

#[test]
fn closing_hands_queued_jobs_back_and_interrupts_the_running_one() {
    let pool = pool(config(1));
    // A guest that does not return, with a deadline far away: only the interrupt stops it.
    let (_, go, first) = block(&pool, |inst| call_unit(inst, "spin"));
    let mut queued = Vec::new();
    for _ in 0..3 {
        let (done, rx) = completion();
        pool.submit(|inst| call(inst, "bump"), done)
            .expect("accepted");
        queued.push(rx);
    }
    go.send(()).expect("the job waits");
    let started = Instant::now();
    pool.close();
    assert!(started.elapsed() < LONG);
    assert_eq!(
        first.recv_timeout(LONG).expect("completed"),
        Ok(Err(Trap::Interrupted))
    );
    for rx in queued {
        assert_eq!(
            rx.recv_timeout(LONG).expect("handed back"),
            Err(JobError::Closed)
        );
    }
    let (done, _rx) = completion::<Result<(), JobError>>();
    let refused = pool.submit(|_| (), done).expect_err("closed");
    assert_eq!(refused.reason, Refusal::Closed);
    // Closing again, and dropping, do nothing more.
    pool.close();
}

#[test]
fn dropping_the_pool_from_its_own_completion_does_not_deadlock() {
    let pool = Arc::new(pool(config(1)));
    let (done, rx) = completion();
    let p = Arc::clone(&pool);
    pool.submit(
        |inst| call(inst, "bump"),
        move |r| {
            // The last handle may go in a completion, on the pool's thread.
            drop(p);
            done(r);
        },
    )
    .expect("accepted");
    drop(pool);
    assert_eq!(rx.recv_timeout(LONG).expect("completed"), Ok(Ok(1)));
}

#[test]
fn the_pool_is_shared_between_threads() {
    fn shared<T: Send + Sync>() {}
    shared::<InstancePool<std::rc::Rc<()>>>();
    let pool = Arc::new(pool(config(4)));
    let total = Arc::new(AtomicUsize::new(0));
    let submitters: Vec<_> = (0..4)
        .map(|_| {
            let pool = Arc::clone(&pool);
            let total = Arc::clone(&total);
            thread::spawn(move || {
                let mut rxs = Vec::new();
                for _ in 0..50 {
                    let (done, rx) = completion();
                    let t = Arc::clone(&total);
                    pool.submit(
                        move |inst| {
                            call(inst, "bump").expect("bumps");
                            t.fetch_add(1, Ordering::SeqCst);
                        },
                        done,
                    )
                    .expect("accepted");
                    rxs.push(rx);
                }
                for rx in rxs {
                    rx.recv_timeout(LONG).expect("completed").expect("ran");
                }
            })
        })
        .collect();
    for s in submitters {
        s.join().expect("the submitter");
    }
    assert_eq!(total.load(Ordering::SeqCst), 200);
    assert_eq!(pool.stats().calls, 200);
}
