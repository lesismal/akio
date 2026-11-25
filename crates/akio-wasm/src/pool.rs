//! The instance pool (ADR-125, section 4): threads that own instances, the bounded queues that
//! feed them, per-call deadlines, remaking an instance that failed, and the pool's stats.

use std::{
    collections::VecDeque,
    fmt,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use crate::{
    Budget, Func, Instance, InstanceLimits, InstantiateError, InterruptHandle, Linker, Module,
    Store, Trap, TypedFunc, Value, WasmParams, WasmResults,
};

/// How an [`InstancePool`] is sized and how long its jobs may wait and run (ADR-125, section 4;
/// the defaults are fit's).
///
/// ```
/// use std::time::Duration;
///
/// let mut config = akio_wasm::PoolConfig::default();
/// config.instances = 4;
/// config.call_timeout = Duration::from_millis(50);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PoolConfig {
    /// Instances, each with its own thread and memory: the CPUs, at most 16, by default. At
    /// least one.
    pub instances: usize,
    /// Jobs that may wait in the shared queue ([`InstancePool::submit`]), 1024 by default; past
    /// it a job is refused with [`Refusal::Overloaded`], never waited for. At least one.
    pub queue: usize,
    /// Jobs that may wait in each instance's own queue ([`InstancePool::submit_to`]), 1024 by
    /// default. At least one.
    pub instance_queue: usize,
    /// How long a job may wait for its instance (1 s); past it it is handed back as
    /// [`JobError::Expired`] (akit answers `503`), whether or not a thread is free to look.
    pub wait_timeout: Duration,
    /// How long a job may run once started (100 ms): its calls share a deadline this far from
    /// its start ([`Pooled::budget`]), past which a call traps with [`Trap::Deadline`] within a
    /// slice of instructions, and the instance is remade.
    pub call_timeout: Duration,
    /// How long making an instance may run (1 s): instantiating it, a WASI reactor's
    /// `_initialize` and [`PoolBuilder::on_start`] share this deadline.
    pub init_timeout: Duration,
    /// Times in a row an instance may fail to be made (3) before the pool is marked failed:
    /// every queued and later job then gets the error ([`JobError::Failed`]).
    pub start_attempts: u32,
    /// The limits on running each instance's store.
    pub limits: InstanceLimits,
    /// The threads' names, followed by each instance's number (`"akio-wasm-"`).
    pub thread_name: String,
}

impl Default for PoolConfig {
    fn default() -> Self {
        let cores = thread::available_parallelism().map_or(4, std::num::NonZero::get);
        Self {
            instances: cores.min(16),
            queue: 1024,
            instance_queue: 1024,
            wait_timeout: Duration::from_secs(1),
            call_timeout: Duration::from_millis(100),
            init_timeout: Duration::from_secs(1),
            start_attempts: 3,
            limits: InstanceLimits::default(),
            thread_name: "akio-wasm-".to_owned(),
        }
    }
}

/// Which instance of a pool, and which making of it: an instance remade after a trap is another
/// one, with what the first held lost ([`InstancePool::submit_to`] refuses the old id).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct InstanceId {
    index: usize,
    generation: u64,
}

impl InstanceId {
    /// Its place in the pool, `0` to [`PoolConfig::instances`] less one: its thread's.
    #[must_use]
    pub const fn index(&self) -> usize {
        self.index
    }

    /// How many times the instance at this place has been made, this making included.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }
}

/// An instance owned by a pool's thread, as a job sees it: the store, the instance in it, and
/// the job's budget.
///
/// Calls made through it ([`call`](Self::call), [`call_typed`](Self::call_typed)) run under the
/// job's [`budget`](Self::budget): the pool's per-call deadline and its interrupt. A trap ends
/// the store, and the pool remakes the instance once the job has returned.
pub struct Pooled<S> {
    store: Store<S>,
    instance: Instance,
    id: InstanceId,
    budget: Budget,
    discard: bool,
    /// The job panicked.
    panicked: bool,
}

impl<S> fmt::Debug for Pooled<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pooled")
            .field("id", &self.id)
            .field("store", &self.store)
            .field("discard", &self.discard)
            .finish_non_exhaustive()
    }
}

impl<S> Pooled<S> {
    /// Which instance this is.
    #[must_use]
    pub const fn id(&self) -> InstanceId {
        self.id
    }

    /// The instance, in [`store`](Self::store).
    #[must_use]
    pub const fn instance(&self) -> Instance {
        self.instance
    }

    /// The store.
    #[must_use]
    pub const fn store(&self) -> &Store<S> {
        &self.store
    }

    /// The store, to call into it directly; give its calls [`budget`](Self::budget).
    pub fn store_mut(&mut self) -> &mut Store<S> {
        &mut self.store
    }

    /// The host's state.
    #[must_use]
    pub const fn state(&self) -> &S {
        self.store.state()
    }

    /// The host's state, to change.
    pub fn state_mut(&mut self) -> &mut S {
        self.store.state_mut()
    }

    /// The job's budget: a deadline [`PoolConfig::call_timeout`] after the job started (or
    /// [`PoolConfig::init_timeout`] after the making started, in [`PoolBuilder::on_start`]), and
    /// the interrupt raised when the pool closes.
    #[must_use]
    pub const fn budget(&self) -> &Budget {
        &self.budget
    }

    /// The instance's export `name`, if it is a function.
    #[must_use]
    pub fn export_func(&self, name: &str) -> Option<Func> {
        self.store.export_func(self.instance, name)
    }

    /// The instance's export `name` as a [`TypedFunc`], its type checked now; look it up once,
    /// in [`PoolBuilder::on_start`], and keep it in the state.
    ///
    /// # Errors
    ///
    /// [`Trap::BadCall`] if there is no such function or its type is not `P` to `R`.
    pub fn typed_func<P: WasmParams, R: WasmResults>(
        &self,
        name: &str,
    ) -> Result<TypedFunc<P, R>, Trap> {
        let f = self
            .export_func(name)
            .ok_or(Trap::BadCall("no such exported function"))?;
        self.store.typed_func(f)
    }

    /// Calls `f` under the job's budget, as [`Store::call`].
    ///
    /// # Errors
    ///
    /// As [`Store::call`]: a trap ends the store, and the instance is remade after the job.
    pub fn call(&mut self, f: Func, args: &[Value], results: &mut [Value]) -> Result<(), Trap> {
        self.store.call(f, args, results, &self.budget)
    }

    /// Calls `f` under the job's budget, as [`TypedFunc::call`].
    ///
    /// # Errors
    ///
    /// As [`TypedFunc::call`].
    pub fn call_typed<P: WasmParams, R: WasmResults>(
        &mut self,
        f: TypedFunc<P, R>,
        params: P,
    ) -> Result<R, Trap> {
        f.call(&mut self.store, params, &self.budget)
    }

    /// Has the pool remake the instance after this job, as after a trap: for a host that finds
    /// the guest's state wrong without a trap (a Proxy-Wasm call that returned an error).
    pub fn discard(&mut self) {
        self.discard = true;
    }
}

/// Why an [`InstancePool`] could not make an instance.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum StartError {
    /// Instantiating the module failed: an import not defined, a limit, a trap in its start.
    Instantiate(InstantiateError),
    /// `_initialize` or [`PoolBuilder::on_start`] trapped (or ran past
    /// [`PoolConfig::init_timeout`]: [`Trap::Deadline`]).
    Trap(Trap),
    /// The state's maker or [`PoolBuilder::on_start`] panicked.
    Panicked,
    /// A thread could not be started: the operating system's message.
    Thread(Box<str>),
}

impl fmt::Display for StartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Instantiate(e) => write!(f, "instantiating the plugin failed: {e}"),
            Self::Trap(t) => write!(f, "initializing the plugin failed: {t}"),
            Self::Panicked => f.write_str("making the plugin's state panicked"),
            Self::Thread(m) => write!(f, "starting the pool's thread failed: {m}"),
        }
    }
}

impl std::error::Error for StartError {}

/// Why a job accepted by an [`InstancePool`] did not run: what its completion gets instead of
/// its result.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum JobError {
    /// It waited longer than [`PoolConfig::wait_timeout`] for its instance.
    Expired,
    /// The instance it was sent to ([`InstancePool::submit_to`]) was remade before it ran.
    Remade,
    /// The pool closed before it ran.
    Closed,
    /// The pool failed: an instance would not start ([`PoolConfig::start_attempts`]).
    Failed(Arc<StartError>),
    /// It ran and panicked; the instance is remade.
    Panicked,
}

impl fmt::Display for JobError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Expired => f.write_str("waited too long for an instance"),
            Self::Remade => f.write_str("the instance was remade"),
            Self::Closed => f.write_str("the pool closed"),
            Self::Failed(e) => write!(f, "the pool failed: {e}"),
            Self::Panicked => f.write_str("the job panicked"),
        }
    }
}

impl std::error::Error for JobError {}

/// Why an [`InstancePool`] refused a job at once, without queueing it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Refusal {
    /// Its queue is full (akit answers `503`).
    Overloaded,
    /// The instance it names is not the one now at its place: remade, or not made yet.
    Remade,
    /// The pool is closed.
    Closed,
    /// The pool failed.
    Failed(Arc<StartError>),
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Overloaded => f.write_str("the plugin's queue is full"),
            Self::Remade => f.write_str("the instance was remade"),
            Self::Closed => f.write_str("the pool is closed"),
            Self::Failed(e) => write!(f, "the pool failed: {e}"),
        }
    }
}

impl std::error::Error for Refusal {}

/// A job refused by [`InstancePool::submit`] or [`InstancePool::submit_to`], handed back with
/// its completion, neither run.
pub struct Refused<J, D> {
    /// Why.
    pub reason: Refusal,
    /// The job.
    pub job: J,
    /// Its completion: the caller answers through it (or not) itself.
    pub done: D,
}

impl<J, D> fmt::Debug for Refused<J, D> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Refused")
            .field("reason", &self.reason)
            .finish_non_exhaustive()
    }
}

impl<J, D> fmt::Display for Refused<J, D> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.reason, f)
    }
}

impl<J, D> std::error::Error for Refused<J, D> {}

/// The traps the pool's jobs ended in, by kind.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct TrapStats {
    /// [`Trap::Deadline`]: a job ran past [`PoolConfig::call_timeout`].
    pub deadline: u64,
    /// [`Trap::OutOfFuel`].
    pub out_of_fuel: u64,
    /// [`Trap::Interrupted`]: the pool closed while a job ran, or the job's own interrupt.
    pub interrupted: u64,
    /// [`Trap::CallStackExhausted`] and [`Trap::ValueStackExhausted`].
    pub stack_exhausted: u64,
    /// [`Trap::MemoryOutOfBounds`].
    pub memory_out_of_bounds: u64,
    /// [`Trap::Unreachable`]: also how a Go or Rust guest's panic ends.
    pub unreachable: u64,
    /// [`Trap::Host`]: a host function failed.
    pub host: u64,
    /// [`Trap::Exit`]: the guest called `proc_exit`.
    pub exit: u64,
    /// Every other trap: arithmetic, conversions, tables, indirect calls.
    pub other: u64,
}

impl TrapStats {
    /// All of them.
    #[must_use]
    pub const fn total(&self) -> u64 {
        self.deadline
            + self.out_of_fuel
            + self.interrupted
            + self.stack_exhausted
            + self.memory_out_of_bounds
            + self.unreachable
            + self.host
            + self.exit
            + self.other
    }

    fn count(&mut self, t: &Trap) {
        let n = match t {
            Trap::Deadline => &mut self.deadline,
            Trap::OutOfFuel => &mut self.out_of_fuel,
            Trap::Interrupted => &mut self.interrupted,
            Trap::CallStackExhausted | Trap::ValueStackExhausted => &mut self.stack_exhausted,
            Trap::MemoryOutOfBounds => &mut self.memory_out_of_bounds,
            Trap::Unreachable => &mut self.unreachable,
            Trap::Host(_) => &mut self.host,
            Trap::Exit(_) => &mut self.exit,
            _ => &mut self.other,
        };
        *n += 1;
    }
}

/// A snapshot of an [`InstancePool`]'s queues and counters, for metrics.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct PoolStats {
    /// Instances made and ready, not being remade.
    pub instances: usize,
    /// Jobs waiting in the shared queue.
    pub queued: usize,
    /// Jobs waiting in each instance's own queue, by [`InstanceId::index`].
    pub instance_queued: Vec<usize>,
    /// Jobs running now.
    pub running: usize,
    /// Jobs run, finished or not.
    pub calls: u64,
    /// Jobs refused at once ([`Refusal`]).
    pub refused: u64,
    /// Jobs that waited past [`PoolConfig::wait_timeout`].
    pub expired: u64,
    /// The traps jobs ended in.
    pub traps: TrapStats,
    /// Jobs (or their completions) that panicked.
    pub panics: u64,
    /// Instances dropped to be made again, after a trap, a panic or [`Pooled::discard`].
    pub remade: u64,
    /// Attempts at making an instance that failed.
    pub start_failures: u64,
    /// Whether the pool failed.
    pub failed: bool,
}

/// A job and its completion, their types erased: run with the instance, giving back the
/// completion to call with the result once the pool has counted the job; or told why not (and
/// the completion called at once).
type Task<S> = Box<dyn FnOnce(Result<&mut Pooled<S>, JobError>) -> Option<Finish> + Send>;

/// A completion with its result, to call.
type Finish = Box<dyn FnOnce()>;

struct Queued<S> {
    task: Task<S>,
    expires: Instant,
}

type MakeState<S> = dyn Fn(usize) -> S + Send + Sync;
type OnStart<S> = dyn Fn(&mut Pooled<S>) -> Result<(), Trap> + Send + Sync;

struct Slot<S> {
    queue: VecDeque<Queued<S>>,
    generation: u64,
    /// Made and ready: `submit_to` with its generation is accepted.
    live: bool,
    /// In `State::idle`, waiting on its condition variable.
    idle: bool,
    running: bool,
    interrupt: InterruptHandle,
}

struct State<S> {
    shared: VecDeque<Queued<S>>,
    slots: Vec<Slot<S>>,
    /// Threads waiting for a job, the most recent last.
    idle: Vec<usize>,
    /// Threads whose first making is settled, made or failed.
    started: usize,
    closed: bool,
    failed: Option<Arc<StartError>>,
    stats: PoolStats,
}

struct Shared<S> {
    state: Mutex<State<S>>,
    /// One per thread: a job for it, or for any idle one.
    wake: Vec<Condvar>,
    /// The reaper: a queue's first job changed, or the pool closed.
    reap: Condvar,
    /// `build`: a thread's first making is settled.
    started: Condvar,
    config: PoolConfig,
    module: Arc<Module>,
    linker: Linker<S>,
    make_state: Box<MakeState<S>>,
    on_start: Option<Box<OnStart<S>>>,
}

impl<S> Shared<S> {
    fn lock(&self) -> MutexGuard<'_, State<S>> {
        // Nothing panics with the lock held (jobs and completions run without it).
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn wait<'a>(&self, cv: &Condvar, g: MutexGuard<'a, State<S>>) -> MutexGuard<'a, State<S>> {
        cv.wait(g).unwrap_or_else(PoisonError::into_inner)
    }
}

/// Tells a task why it did not run, on this thread; a completion that panics is counted.
fn fail<S>(shared: &Shared<S>, tasks: Vec<Task<S>>, e: &JobError) {
    let mut panics = 0;
    for t in tasks {
        let e = e.clone();
        if catch_unwind(AssertUnwindSafe(|| drop(t(Err(e))))).is_err() {
            panics += 1;
        }
    }
    if panics > 0 {
        shared.lock().stats.panics += panics;
    }
}

/// Moves the expired jobs at the front of `q` (the oldest: every job waits as long) to `out`.
fn take_expired<S>(q: &mut VecDeque<Queued<S>>, now: Instant, out: &mut Vec<Task<S>>) {
    while q.front().is_some_and(|j| j.expires <= now) {
        if let Some(j) = q.pop_front() {
            out.push(j.task);
        }
    }
}

/// A pool of instances of one module, each owned by a thread of its own, that runs jobs given
/// from any thread and hands their results back through a completion (ADR-125, section 4).
///
/// WebAssembly runs on the pool's threads, never on the caller's: an I/O thread submits a job
/// and goes on, and the job's completion, run on the pool's thread when the job is done, hands
/// the result back the way akio does elsewhere, without blocking: through akio-http's
/// `Suspended::resume`, a connection's `ResponseSlot`, or a channel a loop reads.
///
/// - [`submit`](Self::submit) queues a job for any instance, in one bounded queue
///   ([`PoolConfig::queue`]); [`submit_to`](Self::submit_to) queues it for one instance, in its
///   own bounded queue ([`PoolConfig::instance_queue`]), which that instance serves before the
///   shared one (a Proxy-Wasm context belongs to the instance that made it). A full queue
///   refuses the job at once, handing it back ([`Refused`]); nothing waits for room.
/// - A job that has not started within [`PoolConfig::wait_timeout`] is handed back as
///   [`JobError::Expired`] when the wait passes, by a thread of the pool's that watches the
///   queues, even while every instance is busy.
/// - A job runs as `FnOnce(&mut Pooled<S>) -> R`, its calls under a deadline
///   [`PoolConfig::call_timeout`] from its start: a guest that does not return is stopped by the
///   interpreter within a slice of instructions ([`Trap::Deadline`]), and no watchdog is needed.
///   A host function that blocks is not stopped: host functions bound their own work.
/// - An instance whose store a trap ended (or whose job panicked, or that was
///   [`discard`](Pooled::discard)ed) is dropped and made again before its thread takes another
///   job; the jobs queued for it get [`JobError::Remade`]. One that fails to be made
///   [`PoolConfig::start_attempts`] times in a row marks the pool failed: every queued and later
///   job then gets that error.
/// - [`stats`](Self::stats) counts calls, traps by kind, remakes, expiries and refusals, and
///   reads the queues' depths.
///
/// Memory is bounded by the instances times [`InstanceLimits::max_memory`], plus the module,
/// shared. Dropping the pool (or [`close`](Self::close)) refuses new jobs, hands the queued
/// ones back as [`JobError::Closed`], interrupts the running ones and joins the threads.
///
/// ```
/// use std::{sync::{Arc, mpsc}, time::Duration};
/// use akio_wasm::{InstancePool, Linker, Module, ModuleLimits, PoolConfig, Value};
///
/// // (module (func (export "add") (param i32 i32) (result i32)
/// //   local.get 0 local.get 1 i32.add))
/// let bytes = [
///     0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x07, 0x01, 0x60, 0x02, 0x7f, 0x7f,
///     0x01, 0x7f, 0x03, 0x02, 0x01, 0x00, 0x07, 0x07, 0x01, 0x03, b'a', b'd', b'd', 0x00, 0x00,
///     0x0a, 0x09, 0x01, 0x07, 0x00, 0x20, 0x00, 0x20, 0x01, 0x6a, 0x0b,
/// ];
/// let module = Arc::new(Module::new(&bytes, &ModuleLimits::default()).unwrap());
/// let mut config = PoolConfig::default();
/// config.instances = 2;
/// let pool = InstancePool::builder(module, Linker::<()>::new(), |_| ())
///     .config(config)
///     .build()
///     .unwrap();
///
/// // From an I/O thread: submit, and go on; the completion runs on the pool's thread.
/// let (tx, rx) = mpsc::channel();
/// pool.submit(
///     |inst| {
///         let add = inst.typed_func::<(i32, i32), i32>("add")?;
///         inst.call_typed(add, (2, 40))
///     },
///     move |r| tx.send(r).unwrap(),
/// )
/// .unwrap();
/// assert_eq!(rx.recv_timeout(Duration::from_secs(5)).unwrap(), Ok(Ok(42)));
/// assert_eq!(pool.stats().calls, 1);
/// ```
pub struct InstancePool<S: 'static> {
    shared: Arc<Shared<S>>,
    threads: Mutex<Vec<JoinHandle<()>>>,
}

impl<S> fmt::Debug for InstancePool<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InstancePool")
            .field("config", &self.shared.config)
            .finish_non_exhaustive()
    }
}

/// Makes an [`InstancePool`]: [`InstancePool::builder`].
pub struct PoolBuilder<S> {
    config: PoolConfig,
    module: Arc<Module>,
    linker: Linker<S>,
    make_state: Box<MakeState<S>>,
    on_start: Option<Box<OnStart<S>>>,
}

impl<S> fmt::Debug for PoolBuilder<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PoolBuilder")
            .field("config", &self.config)
            .field("on_start", &self.on_start.is_some())
            .finish_non_exhaustive()
    }
}

impl<S: 'static> PoolBuilder<S> {
    /// The pool's sizes and timeouts.
    #[must_use]
    pub fn config(mut self, config: PoolConfig) -> Self {
        self.config = config;
        self
    }

    /// Runs `f` on each instance once it is made (and, for a WASI reactor, initialized), before
    /// its first job, under the making's deadline ([`PoolConfig::init_timeout`]): to look up its
    /// exports, or to start a Proxy-Wasm VM (`proxy_on_vm_start`, `proxy_on_configure`). An
    /// error fails the making, as a trap does.
    #[must_use]
    pub fn on_start(
        mut self,
        f: impl Fn(&mut Pooled<S>) -> Result<(), Trap> + Send + Sync + 'static,
    ) -> Self {
        self.on_start = Some(Box::new(f));
        self
    }

    /// Starts the threads and waits until each has made its instance. Call it off the I/O
    /// threads: making an instance runs its initialization (millions of instructions for a Go
    /// guest).
    ///
    /// # Errors
    ///
    /// The [`StartError`] of an instance that failed [`PoolConfig::start_attempts`] times, or of
    /// a thread that could not be started; the pool is closed then.
    pub fn build(self) -> Result<InstancePool<S>, StartError> {
        let mut config = self.config;
        config.instances = config.instances.max(1);
        config.queue = config.queue.max(1);
        config.instance_queue = config.instance_queue.max(1);
        config.start_attempts = config.start_attempts.max(1);
        let n = config.instances;
        let slots = (0..n)
            .map(|_| Slot {
                queue: VecDeque::new(),
                generation: 0,
                live: false,
                idle: false,
                running: false,
                interrupt: InterruptHandle::new(),
            })
            .collect();
        let shared = Arc::new(Shared {
            state: Mutex::new(State {
                shared: VecDeque::new(),
                slots,
                idle: Vec::with_capacity(n),
                started: 0,
                closed: false,
                failed: None,
                stats: PoolStats {
                    instance_queued: vec![0; n],
                    ..PoolStats::default()
                },
            }),
            wake: (0..n).map(|_| Condvar::new()).collect(),
            reap: Condvar::new(),
            started: Condvar::new(),
            config,
            module: self.module,
            linker: self.linker,
            make_state: self.make_state,
            on_start: self.on_start,
        });
        let pool = InstancePool {
            shared: Arc::clone(&shared),
            threads: Mutex::new(Vec::with_capacity(n + 1)),
        };
        for i in 0..=n {
            let sh = Arc::clone(&shared);
            let (name, run): (String, Box<dyn FnOnce() + Send>) = if i < n {
                (
                    format!("{}{i}", shared.config.thread_name),
                    Box::new(move || serve(&sh, i)),
                )
            } else {
                (
                    format!("{}reaper", shared.config.thread_name),
                    Box::new(move || reap(&sh)),
                )
            };
            match thread::Builder::new().name(name).spawn(run) {
                Ok(h) => pool.lock_threads().push(h),
                Err(e) => {
                    let err = StartError::Thread(e.to_string().into());
                    pool.mark_failed(err.clone());
                    pool.close();
                    return Err(err);
                }
            }
        }
        let mut st = shared.lock();
        while st.started < n && st.failed.is_none() {
            st = shared.wait(&shared.started, st);
        }
        if let Some(e) = st.failed.clone() {
            drop(st);
            pool.close();
            return Err(StartError::clone(&e));
        }
        drop(st);
        Ok(pool)
    }
}

impl<S: 'static> InstancePool<S> {
    /// A builder for a pool of instances of `module`, its imports resolved by `linker`, each
    /// store's state made by `state` from the instance's index (on the instance's thread, each
    /// time it is made).
    pub fn builder(
        module: Arc<Module>,
        linker: Linker<S>,
        state: impl Fn(usize) -> S + Send + Sync + 'static,
    ) -> PoolBuilder<S> {
        PoolBuilder {
            config: PoolConfig::default(),
            module,
            linker,
            make_state: Box::new(state),
            on_start: None,
        }
    }

    /// The pool's configuration, as built (each count at least one).
    #[must_use]
    pub fn config(&self) -> &PoolConfig {
        &self.shared.config
    }

    /// The module its instances are made of.
    #[must_use]
    pub fn module(&self) -> &Arc<Module> {
        &self.shared.module
    }

    /// Queues `job` for the first free instance, and returns at once. On a pool thread, `job`
    /// runs with the instance under the job's deadline, then `done` gets its result (the job
    /// already counted in [`stats`](Self::stats), the instance remade only after `done`); if it does
    /// not run, `done` gets why ([`JobError`]), on the thread that found out. `done` hands the
    /// result on and returns: it must not block, it holds the instance (or the pool's reaper).
    ///
    /// # Errors
    ///
    /// [`Refused`], with `job` and `done` unrun, if the shared queue is full, the pool is
    /// closed, or it failed.
    pub fn submit<R, J, D>(&self, job: J, done: D) -> Result<(), Refused<J, D>>
    where
        R: 'static,
        J: FnOnce(&mut Pooled<S>) -> R + Send + 'static,
        D: FnOnce(Result<R, JobError>) + Send + 'static,
    {
        let sh = &self.shared;
        let mut st = sh.lock();
        if let Err(reason) = st.accepting() {
            st.stats.refused += 1;
            return Err(Refused { reason, job, done });
        }
        if st.shared.len() >= sh.config.queue {
            st.stats.refused += 1;
            return Err(Refused {
                reason: Refusal::Overloaded,
                job,
                done,
            });
        }
        let first = st.shared.is_empty();
        st.shared.push_back(Queued {
            task: erase(job, done),
            expires: Instant::now() + sh.config.wait_timeout,
        });
        if let Some(i) = st.idle.pop() {
            st.slots[i].idle = false;
            sh.wake[i].notify_one();
        }
        drop(st);
        if first {
            sh.reap.notify_one();
        }
        Ok(())
    }

    /// Queues `job` for the instance `id` (from [`Pooled::id`]), served before the shared
    /// queue, as [`submit`](Self::submit) otherwise. If the instance is remade before the job
    /// runs, `done` gets [`JobError::Remade`].
    ///
    /// # Errors
    ///
    /// [`Refused`], with `job` and `done` unrun, if that instance's queue is full, it is not
    /// the one now at its place ([`Refusal::Remade`]), or the pool is closed or failed.
    pub fn submit_to<R, J, D>(&self, id: InstanceId, job: J, done: D) -> Result<(), Refused<J, D>>
    where
        R: 'static,
        J: FnOnce(&mut Pooled<S>) -> R + Send + 'static,
        D: FnOnce(Result<R, JobError>) + Send + 'static,
    {
        let sh = &self.shared;
        let mut st = sh.lock();
        let reason = match st.accepting() {
            Err(r) => Some(r),
            Ok(()) => match st.slots.get(id.index) {
                Some(s) if s.live && s.generation == id.generation => {
                    (s.queue.len() >= sh.config.instance_queue).then_some(Refusal::Overloaded)
                }
                _ => Some(Refusal::Remade),
            },
        };
        if let Some(reason) = reason {
            st.stats.refused += 1;
            return Err(Refused { reason, job, done });
        }
        let slot = &mut st.slots[id.index];
        let first = slot.queue.is_empty();
        slot.queue.push_back(Queued {
            task: erase(job, done),
            expires: Instant::now() + sh.config.wait_timeout,
        });
        if slot.idle {
            slot.idle = false;
            st.idle.retain(|&x| x != id.index);
            sh.wake[id.index].notify_one();
        }
        drop(st);
        if first {
            sh.reap.notify_one();
        }
        Ok(())
    }

    /// The queues' depths and the counters now.
    #[must_use]
    pub fn stats(&self) -> PoolStats {
        let st = self.shared.lock();
        let mut s = st.stats.clone();
        s.instances = st.slots.iter().filter(|x| x.live).count();
        s.queued = st.shared.len();
        for (q, slot) in s.instance_queued.iter_mut().zip(&st.slots) {
            *q = slot.queue.len();
        }
        s.running = st.slots.iter().filter(|x| x.running).count();
        s.failed = st.failed.is_some();
        s
    }

    /// Refuses new jobs, hands the queued ones back as [`JobError::Closed`], interrupts the
    /// running ones (their calls trap with [`Trap::Interrupted`] within a slice) and waits for
    /// the threads to end, unless called from one of them. Dropping the pool does this.
    pub fn close(&self) {
        let sh = &self.shared;
        let mut st = sh.lock();
        let mut tasks = Vec::new();
        if !st.closed {
            st.closed = true;
            tasks.extend(st.shared.drain(..).map(|q| q.task));
            for s in &mut st.slots {
                tasks.extend(s.queue.drain(..).map(|q| q.task));
                s.interrupt.interrupt();
            }
            for cv in &sh.wake {
                cv.notify_all();
            }
            sh.reap.notify_all();
            sh.started.notify_all();
        }
        drop(st);
        fail(sh, tasks, &JobError::Closed);
        let me = thread::current().id();
        let threads = std::mem::take(&mut *self.lock_threads());
        for h in threads {
            if h.thread().id() != me {
                let _ = h.join();
            }
        }
    }

    fn lock_threads(&self) -> MutexGuard<'_, Vec<JoinHandle<()>>> {
        self.threads.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn mark_failed(&self, e: StartError) {
        let tasks = mark_failed(&self.shared, e.clone());
        fail(&self.shared, tasks, &JobError::Failed(Arc::new(e)));
    }
}

impl<S: 'static> Drop for InstancePool<S> {
    fn drop(&mut self) {
        self.close();
    }
}

impl<S> State<S> {
    fn accepting(&self) -> Result<(), Refusal> {
        if let Some(e) = &self.failed {
            return Err(Refusal::Failed(Arc::clone(e)));
        }
        if self.closed {
            return Err(Refusal::Closed);
        }
        Ok(())
    }
}

/// Marks the pool failed with `e` and takes every queued job, for the caller to fail.
fn mark_failed<S>(sh: &Shared<S>, e: StartError) -> Vec<Task<S>> {
    let mut st = sh.lock();
    let mut tasks = Vec::new();
    if st.failed.is_none() {
        st.failed = Some(Arc::new(e));
    }
    tasks.extend(st.shared.drain(..).map(|q| q.task));
    for s in &mut st.slots {
        tasks.extend(s.queue.drain(..).map(|q| q.task));
    }
    for cv in &sh.wake {
        cv.notify_all();
    }
    sh.reap.notify_all();
    sh.started.notify_all();
    tasks
}

/// `job` and `done` as one task: the job's panic is caught and reported to `done`.
fn erase<S, R, J, D>(job: J, done: D) -> Task<S>
where
    S: 'static,
    R: 'static,
    J: FnOnce(&mut Pooled<S>) -> R + Send + 'static,
    D: FnOnce(Result<R, JobError>) + Send + 'static,
{
    Box::new(move |r: Result<&mut Pooled<S>, JobError>| match r {
        Ok(p) => {
            let out = catch_unwind(AssertUnwindSafe(|| job(&mut *p)));
            let out = out.map_err(|_| {
                p.panicked = true;
                JobError::Panicked
            });
            Some(Box::new(move || done(out)) as Finish)
        }
        Err(e) => {
            done(Err(e));
            None
        }
    })
}

/// Makes instance `index`: a store, the instance, `_initialize`, `on_start`.
fn make<S>(
    sh: &Shared<S>,
    index: usize,
    generation: u64,
    interrupt: &InterruptHandle,
) -> Result<Pooled<S>, StartError> {
    let cfg = &sh.config;
    let budget = Budget::deadline(Instant::now() + cfg.init_timeout).with_interrupt(interrupt);
    let made = catch_unwind(AssertUnwindSafe(|| -> Result<Pooled<S>, StartError> {
        let mut store = Store::new((sh.make_state)(index), cfg.limits.clone());
        let instance = sh
            .linker
            .instantiate(&mut store, &sh.module, &budget)
            .map_err(StartError::Instantiate)?;
        store
            .initialize_reactor(instance, &budget)
            .map_err(StartError::Trap)?;
        let mut p = Pooled {
            store,
            instance,
            id: InstanceId { index, generation },
            budget: budget.clone(),
            discard: false,
            panicked: false,
        };
        if let Some(f) = &sh.on_start {
            f(&mut p).map_err(StartError::Trap)?;
            if let Some(t) = p.store.trap() {
                return Err(StartError::Trap(t.clone()));
            }
        }
        Ok(p)
    }));
    made.unwrap_or(Err(StartError::Panicked))
}

/// Instance `index`'s thread: makes it, serves its queue and the shared one, remakes it.
fn serve<S: 'static>(sh: &Shared<S>, index: usize) {
    let cfg = &sh.config;
    let interrupt = sh.lock().slots[index].interrupt.clone();
    let mut first = true;
    let mut failures = 0;
    let mut inst: Option<Pooled<S>> = None;
    let mut expired = Vec::new();
    loop {
        let mut p = if let Some(p) = inst.take() {
            p
        } else {
            let generation = {
                let st = sh.lock();
                if st.closed || st.failed.is_some() {
                    return;
                }
                st.slots[index].generation + 1
            };
            match make(sh, index, generation, &interrupt) {
                Ok(p) => {
                    failures = 0;
                    let mut st = sh.lock();
                    let s = &mut st.slots[index];
                    s.generation = generation;
                    s.live = true;
                    if first {
                        first = false;
                        st.started += 1;
                        sh.started.notify_all();
                    }
                    p
                }
                Err(e) => {
                    failures += 1;
                    sh.lock().stats.start_failures += 1;
                    if failures >= cfg.start_attempts {
                        let tasks = mark_failed(sh, e.clone());
                        fail(sh, tasks, &JobError::Failed(Arc::new(e)));
                        return;
                    }
                    continue;
                }
            }
        };
        // Wait for a job: this instance's own first, then the shared queue's.
        let mut st = sh.lock();
        let task = loop {
            if st.closed || st.failed.is_some() {
                break None;
            }
            let now = Instant::now();
            take_expired(&mut st.slots[index].queue, now, &mut expired);
            if let Some(q) = st.slots[index].queue.pop_front() {
                break Some(q.task);
            }
            take_expired(&mut st.shared, now, &mut expired);
            if let Some(q) = st.shared.pop_front() {
                break Some(q.task);
            }
            if !expired.is_empty() {
                st.stats.expired += expired.len() as u64;
                drop(st);
                fail(sh, std::mem::take(&mut expired), &JobError::Expired);
                st = sh.lock();
                continue;
            }
            let slot = &mut st.slots[index];
            if !slot.idle {
                slot.idle = true;
                st.idle.push(index);
            }
            st = sh.wait(&sh.wake[index], st);
        };
        let Some(task) = task else {
            st.slots[index].live = false;
            return;
        };
        let slot = &mut st.slots[index];
        slot.running = true;
        if slot.idle {
            slot.idle = false;
            st.idle.retain(|&x| x != index);
        }
        st.stats.expired += expired.len() as u64;
        drop(st);
        fail(sh, std::mem::take(&mut expired), &JobError::Expired);

        p.budget = Budget::deadline(Instant::now() + cfg.call_timeout).with_interrupt(&interrupt);
        let finish = task(Ok(&mut p));

        // Count the job before its completion runs, so that whoever gets the result sees it in
        // the stats; then hand the result back, then remake the instance if it must be.
        let mut remake = p.discard || p.panicked || p.store.ended();
        let mut st = sh.lock();
        st.stats.calls += 1;
        st.stats.panics += u64::from(p.panicked);
        if let Some(t) = p.store.trap() {
            st.stats.traps.count(t);
        }
        st.slots[index].running = false;
        let mut gone = if remake {
            retire(&mut st, index)
        } else {
            Vec::new()
        };
        drop(st);
        let completion_panicked =
            finish.is_some_and(|f| catch_unwind(AssertUnwindSafe(f)).is_err());
        if completion_panicked {
            // The completion may have left the host's state half-updated too.
            let mut st = sh.lock();
            st.stats.panics += 1;
            if !remake {
                remake = true;
                gone = retire(&mut st, index);
            }
        }
        if remake {
            drop(p);
            fail(sh, gone, &JobError::Remade);
        } else {
            inst = Some(p);
        }
    }
}

/// Takes instance `index` out of service to be remade: refuses `submit_to` for it, and gives
/// back the jobs queued for it.
fn retire<S>(st: &mut State<S>, index: usize) -> Vec<Task<S>> {
    let slot = &mut st.slots[index];
    slot.live = false;
    let gone = slot.queue.drain(..).map(|q| q.task).collect();
    st.stats.remade += 1;
    gone
}

/// The reaper: hands back the jobs that waited past their time while every instance is busy.
fn reap<S>(sh: &Shared<S>) {
    let mut st = sh.lock();
    loop {
        if st.closed || st.failed.is_some() {
            return;
        }
        let now = Instant::now();
        let mut expired = Vec::new();
        take_expired(&mut st.shared, now, &mut expired);
        for s in &mut st.slots {
            take_expired(&mut s.queue, now, &mut expired);
        }
        if !expired.is_empty() {
            st.stats.expired += expired.len() as u64;
            drop(st);
            fail(sh, expired, &JobError::Expired);
            st = sh.lock();
            continue;
        }
        let next = st
            .slots
            .iter()
            .filter_map(|s| s.queue.front())
            .chain(st.shared.front())
            .map(|q| q.expires)
            .min();
        st = match next {
            None => sh.wait(&sh.reap, st),
            Some(at) => {
                sh.reap
                    .wait_timeout(st, at.saturating_duration_since(now))
                    .unwrap_or_else(PoisonError::into_inner)
                    .0
            }
        };
    }
}
