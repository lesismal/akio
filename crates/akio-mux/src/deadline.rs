//! The sniff deadline. The engine has no per-connection timer, so one watchdog thread per
//! process closes connections still undecided at their deadline. Connections register once at
//! open (in one of [`SHARDS`] lists picked by id) and the data path touches none of this.

use std::{
    sync::{
        Arc, Mutex, OnceLock, Weak,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use akio_core::ConnInner;

const SHARDS: usize = 16;
const MIN_TICK: Duration = Duration::from_millis(10);
const MAX_TICK: Duration = Duration::from_secs(1);

struct Watchdog {
    tick_ms: AtomicU64,
    shards: [Mutex<Vec<Weak<Pending>>>; SHARDS],
}

fn watchdog(tick: Duration) -> &'static Watchdog {
    static W: OnceLock<&'static Watchdog> = OnceLock::new();
    W.get_or_init(|| {
        let w: &'static Watchdog = Box::leak(Box::new(Watchdog {
            tick_ms: AtomicU64::new(tick.as_millis() as u64),
            shards: std::array::from_fn(|_| Mutex::new(Vec::new())),
        }));
        std::thread::Builder::new()
            .name("akio-mux-sniff".into())
            .spawn(move || {
                loop {
                    std::thread::sleep(Duration::from_millis(w.tick_ms.load(Ordering::Relaxed)));
                    let now = Instant::now();
                    for s in &w.shards {
                        s.lock().unwrap_or_else(|p| p.into_inner()).retain(|weak| {
                            let Some(p) = weak.upgrade() else {
                                return false;
                            };
                            if p.done.load(Ordering::Relaxed) || !p.conn.is_open() {
                                return false;
                            }
                            if now >= p.deadline {
                                p.conn.close();
                                return false;
                            }
                            true
                        });
                    }
                }
            })
            .expect("akio-mux sniff thread");
        w
    })
}

/// A connection still being sniffed.
pub(crate) struct Pending {
    conn: Arc<ConnInner>,
    deadline: Instant,
    done: AtomicBool,
}

impl Pending {
    /// Closes `conn` unless [`decided`](Self::decided) is called within `d`.
    pub(crate) fn start(conn: &Arc<ConnInner>, d: Duration) -> Arc<Pending> {
        // The deadline is met within a quarter of the timeout.
        let tick = (d / 4).clamp(MIN_TICK, MAX_TICK);
        let w = watchdog(tick);
        w.tick_ms
            .fetch_min(tick.as_millis() as u64, Ordering::Relaxed);
        let p = Arc::new(Pending {
            conn: conn.clone(),
            deadline: Instant::now() + d,
            done: AtomicBool::new(false),
        });
        w.shards[(conn.id() as usize) % SHARDS]
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(Arc::downgrade(&p));
        p
    }

    /// A route was chosen: the deadline no longer applies.
    pub(crate) fn decided(&self) {
        self.done.store(true, Ordering::Relaxed);
    }
}
