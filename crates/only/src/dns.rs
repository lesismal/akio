//! Name resolution off the calling thread (ADR-010).
//!
//! [`resolve`] hands a `host:port` lookup to a small process-wide pool of resolver threads and
//! calls back with the addresses, so a client never blocks an I/O thread (or its caller) in
//! `getaddrinfo`. IP literals are answered on the calling thread without a hop. The pool has no
//! dependency: up to [`MAX_THREADS`] threads named `only-dns`, started on demand, each leaving
//! after [`IDLE`] without work.
//!
//! ```no_run
//! only::dns::resolve("example.com", 443, |r| match r {
//!     Ok(addrs) => println!("{addrs:?}"),
//!     Err(e) => eprintln!("{e}"),
//! });
//! ```

use std::{
    collections::VecDeque,
    io,
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    sync::{Condvar, Mutex, OnceLock},
    time::Duration,
};

/// Most resolver threads running at once.
pub const MAX_THREADS: usize = 4;
/// How long an idle resolver thread waits for work before it exits.
pub const IDLE: Duration = Duration::from_secs(10);

type Done = Box<dyn FnOnce(io::Result<Vec<SocketAddr>>) + Send>;

struct Job {
    host: String,
    port: u16,
    done: Done,
}

#[derive(Default)]
struct State {
    queue: VecDeque<Job>,
    threads: usize,
    idle: usize,
}

struct Pool {
    state: Mutex<State>,
    cv: Condvar,
}

fn pool() -> &'static Pool {
    static POOL: OnceLock<Pool> = OnceLock::new();
    POOL.get_or_init(|| Pool {
        state: Mutex::new(State::default()),
        cv: Condvar::new(),
    })
}

/// An IP literal (`127.0.0.1`, `::1`, `[::1]`), parsed without a lookup.
pub fn literal(host: &str) -> Option<IpAddr> {
    host.strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host)
        .parse()
        .ok()
}

/// Resolves `host` (a name or an IP literal) with `port` and calls `done` with every address in
/// the order the system returned them (an empty answer is an `io::ErrorKind::NotFound` error).
///
/// IP literals are answered at once on the calling thread; names are looked up on a resolver
/// thread, which also runs `done` (keep it short: it should only start the next step, such as
/// `Engine::dial`). A lookup cannot be cancelled; a caller that gave up ignores the late answer.
pub fn resolve(
    host: &str,
    port: u16,
    done: impl FnOnce(io::Result<Vec<SocketAddr>>) + Send + 'static,
) {
    if let Some(ip) = literal(host) {
        return done(Ok(vec![SocketAddr::new(ip, port)]));
    }
    let p = pool();
    let mut st = p.state.lock().unwrap_or_else(|e| e.into_inner());
    st.queue.push_back(Job {
        host: host.to_owned(),
        port,
        done: Box::new(done),
    });
    if st.idle > 0 {
        p.cv.notify_one();
        return;
    }
    if st.threads < MAX_THREADS {
        st.threads += 1;
        drop(st);
        let spawned = std::thread::Builder::new()
            .name("only-dns".into())
            .spawn(worker);
        if spawned.is_err() {
            // No thread: run what is queued here rather than never answering.
            let mut st = p.state.lock().unwrap_or_else(|e| e.into_inner());
            st.threads -= 1;
            let jobs: Vec<Job> = if st.threads == 0 {
                st.queue.drain(..).collect()
            } else {
                Vec::new()
            };
            drop(st);
            jobs.into_iter().for_each(run);
        }
    }
    // Otherwise every thread is busy; the first to finish takes the job.
}

fn lookup(host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    let addrs: Vec<SocketAddr> = (host, port).to_socket_addrs()?.collect();
    if addrs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("{host} did not resolve"),
        ));
    }
    Ok(addrs)
}

fn run(job: Job) {
    let r = lookup(&job.host, job.port);
    (job.done)(r);
}

fn worker() {
    let p = pool();
    let mut st = p.state.lock().unwrap_or_else(|e| e.into_inner());
    loop {
        if let Some(job) = st.queue.pop_front() {
            drop(st);
            run(job);
            st = p.state.lock().unwrap_or_else(|e| e.into_inner());
            continue;
        }
        st.idle += 1;
        let (g, t) =
            p.cv.wait_timeout(st, IDLE)
                .unwrap_or_else(|e| e.into_inner());
        st = g;
        st.idle -= 1;
        if t.timed_out() && st.queue.is_empty() {
            st.threads -= 1;
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    #[test]
    fn literals_resolve_inline() {
        let (tx, rx) = mpsc::channel();
        let me = std::thread::current().id();
        resolve("[::1]", 80, move |r| {
            tx.send((r.map(|a| a[0]).ok(), std::thread::current().id()))
                .ok();
        });
        let (a, t) = rx.try_recv().expect("answered inline");
        assert_eq!(a, Some("[::1]:80".parse().unwrap()));
        assert_eq!(t, me);
        assert_eq!(literal("10.1.2.3"), Some("10.1.2.3".parse().unwrap()));
        assert_eq!(literal("example.com"), None);
    }

    #[test]
    fn names_resolve_on_a_resolver_thread() {
        let (tx, rx) = mpsc::channel();
        for _ in 0..16 {
            let tx = tx.clone();
            resolve("localhost", 8080, move |r| {
                let name = std::thread::current().name().map(str::to_owned);
                tx.send((r.map(|a| a.iter().all(|a| a.port() == 8080)).ok(), name))
                    .ok();
            });
        }
        for _ in 0..16 {
            let (ok, name) = rx.recv_timeout(Duration::from_secs(10)).unwrap();
            assert_eq!(ok, Some(true));
            assert_eq!(name.as_deref(), Some("only-dns"));
        }
        let (tx, rx) = mpsc::channel();
        resolve("no-such-host.invalid", 1, move |r| {
            tx.send(r.is_err()).ok();
        });
        assert!(rx.recv_timeout(Duration::from_secs(30)).unwrap());
    }
}
