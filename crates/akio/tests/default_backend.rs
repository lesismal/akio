//! `AKIO_DEFAULT_BACKEND` (ADR-029): TCP listeners that do not choose a backend follow it;
//! listeners with an explicit backend and UDP listeners do not. The variable is read from the
//! environment when the engine is built and tests must not change their own environment, so
//! each case runs this test binary again as a child process with the variable set.
#![allow(missing_docs)]
#![cfg(target_os = "linux")]

use std::{net::SocketAddr, process::Command, time::Duration};

use akio::{Backend, Config, Conn, Engine, Handler, Listener, UringConfig, fn_acceptor};

/// Set in the child process: only then does `child_report` run.
const CHILD: &str = "AKIO_DEFAULT_BACKEND_TEST_CHILD";

struct Nop;
impl Handler for Nop {
    fn on_data(&mut self, _c: &Conn<Self>, _data: &[u8]) {}
}

fn localhost() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

fn cfg() -> Config {
    let mut c = Config::default();
    c.shutdown_timeout = Duration::from_millis(300);
    c
}

/// The backend names of three listeners: no backend chosen, `Backend::Epoll` chosen
/// explicitly, and a UDP listener without a backend.
fn backends() -> [String; 3] {
    let e = Engine::builder()
        .config(cfg())
        .listen(
            Listener::tcp(localhost())
                .threads(1)
                .serve(fn_acceptor(|_c: &Conn<Nop>| Nop)),
        )
        .listen(
            Listener::tcp(localhost())
                .threads(1)
                .backend(Backend::Epoll)
                .serve(fn_acceptor(|_c: &Conn<Nop>| Nop)),
        )
        .listen(
            Listener::udp(localhost())
                .threads(1)
                .serve(fn_acceptor(|_c: &Conn<Nop>| Nop)),
        )
        .build()
        .unwrap();
    e.start().unwrap();
    let addrs = e.local_addrs();
    let loops = e.metrics().loops;
    let name = |a: SocketAddr| {
        loops
            .iter()
            .find(|l| l.owner.listener == Some(a))
            .map_or_else(|| "none".to_owned(), |l| l.owner.backend.to_owned())
    };
    let out = [name(addrs[0]), name(addrs[1]), name(addrs[2])];
    e.shutdown();
    e.wait();
    out
}

/// Whether this kernel (and sandbox) runs io_uring: a strict io_uring listener builds.
fn uring_available() -> bool {
    let mut u = UringConfig::default();
    u.strict = true;
    Engine::builder()
        .config(cfg())
        .listen(
            Listener::tcp(localhost())
                .threads(1)
                .backend(Backend::IoUring(u))
                .serve(fn_acceptor(|_c: &Conn<Nop>| Nop)),
        )
        .build()
        .is_ok()
}

/// Runs `child_report` in a child process with `AKIO_DEFAULT_BACKEND` set to `value` (unset
/// for `None`) and returns the three backend names it reports.
fn run_child(value: Option<&str>) -> [String; 3] {
    let mut cmd = Command::new(std::env::current_exe().unwrap());
    cmd.args([
        "child_report",
        "--exact",
        "--ignored",
        "--nocapture",
        "--test-threads=1",
    ])
    .env(CHILD, "1")
    .env_remove("AKIO_DEFAULT_BACKEND");
    if let Some(v) = value {
        cmd.env("AKIO_DEFAULT_BACKEND", v);
    }
    let out = cmd.output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "child failed: {stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let line = stdout
        .lines()
        .find_map(|l| l.split_once("BACKENDS ").map(|(_, rest)| rest)) // after libtest's "test child_report ... "
        .unwrap_or_else(|| panic!("no BACKENDS line in {stdout}"));
    let v: Vec<String> = line.split(' ').map(str::to_owned).collect();
    [v[0].clone(), v[1].clone(), v[2].clone()]
}

#[test]
#[ignore = "run by the other tests in a child process"]
fn child_report() {
    if std::env::var_os(CHILD).is_none() {
        return;
    }
    let [a, b, c] = backends();
    println!("BACKENDS {a} {b} {c}");
}

#[test]
fn unset_keeps_epoll() {
    if std::env::var("AKIO_DEFAULT_SCHEDULING").as_deref() == Ok("rounds") {
        return; // rounds listeners report their own backend name (ADR-104)
    }
    assert_eq!(run_child(None), ["epoll", "epoll", "udp"]);
    assert_eq!(run_child(Some("epoll")), ["epoll", "epoll", "udp"]);
}

#[test]
fn uring_applies_only_to_listeners_without_an_explicit_backend() {
    if std::env::var("AKIO_DEFAULT_SCHEDULING").as_deref() == Ok("rounds") {
        return; // rounds listeners report their own backend name (ADR-104)
    }
    // Where io_uring is missing the default listener falls back to epoll (with a warning).
    let want = if uring_available() {
        "io_uring"
    } else {
        "epoll"
    };
    assert_eq!(run_child(Some("uring")), [want, "epoll", "udp"]);
    assert_eq!(run_child(Some("io_uring")), [want, "epoll", "udp"]);
}

#[test]
fn unknown_value_is_ignored() {
    if std::env::var("AKIO_DEFAULT_SCHEDULING").as_deref() == Ok("rounds") {
        return; // rounds listeners report their own backend name (ADR-104)
    }
    assert_eq!(run_child(Some("kqueue")), ["epoll", "epoll", "udp"]);
}
