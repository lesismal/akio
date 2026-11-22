//! `init_from_env`: the `AKIO_LOG` directives, end to end. Each case runs this test binary
//! again as a child process with the variable set (setting it in-process is unsafe in edition
//! 2024) and checks the lines the child's `FmtLogger` writes to stderr.
#![allow(missing_docs)]

use std::process::Command;

use akio_log::{Level, LevelFilter};

/// Which child case to run; unset in the parent.
const CASE: &str = "AKIO_LOG_TEST_CASE";

fn child() {
    akio_log::init_from_env(LevelFilter::Warn).unwrap();
    println!("max={}", akio_log::max_level());
    akio_log::trace!(target: "akio_quic::conn", "quic conn trace");
    akio_log::trace!(target: "akio_quic::stream", "quic stream trace");
    akio_log::debug!(target: "akio_http::server", k = 1u8; "http debug");
    akio_log::error!(target: "akio_http::access", "access error");
    akio_log::info!(target: "app", "app info");
    akio_log::debug!(target: "app", "app debug");
    akio_log::warn!(target: "app", "app warn");
    println!(
        "enabled={}",
        akio_log::log_enabled!(target: "akio_http", Level::Debug)
    );
    akio_log::flush();
}

/// Runs the child with `AKIO_LOG` set to `value` (or unset): (stdout, stderr lines without
/// timestamps).
fn run(value: Option<&str>) -> (String, Vec<String>) {
    let mut cmd = Command::new(std::env::current_exe().unwrap());
    cmd.args([
        "--exact",
        "env_directives",
        "--nocapture",
        "--test-threads=1",
    ])
    .env(CASE, "1");
    match value {
        Some(v) => cmd.env("AKIO_LOG", v),
        None => cmd.env_remove("AKIO_LOG"),
    };
    let out = cmd.output().unwrap();
    assert!(out.status.success(), "{out:?}");
    let err = String::from_utf8(out.stderr).unwrap();
    let lines = err
        .lines()
        .filter_map(|l| {
            // `2026-...Z LEVEL target: message`, or a line of our own.
            if l.starts_with("akio-log:") {
                Some(l.to_owned())
            } else {
                l.split_once("Z ").map(|(_, rest)| rest.to_owned())
            }
        })
        .collect();
    (String::from_utf8(out.stdout).unwrap(), lines)
}

#[test]
fn env_directives() {
    if std::env::var_os(CASE).is_some() {
        return child();
    }

    let (out, lines) = run(Some(
        "info,akio_http=debug,akio_quic::conn=trace,akio_http::access=off",
    ));
    assert!(out.contains("max=TRACE"), "{out}");
    assert!(out.contains("enabled=true"), "{out}");
    assert_eq!(
        lines,
        [
            "TRACE akio_quic::conn: quic conn trace",
            "DEBUG akio_http::server: http debug k=1",
            "INFO  app: app info",
            "WARN  app: app warn",
        ]
    );

    // Unset: the default level for every target.
    let (out, lines) = run(None);
    assert!(
        out.contains("max=WARN") && out.contains("enabled=false"),
        "{out}"
    );
    assert_eq!(
        lines,
        [
            "ERROR akio_http::access: access error",
            "WARN  app: app warn"
        ]
    );

    // Only a target: the rest is off.
    let (out, lines) = run(Some("akio_http=debug"));
    assert!(out.contains("max=DEBUG"), "{out}");
    assert_eq!(
        lines,
        [
            "DEBUG akio_http::server: http debug k=1",
            "ERROR akio_http::access: access error"
        ]
    );

    // A message regex: matched against the message only (not the target, level or key-values).
    let (out, lines) = run(Some("info,akio_http=debug/(?i)HTTP|app warn"));
    assert!(out.contains("max=DEBUG"), "{out}");
    assert_eq!(
        lines,
        [
            "DEBUG akio_http::server: http debug k=1",
            "WARN  app: app warn"
        ]
    );
    let (_, lines) = run(Some("trace/k=1|akio_quic|TRACE"));
    assert!(lines.is_empty(), "{lines:?}");

    // An invalid message regex: said on stderr, the default is used.
    let (_, lines) = run(Some("info/conn (reset"));
    assert_eq!(
        lines[0],
        "akio-log: ignoring AKIO_LOG: invalid log directive `/conn (reset`: invalid message regex: unclosed group at byte 11"
    );
    assert_eq!(lines.len(), 3, "{lines:?}");

    // Invalid: said on stderr, the default is used.
    let (_, lines) = run(Some("info,akio_http=loud"));
    assert_eq!(
        lines[0],
        "akio-log: ignoring AKIO_LOG: invalid log directive `akio_http=loud`: unknown level"
    );
    assert_eq!(
        &lines[1..],
        [
            "ERROR akio_http::access: access error",
            "WARN  app: app warn"
        ]
    );
}
