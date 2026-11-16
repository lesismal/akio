//! `init_from_env`: the `ONLY_LOG` directives, end to end. Each case runs this test binary
//! again as a child process with the variable set (setting it in-process is unsafe in edition
//! 2024) and checks the lines the child's `FmtLogger` writes to stderr.
#![allow(missing_docs)]

use std::process::Command;

use only_log::{Level, LevelFilter};

/// Which child case to run; unset in the parent.
const CASE: &str = "ONLY_LOG_TEST_CASE";

fn child() {
    only_log::init_from_env(LevelFilter::Warn).unwrap();
    println!("max={}", only_log::max_level());
    only_log::trace!(target: "only_quic::conn", "quic conn trace");
    only_log::trace!(target: "only_quic::stream", "quic stream trace");
    only_log::debug!(target: "only_http::server", k = 1u8; "http debug");
    only_log::error!(target: "only_http::access", "access error");
    only_log::info!(target: "app", "app info");
    only_log::debug!(target: "app", "app debug");
    only_log::warn!(target: "app", "app warn");
    println!(
        "enabled={}",
        only_log::log_enabled!(target: "only_http", Level::Debug)
    );
    only_log::flush();
}

/// Runs the child with `ONLY_LOG` set to `value` (or unset): (stdout, stderr lines without
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
        Some(v) => cmd.env("ONLY_LOG", v),
        None => cmd.env_remove("ONLY_LOG"),
    };
    let out = cmd.output().unwrap();
    assert!(out.status.success(), "{out:?}");
    let err = String::from_utf8(out.stderr).unwrap();
    let lines = err
        .lines()
        .filter_map(|l| {
            // `2026-...Z LEVEL target: message`, or a line of our own.
            if l.starts_with("only-log:") {
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
        "info,only_http=debug,only_quic::conn=trace,only_http::access=off",
    ));
    assert!(out.contains("max=TRACE"), "{out}");
    assert!(out.contains("enabled=true"), "{out}");
    assert_eq!(
        lines,
        [
            "TRACE only_quic::conn: quic conn trace",
            "DEBUG only_http::server: http debug k=1",
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
            "ERROR only_http::access: access error",
            "WARN  app: app warn"
        ]
    );

    // Only a target: the rest is off.
    let (out, lines) = run(Some("only_http=debug"));
    assert!(out.contains("max=DEBUG"), "{out}");
    assert_eq!(
        lines,
        [
            "DEBUG only_http::server: http debug k=1",
            "ERROR only_http::access: access error"
        ]
    );

    // Invalid: said on stderr, the default is used.
    let (_, lines) = run(Some("info,only_http=loud"));
    assert_eq!(
        lines[0],
        "only-log: ignoring ONLY_LOG: invalid log directive `only_http=loud`: unknown level"
    );
    assert_eq!(
        &lines[1..],
        [
            "ERROR only_http::access: access error",
            "WARN  app: app warn"
        ]
    );
}
