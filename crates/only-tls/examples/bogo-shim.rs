//! BoGo shim for only-tls: drives only-tls the way BoringSSL's `bssl_shim` drives BoringSSL, so
//! BoringSSL's TLS test runner (`ssl/test/runner`, "BoGo") can test it. Run it through
//! `tools/interop/tls/bogo.sh`, which builds this example, fetches the runner and passes
//! `tools/interop/tls/bogo_config.json` (disabled tests and why).
//!
//! The runner starts one shim per test: `-port P -shim-id N [-ipv6] [-server] ...flags`. For
//! each of the `-resume-count` + 1 connections the shim connects to the runner, writes the shim
//! id (8 bytes, little endian), runs the handshake (as server with `-server`), checks what was
//! negotiated against the `-expect-*` flags, then echoes what it reads with every byte XORed
//! with 0xff until the runner closes (`bssl_shim.cc`'s `DoExchange`). Flags apply to every
//! connection, or with an `-on-initial-` / `-on-resume-` / `-on-retry-` prefix to one of them
//! (`test_config.cc`).
//!
//! A flag the shim does not know, or one asking for something only-tls does not do (TLS 1.0,
//! renegotiation, ECH, ...) or that its API cannot observe (the negotiated group, the peer's
//! signature algorithm, ...), makes it exit with code 89: the runner then counts the test as
//! unimplemented (`-allow-unimplemented`). Errors go to stderr with exit code 1 (the runner
//! wants stderr empty on success); progress notes go to stdout, which the runner shows when a
//! test fails.
#![allow(missing_docs)]

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::process;
use std::time::Duration;

use only_tls::stream::Stream;
use only_tls::{Certificate, ClientConfig, EarlyData, PrivateKey, RootCerts, ServerConfig};

/// The exit code that tells the runner a test needs something the shim does not implement.
const UNIMPLEMENTED: i32 = 89;

const TLS12: u16 = 0x0303;
const TLS13: u16 = 0x0304;

/// The server's ticket key: the same for every configuration this process builds, so a
/// configuration rebuilt for a resumption (`-on-resume-` flags) still opens its tickets.
const TICKET_KEY: [u8; 48] = [0x42; 48];

/// The settings of one connection (initial, resumption or 0-RTT retry).
#[derive(Clone, Debug)]
struct Opts {
    server: bool,
    port: u16,
    shim_id: u64,
    ipv6: bool,
    resume_count: usize,
    cert_file: Option<String>,
    key_file: Option<String>,
    trust_cert: Option<String>,
    host_name: Option<String>,
    min_version: u16,
    max_version: u16,
    no_tls12: bool,
    no_tls13: bool,
    expect_version: u16,
    curves: Vec<u16>,
    tls13_ciphers: Vec<u16>,
    advertise_alpn: Option<Vec<u8>>,
    expect_alpn: Vec<u8>,
    select_alpn: Vec<u8>,
    decline_alpn: bool,
    shim_writes_first: bool,
    shim_initial_write: Vec<u8>,
    repeat_shim_initial_write: usize,
    shim_shuts_down: bool,
    check_close_notify: bool,
    expect_session_miss: bool,
    expect_server_name: Option<String>,
    expect_no_server_name: bool,
    verify_peer: bool,
    require_any_client_certificate: bool,
    enable_ocsp_stapling: bool,
    expect_ocsp_response: Option<Vec<u8>>,
    ocsp_response: Option<Vec<u8>>,
    no_ticket: bool,
    enable_early_data: bool,
    expect_accept_early_data: bool,
    expect_reject_early_data: bool,
    expect_no_offer_early_data: bool,
    key_update: bool,
    expect_cipher: u16,
    expect_peer_cert_file: Option<String>,
    expect_no_peer_cert: bool,
    write_different_record_sizes: bool,
    read_size: usize,
}

impl Default for Opts {
    fn default() -> Opts {
        Opts {
            server: false,
            port: 0,
            shim_id: 0,
            ipv6: false,
            resume_count: 0,
            cert_file: None,
            key_file: None,
            trust_cert: None,
            host_name: None,
            min_version: 0,
            max_version: 0,
            no_tls12: false,
            no_tls13: false,
            expect_version: 0,
            curves: Vec::new(),
            tls13_ciphers: Vec::new(),
            advertise_alpn: None,
            expect_alpn: Vec::new(),
            select_alpn: Vec::new(),
            decline_alpn: false,
            shim_writes_first: false,
            shim_initial_write: b"hello".to_vec(),
            repeat_shim_initial_write: 1,
            shim_shuts_down: false,
            check_close_notify: false,
            expect_session_miss: false,
            expect_server_name: None,
            expect_no_server_name: false,
            verify_peer: false,
            require_any_client_certificate: false,
            enable_ocsp_stapling: false,
            expect_ocsp_response: None,
            ocsp_response: None,
            no_ticket: false,
            enable_early_data: false,
            expect_accept_early_data: false,
            expect_reject_early_data: false,
            expect_no_offer_early_data: false,
            key_update: false,
            expect_cipher: 0,
            expect_peer_cert_file: None,
            expect_no_peer_cert: false,
            write_different_record_sizes: false,
            read_size: 512,
        }
    }
}

/// Exits with [`UNIMPLEMENTED`]. With `BOGO_SHIM_UNIMPLEMENTED_LOG` set (in the runner's
/// environment, which the shims inherit), also appends the reason to that file, to see what
/// the unimplemented tests are missing most (`sort | uniq -c | sort -rn`).
fn unimplemented(why: &str) -> ! {
    println!("unimplemented: {why}");
    if let Some(p) = std::env::var_os("BOGO_SHIM_UNIMPLEMENTED_LOG") {
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(p)
        {
            // One write, so lines from shims running in parallel do not interleave.
            let _ = f.write_all(format!("{why}\n").as_bytes());
        }
    }
    process::exit(UNIMPLEMENTED);
}

fn fail(why: &str) -> ! {
    eprintln!("{why}");
    process::exit(1);
}

/// The command line as bytes (`-advertise-alpn` takes a wire-format list).
fn args() -> Vec<Vec<u8>> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        std::env::args_os()
            .skip(1)
            .map(OsStringExt::into_vec)
            .collect()
    }
    #[cfg(not(unix))]
    {
        std::env::args().skip(1).map(String::into_bytes).collect()
    }
}

/// Flags accepted with no effect: they change how BoringSSL's shim calls its own API
/// (asynchronous callbacks, which callback flavour, extra no-op calls), not what goes on the
/// wire, or they are expectations only-tls cannot violate by construction.
const IGNORED: &[&str] = &[
    "-async",
    "-implicit-handshake",
    "-handshake-twice",
    "-no-op-extra-handshake",
    "-peek-then-read",
    "-partial-write",
    "-use-old-client-cert-callback",
    "-use-custom-verify-callback",
    "-reverify-on-resume",
    "-forbid-renegotiation-after-handshake",
    "-expect-no-session",
    "-expect-ticket-supports-early-data",
    "-allow-hint-mismatch",
    "-no-tls1",
    "-no-tls11",
    "-no-ssl3",
];

/// Ignored flags that take a parameter.
const IGNORED_PARAM: &[&str] = &["-write-settings", "-handshaker-path"];

/// Whether `name` (without prefix) is a flag the shim implements, and whether it takes a
/// parameter; `None` for any other.
fn takes_param(name: &str) -> Option<bool> {
    if IGNORED.contains(&name) {
        return Some(false);
    }
    if IGNORED_PARAM.contains(&name) {
        return Some(true);
    }
    Some(match name {
        "-server"
        | "-ipv6"
        | "-no-tls12"
        | "-no-tls13"
        | "-decline-alpn"
        | "-shim-writes-first"
        | "-shim-shuts-down"
        | "-check-close-notify"
        | "-expect-session-miss"
        | "-expect-no-server-name"
        | "-verify-peer"
        | "-require-any-client-certificate"
        | "-enable-ocsp-stapling"
        | "-no-ticket"
        | "-enable-early-data"
        | "-expect-accept-early-data"
        | "-expect-reject-early-data"
        | "-expect-no-offer-early-data"
        | "-key-update"
        | "-expect-no-peer-cert"
        | "-write-different-record-sizes" => false,
        "-port"
        | "-shim-id"
        | "-resume-count"
        | "-cert-file"
        | "-key-file"
        | "-trust-cert"
        | "-host-name"
        | "-min-version"
        | "-max-version"
        | "-expect-version"
        | "-curves"
        | "-tls13-ciphers"
        | "-advertise-alpn"
        | "-expect-alpn"
        | "-select-alpn"
        | "-shim-initial-write"
        | "-repeat-shim-initial-write"
        | "-expect-server-name"
        | "-expect-ocsp-response"
        | "-ocsp-response"
        | "-expect-cipher"
        | "-expect-cipher-aes"
        | "-expect-cipher-no-aes"
        | "-expect-peer-cert-file"
        | "-read-size"
        | "-expect-selected-credential"
        | "-expect-total-renegotiations"
        | "-resumption-delay" => true,
        _ => return None,
    })
}

fn text(p: &[u8]) -> String {
    String::from_utf8_lossy(p).into_owned()
}

fn int<T: std::str::FromStr>(name: &str, p: &[u8]) -> T {
    text(p)
        .parse()
        .unwrap_or_else(|_| fail(&format!("bad value for {name}: {}", text(p))))
}

fn base64(name: &str, p: &[u8]) -> Vec<u8> {
    only_crypto::base64::STANDARD
        .decode(p)
        .unwrap_or_else(|_| fail(&format!("bad base64 for {name}")))
}

/// Sets flag `name` (known to [`takes_param`]) in `o`.
fn apply(o: &mut Opts, name: &str, p: &[u8]) {
    match name {
        "-server" => o.server = true,
        "-ipv6" => o.ipv6 = true,
        "-port" => o.port = int(name, p),
        "-shim-id" => o.shim_id = int(name, p),
        "-resume-count" => o.resume_count = int(name, p),
        "-cert-file" => o.cert_file = Some(text(p)),
        "-key-file" => o.key_file = Some(text(p)),
        // Empty for a runner credential without a root (a garbage certificate).
        "-trust-cert" => o.trust_cert = Some(text(p)).filter(|t| !t.is_empty()),
        "-host-name" => o.host_name = Some(text(p)),
        "-min-version" => o.min_version = int(name, p),
        "-max-version" => o.max_version = int(name, p),
        "-no-tls12" => o.no_tls12 = true,
        "-no-tls13" => o.no_tls13 = true,
        "-expect-version" => o.expect_version = int(name, p),
        "-curves" => o.curves.push(int(name, p)),
        "-tls13-ciphers" => o.tls13_ciphers.push(int(name, p)),
        "-advertise-alpn" => o.advertise_alpn = Some(p.to_vec()),
        "-expect-alpn" => o.expect_alpn = p.to_vec(),
        "-select-alpn" => o.select_alpn = p.to_vec(),
        "-decline-alpn" => o.decline_alpn = true,
        "-shim-writes-first" => o.shim_writes_first = true,
        "-shim-initial-write" => o.shim_initial_write = p.to_vec(),
        "-repeat-shim-initial-write" => o.repeat_shim_initial_write = int(name, p),
        "-shim-shuts-down" => o.shim_shuts_down = true,
        "-check-close-notify" => o.check_close_notify = true,
        "-expect-session-miss" => o.expect_session_miss = true,
        "-expect-server-name" => o.expect_server_name = Some(text(p)),
        "-expect-no-server-name" => o.expect_no_server_name = true,
        "-verify-peer" => o.verify_peer = true,
        "-require-any-client-certificate" => o.require_any_client_certificate = true,
        "-enable-ocsp-stapling" => o.enable_ocsp_stapling = true,
        "-expect-ocsp-response" => o.expect_ocsp_response = Some(base64(name, p)),
        "-ocsp-response" => o.ocsp_response = Some(base64(name, p)),
        "-no-ticket" => o.no_ticket = true,
        "-enable-early-data" => o.enable_early_data = true,
        "-expect-accept-early-data" => o.expect_accept_early_data = true,
        "-expect-reject-early-data" => o.expect_reject_early_data = true,
        "-expect-no-offer-early-data" => o.expect_no_offer_early_data = true,
        "-key-update" => o.key_update = true,
        // Every x86-64 and AArch64 machine the runner runs on has AES instructions.
        "-expect-cipher" | "-expect-cipher-aes" => o.expect_cipher = int(name, p),
        "-expect-cipher-no-aes" => {}
        "-expect-peer-cert-file" => o.expect_peer_cert_file = Some(text(p)),
        "-expect-no-peer-cert" => o.expect_no_peer_cert = true,
        "-write-different-record-sizes" => o.write_different_record_sizes = true,
        "-read-size" => o.read_size = int::<usize>(name, p).max(1),
        // -1: the default credential, the only one this shim configures.
        "-expect-selected-credential" if int::<i32>(name, p) != -1 => {
            unimplemented("credentials other than the default one");
        }
        "-expect-total-renegotiations" if int::<u32>(name, p) != 0 => {
            unimplemented("renegotiation");
        }
        "-resumption-delay" if int::<u64>(name, p) != 0 => {
            unimplemented("-resumption-delay (no clock to advance)");
        }
        _ => {}
    }
}

/// Removes `prefix` from `name` when `name` is `prefix` followed by `-...`.
fn strip<'a>(name: &'a str, prefix: &str) -> Option<&'a str> {
    name.strip_prefix(prefix).filter(|r| r.starts_with('-'))
}

/// Parses the command line into the initial, resumption and retry settings.
fn parse() -> [Opts; 3] {
    let mut out: [Opts; 3] = Default::default();
    let a = args();
    let mut i = 0;
    while i < a.len() {
        let arg = text(&a[i]);
        i += 1;
        if arg == "-is-handshaker-supported" {
            println!("No");
            process::exit(0);
        }
        let mut name = arg.as_str();
        let mut skip = false;
        if let Some(r) = strip(name, "-on-shim") {
            name = r;
        } else if let Some(r) = strip(name, "-on-handshaker") {
            name = r;
            skip = true;
        }
        let mut target = None;
        if let Some(r) = strip(name, "-on-initial") {
            (name, target) = (r, Some(0));
        } else if let Some(r) = strip(name, "-on-resume") {
            (name, target) = (r, Some(1));
        } else if let Some(r) = strip(name, "-on-retry") {
            (name, target) = (r, Some(2));
        }
        let Some(has_param) = takes_param(name) else {
            unimplemented(&format!("flag {arg}"));
        };
        let param: &[u8] = if has_param {
            let Some(p) = a.get(i) else {
                fail(&format!("missing parameter for {arg}"));
            };
            i += 1;
            p
        } else {
            &[]
        };
        if skip {
            continue;
        }
        match target {
            Some(t) => apply(&mut out[t], name, param),
            None => out.iter_mut().for_each(|o| apply(o, name, param)),
        }
    }
    out
}

fn read_file(p: &str) -> Vec<u8> {
    std::fs::read(p).unwrap_or_else(|e| fail(&format!("{p}: {e}")))
}

fn load_chain(p: &str) -> Vec<Certificate> {
    Certificate::from_pem(&read_file(p)).unwrap_or_else(|e| fail(&format!("{p}: {e}")))
}

fn load_key(p: &str) -> PrivateKey {
    PrivateKey::from_pem(&read_file(p)).unwrap_or_else(|e| unimplemented(&format!("{p}: {e}")))
}

/// The versions to enable: (TLS 1.2, TLS 1.3).
fn versions(o: &Opts) -> (bool, bool) {
    let max = if o.max_version == 0 {
        TLS13
    } else {
        o.max_version
    };
    let range = o.min_version..=max;
    let v12 = range.contains(&TLS12) && !o.no_tls12;
    let v13 = range.contains(&TLS13) && !o.no_tls13;
    if !v12 && !v13 {
        unimplemented("no version but TLS 1.2 and 1.3 is implemented");
    }
    (v12, v13)
}

/// The cipher suites: `-tls13-ciphers` replaces the TLS 1.3 ones.
fn suites(o: &Opts) -> Option<Vec<u16>> {
    if o.tls13_ciphers.is_empty() {
        return None;
    }
    let mut ids = o.tls13_ciphers.clone();
    ids.extend(
        only_tls::__proto::suites::ALL
            .iter()
            .filter(|s| s.tls12.is_some())
            .map(|s| s.id),
    );
    Some(ids)
}

/// A `-advertise-alpn` list (wire format: length-prefixed names).
fn alpn_list(mut w: &[u8]) -> Vec<Vec<u8>> {
    let mut v = Vec::new();
    while let Some((&n, rest)) = w.split_first() {
        let n = usize::from(n);
        if rest.len() < n {
            fail("bad -advertise-alpn");
        }
        v.push(rest[..n].to_vec());
        w = &rest[n..];
    }
    v
}

/// What makes two connections' configurations differ (they are rebuilt only then, so the
/// client's session cache and the server's session cache carry over).
fn config_key(o: &Opts) -> String {
    format!(
        "{:?}",
        (
            (&o.cert_file, &o.key_file, &o.trust_cert),
            (o.min_version, o.max_version, o.no_tls12, o.no_tls13),
            (&o.curves, &o.tls13_ciphers),
            (&o.advertise_alpn, &o.select_alpn, o.decline_alpn),
            (o.verify_peer, o.require_any_client_certificate),
            (o.enable_ocsp_stapling, &o.ocsp_response),
            (o.no_ticket, o.enable_early_data),
        )
    )
}

enum Config {
    Client(ClientConfig),
    Server(ServerConfig),
}

fn build(o: &Opts) -> Config {
    let (v12, v13) = versions(o);
    let built = if o.server {
        let (Some(c), Some(k)) = (&o.cert_file, &o.key_file) else {
            unimplemented("a server without -cert-file and -key-file");
        };
        let mut b = ServerConfig::builder(load_chain(c), load_key(k))
            .tls13_only(!v12)
            .__tls12_only(!v13)
            .certificate_compression(false)
            .handshake_timeout(None);
        if !o.select_alpn.is_empty() && !o.decline_alpn {
            b = b.alpn([o.select_alpn.clone()]);
        }
        if o.verify_peer || o.require_any_client_certificate {
            let mut roots = RootCerts::empty();
            let file = o.trust_cert.as_deref().unwrap_or(c.as_str());
            roots
                .add_pem(&read_file(file))
                .unwrap_or_else(|e| fail(&format!("{file}: {e}")));
            b = if o.require_any_client_certificate {
                b.client_auth_required(roots)
            } else {
                b.client_auth_optional(roots)
            };
        }
        if o.no_ticket {
            // SSL_OP_NO_TICKET: no TLS 1.3 tickets either (TLS 1.2 session IDs stay).
            b = b.__tickets13(0);
        } else {
            b = b.session_ticket_key(TICKET_KEY);
        }
        if o.enable_early_data {
            b = b.early_data(16384);
        }
        if let Some(r) = &o.ocsp_response {
            b = b.ocsp_response(r.clone());
        }
        if let Some(s) = suites(o) {
            b = b.__suites(&s);
        }
        if !o.curves.is_empty() {
            b = b.__groups(&o.curves);
        }
        b.build().map(Config::Server)
    } else {
        let mut b = ClientConfig::builder()
            .insecure_skip_verify()
            .tls13_only(!v12)
            .__tls12_only(!v13)
            .sni(o.host_name.is_some())
            .early_data(o.enable_early_data)
            .ocsp_stapling(o.enable_ocsp_stapling)
            .handshake_timeout(None);
        if let Some(a) = &o.advertise_alpn {
            b = b.alpn(alpn_list(a));
        }
        match (&o.cert_file, &o.key_file) {
            (Some(c), Some(k)) => b = b.client_cert(load_chain(c), load_key(k)),
            (None, None) => {}
            _ => fail("-cert-file and -key-file go together"),
        }
        if let Some(s) = suites(o) {
            b = b.__suites(&s);
        }
        if !o.curves.is_empty() {
            b = b.__groups(&o.curves);
        }
        b.build().map(Config::Client)
    };
    built.unwrap_or_else(|e| unimplemented(&format!("configuration: {e}")))
}

fn version_code(c: &only_tls::__proto::Connection) -> u16 {
    match c.version_name() {
        Some("TLSv1_3") => TLS13,
        Some("TLSv1_2") => TLS12,
        _ => 0,
    }
}

/// `bssl_shim.cc`'s `CheckHandshakeProperties`, for what only-tls can tell.
fn check(o: &Opts, c: &only_tls::__proto::Connection, is_resume: bool) -> Result<(), String> {
    let version = version_code(c);
    if o.expect_version != 0 && version != o.expect_version {
        return Err(format!(
            "want version {:04x}, got {version:04x}",
            o.expect_version
        ));
    }
    // (The check runs once the handshake is done, never while still in early data.)
    let expect_resume = is_resume && !o.expect_session_miss;
    if c.resumed() != expect_resume {
        return Err(format!(
            "session unexpectedly was{} reused",
            if c.resumed() { "" } else { " not" }
        ));
    }
    if let Some(n) = &o.expect_server_name {
        if c.server_name() != Some(n.as_str()) {
            return Err(format!(
                "servername mismatch (got {:?}; want {n})",
                c.server_name()
            ));
        }
    }
    if o.expect_no_server_name && c.server_name().is_some() {
        return Err("unexpected server name".into());
    }
    let want_alpn: &[u8] = if o.server {
        if o.decline_alpn { &[] } else { &o.select_alpn }
    } else {
        &o.expect_alpn
    };
    if c.alpn().unwrap_or_default() != want_alpn {
        return Err(format!(
            "negotiated alpn proto mismatch: got {:?}, want {:?}",
            c.alpn().map(text),
            text(want_alpn)
        ));
    }
    let cipher = c.suite().map_or(0, |s| s.id);
    if o.expect_cipher != 0 && cipher != o.expect_cipher {
        return Err(format!(
            "Cipher ID was {cipher:04x}, wanted {:04x}",
            o.expect_cipher
        ));
    }
    let early = c.early_data();
    if o.expect_accept_early_data && early != EarlyData::Accepted {
        return Err(format!("Early data was not accepted ({early:?})"));
    }
    if o.expect_reject_early_data && early == EarlyData::Accepted {
        return Err("Early data was accepted, but we expected the opposite".into());
    }
    if !o.server && is_resume && o.expect_no_offer_early_data && early != EarlyData::NotAttempted {
        return Err("Client unexpectedly offered early data.".into());
    }
    let peer = c.peer_certificates();
    if o.expect_no_peer_cert {
        if !peer.is_empty() {
            return Err("Received unexpected peer certificate.".into());
        }
    } else if (!o.server || o.require_any_client_certificate) && !c.resumed() && peer.is_empty() {
        return Err("Received no peer certificate but expected one.".into());
    }
    if let Some(f) = &o.expect_peer_cert_file {
        // A resumed session does not carry the peer's chain in only-tls.
        if !c.resumed() {
            let want: Vec<Vec<u8>> = load_chain(f).iter().map(|c| c.as_der().to_vec()).collect();
            if peer != want.as_slice() {
                return Err("peer certificate chain mismatch".into());
            }
        }
    }
    if let Some(r) = &o.expect_ocsp_response {
        if c.ocsp_response() != Some(r.as_slice()) && !c.resumed() {
            return Err("OCSP response mismatch".into());
        }
    }
    Ok(())
}

fn connect(o: &Opts) -> TcpStream {
    let addr = if o.ipv6 {
        format!("[::1]:{}", o.port)
    } else {
        format!("127.0.0.1:{}", o.port)
    };
    let mut s = TcpStream::connect(&addr).unwrap_or_else(|e| fail(&format!("{addr}: {e}")));
    let _ = s.set_nodelay(true);
    s.write_all(&o.shim_id.to_le_bytes())
        .unwrap_or_else(|e| fail(&format!("shim id: {e}")));
    s
}

fn io_err(what: &str, e: &io::Error) -> String {
    format!("{what}: {e}")
}

/// One connection: `bssl_shim.cc`'s `DoExchange`.
fn exchange<S: Read + Write>(
    o: &Opts,
    retry: &Opts,
    s: &mut Stream<S>,
    is_resume: bool,
) -> Result<(), String> {
    let mut wrote_initial = false;
    if !o.server && is_resume && o.enable_early_data && o.shim_writes_first {
        // Goes as early data when the ticket allows it; only-tls sends it again after the
        // handshake when the server rejects it. One write per repetition, as the runner
        // expects one record each.
        for _ in 0..o.repeat_shim_initial_write {
            s.write_early(&o.shim_initial_write)
                .map_err(|e| io_err("early write", &e))?;
        }
        wrote_initial = true;
    }
    s.handshake().map_err(|e| io_err("handshake", &e))?;
    println!(
        "handshake done: version={:?} suite={:?} resumed={} alpn={:?} early={:?}",
        s.conn().version_name(),
        s.conn().suite().map(|x| x.name),
        s.conn().resumed(),
        s.conn().alpn().map(text),
        s.conn().early_data()
    );
    // A client whose early data was rejected goes on as BoringSSL's shim does after
    // SSL_reset_early_data_reject: with the -on-retry- settings.
    let o = if !o.server
        && o.expect_reject_early_data
        && s.conn().early_data() == EarlyData::Rejected
    {
        retry
    } else {
        o
    };
    check(o, s.conn(), is_resume)?;
    if o.key_update {
        // A KeyUpdate before every record sent (BoringSSL's shim sends one after every read,
        // before echoing it).
        s.conn_mut().set_key_update_after(0);
    }
    if o.write_different_record_sizes {
        let buf = vec![0x42u8; 32769];
        for len in [1, 255, 256, 257, 16383, 16384, 16385, 32767, 32768, 32769] {
            s.write_all(&buf[..len]).map_err(|e| io_err("write", &e))?;
        }
    } else {
        if o.shim_writes_first && !wrote_initial {
            for _ in 0..o.repeat_shim_initial_write {
                s.write_all(&o.shim_initial_write)
                    .map_err(|e| io_err("write", &e))?;
            }
        }
        if !o.shim_shuts_down {
            let mut buf = vec![0u8; o.read_size];
            loop {
                let n = s.read(&mut buf).map_err(|e| io_err("read", &e))?;
                if n == 0 {
                    break;
                }
                for b in &mut buf[..n] {
                    *b ^= 0xff;
                }
                s.write_all(&buf[..n]).map_err(|e| io_err("write", &e))?;
            }
        }
    }
    // Without -check-close-notify BoringSSL's shim shuts down quietly (no close_notify).
    if o.check_close_notify {
        if !o.shim_shuts_down && !s.conn().received_close_notify() {
            return Err("Unexpected SSL_shutdown result: 0 != 1 (no close_notify)".into());
        }
        let _ = s.close();
        if o.shim_shuts_down {
            let mut buf = [0u8; 512];
            loop {
                match s.read(&mut buf) {
                    Ok(0) => break,
                    Ok(_) => {}
                    Err(e) => return Err(io_err("read after close_notify", &e)),
                }
            }
            if !s.conn().received_close_notify() {
                return Err("Unexpected SSL_shutdown result: no close_notify from the peer".into());
            }
        }
    }
    Ok(())
}

/// Half-closes the socket and reads until the runner closes its side, so it gets everything
/// sent (an alert above all) rather than a reset.
fn drain(sock: &TcpStream) {
    let _ = sock.shutdown(Shutdown::Write);
    let _ = sock.set_read_timeout(Some(Duration::from_secs(5)));
    let mut buf = [0u8; 4096];
    let mut r = sock;
    while matches!(r.read(&mut buf), Ok(1..)) {}
}

fn main() {
    let [initial, resume, retry] = parse();
    if initial.server && initial.enable_early_data && resume.expect_accept_early_data {
        // The runner wants the early data echoed as half-RTT data, before the client's
        // Finished: only-tls's server sends application data only once the handshake is done.
        unimplemented("half-RTT data (server write before the client Finished)");
    }
    let mut configs: HashMap<String, Config> = HashMap::new();
    for i in 0..=initial.resume_count {
        let o = if i == 0 { &initial } else { &resume };
        let key = config_key(o);
        let cfg = configs.entry(key).or_insert_with(|| build(o));
        let sock = connect(o);
        let io = sock
            .try_clone()
            .unwrap_or_else(|e| fail(&format!("socket: {e}")));
        let r = match cfg {
            Config::Client(c) => {
                let name = o.host_name.as_deref().unwrap_or("127.0.0.1");
                match Stream::client(c, name, io) {
                    Ok(mut s) => exchange(o, &retry, &mut s, i > 0),
                    Err(e) => Err(io_err("client", &e)),
                }
            }
            Config::Server(c) => exchange(o, &retry, &mut Stream::server(c, io), i > 0),
        };
        drain(&sock);
        if let Err(e) = r {
            fail(&format!("connection {} failed: {e}", i + 1));
        }
    }
}
