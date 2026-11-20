//! The operating system's trusted CA certificates, without third-party crates (ADR-010).
//!
//! Order: `SSL_CERT_FILE` and `SSL_CERT_DIR` when either is set (the OpenSSL convention, so a
//! deployment can point every client at its own store); otherwise, on macOS, the keychains
//! exported by `/usr/bin/security` with the trust settings applied (ADR-059), falling back to
//! `/etc/ssl/cert.pem`; on other Unix systems
//! the first CA bundle file that exists among the distributions' usual paths, else the
//! certificate directories.

use std::path::{Path, PathBuf};

/// CA bundle files of the common distributions, first found wins.
const BUNDLES: &[&str] = &[
    "/etc/ssl/certs/ca-certificates.crt", // Debian, Ubuntu, Gentoo, Arch, Alpine (with ca-certificates)
    "/etc/pki/tls/certs/ca-bundle.crt",   // Fedora, RHEL 6
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", // CentOS, RHEL 7+
    "/etc/ssl/ca-bundle.pem",             // openSUSE
    "/etc/pki/tls/cacert.pem",            // OpenELEC
    "/etc/ssl/cert.pem",                  // Alpine, macOS, OpenBSD
    "/usr/local/share/certs/ca-root-nss.crt", // FreeBSD
    "/usr/local/etc/ssl/cert.pem",        // FreeBSD
];

/// Certificate directories (one PEM file per CA), used when no bundle exists.
const DIRS: &[&str] = &[
    "/etc/ssl/certs",
    "/etc/pki/tls/certs",
    "/system/etc/security/cacerts", // Android
];

/// Where the certificates came from, for error messages.
pub(crate) struct Found {
    pub(crate) pems: Vec<Vec<u8>>,
    /// Certificates already decoded (macOS, after the trust settings).
    pub(crate) ders: Vec<Vec<u8>>,
    pub(crate) tried: Vec<String>,
}

/// Every PEM blob of the system store (unparsed).
pub(crate) fn load() -> Found {
    let file = std::env::var_os("SSL_CERT_FILE").map(PathBuf::from);
    let dir = std::env::var_os("SSL_CERT_DIR");
    let mut f = Found {
        pems: Vec::new(),
        ders: Vec::new(),
        tried: Vec::new(),
    };
    if file.is_some() || dir.is_some() {
        if let Some(p) = file {
            read_file(&p, &mut f);
        }
        if let Some(d) = dir {
            // `SSL_CERT_DIR` may list several directories (`:`-separated).
            for d in std::env::split_paths(&d) {
                read_dir(&d, &mut f);
            }
        }
        return f;
    }
    if cfg!(target_os = "macos") {
        keychains(&mut f);
        if f.pems.is_empty() && f.ders.is_empty() {
            read_file(Path::new("/etc/ssl/cert.pem"), &mut f);
        }
        return f;
    }
    from_paths(BUNDLES, DIRS, &mut f);
    f
}

/// The first existing bundle, else every directory.
pub(crate) fn from_paths(bundles: &[&str], dirs: &[&str], f: &mut Found) {
    for b in bundles {
        if read_file(Path::new(b), f) {
            return;
        }
    }
    for d in dirs {
        read_dir(Path::new(d), f);
    }
}

fn read_file(p: &Path, f: &mut Found) -> bool {
    f.tried.push(p.display().to_string());
    match std::fs::read(p) {
        Ok(b) if b.windows(27).any(|w| w == b"-----BEGIN CERTIFICATE-----") => {
            f.pems.push(b);
            true
        }
        _ => false,
    }
}

fn read_dir(d: &Path, f: &mut Found) {
    f.tried.push(d.display().to_string());
    let Ok(rd) = std::fs::read_dir(d) else { return };
    let mut paths: Vec<PathBuf> = rd.filter_map(|e| e.ok().map(|e| e.path())).collect();
    paths.sort();
    for p in paths {
        // Hash links (`5ed36f99.0`) and named files (`*.pem`, `*.crt`) both hold PEM; a
        // directory with both reads each CA twice, which a root store tolerates.
        if p.is_file() {
            if let Ok(b) = std::fs::read(&p) {
                if b.windows(27).any(|w| w == b"-----BEGIN CERTIFICATE-----") {
                    f.pems.push(b);
                }
            }
        }
    }
}

const SYSTEM_ROOTS: &str = "/System/Library/Keychains/SystemRootCertificates.keychain";
const SYSTEM_KEYCHAIN: &str = "/Library/Keychains/System.keychain";

/// `security find-certificate -a -p <keychain>`: the keychain's certificates as PEM.
fn export_keychain(kc: &str, f: &mut Found) -> Option<Vec<u8>> {
    f.tried
        .push(format!("security find-certificate -a -p {kc}"));
    let o = std::process::Command::new("/usr/bin/security")
        .args(["find-certificate", "-a", "-p", kc])
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    (o.status.success() && !o.stdout.is_empty()).then_some(o.stdout)
}

/// `security trust-settings-export [-d|-s]`: one domain's trust settings (user when `flag` is
/// empty). It only writes to a file: a fresh private directory under the temporary directory.
fn export_trust(
    flag: Option<&str>,
) -> Option<std::collections::HashMap<[u8; 20], crate::trust::Verdict>> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    let dir = std::env::temp_dir().join(format!("only-tls-trust-{}-{nanos}", std::process::id()));
    // `create_dir` fails if the path exists: nobody else's directory (or link) is used.
    std::fs::create_dir(&dir).ok()?;
    let file = dir.join("trust.plist");
    let mut cmd = std::process::Command::new("/usr/bin/security");
    cmd.arg("trust-settings-export");
    if let Some(f) = flag {
        cmd.arg(f);
    }
    let ok = cmd
        .arg(&file)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    let xml = ok.then(|| std::fs::read_to_string(&file).ok()).flatten();
    let _ = std::fs::remove_dir_all(&dir);
    match xml {
        Some(x) => crate::trust::trust_list(&x),
        // No settings in this domain: `security` fails with "No Trust Settings were found".
        None if ok => None,
        None => Some(std::collections::HashMap::new()),
    }
}

/// macOS: the certificates of the system roots, the System keychain (administrator-installed
/// CAs) and the login keychain, kept by the trust settings (ADR-059): the user's, then the
/// administrator's, then the system's say whether a certificate is a TLS root (trusted,
/// distrusted, or nothing, in which case only the system roots count). When no domain's
/// settings can be read, the system roots and the System keychain are taken as they are.
fn keychains(f: &mut Found) {
    let roots = export_keychain(SYSTEM_ROOTS, f);
    let admin = export_keychain(SYSTEM_KEYCHAIN, f);
    let login = std::env::var_os("HOME").and_then(|h| {
        let p = Path::new(&h).join("Library/Keychains/login.keychain-db");
        p.exists()
            .then(|| export_keychain(&p.display().to_string(), f))
            .flatten()
    });
    f.tried.push("security trust-settings-export".into());
    let domains = [
        export_trust(None),
        export_trust(Some("-d")),
        export_trust(Some("-s")),
    ];
    if domains.iter().all(Option::is_none) {
        f.pems.extend(roots);
        f.pems.extend(admin);
        return;
    }
    let mut seen = std::collections::HashSet::new();
    for (pem, system) in [(roots, true), (admin, false), (login, false)] {
        let Some(pem) = pem else { continue };
        let Ok(ders) = only_crypto::pem::decode_label(&pem, "CERTIFICATE") else {
            continue;
        };
        for der in ders {
            let sha1 = only_crypto::hash::Sha1::digest(&der);
            if !seen.insert(sha1) {
                continue;
            }
            if keep(&domains, &sha1, system) {
                f.ders.push(der);
            }
        }
    }
}

/// Whether a certificate is a root: the first domain (user, admin, system) with a verdict
/// decides; with none, only the system roots are.
fn keep(
    domains: &[Option<std::collections::HashMap<[u8; 20], crate::trust::Verdict>>],
    sha1: &[u8; 20],
    system_root: bool,
) -> bool {
    use crate::trust::Verdict;
    for d in domains.iter().flatten() {
        match d.get(sha1) {
            Some(Verdict::Trusted) => return true,
            Some(Verdict::Distrusted) => return false,
            Some(Verdict::Unspecified) | None => {}
        }
    }
    system_root
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundle_wins_over_directories_and_missing_paths_are_skipped() {
        let dir = std::env::temp_dir().join(format!("only-tls-roots-{}", std::process::id()));
        let certs = dir.join("certs");
        std::fs::create_dir_all(&certs).unwrap();
        let pem = b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
        std::fs::write(certs.join("a.pem"), pem).unwrap();
        std::fs::write(certs.join("b.0"), pem).unwrap();
        std::fs::write(certs.join("readme.txt"), b"not a cert").unwrap();
        let bundle = dir.join("bundle.crt");
        std::fs::write(&bundle, pem).unwrap();

        let (b, d) = (bundle.to_str().unwrap(), certs.to_str().unwrap());
        let mut f = Found {
            pems: Vec::new(),
            ders: Vec::new(),
            tried: Vec::new(),
        };
        from_paths(&["/nonexistent/x.pem", b], &[d], &mut f);
        assert_eq!(f.pems.len(), 1);
        assert_eq!(f.tried.len(), 2);

        let mut f = Found {
            pems: Vec::new(),
            ders: Vec::new(),
            tried: Vec::new(),
        };
        from_paths(&["/nonexistent/x.pem"], &[d, "/nonexistent"], &mut f);
        assert_eq!(f.pems.len(), 2, "two PEM files, the text file skipped");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn trust_settings_decide_by_domain() {
        use crate::trust::Verdict;
        use std::collections::HashMap;
        let (a, b, c) = ([1u8; 20], [2u8; 20], [3u8; 20]);
        let user = HashMap::from([(a, Verdict::Distrusted)]);
        let admin = HashMap::from([(a, Verdict::Trusted), (b, Verdict::Trusted)]);
        let system = HashMap::from([(c, Verdict::Unspecified)]);
        let d = [Some(user), Some(admin), Some(system)];
        assert!(
            !keep(&d, &a, true),
            "the user's Deny wins over the admin's trust"
        );
        assert!(
            keep(&d, &b, false),
            "trusted by the admin: kept from any keychain"
        );
        assert!(keep(&d, &c, true), "unspecified: a system root stays");
        assert!(
            !keep(&d, &c, false),
            "unspecified: other keychains' certificates do not count"
        );
        assert!(keep(&[None, None, None], &c, true));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_keychains_with_trust_settings() {
        let mut f = Found {
            pems: Vec::new(),
            ders: Vec::new(),
            tried: Vec::new(),
        };
        keychains(&mut f);
        eprintln!(
            "trust-filtered roots: {}, raw PEM blobs: {}",
            f.ders.len(),
            f.pems.len()
        );
        // Either the trust settings were read (decoded certificates) or the fallback ran.
        assert!(!f.ders.is_empty() || !f.pems.is_empty(), "{:?}", f.tried);
        assert!(
            f.ders.len() >= 100 || !f.pems.is_empty(),
            "{}",
            f.ders.len()
        );
    }
}
