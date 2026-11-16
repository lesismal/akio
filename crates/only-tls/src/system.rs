//! The operating system's trusted CA certificates, without third-party crates (ADR-010).
//!
//! Order: `SSL_CERT_FILE` and `SSL_CERT_DIR` when either is set (the OpenSSL convention, so a
//! deployment can point every client at its own store); otherwise, on macOS, the system keychains
//! exported by `/usr/bin/security`, falling back to `/etc/ssl/cert.pem`; on other Unix systems
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
    pub(crate) tried: Vec<String>,
}

/// Every PEM blob of the system store (unparsed).
pub(crate) fn load() -> Found {
    let file = std::env::var_os("SSL_CERT_FILE").map(PathBuf::from);
    let dir = std::env::var_os("SSL_CERT_DIR");
    let mut f = Found {
        pems: Vec::new(),
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
        if f.pems.is_empty() {
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

/// macOS: the system roots and the admin-installed CAs, exported as PEM by `security`. Trust
/// settings (a CA an administrator marked as distrusted) are not applied.
fn keychains(f: &mut Found) {
    for kc in [
        "/System/Library/Keychains/SystemRootCertificates.keychain",
        "/Library/Keychains/System.keychain",
    ] {
        f.tried
            .push(format!("security find-certificate -a -p {kc}"));
        let out = std::process::Command::new("/usr/bin/security")
            .args(["find-certificate", "-a", "-p", kc])
            .stdin(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .output();
        if let Ok(o) = out {
            if o.status.success() && !o.stdout.is_empty() {
                f.pems.push(o.stdout);
            }
        }
    }
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
            tried: Vec::new(),
        };
        from_paths(&["/nonexistent/x.pem", b], &[d], &mut f);
        assert_eq!(f.pems.len(), 1);
        assert_eq!(f.tried.len(), 2);

        let mut f = Found {
            pems: Vec::new(),
            tried: Vec::new(),
        };
        from_paths(&["/nonexistent/x.pem"], &[d, "/nonexistent"], &mut f);
        assert_eq!(f.pems.len(), 2, "two PEM files, the text file skipped");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
