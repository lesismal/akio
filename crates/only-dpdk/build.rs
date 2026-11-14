//! Builds the C shim over DPDK (`csrc/shim.c`) when the `pmd` feature is on and `pkg-config`
//! finds `libdpdk` (Linux). Otherwise nothing is built and `Device::Dpdk` reports `Unsupported`
//! at runtime; `ONLY_DPDK_REQUIRE=1` turns a missing libdpdk into a build error.

fn main() {
    println!("cargo::rustc-check-cfg=cfg(only_dpdk_linked)");
    println!("cargo::rerun-if-changed=csrc/shim.c");
    println!("cargo::rerun-if-env-changed=ONLY_DPDK_REQUIRE");
    #[cfg(feature = "pmd")]
    pmd();
}

#[cfg(feature = "pmd")]
fn pmd() {
    let require = std::env::var("ONLY_DPDK_REQUIRE").is_ok_and(|v| v == "1");
    let linux = std::env::var("CARGO_CFG_TARGET_OS").is_ok_and(|os| os == "linux");
    let lib = if linux {
        pkg_config::Config::new()
            .atleast_version("21.11")
            .probe("libdpdk")
            .map_err(|e| e.to_string())
    } else {
        Err("DPDK is only supported on Linux".to_owned())
    };
    let lib = match lib {
        Ok(lib) => lib,
        Err(e) if require => panic!("only-dpdk: libdpdk not found ({e})"),
        // Elsewhere DPDK is simply not available; no need to say so on every build.
        Err(_) if !linux => return,
        Err(e) => {
            println!(
                "cargo::warning=only-dpdk: libdpdk not found ({}); Device::Dpdk will be unsupported",
                e.lines()
                    .map(str::trim)
                    .find(|l| !l.is_empty())
                    .unwrap_or_default()
            );
            return;
        }
    };
    let mut build = cc::Build::new();
    build.file("csrc/shim.c").warnings(false);
    for p in &lib.include_paths {
        build.include(p);
    }
    // `pkg-config --cflags libdpdk` also carries `-include rte_config.h` and `-march=...`.
    let cflags = std::process::Command::new("pkg-config")
        .args(["--cflags", "libdpdk"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();
    let mut it = cflags.split_whitespace();
    while let Some(f) = it.next() {
        if f == "-include" {
            if let Some(h) = it.next() {
                build.flag("-include").flag(h);
            }
        } else if f.starts_with("-march") || f.starts_with("-m") || f.starts_with("-D") {
            build.flag(f);
        }
    }
    build.compile("only_dpdk_shim");
    // DPDK's PMDs register themselves from constructors in shared objects the EAL loads from
    // its plugin directory; nothing else needs linking beyond what pkg-config reported.
    println!("cargo::rustc-cfg=only_dpdk_linked");
}
