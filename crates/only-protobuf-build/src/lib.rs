#![forbid(unsafe_code)]
//! Generates Rust code for `.proto` files, for the `only-protobuf` runtime and `only-grpc`,
//! from `build.rs`. No `protoc`, no third-party crates: the `.proto` parser is built in.
//!
//! * proto3 and proto2: messages, nested messages and enums, scalar fields, `optional`
//!   (explicit presence, `Option<T>`), `required`, `repeated` (packed per the syntax or
//!   `[packed = ...]`), `map<K, V>`, `oneof` (an enum), proto2 `[default = ...]` (getters),
//!   recursive messages (boxed), packages and imports (searched in the include directories).
//! * Enums are open: a newtype over `i32` with one constant per value.
//! * Unknown fields are kept and re-encoded (can be turned off).
//! * `google/protobuf/{empty,timestamp,duration,any,wrappers,field_mask,struct}.proto` are
//!   built in and map to `only_protobuf::well_known`.
//! * Services become `only-grpc` stubs: a `<service>_server` module with a trait and a
//!   `register` function, and a `<service>_client` module with a typed client. Messages then
//!   also implement `only_grpc::codec::Message`.
//! * Not supported: groups, extensions (parsed and ignored), editions, custom options (ignored).
//!
//! One `<package>.rs` file is written per protobuf package (`_.rs` for files without one);
//! include it with `only_protobuf::include_proto!("<package>")`. Types of another package are
//! referred to with relative paths (`super::other::Type`), so mirror the package hierarchy with
//! nested modules, as with prost.
//!
//! ```no_run
//! // in build.rs
//! let out = std::env::var("OUT_DIR").unwrap();
//! only_protobuf_build::compile(&["proto/route_guide.proto"], &out).unwrap();
//! // or, with settings:
//! only_protobuf_build::Config::new()
//!     .include("proto")
//!     .btree_maps(true)
//!     .compile(&["proto/route_guide.proto"], &out)
//!     .unwrap();
//! ```
//!
//! Guide: [gRPC](https://lesismal.github.io/only/en/protocols/grpc.html)
//! (中文: [gRPC](https://lesismal.github.io/only/zh-CN/protocols/grpc.html)).
#![warn(clippy::unwrap_used)]

mod generate;
mod parse;
mod wkt;

use std::{
    collections::HashSet,
    io,
    path::{Path, PathBuf},
};

/// Code generation settings. [`compile`] is `Config::new().compile(..)`.
#[derive(Clone, Debug)]
pub struct Config {
    includes: Vec<PathBuf>,
    grpc: Option<bool>,
    btree_maps: bool,
    unknown_fields: bool,
    extern_paths: Vec<(String, String)>,
    compile_well_known_types: bool,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            includes: Vec::new(),
            grpc: None,
            btree_maps: false,
            unknown_fields: true,
            extern_paths: Vec::new(),
            compile_well_known_types: false,
        }
    }
}

impl Config {
    /// The defaults: imports searched next to the input files, gRPC code when there are
    /// services, `HashMap` for maps, unknown fields kept.
    pub fn new() -> Config {
        Config::default()
    }

    /// Searches `dir` for imports (before the input files' own directories). Input files under
    /// it are named relative to it, as `protoc -I` does.
    #[must_use]
    pub fn include(mut self, dir: impl Into<PathBuf>) -> Config {
        self.includes.push(dir.into());
        self
    }

    /// Generates the `only-grpc` code: service stubs and `only_grpc::codec::Message` for every
    /// message (the crate then depends on `only-grpc`). Default: on when a compiled file
    /// declares a service.
    #[must_use]
    pub fn grpc(mut self, on: bool) -> Config {
        self.grpc = Some(on);
        self
    }

    /// `BTreeMap` instead of `HashMap` for map fields (sorted, deterministic encoding).
    #[must_use]
    pub fn btree_maps(mut self, on: bool) -> Config {
        self.btree_maps = on;
        self
    }

    /// Keeps unknown fields in an `unknown_fields` member and writes them back (default on).
    /// Off, messages have only their declared fields and unknown ones are skipped.
    #[must_use]
    pub fn unknown_fields(mut self, on: bool) -> Config {
        self.unknown_fields = on;
        self
    }

    /// Uses existing Rust types for a protobuf package or type instead of generating them:
    /// `extern_path(".my.common", "::common_protos")` makes `.my.common.Point` the Rust type
    /// `::common_protos::Point` (nested types under snake_case modules, as generated).
    /// `.google.protobuf` maps to `::only_protobuf::well_known` unless
    /// [`compile_well_known_types`](Self::compile_well_known_types) is on.
    #[must_use]
    pub fn extern_path(mut self, proto: &str, rust: &str) -> Config {
        let p = if proto.starts_with('.') {
            proto.to_owned()
        } else {
            format!(".{proto}")
        };
        self.extern_paths
            .push((p, rust.trim_end_matches("::").to_owned()));
        self
    }

    /// Generates the `google.protobuf` well-known types too, instead of using
    /// `only_protobuf::well_known`.
    #[must_use]
    pub fn compile_well_known_types(mut self, on: bool) -> Config {
        self.compile_well_known_types = on;
        self
    }

    /// Generates the code without writing it: `(file name, Rust source)` per package, sorted by
    /// file name.
    pub fn generate(&self, protos: &[impl AsRef<Path>]) -> io::Result<Vec<(String, String)>> {
        let (files, _) = self.load(protos)?;
        generate::generate(self, files).map_err(invalid)
    }

    /// Generates the code for `protos` (and the files they import) into `out_dir`. Writes a file
    /// only when its content changed, and prints `cargo:rerun-if-changed` for every `.proto`
    /// file read.
    pub fn compile(
        &self,
        protos: &[impl AsRef<Path>],
        out_dir: impl AsRef<Path>,
    ) -> io::Result<()> {
        let (files, read) = self.load(protos)?;
        let out = generate::generate(self, files).map_err(invalid)?;
        let dir = out_dir.as_ref();
        std::fs::create_dir_all(dir)?;
        for (name, code) in out {
            let path = dir.join(name);
            if std::fs::read(&path).ok().as_deref() != Some(code.as_bytes()) {
                std::fs::write(&path, code)?;
            }
        }
        for p in read {
            println!("cargo:rerun-if-changed={}", p.display());
        }
        Ok(())
    }

    /// Reads and parses `protos` and their imports. Returns the files and the paths read
    /// from disk.
    fn load(&self, protos: &[impl AsRef<Path>]) -> io::Result<(Vec<parse::File>, Vec<PathBuf>)> {
        let mut includes = self.includes.clone();
        for p in protos {
            let parent = p
                .as_ref()
                .parent()
                .unwrap_or_else(|| Path::new(""))
                .to_path_buf();
            if !includes.contains(&parent) {
                includes.push(parent);
            }
        }
        let mut files = Vec::new();
        let mut read = Vec::new();
        let mut seen = HashSet::new();
        let mut queue: Vec<(String, Option<PathBuf>)> = Vec::new();
        for p in protos {
            let p = p.as_ref();
            let name = includes
                .iter()
                .find_map(|i| p.strip_prefix(i).ok())
                .map(|r| {
                    r.components()
                        .map(|c| c.as_os_str().to_string_lossy().into_owned())
                        .collect::<Vec<_>>()
                        .join("/")
                })
                .filter(|n| !n.is_empty())
                .unwrap_or_else(|| p.display().to_string());
            queue.push((name, Some(p.to_path_buf())));
        }
        while let Some((name, path)) = queue.pop() {
            if !seen.insert(name.clone()) {
                continue;
            }
            let src = if let Some(s) = wkt::source(&name) {
                s.to_owned()
            } else {
                let path = match path {
                    Some(p) => p,
                    None => includes
                        .iter()
                        .map(|i| i.join(&name))
                        .find(|p| p.is_file())
                        .ok_or_else(|| {
                            invalid(format!(
                                "import {name:?} not found in {}",
                                includes
                                    .iter()
                                    .map(|i| format!("{:?}", i.display().to_string()))
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            ))
                        })?,
                };
                let s = std::fs::read_to_string(&path)
                    .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", path.display())))?;
                read.push(path);
                s
            };
            let f = parse::parse(&src, &name).map_err(invalid)?;
            for i in &f.imports {
                queue.push((i.clone(), None));
            }
            files.push(f);
        }
        Ok((files, read))
    }
}

/// Generates the code for `protos` into `out_dir` with the default [`Config`].
pub fn compile(protos: &[impl AsRef<Path>], out_dir: impl AsRef<Path>) -> io::Result<()> {
    Config::new().compile(protos, out_dir)
}

fn invalid(m: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, m.into())
}
