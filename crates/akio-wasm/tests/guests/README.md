# fit's guests, built for the tests

`tests/guests.rs` runs these WebAssembly plugins from fit (`plugin/wasm`, fit at `7daee573`;
`plugin/wasm` is the same at `edbe1cfe`, which built them), gzipped, on a test linker with fit's
ABI, its sync ABI and Proxy-Wasm's (ADR-125, section 7):

| File | Source in fit | Built with | Size |
| --- | --- | --- | --- |
| `headers-go.wasm.gz` | `testdata/headers`: fit's own ABI, edits fields, answers, and `/loop`, `/grow`, `/panic` | Go 1.27.3, `GOOS=wasip1 GOARCH=wasm -buildmode=c-shared` | 4.6 MB |
| `http_routing-go.wasm.gz` | `testdata/proxywasm/http_routing`: the Proxy-Wasm Go SDK's example (Apache 2.0, © Tetrate) | Go 1.27.3, the same | 2.9 MB |
| `sync-rust.wasm.gz` | `testdata/rust`: the sync modules' plugin, on the `fit-guest` crate | Rust 1.98, `wasm32-wasip1`, release | 0.2 MB |

They are built once and committed, so the tests need no toolchain. To rebuild them, when fit's
guests or the toolchains move:

```bash
crates/akio-wasm/tests/guests/build.sh <path to a fit checkout>
```

The script builds each guest whose toolchain it finds (Go, TinyGo, and Rust with
`rustup target add wasm32-wasip1`), gzips it (`gzip -9 -n`), and replaces the file here; then
run `cargo test -p akio-wasm --test guests` and commit. It also builds fit's sync plugin with
TinyGo 0.44 (`tinygo build -target=wasip1 -buildmode=c-shared -scheduler=none`) as
`sync-tinygo.wasm.gz` when `tinygo` is on the path; that guest is not committed yet.

The files are excluded from the published crate (`Cargo.toml`, `exclude`).
