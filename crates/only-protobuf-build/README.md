# only-protobuf-build

[中文](README.zh-CN.md)

Generates Rust code for `.proto` files from `build.rs`, for
[`only-protobuf`](../only-protobuf) and [`only-grpc`](../only-grpc). The `.proto` parser is
built in: no `protoc`, no `syn` / `quote`, no third-party crates.

- proto3 and proto2: messages, nested types, enums (open: a newtype over `i32` with one constant
  per value), every scalar type, `optional` (`Option<T>`), `required`, `repeated` (packed per
  syntax or `[packed = ...]`), `map<K, V>` (`HashMap`, or `BTreeMap` with `btree_maps(true)`),
  `oneof` (an enum), proto2 `[default = ...]` (getters), recursive messages (boxed), packages
  and imports, proto comments as doc comments.
- Unknown fields kept in an `unknown_fields` member (turn off with `unknown_fields(false)`, then
  struct literals need no `..Default::default()`).
- `google/protobuf/{empty,timestamp,duration,any,wrappers,field_mask,struct}.proto` are built in
  and map to `only_protobuf::well_known`; `extern_path` maps other packages to existing crates.
- Services become `only-grpc` code: `<service>_server::{<Service> trait, register}` and
  `<service>_client::<Service>Client`, for unary, server-streaming, client-streaming and
  bidirectional methods; every message then implements `only_grpc::codec::Message`.
- Not supported: groups, extensions (parsed and ignored), editions, custom options (ignored).

```rust,ignore
// build.rs
fn main() {
    let out = std::env::var("OUT_DIR").unwrap();
    only_protobuf_build::compile(&["proto/route_guide.proto"], &out).unwrap();
}

// src/lib.rs: one file per package, included as a module
pub mod routeguide {
    only_protobuf::include_proto!("routeguide");
}
```

A server implements the generated trait and registers it:

```rust,ignore
use only_grpc::{GrpcServer, Metadata, Sink, Status};
use routeguide::{route_guide_server::{self, RouteGuide}, Feature, Point};

struct Guide;
impl RouteGuide for Guide {
    fn get_feature(&self, _md: &Metadata, p: Point) -> Result<Feature, Status> {
        Ok(Feature { name: "here".into(), location: Some(p), ..Default::default() })
    }
    // list_features(.., sink: Sink), record_route(.., Vec<Point>), route_chat(..) -> Box<dyn FnMut>
}
let grpc = route_guide_server::register(GrpcServer::new(), Guide);
```

and a client wraps a `GrpcClient`:
`RouteGuideClient::new(grpc).get_feature(&point, CallOptions::default())?`.

Guide: [gRPC](https://lesismal.github.io/only/en/protocols/grpc.html).
