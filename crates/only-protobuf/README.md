# only-protobuf

[中文](README.zh-CN.md)

The Protocol Buffers runtime of [`only`](https://github.com/lesismal/only), with no
dependencies. Messages are generated from `.proto` files by
[`only-protobuf-build`](../only-protobuf-build) (no `protoc`).

- `encoding`: the wire format (varints, ZigZag, fixed-width values, length-delimited fields,
  groups skipped) and the per-field encoders and decoders generated code calls.
- `Message`: encode, decode, merge, length-delimited framing. `Enumeration` for open enums
  (unknown numbers survive), `UnknownFields` keeps fields a message does not know and writes
  them back, `Name` gives the full name and the `Any` type URL.
- `well_known`: `Empty`, `Timestamp`, `Duration`, `Any`, the wrappers, `FieldMask`, `Struct` /
  `Value` / `ListValue`, with `SystemTime` / `std::time::Duration` conversions and
  `Any::pack` / `unpack`.
- Bounded decoding: 100 levels of nesting, lengths checked against the input, UTF-8 checked; a
  field with an unexpected wire type is kept as an unknown field (as in C++ and Go).
- Encodes as protoc's C++ runtime does (fields in number order, `-0.0` and map entries'
  default keys and values written), checked against golden encodings made by protoc.
- `reflect`: descriptor pools and `DynamicMessage` (messages of types known at run time);
  `json`: the canonical proto3 JSON mapping; `Extendable` / `Extension` for proto2 extensions,
  closed enums, groups and editions (ADR-022).
- `text`: the text format, parsed and printed as protoc does (ADR-030).

```rust,ignore
// build.rs:  only_protobuf_build::compile(&["proto/route_guide.proto"], std::env::var("OUT_DIR")?)?;
pub mod routeguide {
    only_protobuf::include_proto!("routeguide");
}

use only_protobuf::Message;
let p = routeguide::Point { latitude: 1, longitude: 2, ..Default::default() };
let bytes = p.encode_to_vec();
assert_eq!(routeguide::Point::decode(&bytes)?, p);
```

Tests (`tools/protobuf-test`): golden encodings from protoc, round trips, merge semantics,
limits, differential tests and a fuzz target against prost, and the gRPC interop run with
grpc-go's generated route_guide / helloworld code (`tools/interop/grpc/run.sh`).

Guide: [gRPC](https://lesismal.github.io/only/en/protocols/grpc.html).
