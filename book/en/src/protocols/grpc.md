# gRPC

`only-grpc` provides a gRPC server that is a only-http `Service` (so it shares the port and the
HTTP/2 stack with ordinary HTTP routes) and a client on only-http's HTTP/2 client. Interop with
grpc-go is tested in both directions (`tools/interop/grpc/run.sh`).

## Server

```rust,ignore
{{#include ../../../../crates/only-grpc/examples/guide-grpc.rs:server}}
```

Registering methods (`path` is `/package.Service/Method`):

| Builder | Handler signature | Use |
|---|---|---|
| `unary(path, f)` | `Fn(&Metadata, Vec<u8>, Sink)` | one request, one response |
| `server_stream(path, f)` | `Fn(&Metadata, Vec<u8>, Sink)` | one request, many responses |
| `client_stream(path, f)` | `Fn(&Metadata, Vec<Vec<u8>>, Sink)` | many requests (delivered at half-close), one response |
| `bidi(path, open)` | `Fn(&Metadata, Sink) -> OnMessage` | the general form: `OnMessage` gets `Some(msg)` per request, then `None` at half-close |

Other settings: `interceptor(Fn(&Metadata) -> Result<(), Status>)` runs before every call (an
`Err` ends it with that status), `max_message_bytes(n)` (default 4 MiB), `compress(bool)` (gzip
responses for clients that accept it; gzip requests are always accepted).

The `Sink` answers, from any thread: `send(msg) -> bool`, `set_header`, `set_trailer`,
`finish(Status)`, `is_finished`. `Status::ok()`, `Status::new(Code::.., message)`; `Code` has
the standard gRPC codes. Unknown methods get `Unimplemented`; errors before any message are sent
as trailers-only responses; `grpc-timeout` deadlines are enforced.

Handlers run on the I/O thread: answer inline when it is quick, or move the `Sink` to another
thread (the server-streaming example above does) when it is not.

Serving it: `only_http::serve(grpc)` on its own, or as the `fallback` (or a route) of a
`Router` as above. gRPC needs HTTP/2: cleartext with prior knowledge, or TLS with ALPN `h2`.

## Client

```rust,ignore
{{#include ../../../../crates/only-grpc/examples/guide-grpc.rs:client}}
```

- `GrpcClient::new(h2_client, base_url)`; `.compress(true)` compresses requests.
- `unary(path, msg, CallOptions) -> Result<Vec<u8>, Status>` blocks the calling thread (do not
  call it on an I/O thread).
- `collect(path, requests, opts) -> (Vec<Vec<u8>>, Status)` for streaming calls, also blocking.
- `bidi(path, opts, on_message, on_done) -> ClientSink` is the non-blocking general form:
  `ClientSink::send`, `close_send`.
- `CallOptions`: `timeout` (sent as `grpc-timeout`), `metadata`.

## Messages

Messages are bytes. `only_grpc::codec::{encode, decode}` convert any type implementing
`codec::Message` (`encode_to` / `decode_from`), so any serializer plugs in. For protobuf, `only`
has its own runtime and code generator, with no `protoc` and no third-party crates:

- `only-protobuf`: the wire format, the `Message` trait, open enums, unknown fields, the
  well-known types (`Timestamp`, `Duration`, `Any`, `Struct`, wrappers ...).
- `only-protobuf-build`: a `.proto` parser and Rust generator for `build.rs`. proto3 and proto2
  messages, enums, `optional`, `repeated`, `map`, `oneof`, nested and recursive types, packages,
  imports; services become typed server traits and clients on `only-grpc`.

### Defining messages without prost

Dependencies: `only-protobuf` and `only-grpc`, plus `only-protobuf-build` under
`[build-dependencies]`. Then, in `build.rs` (from `tools/protobuf-test`, whose `proto/` holds
grpc-go's route_guide and helloworld definitions):

```rust,ignore
{{#include ../../../../tools/protobuf-test/build.rs:build}}
```

Every protobuf package becomes one file in `OUT_DIR`; include it as a module. Types of another
package are referred to as `super::other::Type`, so nest the modules like the packages
(`test.all` -> `pub mod test { pub mod all { .. } }`):

```rust,ignore
pub mod routeguide {
    only_protobuf::include_proto!("routeguide");
}
```

What a `.proto` construct becomes:

| `.proto` | Rust |
|---|---|
| `message Point { int32 latitude = 1; }` | `pub struct Point { pub latitude: i32, pub unknown_fields: UnknownFields }` (`Clone`, `PartialEq`, `Debug`, `Default`; `Eq` when there are no floats) |
| `string`, `bytes` | `String`, `Vec<u8>` |
| message-typed field, proto3 `optional`, proto2 `optional` | `Option<T>` (`Option<Box<T>>` when recursive); proto2 defaults through getters (`p.a()`) |
| `repeated T` / `map<K, V>` | `Vec<T>` / `HashMap<K, V>` (`BTreeMap` with `Config::btree_maps(true)`) |
| `oneof kind { .. }` | `pub kind: Option<point::Kind>`, an enum in the message's module |
| `enum Corpus { CORPUS_WEB = 1; }` | `pub struct Corpus(pub i32)` with `Corpus::WEB`: open, unknown numbers survive |
| nested `message Inner` in `Outer` | `outer::Inner` |
| `google.protobuf.Timestamp` ... | `only_protobuf::well_known::Timestamp` ... |

Messages keep unknown fields and write them back (`Config::unknown_fields(false)` removes the
member, so struct literals need no `..Default::default()`). Encoding matches protoc's C++
runtime byte for byte; decoding is bounded (100 nesting levels, checked lengths, UTF-8).

### Services

For `service RouteGuide`, the generator writes `route_guide_server` with a trait to implement:

```rust,ignore
{{#include ../../../../tools/protobuf-test/src/service.rs:server}}
```

Unary methods return the response; server-streaming ones get the `Sink` (usable from any
thread; `sink.send_message(&m)`, then `finish`); client-streaming ones get every request once
the client has half-closed; bidirectional ones return the function that receives each request.
`register` adds every method to a `GrpcServer`, next to raw ones:

```rust,ignore
{{#include ../../../../tools/protobuf-test/src/service.rs:register}}
```

and `route_guide_client::RouteGuideClient` wraps a `GrpcClient`:

```rust,ignore
let rg = RouteGuideClient::new(grpc_client);
let feature = rg.get_feature(&point, CallOptions::default())?;           // unary
let features = rg.list_features(&rect, CallOptions::default())?;         // Vec<Feature>
let summary = rg.record_route(&points, CallOptions::default())?;         // client streaming
let sink = rg.route_chat(CallOptions::default(), |note| { /* each reply */ }, |status, _| {});
sink.send_message(&note);
sink.close_send();
```

The unary and collecting calls block; the bidirectional one does not. Requests that do not
decode are answered with `INVALID_ARGUMENT`. Interop: `tools/interop/grpc/run.sh` runs these
stubs against grpc-go's own generated route_guide and helloworld code and the well-known types
of `google.golang.org/protobuf`, in both directions.

### prost (deprecated)

With the `prost` feature every prost-generated message implements `codec::Message`. It still
works but is deprecated in favour of `only-protobuf`; it names prost's types, so the feature is
outside the semver promise (a prost upgrade, or its removal, may come in a minor release).

Not provided: server reflection, the standard health-checking service, client-side load
balancing. Interop has been run against grpc-go only (not tonic).
