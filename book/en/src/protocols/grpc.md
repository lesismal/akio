# gRPC

`flash-grpc` provides a gRPC server that is a flash-http `Service` (so it shares the port and the
HTTP/2 stack with ordinary HTTP routes) and a client on flash-http's HTTP/2 client. Interop with
grpc-go is tested in both directions (`tools/interop/grpc/run.sh`).

## Server

```rust,ignore
{{#include ../../../../crates/flash-grpc/examples/guide-grpc.rs:server}}
```

Registering methods (`path` is `/package.Service/Method`):

| Builder | Handler signature | Use |
|---|---|---|
| `unary(path, f)` | `Fn(&Metadata, Vec<u8>, Sink)` | one request, one response |
| `server_stream(path, f)` | `Fn(&Metadata, Vec<u8>, Sink)` | one request, many responses |
| `client_stream(path, f)` | `Fn(&Metadata, Vec<Vec<u8>>, Sink)` | many requests (delivered at half-close), one response |
| `bidi(path, open)` | `Fn(&Metadata, Sink) -> OnMessage` | the general form: `OnMessage` gets `Some(msg)` per request, then `None` at half-close |

Other settings: `interceptor(Fn(&Metadata) -> Result<(), Status>)` runs before every call (an
`Err` ends it with that status), `max_message(n)` (default 4 MiB), `compress(bool)` (gzip
responses for clients that accept it; gzip requests are always accepted).

The `Sink` answers, from any thread: `send(msg) -> bool`, `set_header`, `set_trailer`,
`finish(Status)`, `is_finished`. `Status::ok()`, `Status::new(Code::.., message)`; `Code` has
the standard gRPC codes. Unknown methods get `Unimplemented`; errors before any message are sent
as trailers-only responses; `grpc-timeout` deadlines are enforced.

Handlers run on the I/O thread: answer inline when it is quick, or move the `Sink` to another
thread (the server-streaming example above does) when it is not.

Serving it: `flash_http::serve(grpc)` on its own, or as the `fallback` (or a route) of a
`Router` as above. gRPC needs HTTP/2: cleartext with prior knowledge, or TLS with ALPN `h2`.

## Client

```rust,ignore
{{#include ../../../../crates/flash-grpc/examples/guide-grpc.rs:client}}
```

- `GrpcClient::new(h2_client, base_url)`; `.compress(true)` compresses requests.
- `unary(path, msg, CallOptions) -> Result<Vec<u8>, Status>` blocks the calling thread (do not
  call it on an I/O thread).
- `collect(path, requests, opts) -> (Vec<Vec<u8>>, Status)` for streaming calls, also blocking.
- `bidi(path, opts, on_message, on_done) -> ClientSink` is the non-blocking general form:
  `ClientSink::send`, `close_send`.
- `CallOptions`: `timeout` (sent as `grpc-timeout`), `metadata`.

## Messages

Messages are bytes. With the `prost` feature, `flash_grpc::codec` converts prost-generated
messages; any other serializer works by encoding to `Vec<u8>` yourself.

Not provided: server reflection, the standard health-checking service, client-side load
balancing. Interop has been run against grpc-go only (not tonic).
