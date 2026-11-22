# ADR-003: Handler and per-connection state

English | [简体中文](003-handler-and-state.zh-CN.md)

Status: accepted (2026-11-13)

## Decision

The per-connection state **is** the handler value: `trait Handler: Send + Sized + 'static` with `on_data(&mut self, &Conn<Self>, &[u8])`, `on_close`, `on_hangup`. An `Acceptor` (shared, `Sync`) creates one `Handler` per connection in `on_open`. `Conn<H>` is generic over the handler type only so that `spawn_blocking`'s completion callback can be typed `FnOnce(&mut H, &Conn<H>, R)`; thanks to `PhantomData<fn() -> H>` the handle is `Send + Sync` for any `H`.

Prototyped alternatives (rejected): (a) untyped `Conn` + `Box<dyn Any>` state, which costs a downcast on every callback and loses type safety; (b) one shared `&self` handler with an associated per-connection state type, which makes `done` callbacks awkward to type. The prototype in `crates/akio-core` compiles and is exercised by `tests/api.rs`.

## Consequences

- Handlers may hold `Cell` and other `!Sync` data; no `Sync` bound anywhere on the hot path.
- Erased storage inside the engine (`Box<dyn ErasedHandler>`) lets one Engine serve listeners with different handler types.
- Finding: a blanket `impl Acceptor for Fn(&Conn<H>) -> H` is rejected by coherence (unconstrained `H`), so closures are wrapped with `fn_acceptor`.
