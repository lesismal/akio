# ADR-124: `Files` as a gateway's static handler, bounded in memory, and file bodies encoded

English | [简体中文](124-files-as-a-gateway-static-handler.zh-CN.md)

Status: accepted (2026-11-25)

## Context

akit serves fit's `static` handler with akio-http's `Files` and ports fit's tests. Three akit
requests (`akit/docs/akio-api-requests.md`) remained:

- **A14.** fit answers some requests otherwise than `Files`: index files tried in order (or
  none), a directory asked for without its slash redirected (`301`, the query kept), a file asked
  for with a trailing slash `404`, Go's content types (`.xml` as `text/xml; charset=utf-8`,
  `.avif`, the system's `mime.types`), a `default_type`, else the type sniffed from the first 512
  bytes, `403` for a file that may not be read, only regular files opened (a FIFO held a disk pool
  thread until a writer came), `:` a character like others, its own short error bodies, and a
  listing below a stripped prefix titled by the whole path.
- **A15.** fit keeps at most `max_cache_bytes` (64 MiB) of files in memory and answers `503` a
  request that waited on its file pool past the pool's timeout. `Files` bounded the size of each
  file kept, not the total, and a queued request waited as long as the disk took.
- **A92.** fit's `compress` middleware compresses a large file read from disk too. akio sends a
  file body with `sendfile(2)` (or reads it on the transport's side); a filter could not give it
  a coding, and the file cannot be read on an I/O thread to encode it.

## Decision

**A14**, as builder settings on `Files` (defaults unchanged where not said):

- `index_files(&[&str])`: the files that stand for a directory, tried in order; none is allowed.
  `index(name)` stays, a list of one.
- `redirect_directories(bool)`: a directory asked for without its slash answers `301` to the
  request's path with the slash (the prefix included), the query kept, a path that would read as
  a host (`//x`) made safe.
- `mime_types(Arc<MimeTypes>)`: the content types by extension. `MimeTypes::builtin()` is Go's
  built-in table; `MimeTypes::system()` adds the system's files as Go's `mime` package reads them
  on Unix (a shared-mime-info `globs2` adding extensions, else the `mime.types` files over each
  other; `text/` types get `charset=utf-8`), read once and bounded in size. Without it, `Files`'
  own short table, as before.
- `default_type(Option<&str>)` and `sniff(bool)`: the type of a file whose extension gives none.
  `files::sniff` is Go's `http.DetectContentType`; the bytes are read with the file on the disk
  pool and the type kept with the entry. A compressed twin of such a file is the default type,
  else `application/octet-stream`.
- `error_response(f)`: the answers `Files` makes (`301`, `403`, `404`, `405`, `500`, `503`), with
  `Location`, `Allow` and `Retry-After` added by `Files`.
- `serve_prefixed(ctx, prefix, path)`: `serve` for a caller that took a prefix off the path, so
  listings and redirects name the whole path. `Service::call` under a route does the same with
  the route's part, and keeps the request's trailing slash, which the router's wildcard drops.
- Fixed: `403` for a file that may not be read (`PermissionDenied`), `404` for what is neither a
  regular file nor a directory (never opened) and for a file asked for with a trailing slash; `:`
  is allowed in a name.

**A15**:

- `max_cache_bytes(n)` (default 64 MiB): the bytes kept in memory, files, compressed twins and
  copies (`compress`, charged when made) together, evicted least recently used first with the
  CLOCK the open handles use. The cache keeps two rings under its one lock: the open handles
  (`max_open_files`) and the entries holding bytes. A file larger than the bound alone is read
  for its request and not kept.
- `disk_timeout(Option<Duration>)`: a request queued on the disk pool and not answered within the
  timeout is answered `503` with `Retry-After: 1`; its work, when it runs, answers nothing. The
  requests waiting are kept in order of their deadline; a sweep on akio-http's timer thread every
  eighth of the timeout, scheduled only while some wait, answers those past it and drops those
  answered. The list is bounded (8192, compacted past it). The work holds the request, not its
  answer's lock, while it reads the disk, so a disk that hangs never holds the sweep.

**A92**: when the response filters leave a stream coding (`Response::set_stream_coding`, ADR-112)
on a response whose body is a file, the response is sent as a streamed one: `Content-Length`
dropped, chunked on keep-alive HTTP/1.1 (close-delimited otherwise, framed on HTTP/2 and HTTP/3),
the file read in 64 KiB pieces on `Files`' disk pool, each piece encoded there and written, the
next once fewer than 256 KiB are queued on the connection (`BodyStream::on_drain`). A failed read
or write drops the stream, which cuts the body and closes the connection; a full pool is asked
again every 5 ms for a second. A HEAD answer sends the head. The filters now run in one place for
HTTP/1 as for HTTP/2 and HTTP/3 (`Out::send`).

## Consequences

- akit's `static` handler takes fit's `index` lists, `default_type` and `max_cache_bytes`, and its
  `compress` middleware compresses bodies sent from disk.
- `Files` now bounds its memory by default (64 MiB), where it was bounded only per file: a server
  with many small files keeps the most used of them.
- Tests: `files::mime::tests` (Go's table, the system files as Go reads them, Go's sniffing
  cases); `files::tests::memory_cache_is_bounded_and_keeps_hot_files` and
  `compressed_copies_count_in_the_memory_bound` (the rings' invariants after every step);
  `tests/files_gateway.rs` (index files, redirects under a route and a prefix, trailing slashes,
  `:`, content types, `403`, a FIFO, error bodies, the disk timeout's `503` with a disk that
  hangs); `tests/file_coding.rs` (gzip over HTTP/1.1, HTTP/1.0 and HTTP/2, HEAD, a slow client
  over 3 MiB that does not compress, a client gone midway). Epoll and io_uring.
