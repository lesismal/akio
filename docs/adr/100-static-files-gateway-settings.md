# ADR-100: Static files for a gateway: a path the caller names, twins by q value, candidate paths, directory listings

English | [简体中文](100-static-files-gateway-settings.zh-CN.md)

Status: accepted (2026-11-24)

## Context

akit, a reverse proxy and gateway built on akio, serves files with `akio_http::files::Files` for
its `static` handler, which must answer as fit's (the gateway akit rebuilds) does. akit's
requests A13, A16, A17 and A18 name four things `Files` could not do:

- **A13.** `Files` takes the path from the route parameter `path` (set only by akio's own
  `Router`) or from the request target. A caller that routes by a path of its own, with a prefix
  stripped or dot segments removed, could not give it that path.
- **A16.** A file's `.br`, `.zst` or `.gz` twin went to the first of `br`, `zstd`, `gzip` whose
  name the `Accept-Encoding` field held, whatever its q value. `br;q=0` got the `br` twin the
  client had refused; `*` got none; `GZIP` and `gzip ;q=1` got none. The twins could not be
  limited to some encodings or turned off, and `Vary: Accept-Encoding` was always sent.
- **A17.** No `try_files`: candidate paths tried in turn, the first that exists served
  (`["{path}", "{path}/", "/index.html"]` for a single-page application). `Files` answered its
  own 404 on the disk pool, so a caller could neither try another path nor learn that one was
  missing without doing the disk work on the I/O thread.
- **A18.** No directory listings: a directory without its index file was 404, from the disk pool,
  where a caller could not list it.

Constraints: additive API, default behaviour unchanged except the twin choice, which follows RFC
9110 now; nothing on the I/O thread touches the disk; every new memory bounded; the cache hit path
no slower.

## Decision

All in `akio-http`'s `files.rs`.

- **`Files::serve(&self, ctx, path)`** (A13): the `Service::call` body with the path given
  (percent-encoded, as sent). It is decoded and checked as before: `..`, NUL, `\` and `:` segments
  are refused. `call` now calls it with the route parameter or the request path.
- **Twin choice by q value** (A16): `pick` ranks the twins on disk by their q value in every
  `Accept-Encoding` field (RFC 9110 section 12.5.3): the coding's own, else `*`'s, 0 refusing.
  Names compare case-insensitively and blanks are trimmed; a q value that does not parse or lies
  outside 0 to 1 counts as 1, as Go's fit does. Among equals the first in `Files::twins` order
  wins.
  - `Files::twins(&[&str])` sets which encodings are looked up and that order. The default is
    `br`, `zstd`, `gzip`, as before; unknown names and repeats are left out.
  - With none, no twin is looked up and `Vary` is not sent.
  - The cost on a hit is nothing for a file without twins. Otherwise the field is parsed once per
    configured twin found.
- **`Files::try_paths(&[&str])`** (A17): candidate templates, `{path}` standing for the decoded
  path asked for with a leading `/`.
  - They are resolved in turn on the disk pool. A candidate ending in `/` names a directory, served
    by its index file or its listing.
  - A candidate is passed over when it names a directory without the slash, a file with one,
    something that is neither a regular file nor a directory, a path that does not pass the
    checks above, or a path `hide` hides. None found is 404. No redirect is ever sent for a
    directory.
  - What a request path resolved to is kept in a map of at most 4096 paths, cleared when full,
    and trusted for `check_interval` while the file's own entry is fresh. A request for a path
    resolved lately is then answered on the I/O thread like any hit.
  - **`Files::hide(f)`**: a test of decoded paths. The path asked for is answered 404 when it
    returns true, and a candidate is passed over (fit's dotfiles). It must be `RefUnwindSafe`,
    so `Files` stays `UnwindSafe`.
- **`Files::list_directories(max_entries)`** (A18, off by default): a directory without its index
  file, asked for with its trailing slash (or reached by a `try_paths` candidate ending in `/`),
  is listed on the disk pool for every request.
  - At most `max_entries` entries are read; one more read tells the page to say there are more.
    Names starting with a dot are dropped, then directories come first and each group is sorted
    by name.
  - The page is an HTML table whose names are HTML-escaped and whose links are relative,
    percent-escaped segments, with sizes and UTC modification times. It is sent with
    `Content-Type: text/html; charset=utf-8` and `Cache-Control: no-cache`.
  - The page is fit's, byte for byte.

Rejected:

- A public way to set route parameters: it would let any service rewrite what the router
  matched, for one use.
- A response filter for the caller to catch `Files`' 404s: filters run wherever the response is
  sent, which is not a contract for disk work.
- Caching listings: fit does not, they are bounded by `max_entries`, and a cached listing would
  need its directory watched.

## Consequences

- akit's `static` handler can serve `strip_prefix` and canonical paths, fit's `precompressed`
  choice, `try_files` and `browse`. The other gaps of akit's A14 and A15 stay open.
- A client that sent `br;q=0` and got `br` before now gets the file as it is; one that sent `*`
  now gets the preferred twin. Both follow RFC 9110; CHANGELOG lists it under Changed.
- Tests: `features.rs` (twins by q value, configured and none, from the pool and from the cache;
  `serve` with a prefix stripped and traversal refused; `try_paths` with and without a check
  interval, hidden and unsafe candidates, a resolution that changes on disk, 5000 distinct paths;
  listings, their escaping, order, bounds, HEAD and through `try_paths`). The `files` unit tests
  cover q values, escaping and dates.
