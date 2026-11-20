#!/usr/bin/env bash
# only-http <-> Go: WebSocket over HTTP/2 (RFC 8441), both directions, over h2c and TLS (Go's
# net/http server, golang.org/x/net/http2 client; Go 1.24 or later, extended CONNECT behind
# GODEBUG=http2xconnect=1). Then a browser (Chrome or Chromium, headless; CHROME=path to pick
# one) opens a WebSocket on the HTTP/2 connection of the page it loaded; skipped without one.
set -eu
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
OUT=${TMPDIR:-/tmp}
cd "$ROOT" && cargo build -q --release -p only-http --example h2-ws-interop
RS=$ROOT/target/release/examples/h2-ws-interop
cd "$ROOT/tools/interop/h2ws" && GOFLAGS=-mod=mod go build -tags http2legacy -o "$OUT/h2ws-go" .
export GODEBUG=http2xconnect=1
"$OUT/h2ws-go" server 127.0.0.1:9420 127.0.0.1:9421 > "$OUT/h2ws-go-server.log" 2>&1 &
GS=$!
"$RS" server 127.0.0.1:9422 127.0.0.1:9423 > "$OUT/h2ws-rust-server.log" 2>&1 &
RSV=$!
trap 'kill $GS $RSV 2>/dev/null || true' EXIT
sleep 1
"$OUT/h2ws-go" client 127.0.0.1:9422 127.0.0.1:9423
"$RS" client 127.0.0.1:9420 127.0.0.1:9421
CHROME=${CHROME:-$(command -v google-chrome chromium chromium-browser 2>/dev/null | head -n 1 || true)}
MAC_CHROME="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
if [ -z "$CHROME" ] && [ -x "$MAC_CHROME" ]; then CHROME=$MAC_CHROME; fi
if [ -n "$CHROME" ]; then
    "$RS" browser 127.0.0.1:9424 "$CHROME"
else
    echo "no Chrome or Chromium found: browser check skipped"
fi
echo "h2 websocket interop: all passed"
