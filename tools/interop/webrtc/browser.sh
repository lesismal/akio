#!/usr/bin/env bash
# only-webrtc <-> headless Chrome, both offer directions: Chrome offers to the only ICE-lite
# RtcServer (data channels, fake camera/microphone media echoed back and decoded by Chrome), and
# the only full-ICE Endpoint offers to Chrome (data channel echo). Needs Node >= 22 and Chrome
# (CHROME=/path/to/chrome; the macOS default location is tried).
set -eu
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
CHROME=${CHROME:-"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"}
cd "$ROOT" && cargo build -q --release -p only-webrtc --example webrtc-interop
RS=$ROOT/target/release/examples/webrtc-interop
W=$(mktemp -d)
PIDS=""
trap 'kill $PIDS 2>/dev/null || true; sleep 1; rm -rf "$W" 2>/dev/null || true' EXIT

"$CHROME" --headless=new --remote-debugging-port=9520 --user-data-dir="$W/profile" \
  --use-fake-device-for-media-stream --use-fake-ui-for-media-stream \
  --allow-loopback-in-peer-connection --no-first-run --no-default-browser-check \
  about:blank >"$W/chrome.log" 2>&1 & PIDS="$PIDS $!"
$RS server 127.0.0.1:9510 127.0.0.1:9511 2>"$W/server.log" & PIDS="$PIDS $!"
sleep 2

echo "== Chrome offers to the only ICE-lite server"
node "$ROOT/tools/interop/webrtc/browser.mjs" 9520 offer 127.0.0.1:9511
echo "== only (full ICE Endpoint) offers to Chrome"
node "$ROOT/tools/interop/webrtc/browser.mjs" 9520 answer 127.0.0.1:9512 & PIDS="$PIDS $!"
sleep 1
$RS client 127.0.0.1:9512 dc
echo "webrtc browser interop: all passed"
