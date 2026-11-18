#!/usr/bin/env bash
# only-media WHIP/WHEP with media and multivariant fMP4 LL-HLS against headless Chrome, with the
# setup of tools/interop/webrtc/browser.sh (Chrome's fake camera and microphone, the DevTools
# Protocol from Node): Chrome publishes VP8, VP9, AV1 and H.264 over WHIP to the `whip-server`
# example and decodes each over WHEP, then plays the multivariant playlist of two WHIP
# AV1 renditions with its own HLS player and hls.js (see browser.mjs). Needs Node >= 22
# and Chrome (CHROME=/path/to/chrome; the macOS default location is tried). Ports 9540-9543
# (CDP_PORT, BASE_PORT to move them).
set -eu
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
CHROME=${CHROME:-"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"}
CDP=${CDP_PORT:-9540}
BASE=${BASE_PORT:-9541}
cd "$ROOT" && cargo build -q --release -p only-media --features webrtc --example whip-server
MS=$ROOT/target/release/examples/whip-server
W=$(mktemp -d)
PIDS=""
trap 'kill $PIDS 2>/dev/null || true; sleep 1; rm -rf "$W" 2>/dev/null || true' EXIT

"$CHROME" --headless=new --remote-debugging-port="$CDP" --user-data-dir="$W/profile" \
  --use-fake-device-for-media-stream --use-fake-ui-for-media-stream \
  --allow-loopback-in-peer-connection --autoplay-policy=no-user-gesture-required \
  --no-first-run --no-default-browser-check \
  about:blank >"$W/chrome.log" 2>&1 & PIDS="$PIDS $!"
HTTP=127.0.0.1:$((BASE + 1))
$MS "127.0.0.1:$BASE" "$HTTP" "127.0.0.1:$((BASE + 2))" >"$W/server.log" 2>&1 & PIDS="$PIDS $!"
sleep 2
node "$ROOT/tools/interop/media/browser.mjs" "$CDP" "$HTTP" || { cat "$W/server.log" >&2; exit 1; }
echo "only-media browser interop: all passed"
