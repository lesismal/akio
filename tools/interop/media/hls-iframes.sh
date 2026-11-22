#!/usr/bin/env bash
# akio-media HLS I-frame playlists of AES-128 renditions in headless Chrome (setup as in
# browser.sh): the `serve_aes128_iframes` server of crates/akio-media/tests/hls_iframes.rs
# publishes H.264 + AAC and H.265 + AAC renditions under the multivariant playlist live/cam,
# encrypted with AES-128 (keys rotated every two segments), in MPEG-TS and in fMP4; hls.js
# plays each format's multivariant playlist and the H.264 I-frame playlist on its own, and
# Shaka Player plays the multivariant playlist and switches to its I-frame (trick mode) track
# (see hls-iframes.mjs; both from jsDelivr, skipped when unreachable). Needs Node >= 22 and
# Chrome (CHROME=/path/to/chrome; the macOS default location is tried). Ports 9550-9552
# (CDP_PORT, BASE_PORT to move them).
set -eu
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
CHROME=${CHROME:-"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"}
CDP=${CDP_PORT:-9550}
BASE=${BASE_PORT:-9551}
TS=127.0.0.1:$BASE
MP4=127.0.0.1:$((BASE + 1))
cd "$ROOT" && cargo test -q -p akio-media --test hls_iframes --no-run
W=$(mktemp -d)
PIDS=""
# The server is the test binary under cargo: killed by its name too.
trap 'kill $PIDS 2>/dev/null || true; pkill -f "hls_iframes-.*serve_aes128_iframes" 2>/dev/null || true; sleep 1; rm -rf "$W" 2>/dev/null || true' EXIT

"$CHROME" --headless=new --remote-debugging-port="$CDP" --user-data-dir="$W/profile" \
  --autoplay-policy=no-user-gesture-required --no-first-run --no-default-browser-check \
  about:blank >"$W/chrome.log" 2>&1 & PIDS="$PIDS $!"
AKIO_HLS_IFRAMES_ADDRS="$TS,$MP4" AKIO_HLS_IFRAMES_SECS=${AKIO_HLS_IFRAMES_SECS:-150} \
  cargo test -q -p akio-media --test hls_iframes serve_aes128_iframes -- --ignored --nocapture \
  >"$W/server.log" 2>&1 & PIDS="$PIDS $!"
for _ in $(seq 100); do grep -q READY "$W/server.log" && break; sleep 0.2; done
grep -q READY "$W/server.log" || { cat "$W/server.log" >&2; exit 1; }
node "$ROOT/tools/interop/media/hls-iframes.mjs" "$CDP" "$TS" "$MP4" || { cat "$W/server.log" >&2; exit 1; }
echo "akio-media HLS I-frame interop: all passed"
