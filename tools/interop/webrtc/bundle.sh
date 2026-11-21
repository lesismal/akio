#!/usr/bin/env bash
# Sessions without BUNDLE and data channel priorities against headless Chrome (ADR-072):
# Chrome offers with bundlePolicy "max-compat" (audio, video, data channels, one of them with
# priority "high") to the only ICE-lite RtcServer configured to refuse BUNDLE: a transport per
# section on both sides (checked in Chrome's statistics), data and media echoed, and the
# server logs the channel's DCEP priority; then the only Endpoint offers audio and a "high"
# channel without BUNDLE to Chrome, which answers with a transport per section and sends its
# microphone. Chrome 157 has no RTCDataChannel.priority (it sends 256 and reports undefined),
# so the priority lines are informative only. Needs Node >= 22 and Chrome (CHROME=...). Ports
# 9540-9544.
set -eu
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
CHROME=${CHROME:-"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"}
cd "$ROOT" && cargo build -q --release -p only-webrtc --example webrtc-interop
RS=$ROOT/target/release/examples/webrtc-interop
W=$(mktemp -d)
PIDS=""
trap 'kill $PIDS 2>/dev/null || true; sleep 1; rm -rf "$W" 2>/dev/null || true' EXIT

"$CHROME" --headless=new --remote-debugging-port=9540 --user-data-dir="$W/profile" \
  --use-fake-device-for-media-stream --use-fake-ui-for-media-stream \
  --allow-loopback-in-peer-connection --no-first-run --no-default-browser-check \
  --disable-features=WebRtcHideLocalIpsWithMdns ${CHROME_ARGS:-} \
  about:blank >"$W/chrome.log" 2>&1 & PIDS="$PIDS $!"
ONLY_INTEROP_BUNDLE=off $RS server 127.0.0.1:9541 127.0.0.1:9542 2>"$W/server.log" & PIDS="$PIDS $!"
sleep 2

echo "== Chrome (max-compat) offers to the only server, which refuses BUNDLE"
node "$ROOT/tools/interop/webrtc/browser.mjs" 9540 offer-maxcompat 127.0.0.1:9542
grep 'channel "chrome" open' "$W/server.log"

echo "== the only Endpoint offers audio and a high-priority channel without BUNDLE to Chrome"
node "$ROOT/tools/interop/webrtc/browser.mjs" 9540 answer 127.0.0.1:9543 nobundle >"$W/answer.log" 2>&1 &
NP=$!
sleep 1
ONLY_INTEROP_BUNDLE=off ONLY_INTEROP_PRIORITY=high $RS client 127.0.0.1:9543 media-in || { cat "$W/answer.log"; exit 1; }
for _ in $(seq 75); do grep -q "chrome: nobundle" "$W/answer.log" && break; sleep 0.2; done
kill $NP 2>/dev/null || true
grep "chrome: nobundle" "$W/answer.log"
grep -q "chrome: nobundle ok" "$W/answer.log"
echo "ok: bundle.sh"
