#!/usr/bin/env bash
# only-webrtc <-> headless Chrome, both offer directions: Chrome offers to the only ICE-lite
# RtcServer (data channels, fake camera/microphone media echoed back and decoded by Chrome), and
# the only full-ICE Endpoint offers to Chrome (data channel echo). Needs Node >= 22 and Chrome
# (CHROME=/path/to/chrome; the macOS default location is tried). CHROME_ARGS adds Chrome flags:
# CHROME_ARGS=--force-fieldtrials=WebRTC-DataChannelMessageInterleaving/Enabled/ makes Chrome
# offer I-DATA (RFC 8260), so the data channels run interleaved (Chrome 157 uses DATA otherwise).
# Ports 9510-9522 (run.sh uses 9510-9520: do not run both at once).
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
  --disable-features=WebRtcHideLocalIpsWithMdns --ignore-certificate-errors ${CHROME_ARGS:-} \
  about:blank >"$W/chrome.log" 2>&1 & PIDS="$PIDS $!"
$RS server 127.0.0.1:9510 127.0.0.1:9511 127.0.0.1:9513 2>"$W/server.log" & PIDS="$PIDS $!"
$RS turn 127.0.0.1:9515 127.0.0.1 alice wonderland 127.0.0.1:9516 127.0.0.1:9517 \
  2>"$W/turn.log" & PIDS="$PIDS $!"
$RS sfu 127.0.0.1:9518 127.0.0.1:9519 2>"$W/sfu.log" & PIDS="$PIDS $!"
sleep 2

echo "== Chrome offers to the only ICE-lite server"
node "$ROOT/tools/interop/webrtc/browser.mjs" 9520 offer 127.0.0.1:9511
echo "== only (full ICE Endpoint) offers to Chrome"
node "$ROOT/tools/interop/webrtc/browser.mjs" 9520 answer 127.0.0.1:9512 & PIDS="$PIDS $!"
sleep 1
$RS client 127.0.0.1:9512 dc
echo "== Chrome offers to the only server over ICE-TCP only"
node "$ROOT/tools/interop/webrtc/browser.mjs" 9520 offer-tcp 127.0.0.1:9511
echo "== Chrome offers to the only server, relay only (only-turn over UDP, TCP, TLS)"
for u in "turn:127.0.0.1:9515" "turn:127.0.0.1:9516?transport=tcp" "turns:localhost:9517?transport=tcp"; do
  node "$ROOT/tools/interop/webrtc/browser.mjs" 9520 offer-relay 127.0.0.1:9511 "$u"
done
# Answerers that check the pair Chrome uses: over TCP, or to the Endpoint's relayed candidate.
answer() { # <how> <client args...>
  how=$1; shift
  node "$ROOT/tools/interop/webrtc/browser.mjs" 9520 answer 127.0.0.1:9514 "$how" >"$W/answer.log" 2>&1 &
  NP=$!
  sleep 1
  $RS client 127.0.0.1:9514 "$@"
  for _ in $(seq 50); do grep -q "chrome: pair" "$W/answer.log" && break; sleep 0.2; done
  kill $NP 2>/dev/null || true
  grep "chrome: pair" "$W/answer.log"
  grep -q "chrome: pair ok" "$W/answer.log"
}
echo "== only Endpoint (aggressive nomination) offers to Chrome"
ONLY_INTEROP_NOMINATION=aggressive $RS client 127.0.0.1:9512 dc
echo "== only Endpoint (passive ICE-TCP only) offers to Chrome"
answer tcp dc-tcp
echo "== only Endpoint (relayed candidates over TCP and TLS only) offers to Chrome"
answer relay dc-relay-url "turn:127.0.0.1:9516?transport=tcp" alice wonderland
answer relay dc-relay-url "turns:127.0.0.1:9517" alice wonderland
echo "== only Endpoint (its host address behind an mDNS name) offers to Chrome with mDNS concealment on"
# A second Chrome with its default WebRtcHideLocalIpsWithMdns: both sides' host candidates are
# .local names, each resolves the other's over the LAN's mDNS (needs a LAN address).
"$CHROME" --headless=new --remote-debugging-port=9521 --user-data-dir="$W/profile-mdns" \
  --no-first-run --no-default-browser-check about:blank >"$W/chrome-mdns.log" 2>&1 & PIDS="$PIDS $!"
sleep 2
for _ in 1 2 3; do
  node "$ROOT/tools/interop/webrtc/browser.mjs" 9521 answer 127.0.0.1:9522 mdns >"$W/answer.log" 2>&1 &
  NP=$!
  sleep 1
  ONLY_LOG=only_webrtc=debug $RS client 127.0.0.1:9522 dc-mdns 2>"$W/client-mdns.log"
  for _ in $(seq 50); do grep -q "chrome: pair" "$W/answer.log" && break; sleep 0.2; done
  kill $NP 2>/dev/null || true
  grep "chrome: pair" "$W/answer.log"
  grep -q "chrome: pair ok" "$W/answer.log"
  # Ours resolved Chrome's name and answered Chrome's query for ours.
  grep -E "mdns: [0-9a-f-]+\.local is" "$W/client-mdns.log" | head -1
  grep -E "mdns: answering .* for [0-9a-f-]+\.local" "$W/client-mdns.log" | head -1
  grep -qE "mdns: [0-9a-f-]+\.local is" "$W/client-mdns.log"
  grep -qE "mdns: answering" "$W/client-mdns.log"
done
echo "== Chrome simulcast through the only SFU (layers in, simulcast and layer selection out)"
node "$ROOT/tools/interop/webrtc/browser.mjs" 9520 simulcast 127.0.0.1:9519
echo "webrtc browser interop: all passed"
