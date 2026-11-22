#!/usr/bin/env bash
# akio-webrtc <-> headless Chrome, both offer directions: Chrome offers to the only ICE-lite
# RtcServer (data channels, fake camera/microphone media echoed back and decoded by Chrome), and
# the only full-ICE Endpoint offers to Chrome (data channel echo). Needs Node >= 22 and Chrome
# (CHROME=/path/to/chrome; the macOS default location is tried). CHROME_ARGS adds Chrome flags:
# CHROME_ARGS=--force-fieldtrials=WebRTC-DataChannelMessageInterleaving/Enabled/ makes Chrome
# offer I-DATA (RFC 8260), so the data channels run interleaved (Chrome 157 uses DATA otherwise).
# ADR-048 cases: DTLS 1.3 in both DTLS roles (Chrome 157 offers it by default; its stats must say
# FEFC), cryptex both ways (Chrome with --enable-experimental-web-platform-features and
# rtpHeaderEncryptionPolicy "require", which fails without cryptex; DTLS 1.3 and AES-GCM SRTP as
# well), and the SFU sending its simulcast line with ULPFEC per encoding through 5 % loss with
# NACK off (without FEC the line does not decode).
# Ports 9510-9534 (run.sh uses 9510-9520: do not run both at once).
set -eu
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
CHROME=${CHROME:-"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"}
cd "$ROOT" && cargo build -q --release -p akio-webrtc --example webrtc-interop
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
echo "== Chrome offers to the akio server over ICE-TCP only"
node "$ROOT/tools/interop/webrtc/browser.mjs" 9520 offer-tcp 127.0.0.1:9511
echo "== Chrome offers to the akio server, relay only (akio-turn over UDP, TCP, TLS)"
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
AKIO_INTEROP_NOMINATION=aggressive $RS client 127.0.0.1:9512 dc
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
  AKIO_LOG=akio_webrtc=debug $RS client 127.0.0.1:9522 dc-mdns 2>"$W/client-mdns.log"
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
echo "== only Endpoint on its IPv6 address (behind an mDNS name) offers to Chrome with mDNS concealment on"
# ADR-078: the Endpoint's only host candidate is its primary IPv6 address, concealed; Chrome's
# IPv6 candidate is a name too. Chrome queries ours over ff02::fb (we answer with AAAA on the
# link of the query), we resolve Chrome's (over either family), and the pair is IPv6. Needs an
# IPv6 address on the LAN (skipped otherwise).
if route -n get -inet6 2001:db8::1 >/dev/null 2>&1 || ip -6 route get 2001:db8::1 >/dev/null 2>&1; then
  node "$ROOT/tools/interop/webrtc/browser.mjs" 9521 answer 127.0.0.1:9534 mdns >"$W/answer.log" 2>&1 &
  NP=$!
  sleep 1
  AKIO_INTEROP_BIND="[::]:0" AKIO_LOG=akio_webrtc=debug $RS client 127.0.0.1:9534 dc-mdns \
    2>"$W/client-mdns6.log"
  for _ in $(seq 50); do grep -q "chrome: pair" "$W/answer.log" && break; sleep 0.2; done
  kill $NP 2>/dev/null || true
  grep "chrome: pair" "$W/answer.log"
  grep -q "chrome: pair ok" "$W/answer.log"
  grep -E "IcePair \{ local: \[" "$W/client-mdns6.log" | head -1
  grep -E "mdns: answering \[[0-9a-f:]+%[0-9]+\]:5353" "$W/client-mdns6.log" | head -1
  grep -E "mdns: [0-9a-f-]+\.local is \[[0-9a-f]*:[0-9a-f:]*\]" "$W/client-mdns6.log" | head -1
  grep -qE "IcePair \{ local: \[" "$W/client-mdns6.log"
  grep -qE "mdns: answering \[[0-9a-f:]+%[0-9]+\]:5353" "$W/client-mdns6.log"
  grep -qE "mdns: [0-9a-f-]+\.local is \[[0-9a-f]*:[0-9a-f:]*\]" "$W/client-mdns6.log"
else
  echo "skipped: no IPv6 route"
fi
echo "== Chrome simulcast through the only SFU (layers in, simulcast and layer selection out)"
node "$ROOT/tools/interop/webrtc/browser.mjs" 9520 simulcast 127.0.0.1:9519

echo "== DTLS 1.3: Chrome offers to the akio server (the only side is the DTLS client)"
AKIO_INTEROP_DTLS13=1 AKIO_LOG=akio_webrtc=debug $RS server 127.0.0.1:9523 127.0.0.1:9524 \
  2>"$W/server-dtls13.log" & PIDS="$PIDS $!"
sleep 1
node "$ROOT/tools/interop/webrtc/browser.mjs" 9520 offer 127.0.0.1:9524 | tee "$W/dtls13.out"
grep -q '"tlsVersion":"FEFC"' "$W/dtls13.out"
grep -q "dtls: connected with DTLS 1.3" "$W/server-dtls13.log"
echo "== DTLS 1.3: the only Endpoint offers to Chrome (the only side is the DTLS server)"
node "$ROOT/tools/interop/webrtc/browser.mjs" 9520 answer 127.0.0.1:9525 media >"$W/answer.log" 2>&1 &
NP=$!
sleep 1
AKIO_INTEROP_DTLS13=1 AKIO_LOG=akio_webrtc=debug $RS client 127.0.0.1:9525 media-in 2>"$W/client-dtls13.log"
for _ in $(seq 50); do grep -q "chrome: audio" "$W/answer.log" && break; sleep 0.2; done
kill $NP 2>/dev/null || true
grep "chrome: audio" "$W/answer.log"
grep -q '"tlsVersion":"FEFC","dtlsCipher":"TLS_AES_128_GCM_SHA256"' "$W/answer.log"
grep -q "dtls: connected with DTLS 1.3" "$W/client-dtls13.log"

echo "== cryptex both ways (Chrome requires it), with DTLS 1.3"
"$CHROME" --headless=new --remote-debugging-port=9526 --user-data-dir="$W/profile-cryptex" \
  --use-fake-device-for-media-stream --use-fake-ui-for-media-stream \
  --allow-loopback-in-peer-connection --no-first-run --no-default-browser-check \
  --disable-features=WebRtcHideLocalIpsWithMdns --enable-experimental-web-platform-features \
  about:blank >"$W/chrome-cryptex.log" 2>&1 & PIDS="$PIDS $!"
AKIO_INTEROP_DTLS13=1 AKIO_INTEROP_CRYPTEX=1 AKIO_INTEROP_STATS=1 $RS server 127.0.0.1:9527 \
  127.0.0.1:9528 2>"$W/server-cryptex.log" & PIDS="$PIDS $!"
sleep 2
export PC_CONFIG='{"rtpHeaderEncryptionPolicy":"require"}'
node "$ROOT/tools/interop/webrtc/browser.mjs" 9526 offer 127.0.0.1:9528 | tee "$W/cryptex.out"
sleep 1.5
crypt() { grep -o "cryptex_received: [0-9]*" "$1" | tail -1 | cut -d' ' -f2; }
echo "ok: the server got $(crypt "$W/server-cryptex.log") cryptex packets from Chrome"
[ "$(crypt "$W/server-cryptex.log")" -gt 50 ]
grep -q '"tlsVersion":"FEFC"' "$W/cryptex.out"
node "$ROOT/tools/interop/webrtc/browser.mjs" 9526 answer 127.0.0.1:9529 media >"$W/answer.log" 2>&1 &
NP=$!
sleep 1
AKIO_INTEROP_DTLS13=1 AKIO_INTEROP_CRYPTEX=1 AKIO_INTEROP_STATS=1 $RS client 127.0.0.1:9529 media-in \
  2>"$W/client-cryptex.log"
for _ in $(seq 50); do grep -q "chrome: audio" "$W/answer.log" && break; sleep 0.2; done
kill $NP 2>/dev/null || true
unset PC_CONFIG
grep "chrome: audio" "$W/answer.log"
# Chrome decoded our cryptex packets (it received audio) and sent its own with cryptex.
awk '/chrome: audio/ { exit !($3 > 100) }' "$W/answer.log"
grep -q '"srtpCipher":"SRTP_AEAD_AES_128_GCM"' "$W/answer.log"
echo "ok: the Endpoint got $(crypt "$W/client-cryptex.log") cryptex packets from Chrome"
[ "$(crypt "$W/client-cryptex.log")" -gt 50 ]

echo "== FEC on simulcast: the SFU's simulcast line with ULPFEC per encoding, 5 % loss, no NACK"
sfu_view() { # <fec mechanism or empty>: the SFU behind a lossy proxy, one viewer run in a fresh
  # Chrome (its fake camera fails when reused across tabs of one Chrome)
  rm -rf "$W/profile-sfu"
  "$CHROME" --headless=new --remote-debugging-port=9533 --user-data-dir="$W/profile-sfu" \
    --use-fake-device-for-media-stream --use-fake-ui-for-media-stream \
    --allow-loopback-in-peer-connection --no-first-run --no-default-browser-check \
    --disable-features=WebRtcHideLocalIpsWithMdns about:blank >"$W/chrome-sfu.log" 2>&1 & CP=$!
  AKIO_INTEROP_FEC=$1 AKIO_INTEROP_FEC_MIN=80 $RS sfu 127.0.0.1:9530 127.0.0.1:9531 127.0.0.1:9532 \
    loss-out=5 periodic 2>"$W/sfu-fec.log" & SP=$!
  sleep 2
  r=0
  NO_NACK=1 VIEW_SECS=10 node "$ROOT/tools/interop/webrtc/browser.mjs" 9533 simulcast 127.0.0.1:9531 \
    >"$W/sfu-fec.out" 2>&1 || r=$?
  kill $SP $CP 2>/dev/null || true
  wait $SP $CP 2>/dev/null || true
  return $r
}
if sfu_view ""; then
  # It may get through on keyframes; then it must decode far less than with FEC.
  NOFEC=$(grep -o '"decoded":[0-9]*' "$W/sfu-fec.out" | cut -d: -f2)
else
  NOFEC=0
fi
sfu_view ulpfec || { cat "$W/sfu-fec.out"; exit 1; }
cat "$W/sfu-fec.out"
node -e '
  const o = require("fs").readFileSync(process.argv[1], "utf8"), v = JSON.parse(o.match(/view (\{[^}]*\})/)[1]);
  if (!(v.decoded >= 0.9 * v.sent && v.decoded > 2 * Number(process.argv[2]) && v.freezes <= 2)) { console.error("FAIL: " + o); process.exit(1); }
  console.log("ok: simulcast line with ULPFEC: " + v.decoded + "/" + v.sent + " frames decoded, " + v.lost + " packets lost (" + process.argv[2] + " decoded without FEC)");
' "$W/sfu-fec.out" "$NOFEC"
echo "webrtc browser interop: all passed"
