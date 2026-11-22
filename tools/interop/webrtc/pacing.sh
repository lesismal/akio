#!/usr/bin/env bash
# akio-webrtc -> headless Chrome: the pacer (ADR-073). Chrome offers VP8 video to the akio
# fec-server with its estimator on and capped at 300 kbps (so it paces at 750 kbps with a 3.75 kB
# burst allowance: about 3 packets), which echoes the video back through the example's UDP proxy
# and asks Chrome for a keyframe every 500 ms (keyframes are what exceed the allowance); the
# proxy logs the bursts of RTP towards Chrome (packets less than 300 us apart). Runs the server
# with pacing and without (nopace), with transport-wide feedback, then paced with RFC 8888
# feedback; prints the largest burst, the bursts of 6 packets or more and Chrome's decoded
# frames, and checks that the paced bursts stay within the allowance (at most 5 packets), the
# unpaced ones do not, and Chrome decodes the paced echo (NO_CHECK=1 skips the checks). Needs Node >= 22, perl and Chrome
# (CHROME=/path/to/chrome; the macOS default location is tried). Ports 9640-9642 and 9650.
set -eu
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
CHROME=${CHROME:-"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"}
TRIALS="WebRTC-RFC8888CongestionControlFeedback/Enabled,offer:true/"
if [ -z "${RS:-}" ]; then
  (cd "$ROOT" && cargo build -q --release -p akio-webrtc --example webrtc-interop)
  RS=$ROOT/target/release/examples/webrtc-interop
fi
SECS=${SECS:-15}
W=$(mktemp -d)
CP=""
trap 'kill $CP 2>/dev/null || true; sleep 1; rm -rf "$W" 2>/dev/null || true' EXIT

# run <label> <server options...>: leaves $W/<label>.out (Chrome) and $W/<label>.log.
run() {
  label=$1; shift
  "$CHROME" --headless=new --remote-debugging-port=9650 --user-data-dir="$W/profile-$label" \
    --use-fake-device-for-media-stream --use-fake-ui-for-media-stream \
    --allow-loopback-in-peer-connection --no-first-run --no-default-browser-check \
    --disable-features=WebRtcHideLocalIpsWithMdns "--force-fieldtrials=$TRIALS" \
    about:blank >"$W/chrome-$label.log" 2>&1 & CP=$!
  "$RS" fec-server 127.0.0.1:9640 127.0.0.1:9641 127.0.0.1:9642 bwe bwemax=300000 pli=500 "$@" \
    >"$W/$label.log" 2>&1 &
  SP=$!
  sleep 2
  node "$ROOT/tools/interop/webrtc/browser.mjs" 9650 fec 127.0.0.1:9642 nack "$SECS" >"$W/$label.out"
  pkill -f "fec-server 127.0.0.1:9640" 2>/dev/null || true
  kill $CP 2>/dev/null || true
  wait $SP $CP 2>/dev/null || true
  CP=""
}

# report <label> <paced: 1|0>
report() {
  node -e '
    const fs = require("fs"); const [out, log, paced, check] = process.argv.slice(1);
    const m = [...fs.readFileSync(log, "utf8").matchAll(/max burst (\d+), bursts of 6\+ (\d+)/g)].pop();
    const [burst, big] = m ? [Number(m[1]), Number(m[2])] : [0, 0];
    const s = JSON.parse(fs.readFileSync(out, "utf8").match(/^stats: (.*)$/m)[1]);
    console.log(`largest burst ${burst} packets, ${big} bursts of 6+; ` +
      `Chrome decoded ${s.in.framesDecoded} of ${s.out.framesSent} frames, sent ${s.out.packetsSent} packets`);
    if (check !== "1") {
      if (!m) { console.error("FAIL: no burst statistics"); process.exit(1); }
      if (paced === "1" && burst > 5) { console.error("FAIL: paced bursts above the allowance"); process.exit(1); }
      if (paced === "0" && burst <= 5) { console.error("FAIL: unpaced bursts as small as paced ones"); process.exit(1); }
      if (paced === "1" && !(s.in.framesDecoded >= 0.8 * s.out.framesSent)) { console.error("FAIL: Chrome decoded too few frames"); process.exit(1); }
    }
  ' "$W/$1.out" "$W/$1.log" "$2" "${NO_CHECK:-}"
}

echo "== paced, transport-wide feedback"
run paced
report paced 1
echo "== not paced (nopace)"
run unpaced nopace
report unpaced 0
echo "== paced, RFC 8888 feedback"
run paced-ccfb ccfb
report paced-ccfb 1
echo "webrtc pacing interop: done"
