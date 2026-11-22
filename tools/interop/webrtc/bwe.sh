#!/usr/bin/env bash
# akio-webrtc -> headless Chrome: bandwidth probing (ADR-050). Chrome offers VP8 video to the only
# fec-server with its estimator on (start 1 Mbps), which echoes the video back: Chrome is the
# receiver of our stream and sends the congestion control feedback. The echo is application-
# limited by Chrome's own send rate, so without probes our estimate stays within 1.5 x what
# Chrome acknowledges; with probes (RTX copies of the echoed video, which Chrome must take as
# duplicates) it climbs. Prints, for transport-wide feedback and for RFC 8888, how long after
# the connection the estimate reached 2, 5 and 10 Mbps, the last estimate and Chrome's decoded
# frames; checks the estimate reached 5 Mbps within 5 s and Chrome kept decoding (NO_CHECK=1
# skips the checks). RS=<webrtc-interop binary> runs another build (a before / after
# comparison). Needs Node >= 22, perl and Chrome (CHROME=/path/to/chrome; the macOS default
# location is tried). Ports 9640-9642 and 9650.
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

# run <label> <server options...>: leaves $W/<label>.out (Chrome) and $W/<label>.log (server
# stderr, each line prefixed with the time in seconds).
run() {
  label=$1; shift
  "$CHROME" --headless=new --remote-debugging-port=9650 --user-data-dir="$W/profile-$label" \
    --use-fake-device-for-media-stream --use-fake-ui-for-media-stream \
    --allow-loopback-in-peer-connection --no-first-run --no-default-browser-check \
    --disable-features=WebRtcHideLocalIpsWithMdns "--force-fieldtrials=$TRIALS" \
    about:blank >"$W/chrome-$label.log" 2>&1 & CP=$!
  "$RS" fec-server 127.0.0.1:9640 127.0.0.1:9641 127.0.0.1:9642 bwe "$@" 2>&1 \
    | perl -MTime::HiRes=time -ne '$|=1; printf "%.3f %s", time, $_' >"$W/$label.log" &
  SP=$!
  sleep 2
  node "$ROOT/tools/interop/webrtc/browser.mjs" 9650 fec 127.0.0.1:9642 nack "$SECS" >"$W/$label.out"
  pkill -f "fec-server 127.0.0.1:9640" 2>/dev/null || true
  kill $CP 2>/dev/null || true
  wait $SP $CP 2>/dev/null || true
  CP=""
}

report() { # <label>
  node -e '
    const fs = require("fs"); const [out, log, check] = process.argv.slice(1);
    const lines = fs.readFileSync(log, "utf8").split("\n");
    const t0 = Number((lines.find((l) => / server: connected/.test(l)) || "").split(" ")[0]);
    const est = lines.map((l) => l.match(/^([\d.]+) .*EgressBitrateEstimate\((\d+)\)/))
      .filter(Boolean).map((m) => [Number(m[1]) - t0, Number(m[2])]);
    const reach = (b) => { const e = est.find(([, v]) => v >= b); return e ? e[0].toFixed(2) + " s" : "never"; };
    const last = est.length ? est[est.length - 1][1] : 0;
    const s = JSON.parse(fs.readFileSync(out, "utf8").match(/^stats: (.*)$/m)[1]);
    console.log(`2 Mbps after ${reach(2e6)}, 5 Mbps after ${reach(5e6)}, 10 Mbps after ${reach(10e6)}; ` +
      `last estimate ${last} bps; Chrome decoded ${s.in.framesDecoded} of ${s.out.framesSent} frames`);
    if (check !== "1") {
      const t5 = (est.find(([, v]) => v >= 5e6) || [Infinity])[0];
      if (!(t5 <= 5)) { console.error("FAIL: no 5 Mbps estimate within 5 s"); process.exit(1); }
      if (!(s.in.framesDecoded >= 0.8 * s.out.framesSent)) { console.error("FAIL: Chrome decoded too few frames"); process.exit(1); }
    }
  ' "$W/$1.out" "$W/$1.log" "${NO_CHECK:-}"
}

echo "== transport-wide feedback from Chrome"
run twcc
report twcc
echo "== RFC 8888 feedback from Chrome"
run ccfb ccfb
report ccfb
echo "webrtc bandwidth probing interop: done"
