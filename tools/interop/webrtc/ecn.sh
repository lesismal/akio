#!/usr/bin/env bash
# ECN-capable RTP toward headless Chrome (ADR-077). Chrome offers VP8 video with RFC 8888
# feedback (field trial) to the only fec-server, which echoes it back with its estimator on and
# ECN marking (ONLY_INTEROP_ECN, ECT(1) by default; ECN=ect0 for ECT(0)), directly on the
# loopback socket (no proxy, which would clear the codepoint). Prints the server's ECN state
# (testing / capable / failed), the RTP packets it sent marked, the CE marks reported back,
# what Chrome counts as received with ECT(1) / CE (its getStats, when it has the fields) and
# the frames it decoded; checks the server's path validated ("capable": Chrome's RFC 8888
# reports carried the marks) and that Chrome kept decoding; then the same through fec-server's
# UDP proxy, which clears the codepoint: the path must fail validation (Chrome reports the
# marked packets Not-ECT) and media go on unmarked (NO_CHECK=1 skips the checks).
# Needs Node >= 22 and Chrome (CHROME=...; the macOS default location is tried). Ports 9670-9672
# and 9680.
set -eu
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
CHROME=${CHROME:-"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"}
TRIALS="WebRTC-RFC8888CongestionControlFeedback/Enabled,offer:true/${EXTRA_TRIALS:-}"
if [ -z "${RS:-}" ]; then
  (cd "$ROOT" && cargo build -q --release -p only-webrtc --example webrtc-interop)
  RS=$ROOT/target/release/examples/webrtc-interop
fi
SECS=${SECS:-10}
W=$(mktemp -d)
PIDS=""
CP=""
trap 'kill $PIDS 2>/dev/null || true; sleep 1; rm -rf "$W" 2>/dev/null || true' EXIT

# run <label> <server options...>
run() {
  label=$1; shift
  "$CHROME" --headless=new --remote-debugging-port=9680 --user-data-dir="$W/profile-$label" \
    --use-fake-device-for-media-stream --use-fake-ui-for-media-stream \
    --allow-loopback-in-peer-connection --no-first-run --no-default-browser-check \
    --disable-features=WebRtcHideLocalIpsWithMdns "--force-fieldtrials=$TRIALS" \
    about:blank >"$W/chrome-$label.log" 2>&1 & CP=$!
  ONLY_INTEROP_ECN=${ECN:-ect1} "$RS" fec-server 127.0.0.1:9671 127.0.0.1:9670 127.0.0.1:9672 \
    ccfb bwe "$@" >"$W/$label.log" 2>&1 & SP=$!
  PIDS="$CP $SP"
  sleep 2
  node "$ROOT/tools/interop/webrtc/browser.mjs" 9680 fec 127.0.0.1:9672 nack "$SECS" >"$W/$label.out"
  kill $SP $CP 2>/dev/null || true
  wait $SP $CP 2>/dev/null || true
  PIDS=""
  node -e '
    const fs = require("fs"); const [label, out, log, check] = process.argv.slice(1);
    const stats = fs.readFileSync(log, "utf8").split("\n").filter((l) => l.includes("PeerStats"));
    const last = stats[stats.length - 1] || "";
    const f = (k) => (last.match(new RegExp(k + ": ([^,}]+)")) || [])[1];
    const s = JSON.parse(fs.readFileSync(out, "utf8").match(/^stats: (.*)$/m)[1]);
    console.log(`${label}: server ecn_state ${f("ecn_state")}, ${f("ecn_marked_sent")} RTP packets sent marked, ` +
      `${f("ecn_ce_reported")} reported CE, ${f("ecn_failures")} failed paths; from Chrome ` +
      `${f("ecn_ect_received")} ECN-capable of ${f("packets_received")} packets`);
    console.log(`${label}: chrome ${s.in.packetsReceived} packets received, with ECT(1) ${s.in.packetsReceivedWithEct1}, ` +
      `CE ${s.in.packetsReceivedWithCe}; decoded ${s.in.framesDecoded} of ${s.out.framesSent} frames`);
    if (check !== "1") {
      const want = label === "direct" ? "\"capable\"" : "\"failed\"";
      if (f("ecn_state") !== want) { console.error(`FAIL: ${label}: ecn_state ${f("ecn_state")}, expected ${want}`); process.exit(1); }
      if (!(s.in.framesDecoded > s.out.framesSent * 0.8)) { console.error("FAIL: Chrome stopped decoding"); process.exit(1); }
    }
  ' "$label" "$W/$label.out" "$W/$label.log" "${NO_CHECK:-}"
}

echo "== direct: the marks reach Chrome"
run direct direct
echo "== through a proxy that clears them: marking stops, media goes on"
run proxy
echo "ok: ecn.sh"
