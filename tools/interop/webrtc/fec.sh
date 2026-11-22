#!/usr/bin/env bash
# akio-webrtc <-> headless Chrome: FEC, RFC 8888, RTCP XR and TMMBR (ADR-039). Chrome offers VP8
# video to the akio fec-server, which echoes it back through a UDP proxy that drops RTP:
#   1. one RTP packet in 20 dropped each way and NACK removed from the SDP, so FEC is the only
#      repair: without FEC Chrome decodes few frames; with ULPFEC (red + ulpfec) and with FlexFEC
#      (flexfec-03, field trials below) it decodes most of them (losses FEC cannot repair stay:
#      two in a group, or a lost ULPFEC packet, whose sequence number is a gap to wait out), and
#      the server rebuilds packets from Chrome's own FEC;
#   2. RFC 8888 feedback both ways (Chrome's estimate grows on ours, ours runs on Chrome's) and
#      XR receiver reference times (the server measures its RTT from Chrome's DLRR);
#   3. a TMMBR of 150 kbps from the server: Chrome's send rate follows it and Chrome answers
#      with TMMBN;
#   4. Opus RED (ADR-048) under 10 % loss each way: the server lists RED before Opus, so Chrome
#      sends RED, which the server splits (copies stand in for lost packets), and the server
#      echoes with two redundant blocks: Chrome conceals far fewer samples than without RED;
#   5. Chrome publishing three simulcast layers with its ULPFEC per layer (NACK removed) through
#      5 % loss: the server repairs packets of the layers from it.
# Needs Node >= 22 and Chrome (CHROME=/path/to/chrome; the macOS default location is tried).
set -eu
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
CHROME=${CHROME:-"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"}
TRIALS="WebRTC-FlexFEC-03-Advertised/Enabled/WebRTC-FlexFEC-03/Enabled/WebRTC-RFC8888CongestionControlFeedback/Enabled,offer:true/"
cd "$ROOT" && cargo build -q --release -p akio-webrtc --example webrtc-interop
RS=$ROOT/target/release/examples/webrtc-interop
W=$(mktemp -d)
CP=""
trap 'kill $CP 2>/dev/null || true; sleep 1; rm -rf "$W" 2>/dev/null || true' EXIT

# run <label> <nack|-> <secs> <server options...>: one Chrome (fresh, its fake camera is not
# shared between runs) and one server; leaves $W/<label>.out (Chrome) and $W/<label>.log.
run() {
  label=$1; nack=$2; secs=$3; shift 3
  "$CHROME" --headless=new --remote-debugging-port=9620 --user-data-dir="$W/profile-$label" \
    --use-fake-device-for-media-stream --use-fake-ui-for-media-stream \
    --allow-loopback-in-peer-connection --no-first-run --no-default-browser-check \
    --disable-features=WebRtcHideLocalIpsWithMdns "--force-fieldtrials=$TRIALS" \
    about:blank >"$W/chrome-$label.log" 2>&1 & CP=$!
  "$RS" fec-server 127.0.0.1:9630 127.0.0.1:9631 127.0.0.1:9632 "$@" 2>"$W/$label.log" & SP=$!
  sleep 2
  node "$ROOT/tools/interop/webrtc/browser.mjs" 9620 fec 127.0.0.1:9632 "$nack" "$secs" >"$W/$label.out"
  kill $SP $CP 2>/dev/null || true
  wait $SP $CP 2>/dev/null || true
  CP=""
}
# js <label> <expression over s (Chrome stats), a (answer lines), p (last server PeerStats text),
# l (server log)>: prints the value; fails the script when it is false.
js() {
  node -e '
    const fs = require("fs"); const [out, log, expr] = process.argv.slice(1);
    const o = fs.readFileSync(out, "utf8"), l = fs.readFileSync(log, "utf8");
    const s = JSON.parse(o.match(/^stats: (.*)$/m)[1]), a = JSON.parse(o.match(/^answer: (.*)$/m)[1]);
    const p = (l.match(/PeerStats \{[^}]*\}/g) || [""]).pop();
    const n = (k) => Number((p.match(new RegExp(k + ": (?:Some\\()?(\\d+)")) || [0, NaN])[1]);
    const v = eval(expr);
    if (!v) { console.error("FAIL: " + expr + "\n" + o + p); process.exit(1); }
  ' "$W/$1.out" "$W/$1.log" "$2"
}
decoded() { node -e 'const s=JSON.parse(require("fs").readFileSync(process.argv[1],"utf8").match(/^stats: (.*)$/m)[1]); console.log(s.in.framesDecoded + "/" + s.out.framesSent)' "$W/$1.out"; }

echo "== FEC: 5 % periodic loss each way, no NACK"
run none - 20 loss-out=5 loss-in=5 periodic
echo "no FEC: Chrome decoded $(decoded none) frames"
BASE=$(decoded none | cut -d/ -f1)
for f in ulpfec flexfec; do
  run $f - 20 fec=$f min=80 loss-out=5 loss-in=5 periodic
  js $f "s.in.framesDecoded >= 0.75 * s.out.framesSent && s.in.framesDecoded >= 4 * $BASE"
  js $f "n('fec_recovered') > 20 && n('fec_sent') > 100"
  echo "$f: Chrome decoded $(decoded $f) frames; $(grep -o 'fec_sent: [0-9]*, fec_received: [0-9]*, fec_recovered: [0-9]*' "$W/$f.log" | tail -1)"
done
js ulpfec 'a.some((x) => /red\/90000/.test(x)) && a.some((x) => /ulpfec\/90000/.test(x))'
js flexfec 'a.some((x) => /flexfec-03/.test(x)) && a.some((x) => /FEC-FR/.test(x)) && s.in.fecPacketsReceived > 100'
js none "s.in.framesDecoded < 0.5 * s.out.framesSent"

echo "== RFC 8888 feedback and XR receiver RTT"
run ccfb nack 20 ccfb xr bwe
js ccfb 'a.some((x) => /ack ccfb/.test(x)) && a.some((x) => /rtcp-xr:rcvr-rtt/.test(x))'
js ccfb "/ccfb: true/.test(p) && /xr_rtt_ms: Some/.test(p) && /EgressBitrateEstimate/.test(l)"
# Chrome starts at 300 kbps and has no other feedback to grow on.
js ccfb "s.pair.availableOutgoingBitrate > 600000"
echo "ok: RFC 8888 both ways (Chrome's available bitrate $(grep -o 'availableOutgoingBitrate":[0-9]*' "$W/ccfb.out" | cut -d: -f2) bps on ours), $(grep -o 'xr_rtt_ms: [^,]*' "$W/ccfb.log" | tail -1)"

echo "== TMMBR"
run tmmbr nack 20 tmmbr=150000
js tmmbr "s.pair.availableOutgoingBitrate <= 160000 && s.lastHalfBitrate < 200000"
js tmmbr "/MaxBitrateNotification \{ ssrc: \d+, entries: \[\(\d+, 150000\)\] \}/.test(l)"
echo "ok: Chrome's send rate $(node -e 'console.log(JSON.parse(require("fs").readFileSync(process.argv[1],"utf8").match(/^stats: (.*)$/m)[1]).lastHalfBitrate)' "$W/tmmbr.out") bps under a 150 kbps TMMBR, TMMBN received"
echo "== Opus RED: 10 % loss each way"
red() { # <label> <RED blocks or empty>
  rm -rf "$W/profile-$1"
  "$CHROME" --headless=new --remote-debugging-port=9620 --user-data-dir="$W/profile-$1" \
    --use-fake-device-for-media-stream --use-fake-ui-for-media-stream \
    --autoplay-policy=no-user-gesture-required --allow-loopback-in-peer-connection \
    --no-first-run --no-default-browser-check --disable-features=WebRtcHideLocalIpsWithMdns \
    about:blank >"$W/chrome-$1.log" 2>&1 & CP=$!
  AKIO_INTEROP_RED=$2 AKIO_INTEROP_STATS=1 "$RS" fec-server 127.0.0.1:9630 127.0.0.1:9631 \
    127.0.0.1:9632 loss-in=10 loss-out=10 2>"$W/$1.log" & SP=$!
  sleep 2
  node "$ROOT/tools/interop/webrtc/browser.mjs" 9620 red 127.0.0.1:9632 15 >"$W/$1.out"
  sleep 1.2
  kill $SP $CP 2>/dev/null || true
  wait $SP $CP 2>/dev/null || true
  CP=""
}
concealed() { node -e 'const s=JSON.parse(require("fs").readFileSync(process.argv[1],"utf8").match(/^stats: (.*)$/m)[1]).audioIn; console.log((s.concealedSamples / s.totalSamplesReceived).toFixed(3))' "$W/$1.out"; }
red red-none ""
red red2 2
js red2 'a.some((x) => /^m=audio 9 UDP\/TLS\/RTP\/SAVPF 63 111/.test(x)) && a.some((x) => /red\/48000\/2/.test(x))'
js red-none '!a.some((x) => /red\//.test(x)) && s.audioIn.totalSamplesReceived > 300000'
js red2 "n('red_recovered') > 50 && s.audioIn.totalSamplesReceived > 300000"
js red2 "s.audioIn.concealedSamples / s.audioIn.totalSamplesReceived < 0.5 * $(concealed red-none)"
echo "ok: Chrome concealed $(concealed red-none) of its samples without RED, $(concealed red2) with RED both ways; the server took $(grep -o 'red_recovered: [0-9]*' "$W/red2.log" | tail -1 | cut -d' ' -f2) packets from Chrome's RED"

echo "== ULPFEC per simulcast layer from Chrome: 5 % periodic loss, no NACK"
rm -rf "$W/profile-sim"
"$CHROME" --headless=new --remote-debugging-port=9620 --user-data-dir="$W/profile-sim" \
  --use-fake-device-for-media-stream --use-fake-ui-for-media-stream \
  --allow-loopback-in-peer-connection --no-first-run --no-default-browser-check \
  --disable-features=WebRtcHideLocalIpsWithMdns about:blank >"$W/chrome-sim.log" 2>&1 & CP=$!
AKIO_INTEROP_STATS=1 "$RS" fec-server 127.0.0.1:9630 127.0.0.1:9631 127.0.0.1:9632 fec=ulpfec \
  loss-in=5 periodic 2>"$W/sim.log" & SP=$!
sleep 2
node "$ROOT/tools/interop/webrtc/browser.mjs" 9620 simulcast-fec 127.0.0.1:9632 15 >"$W/sim.out"
sleep 1.2
kill $SP $CP 2>/dev/null || true
wait $SP $CP 2>/dev/null || true
CP=""
js sim 'a.some((x) => /ulpfec\/90000/.test(x)) && a.some((x) => /simulcast:recv/.test(x)) && ["l", "m", "h"].every((r) => s[r].framesSent > 200)'
js sim "n('fec_received') > 100 && n('fec_recovered') > 10"
# Every layer arrived (per RID: frames, whole frames).
js sim '(() => { const x = (l.match(/rid frames.*/g) || [""]).pop(); return ["l", "m", "h"].every((r) => Number((x.match(new RegExp("\"" + r + "\": \\((\\d+)")) || [0, 0])[1]) > 150); })()'
echo "ok: $(grep -o 'fec_received: [0-9]*, fec_recovered: [0-9]*' "$W/sim.log" | tail -1); frames per layer (all, whole): $(grep -o 'rid frames.*' "$W/sim.log" | tail -1)"
echo "webrtc FEC / feedback interop: all passed"
