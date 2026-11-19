#!/usr/bin/env bash
# only-webrtc <-> headless Firefox data channels (usrsctp on Firefox's side), both offer
# directions: Firefox offers to the only ICE-lite RtcServer (echoes on ordered and unordered
# channels, 70 kB and 200 kB messages, an idle spell with HEARTBEATs both ways, a channel
# closed by Firefox and a new one), and the only full-ICE Endpoint offers to Firefox (echo).
# Driven over WebDriver BiDi by firefox/main.go. Needs Go and Firefox (FIREFOX=/path/to/firefox;
# `firefox` on PATH or the macOS default location otherwise; a snap Firefox keeps its profile
# under ~/snap/firefox/common). IDLE_SECONDS: the idle spell (default 75). IP: the address the
# only side listens on (default 127.0.0.1). Firefox 158 on Linux gathered no loopback
# candidates even with media.peerconnection.ice.loopback, so there pass a LAN address
# (IP=192.168.1.10).
set -eu
IP=${IP:-127.0.0.1}
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
if [ -z "${FIREFOX:-}" ]; then
  FIREFOX=$(command -v firefox || echo "/Applications/Firefox.app/Contents/MacOS/firefox")
fi
cd "$ROOT" && cargo build -q --release -p only-webrtc --example webrtc-interop
RS=${CARGO_TARGET_DIR:-$ROOT/target}/release/examples/webrtc-interop
W=$(mktemp -d)
(cd "$ROOT/tools/interop/webrtc/firefox" && GOFLAGS=-mod=mod go build -o "$W/ff" .)
if [ -d "$HOME/snap/firefox/common" ]; then
  PROFILE=$(mktemp -d "$HOME/snap/firefox/common/only-ff.XXXXXX")
else
  PROFILE=$W/profile
  mkdir -p "$PROFILE"
fi
PIDS=""
trap 'kill $PIDS 2>/dev/null || true; sleep 1; rm -rf "$W" "$PROFILE" 2>/dev/null || true' EXIT
# Loopback ICE candidates where Firefox takes them, plain host addresses (no mDNS), a fake
# microphone without a permission prompt (see main.go), no first-run noise.
cat >"$PROFILE/user.js" <<'EOF'
user_pref("media.peerconnection.ice.loopback", true);
user_pref("media.peerconnection.ice.obfuscate_host_addresses", false);
user_pref("browser.shell.checkDefaultBrowser", false);
user_pref("datareporting.policy.dataSubmissionEnabled", false);
user_pref("media.navigator.streams.fake", true);
user_pref("media.navigator.permission.disabled", true);
EOF
"$FIREFOX" --headless --no-remote --profile "$PROFILE" --remote-debugging-port=9620 about:blank \
  >"$W/firefox.log" 2>&1 & PIDS="$PIDS $!"
ONLY_LOG=only_webrtc=debug $RS server $IP:9610 127.0.0.1:9611 $IP:9613 2>"$W/server.log" &
PIDS="$PIDS $!"
sleep 3
"$FIREFOX" --version 2>/dev/null | grep -i firefox || true

echo "== Firefox offers to the only ICE-lite server"
"$W/ff" 9620 offer 127.0.0.1:9611
echo "== only (full ICE Endpoint) offers to Firefox"
"$W/ff" 9620 answer 127.0.0.1:9612 2>"$W/answer.log" & PIDS="$PIDS $!"
for _ in $(seq 100); do grep -q "answerer on" "$W/answer.log" && break; sleep 0.1; done
ONLY_INTEROP_BIND=$IP:0 ONLY_LOG=only_webrtc=debug $RS client 127.0.0.1:9612 dc 2>"$W/client.log"
# The DTLS version of each side (DTLS 1.3 by default, ADR-048).
grep -ho "dtls: connected with DTLS 1\.[23]" "$W/server.log" "$W/client.log"
echo "webrtc firefox interop: all passed"
