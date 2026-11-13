#!/usr/bin/env bash
# Runs the Autobahn|Testsuite fuzzing client against flash's WebSocket echo server.
#   tools/autobahn/run.sh [base|pmd]     (base: all but 12.*/13.*, pmd: the permessage-deflate cases)
# Needs docker and a built `ws-echo` example. On macOS the container reaches the host through
# host.docker.internal; on Linux it shares the host network.
set -eu
PART=${1:-base}
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
OUT=${OUT:-/tmp/autobahn-$PART}
rm -rf "$OUT"; mkdir -p "$OUT/config" "$OUT/reports"
if [ "$(uname -s)" = Darwin ]; then URL=ws://host.docker.internal:9001; NET=""; else URL=ws://127.0.0.1:9001; NET="--network host"; fi
if [ "$PART" = pmd ]; then CASES='["12.*","13.*"]'; EXCL='[]'; else CASES='["*"]'; EXCL='["12.*","13.*"]'; fi
cat > "$OUT/config/fuzzingclient.json" <<JSON
{"outdir":"/reports","servers":[{"agent":"flash-$PART","url":"$URL"}],"cases":$CASES,"exclude-cases":$EXCL,"exclude-agent-cases":{}}
JSON
"${WS_ECHO:-$ROOT/target/release/examples/ws-echo}" 0.0.0.0:9001 > "$OUT/server.log" 2>&1 &
SERVER=$!
trap 'kill $SERVER 2>/dev/null || true' EXIT
sleep 1
# shellcheck disable=SC2086
docker run --rm $NET -v "$OUT/config:/config" -v "$OUT/reports:/reports" \
  crossbario/autobahn-testsuite wstest -m fuzzingclient -s /config/fuzzingclient.json > "$OUT/autobahn.log" 2>&1
python3 "$ROOT/tools/autobahn/check.py" "$OUT/reports"
