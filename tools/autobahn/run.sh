#!/usr/bin/env bash
# Runs the Autobahn|Testsuite against only's WebSocket implementation.
#   tools/autobahn/run.sh [base|pmd]     server: the fuzzing client against the `ws-echo` example
#                                        (base: all but 12.*/13.*, pmd: the permessage-deflate cases)
#   tools/autobahn/run.sh client         client: the `ws-autobahn-client` example against the
#                                        fuzzing server, all cases (1-13), then the
#                                        permessage-deflate cases again offering
#                                        client_no_context_takeover
# Needs docker and the built examples (`cargo build --release -p akio-http --example ws-echo`,
# `cargo build --release -p akio-ws --example ws-autobahn-client`). On macOS the container
# reaches the host through host.docker.internal; on Linux it shares the host network.
set -eu
PART=${1:-base}
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
OUT=${OUT:-/tmp/autobahn-$PART}
rm -rf "$OUT"; mkdir -p "$OUT/config" "$OUT/reports"

if [ "$PART" = client ]; then
  PORT=${PORT:-9001} # host port the fuzzing server is published on
  cat > "$OUT/config/fuzzingserver.json" <<JSON
{"url":"ws://127.0.0.1:$PORT","outdir":"/reports","cases":["*"],"exclude-cases":[],"exclude-agent-cases":{}}
JSON
  NAME=akio-autobahn-fuzzingserver-$$
  docker run -d --rm --name "$NAME" -p "$PORT:$PORT" -v "$OUT/config:/config" -v "$OUT/reports:/reports" \
    crossbario/autobahn-testsuite wstest -m fuzzingserver -s /config/fuzzingserver.json > /dev/null
  trap 'docker logs "$NAME" > "$OUT/autobahn.log" 2>&1 || true; docker rm -f "$NAME" > /dev/null 2>&1 || true' EXIT
  # Wait for the server to answer HTTP.
  for _ in $(seq 1 120); do
    if curl -s -o /dev/null http://127.0.0.1:"$PORT"/; then break; fi
    sleep 1
  done
  CLIENT=${WS_CLIENT:-$ROOT/target/release/examples/ws-autobahn-client}
  "$CLIENT" ws://127.0.0.1:"$PORT" akio-client 2>&1 | tee "$OUT/client.log"
  CASES=12.,13. PMD_NCT=1 "$CLIENT" ws://127.0.0.1:"$PORT" akio-client-nct 2>&1 | tee -a "$OUT/client.log"
  python3 "$ROOT/tools/autobahn/check.py" "$OUT/reports"
  exit
fi

if [ "$(uname -s)" = Darwin ]; then URL=ws://host.docker.internal:9001; NET=""; else URL=ws://127.0.0.1:9001; NET="--network host"; fi
if [ "$PART" = pmd ]; then CASES='["12.*","13.*"]'; EXCL='[]'; else CASES='["*"]'; EXCL='["12.*","13.*"]'; fi
cat > "$OUT/config/fuzzingclient.json" <<JSON
{"outdir":"/reports","servers":[{"agent":"akio-$PART","url":"$URL"}],"cases":$CASES,"exclude-cases":$EXCL,"exclude-agent-cases":{}}
JSON
"${WS_ECHO:-$ROOT/target/release/examples/ws-echo}" 0.0.0.0:9001 > "$OUT/server.log" 2>&1 &
SERVER=$!
trap 'kill $SERVER 2>/dev/null || true' EXIT
sleep 1
# shellcheck disable=SC2086
docker run --rm $NET -v "$OUT/config:/config" -v "$OUT/reports:/reports" \
  crossbario/autobahn-testsuite wstest -m fuzzingclient -s /config/fuzzingclient.json > "$OUT/autobahn.log" 2>&1
python3 "$ROOT/tools/autobahn/check.py" "$OUT/reports"
