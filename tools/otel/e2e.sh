#!/usr/bin/env bash
# End-to-end test of only-export against the OpenTelemetry Collector (contrib): OTLP/HTTP in
# protobuf and JSON, and DogStatsD into the collector's statsd receiver.
#
#   tools/otel/e2e.sh                 # cargo test on this host against a collector container
#   NETWORK=name tools/otel/e2e.sh    # the collector joins this docker network as `otelcol`
#                                     # (for a test run in another container on that network:
#                                     # it prints the env to pass and leaves the collector up
#                                     # until the command in $RUN exits)
#
# Needs docker. The image is pinned; the test is `crates/only-export/tests/collector.rs`, which
# does nothing unless ONLY_OTEL_COLLECTOR is set.
set -eu
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
IMAGE=${IMAGE:-otel/opentelemetry-collector-contrib:0.115.1}
OUT=${OUT:-$(mktemp -d /tmp/only-otel.XXXXXX)}
mkdir -p "$OUT"
chmod 777 "$OUT"
NAME=only-otel-$$
NET_ARGS=()
if [ -n "${NETWORK:-}" ]; then
  NET_ARGS=(--network "$NETWORK" --network-alias otelcol)
fi
docker run -d --rm --name "$NAME" "${NET_ARGS[@]}" \
  -p 127.0.0.1::4318 -p 127.0.0.1::8125/udp \
  -v "$ROOT/tools/otel/collector.yaml:/etc/otelcol-contrib/config.yaml:ro" \
  -v "$OUT:/out" "$IMAGE" > /dev/null
trap 'docker logs "$NAME" > "$OUT/collector.log" 2>&1 || true; docker rm -f "$NAME" > /dev/null 2>&1 || true' EXIT
HTTP=$(docker port "$NAME" 4318/tcp | head -1)
UDP=$(docker port "$NAME" 8125/udp | head -1)
for _ in $(seq 1 60); do
  if curl -s -o /dev/null -X POST -H 'Content-Type: application/json' -d '{}' "http://$HTTP/v1/metrics"; then break; fi
  sleep 1
done
export ONLY_OTEL_OUT="$OUT"
if [ -n "${RUN:-}" ]; then
  # Another container on $NETWORK runs the test; it sees the output through $OUT.
  ONLY_OTEL_COLLECTOR=http://otelcol:4318 ONLY_OTEL_STATSD=otelcol:8125 bash -c "$RUN"
else
  ONLY_OTEL_COLLECTOR=http://$HTTP ONLY_OTEL_STATSD=$UDP \
    cargo test --manifest-path "$ROOT/Cargo.toml" -p only-export --test collector -- --nocapture
fi
echo "collector output in $OUT"
