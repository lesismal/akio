#!/usr/bin/env bash
# End-to-end test of akio-export against the OpenTelemetry Collector (contrib): OTLP/HTTP in
# protobuf and JSON, OTLP/gRPC, both plain and over TLS with client certificates (a private CA
# made here with openssl), traces, metrics (exemplars) and logs, and DogStatsD into the
# collector's statsd receiver.
#
#   tools/otel/e2e.sh                 # cargo test on this host against a collector container
#   NETWORK=name tools/otel/e2e.sh    # the collector joins this docker network as `otelcol`
#                                     # (for a test run in another container on that network:
#                                     # it prints the env to pass and leaves the collector up
#                                     # until the command in $RUN exits)
#
# Needs docker and openssl. The image is pinned; the tests are
# `crates/akio-export/tests/collector.rs` (plain) and `collector_tls.rs` (gRPC, TLS), which do
# nothing unless AKIO_OTEL_COLLECTOR is set.
set -eu
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
IMAGE=${IMAGE:-otel/opentelemetry-collector-contrib:0.115.1}
OUT=${OUT:-$(mktemp -d /tmp/akio-otel.XXXXXX)}
CERTS="$OUT/certs"
mkdir -p "$OUT" "$CERTS"
chmod 777 "$OUT"

# A private CA, a server certificate for localhost / 127.0.0.1 / otelcol and a client one.
key() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1" 2>/dev/null; }
key "$CERTS/ca.key"
openssl req -x509 -new -key "$CERTS/ca.key" -subj "/CN=akio e2e CA" -days 2 \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out "$CERTS/ca.pem" 2>/dev/null
leaf() { # name subject extensions
  key "$CERTS/$1.key"
  openssl req -new -key "$CERTS/$1.key" -subj "/CN=$2" -out "$CERTS/$1.csr" 2>/dev/null
  printf '%s\n' "$3" > "$CERTS/$1.ext"
  openssl x509 -req -in "$CERTS/$1.csr" -CA "$CERTS/ca.pem" -CAkey "$CERTS/ca.key" \
    -CAcreateserial -days 2 -extfile "$CERTS/$1.ext" -out "$CERTS/$1.pem" 2>/dev/null
}
leaf server localhost "subjectAltName=DNS:localhost,DNS:otelcol,IP:127.0.0.1
extendedKeyUsage=serverAuth"
leaf client akio-export "extendedKeyUsage=clientAuth"
chmod 644 "$CERTS"/*

NAME=akio-otel-$$
NET_ARGS=()
if [ -n "${NETWORK:-}" ]; then
  NET_ARGS=(--network "$NETWORK" --network-alias otelcol)
fi
docker run -d --rm --name "$NAME" "${NET_ARGS[@]}" \
  -p 127.0.0.1::4317 -p 127.0.0.1::4318 -p 127.0.0.1::4319 -p 127.0.0.1::4320 \
  -p 127.0.0.1::8125/udp \
  -v "$ROOT/tools/otel/collector.yaml:/etc/otelcol-contrib/config.yaml:ro" \
  -v "$CERTS:/certs:ro" -v "$OUT:/out" "$IMAGE" > /dev/null
trap 'docker logs "$NAME" > "$OUT/collector.log" 2>&1 || true; docker rm -f "$NAME" > /dev/null 2>&1 || true' EXIT
port() { docker port "$NAME" "$1" | head -1 | sed 's/.*://'; }
HTTP=127.0.0.1:$(port 4318/tcp)
UDP=127.0.0.1:$(port 8125/udp)
for _ in $(seq 1 60); do
  if curl -s -o /dev/null -X POST -H 'Content-Type: application/json' -d '{}' "http://$HTTP/v1/metrics"; then break; fi
  sleep 1
done
export AKIO_OTEL_OUT="$OUT" AKIO_OTEL_CERTS="$CERTS"
if [ -n "${RUN:-}" ]; then
  # Another container on $NETWORK runs the test; it sees the output through $OUT.
  AKIO_OTEL_COLLECTOR=http://otelcol:4318 AKIO_OTEL_STATSD=otelcol:8125 \
    AKIO_OTEL_GRPC=http://otelcol:4317 AKIO_OTEL_GRPCS=https://otelcol:4319 \
    AKIO_OTEL_HTTPS=https://otelcol:4320 bash -c "$RUN"
else
  AKIO_OTEL_COLLECTOR=http://$HTTP AKIO_OTEL_STATSD=$UDP \
    AKIO_OTEL_GRPC=http://127.0.0.1:$(port 4317/tcp) \
    AKIO_OTEL_GRPCS=https://localhost:$(port 4319/tcp) \
    AKIO_OTEL_HTTPS=https://127.0.0.1:$(port 4320/tcp) \
    cargo test --manifest-path "$ROOT/Cargo.toml" -p akio-export --test collector --test collector_tls -- --nocapture
fi
echo "collector output in $OUT"
