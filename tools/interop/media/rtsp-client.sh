#!/usr/bin/env bash
# The akio-media RTSP client against mediamtx (bluenviron/mediamtx:latest, in Docker) and
# ffmpeg's RTSP listen mode:
#   1. on the host, over TCP: our client records (push) the samples to mediamtx, ffprobe reads
#      them from mediamtx, our client plays (pull) them back; ffmpeg -rtsp_flags listen
#      receives our push over TCP and UDP (ffmpeg/ffprobe from PATH, skipped without them);
#   2. in a Linux container (rust:1) on the Docker network of mediamtx, over UDP and TCP: the
#      same record and play. UDP RTP does not cross Docker Desktop's NAT with the client_port
#      the client announced, hence the container; on Linux with Docker Engine, step 1 with
#      AKIO_MEDIAMTX_TRANSPORTS=tcp,udp works too.
#
#   tools/interop/media/rtsp-client.sh            # both steps
#   tools/interop/media/rtsp-client.sh host       # step 1 only
#   tools/interop/media/rtsp-client.sh container  # step 2 only
#   AKIO_MEDIAMTX_HOLD=75 AKIO_MEDIAMTX_TRANSPORTS=udp tools/interop/media/rtsp-client.sh container
#                                                 # sessions held past mediamtx's 60 s timeout
set -eu
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
NET=akio-media-interop
MTX=akio-media-mtx
PORT=${AKIO_MEDIAMTX_PORT:-18554}
STEP=${1:-all}

docker network inspect "$NET" >/dev/null 2>&1 || docker network create "$NET" >/dev/null
docker rm -f "$MTX" >/dev/null 2>&1 || true
# RTSP on $PORT both inside and on the host, so the URLs match; default RTP/RTCP ports.
docker run -d --rm --name "$MTX" --network "$NET" -e MTX_RTSPADDRESS=:$PORT \
    -p "$PORT:$PORT" bluenviron/mediamtx:latest >/dev/null
trap 'docker rm -f "$MTX" >/dev/null 2>&1 || true' EXIT
sleep 2

if [ "$STEP" = all ] || [ "$STEP" = host ]; then
    echo "== host: mediamtx over TCP, ffmpeg listen over TCP and UDP"
    (cd "$ROOT" && AKIO_MEDIAMTX=127.0.0.1:$PORT AKIO_MEDIAMTX_TRANSPORTS=tcp \
        cargo test -p akio-media --test rtsp_client -- mediamtx ffmpeg --nocapture)
fi

if [ "$STEP" = all ] || [ "$STEP" = container ]; then
    echo "== container: mediamtx over UDP and TCP (host name resolved by the client)"
    docker run --rm --network "$NET" -v "$ROOT":/w -w /w \
        -v akio-cargo-reg:/usr/local/cargo/registry \
        -v "${AKIO_INTEROP_TARGET:-akio-interop-target}":/tmp/t -e CARGO_TARGET_DIR=/tmp/t \
        -e AKIO_MEDIAMTX="$MTX:$PORT" -e AKIO_MEDIAMTX_HOLD="${AKIO_MEDIAMTX_HOLD:-0}" \
        -e AKIO_MEDIAMTX_TRANSPORTS="${AKIO_MEDIAMTX_TRANSPORTS:-udp,tcp}" rust:1 \
        cargo test -p akio-media --test rtsp_client -- mediamtx --nocapture
fi
docker logs "$MTX" 2>&1 | grep -E "RTSP|path akio_" | grep -vE "listener opened" | tail -20 || true
