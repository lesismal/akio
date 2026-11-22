#!/usr/bin/env bash
# The RTSP redirects, receiver reports and lookups on reconnect of akio-media against mediamtx
# (bluenviron/mediamtx, Docker) and GStreamer (rtspclientsink, in an image built here from
# ubuntu:24.04). Linux with Docker Engine (host networking for UDP):
#   1. redirect: mediamtx's path `moved` is `source: redirect` to `rsrc`; our client records to
#      `rsrc` and plays `moved` over TCP and UDP (tests/rtsp_client.rs mediamtx_redirect), then
#      records and plays held past mediamtx's 60 s session timeout over UDP, kept alive by
#      the pull's receiver reports (mediamtx_record_and_play);
#   2. receiver reports: rtspclientsink records to our server over TCP and UDP and must log our
#      reports (tests/rtsp_interop.rs gstreamer_record_gets_receiver_reports);
#   3. lookups on reconnect: on a Docker network, mediamtx A answers to the name `rtspsrv`;
#      our test binary (host-built, run in ubuntu:24.04 on that network) records to it and
#      plays back, both reconnecting; A is removed and mediamtx B starts at another address
#      under the same name: both clients must find B (server_moves_to_another_address), over
#      TCP, then UDP.
#
#   tools/interop/media/rtsp-redirect.sh            # all steps
#   tools/interop/media/rtsp-redirect.sh redirect   # or: reports, move
# MTX_IMAGE (default bluenviron/mediamtx:latest), RTSP_PORT (18654; RTP/RTCP on the two
# ports after it, +46 and +47), MOVE_SUBNET (172.31.249.0/24); CARGO_TARGET_DIR as for cargo.
set -eu
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
STEP=${1:-all}
MTX_IMAGE=${MTX_IMAGE:-bluenviron/mediamtx:latest}
PORT=${RTSP_PORT:-18654}
SUBNET=${MOVE_SUBNET:-172.31.249.0/24}
NET=akio-media-move
GST_IMAGE=akio-media-gst
TARGET=${CARGO_TARGET_DIR:-$ROOT/target}
W=$(mktemp -d)
cleanup() {
    docker rm -f akio-media-redir akio-media-move-a akio-media-move-b akio-media-move-client \
        >/dev/null 2>&1 || true
    docker network rm "$NET" >/dev/null 2>&1 || true
    rm -rf "$W"
}
trap cleanup EXIT

cd "$ROOT"
cargo test -q -p akio-media --test rtsp_client --test rtsp_interop --no-run 2>/dev/null
BIN=$(cargo test -q -p akio-media --test rtsp_client --no-run --message-format=json 2>/dev/null \
    | sed -n 's/.*"executable":"\([^"]*rtsp_client[^"]*\)".*/\1/p' | tail -1)

if [ "$STEP" = all ] || [ "$STEP" = redirect ]; then
    echo "== redirect: mediamtx (host network, RTSP on $PORT)"
    cat >"$W/mtx.yml" <<EOF
rtspAddress: :$PORT
rtpAddress: :$((PORT + 46))
rtcpAddress: :$((PORT + 47))
rtmp: no
hls: no
webrtc: no
srt: no
paths:
  moved:
    source: redirect
    sourceRedirect: rtsp://127.0.0.1:$PORT/rsrc
  all_others:
EOF
    docker run -d --rm --name akio-media-redir --network host \
        -v "$W/mtx.yml:/mediamtx.yml:ro" "$MTX_IMAGE" >/dev/null
    sleep 2
    AKIO_MEDIAMTX_REDIRECT=127.0.0.1:$PORT AKIO_MEDIAMTX_TRANSPORTS=tcp,udp AKIO_MEDIAMTX_HOLD=10 \
        cargo test -q -p akio-media --test rtsp_client mediamtx_redirect -- --nocapture
    AKIO_MEDIAMTX=127.0.0.1:$PORT AKIO_MEDIAMTX_TRANSPORTS=udp AKIO_MEDIAMTX_HOLD=75 \
        cargo test -q -p akio-media --test rtsp_client mediamtx_record_and_play -- --nocapture
    docker logs akio-media-redir 2>&1 | grep -E "redirect|closed|timed out" | tail -8 || true
    docker rm -f akio-media-redir >/dev/null
fi

if [ "$STEP" = all ] || [ "$STEP" = reports ]; then
    echo "== receiver reports: GStreamer rtspclientsink records to our server"
    if ! docker image inspect "$GST_IMAGE" >/dev/null 2>&1; then
        docker build -q -t "$GST_IMAGE" - >/dev/null <<'EOF'
FROM ubuntu:24.04
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    gstreamer1.0-tools gstreamer1.0-rtsp gstreamer1.0-plugins-base gstreamer1.0-plugins-good \
    gstreamer1.0-plugins-bad gstreamer1.0-plugins-ugly && rm -rf /var/lib/apt/lists/*
EOF
    fi
    AKIO_GST_IMAGE=$GST_IMAGE cargo test -q -p akio-media --test rtsp_interop gstreamer -- --nocapture
fi

if [ "$STEP" = all ] || [ "$STEP" = move ]; then
    echo "== lookups on reconnect: rtspsrv moves from mediamtx A to mediamtx B"
    docker network create --subnet "$SUBNET" "$NET" >/dev/null
    PREFIX=${SUBNET%.*}
    for t in tcp udp; do
        docker run -d --rm --name akio-media-move-a --network "$NET" --ip "$PREFIX.10" \
            --network-alias rtspsrv "$MTX_IMAGE" >/dev/null
        sleep 2
        docker run -d --name akio-media-move-client --network "$NET" \
            -v "$ROOT:$ROOT:ro" -v "$BIN:/t/rtsp_client:ro" \
            -e AKIO_MOVING_SERVER=rtspsrv:8554 -e AKIO_MEDIAMTX_TRANSPORTS=$t \
            ubuntu:24.04 /t/rtsp_client server_moves_to_another_address --nocapture >/dev/null
        for _ in $(seq 60); do
            docker logs akio-media-move-client 2>&1 | grep -q READY && break
            sleep 1
        done
        docker logs akio-media-move-client 2>&1 | grep READY
        docker rm -f akio-media-move-a >/dev/null
        sleep 1
        docker run -d --rm --name akio-media-move-b --network "$NET" --ip "$PREFIX.20" \
            --network-alias rtspsrv "$MTX_IMAGE" >/dev/null
        code=$(docker wait akio-media-move-client)
        docker logs akio-media-move-client 2>&1 | grep -E "MOVED|panicked|test result" || true
        echo "rtspsrv moved $PREFIX.10 -> $PREFIX.20 over $t: exit $code"
        docker logs akio-media-move-b 2>&1 | grep -E "is publishing|is reading" | head -2 || true
        docker rm -f akio-media-move-client akio-media-move-b >/dev/null
        [ "$code" = 0 ]
    done
fi
echo "akio-media RTSP redirect / receiver report / move interop: all passed"
