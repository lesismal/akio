#!/usr/bin/env bash
# The RTSP server's REDIRECT and the RTMP client's lookups on reconnect against third-party
# software, in Docker (Linux with Docker Engine: host networking for RTSP over UDP):
#   1. clients: what ffmpeg (the host's), GStreamer (rtspsrc, rtspclientsink; in an image built
#      here from ubuntu:24.04), live555 (openRTSP, the library VLC plays RTSP with; only when an
#      image L555_IMAGE with openRTSP exists, no distribution packages it now) and mediamtx
#      (a path whose source is our server) do when our server sends REDIRECT
#      (tests/rtsp_interop.rs third_party_redirect, one run per client and transport): the
#      answer, whether it moves to the other server, and that our server ends the session once
#      the grace passed either way;
#   2. target: our server moves our own pull and push to mediamtx with REDIRECT
#      (tests/rtsp_client.rs server_redirect_to_mediamtx), over TCP and UDP;
#   3. rtmp: on a Docker network the name `rtmpsrv` moves from mediamtx A to mediamtx B; our
#      reconnecting RTMP push and pull (the test binary, host-built, run in ubuntu:24.04 on that
#      network) must find B (tests/rtmp_client.rs rtmp_server_moves_to_another_address).
#
#   tools/interop/media/rtsp-server-redirect.sh            # all steps
#   tools/interop/media/rtsp-server-redirect.sh clients    # or: target, rtmp
# MTX_IMAGE (default bluenviron/mediamtx:latest), RTSP_PORT (18754: mediamtx's RTSP port, RTP
# and RTCP on +46 and +47; the proxy of step 1 listens on +1), MOVE_SUBNET (172.31.248.0/24);
# CARGO_TARGET_DIR as for cargo.
set -eu
FAIL=0
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
STEP=${1:-all}
MTX_IMAGE=${MTX_IMAGE:-bluenviron/mediamtx:latest}
PORT=${RTSP_PORT:-18754}
SUBNET=${MOVE_SUBNET:-172.31.248.0/24}
NET=akio-media-rtmp-move
GST_IMAGE=akio-media-gst
L555_IMAGE=${L555_IMAGE:-akio-media-live555}
W=$(mktemp -d)
cleanup() {
    docker rm -f akio-media-rd-client akio-media-rd-mtx akio-media-rtmp-a akio-media-rtmp-b \
        akio-media-rtmp-client >/dev/null 2>&1 || true
    docker network rm "$NET" >/dev/null 2>&1 || true
    rm -rf "$W"
}
trap cleanup EXIT
cd "$ROOT"

image() { # name, base, packages
    docker image inspect "$1" >/dev/null 2>&1 && return
    docker build -q -t "$1" - >/dev/null <<EOF
FROM $2
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    $3 && rm -rf /var/lib/apt/lists/*
EOF
}

# One client: mode, label, command ({url} is the stream on our server, through the proxy).
redirect() {
    local mode=$1 label=$2 cmd=$3 out
    out=$(AKIO_REDIRECT_MODE=$mode AKIO_REDIRECT_CLIENT="$cmd" AKIO_REDIRECT_PORT=$((PORT + 1)) \
        AKIO_REDIRECT_STOP="docker rm -f akio-media-rd-client akio-media-rd-mtx >/dev/null 2>&1" \
        cargo test -q -p akio-media --test rtsp_interop third_party_redirect -- --nocapture 2>&1) \
        || { echo "$out" | grep -E "REDIRECT-RESULT|panicked" | tail -5; echo "FAILED: $label"; FAIL=1; return 0; }
    echo "$label: $(echo "$out" | grep REDIRECT-RESULT | sed 's/^REDIRECT-RESULT //')"
}

if [ "$STEP" = all ] || [ "$STEP" = clients ]; then
    echo "== clients: our server sends REDIRECT"
    cargo test -q -p akio-media --test rtsp_interop --no-run 2>/dev/null
    image "$GST_IMAGE" ubuntu:24.04 "gstreamer1.0-tools gstreamer1.0-rtsp gstreamer1.0-plugins-base \
        gstreamer1.0-plugins-good gstreamer1.0-plugins-bad gstreamer1.0-plugins-ugly"
    D="docker run --rm --name akio-media-rd-client --network host"
    ffmpeg -version | head -1
    for t in tcp udp; do
        redirect play "ffmpeg play $t" \
            "exec ffmpeg -nostdin -loglevel error -rtsp_transport $t -i {url} -f null -"
        redirect record "ffmpeg record $t" \
            "exec ffmpeg -nostdin -loglevel error -re -f lavfi -i testsrc=size=320x240:rate=25 \
             -t 60 -pix_fmt yuv420p -c:v libx264 -g 25 -f rtsp -rtsp_transport $t {url}"
    done
    docker run --rm "$GST_IMAGE" gst-launch-1.0 --version | sed -n 2p
    for t in tcp udp; do
        redirect play "gstreamer rtspsrc $t" \
            "exec $D $GST_IMAGE gst-launch-1.0 -q rtspsrc location={url} protocols=$t ! fakesink"
        redirect record "gstreamer rtspclientsink $t" \
            "exec $D $GST_IMAGE gst-launch-1.0 -q videotestsrc is-live=true \
             ! video/x-raw,width=320,height=240,framerate=25/1 ! x264enc tune=zerolatency \
             key-int-max=25 ! rtspclientsink location={url} protocols=$t"
    done
    # live555 (openRTSP): neither Ubuntu 24.04 nor Debian 12 packages it any more; runs when an
    # image of that name with openRTSP on its PATH exists (L555_IMAGE).
    if docker image inspect "$L555_IMAGE" >/dev/null 2>&1; then
        redirect play "live555 openRTSP tcp" "exec $D $L555_IMAGE openRTSP -t -d 60 -F /tmp/o {url}"
        redirect play "live555 openRTSP udp" "exec $D $L555_IMAGE openRTSP -d 60 -F /tmp/o {url}"
    else
        echo "live555: no $L555_IMAGE image, skipped"
    fi
    for t in tcp udp; do
        cat >"$W/mtx-$t.yml" <<EOF
rtspAddress: :$PORT
rtpAddress: :$((PORT + 46))
rtcpAddress: :$((PORT + 47))
rtmp: no
hls: no
webrtc: no
srt: no
paths:
  px:
    source: rtsp://127.0.0.1:$((PORT + 1))/src
    rtspTransport: $t
EOF
        redirect play "mediamtx source $t" \
            "exec docker run --rm --name akio-media-rd-mtx --network host \
             -v $W/mtx-$t.yml:/mediamtx.yml:ro $MTX_IMAGE"
    done
    docker run --rm "$MTX_IMAGE" --version 2>&1 | head -1 || true
    [ "$FAIL" = 0 ]
fi

if [ "$STEP" = all ] || [ "$STEP" = target ]; then
    echo "== target: our server moves our pull and push to mediamtx (RTSP on $PORT)"
    cat >"$W/mtx.yml" <<EOF
rtspAddress: :$PORT
rtpAddress: :$((PORT + 46))
rtcpAddress: :$((PORT + 47))
rtmp: no
hls: no
webrtc: no
srt: no
paths:
  all_others:
EOF
    docker run -d --rm --name akio-media-rd-mtx --network host \
        -v "$W/mtx.yml:/mediamtx.yml:ro" "$MTX_IMAGE" >/dev/null
    sleep 2
    AKIO_MEDIAMTX_TARGET=127.0.0.1:$PORT AKIO_MEDIAMTX_TRANSPORTS=tcp,udp \
        cargo test -q -p akio-media --test rtsp_client server_redirect_to_mediamtx -- --nocapture \
        2>&1 | grep -E "MOVED-TO-MEDIAMTX|panicked|test result"
    docker rm -f akio-media-rd-mtx >/dev/null
fi

if [ "$STEP" = all ] || [ "$STEP" = rtmp ]; then
    echo "== rtmp: rtmpsrv moves from mediamtx A to mediamtx B"
    cargo test -q -p akio-media --test rtmp_client --no-run 2>/dev/null
    BIN=$(cargo test -q -p akio-media --test rtmp_client --no-run --message-format=json 2>/dev/null \
        | sed -n 's/.*"executable":"\([^"]*rtmp_client[^"]*\)".*/\1/p' | tail -1)
    docker network create --subnet "$SUBNET" "$NET" >/dev/null
    PREFIX=${SUBNET%.*}
    docker run -d --rm --name akio-media-rtmp-a --network "$NET" --ip "$PREFIX.10" \
        --network-alias rtmpsrv "$MTX_IMAGE" >/dev/null
    sleep 2
    docker run -d --name akio-media-rtmp-client --network "$NET" \
        -v "$ROOT:$ROOT:ro" -v "$BIN:/t/rtmp_client:ro" -e AKIO_MOVING_RTMP=rtmpsrv:1935 \
        ubuntu:24.04 /t/rtmp_client rtmp_server_moves_to_another_address --nocapture >/dev/null
    for _ in $(seq 60); do
        docker logs akio-media-rtmp-client 2>&1 | grep -q READY && break
        sleep 1
    done
    docker logs akio-media-rtmp-client 2>&1 | grep READY
    docker rm -f akio-media-rtmp-a >/dev/null
    sleep 1
    docker run -d --rm --name akio-media-rtmp-b --network "$NET" --ip "$PREFIX.20" \
        --network-alias rtmpsrv "$MTX_IMAGE" >/dev/null
    code=$(docker wait akio-media-rtmp-client)
    docker logs akio-media-rtmp-client 2>&1 | grep -E "MOVED|panicked|test result" || true
    echo "rtmpsrv moved $PREFIX.10 -> $PREFIX.20: exit $code"
    docker logs akio-media-rtmp-b 2>&1 | grep -E "is publishing|is reading" | head -2 || true
    [ "$code" = 0 ]
fi
echo "akio-media RTSP server REDIRECT / RTMP move interop: done"
