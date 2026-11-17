#!/usr/bin/env bash
# WebRTC media through the only-media hub (only_media::webrtc::RtcMedia, cargo feature
# `webrtc`) against ffmpeg and pion (webrtc v4). Runs the `whip-server` example (WHIP/WHEP,
# RTMP and HTTP-FLV on one hub) and checks:
#
#   1. ffmpeg's WHIP muxer publishes H.264 (libx264 -bf 0) + Opus; the hub stream has tracks
#      H264,Opus; it plays out over RTMP and HTTP-FLV (ffprobe).
#   2. a pion WHIP client publishes H.264 (Annex B file, 10 s GOP) + Opus (Ogg); a pion WHEP
#      client plays it, starts at a keyframe, gets Opus, sends a PLI and gets a keyframe within
#      600 ms (the WHIP client jumps to the next IDR on a PLI, so that keyframe proves the PLI
#      went viewer -> hub -> publisher); the WHIP client counts the PLIs; the received H.264
#      decodes (ffprobe / ffmpeg).
#   3. ffmpeg publishes H.264 + G.711 A-law over RTMP; the pion WHEP client plays it (PCMA
#      passes through).
#
# Needs Go, ffmpeg and ffprobe (FFMPEG=/path/to/ffmpeg, FFPROBE=...; ffmpeg 7.1+ for WHIP).
set -eu
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
FFMPEG=${FFMPEG:-ffmpeg}
FFPROBE=${FFPROBE:-ffprobe}
SRC=$ROOT/crates/only-media/testdata/h264_aac.flv
W=$(mktemp -d)
PIDS=""
trap 'kill $PIDS 2>/dev/null || true; rm -rf "$W"' EXIT

cd "$ROOT" && cargo build -q --release -p only-media --features webrtc --example whip-server
RS=$ROOT/target/release/examples/whip-server
cd "$ROOT/tools/interop/webrtc" && GOFLAGS=-mod=mod go build -o "$W/whip-pion" ./whip
GO=$W/whip-pion

UDP=127.0.0.1:9610 HTTP=127.0.0.1:9611 RTMP=127.0.0.1:9612
$RS $UDP $HTTP $RTMP >"$W/server.log" 2>&1 & PIDS="$PIDS $!"
streams() { curl -fsS "http://$HTTP/streams"; }
for _ in $(seq 50); do streams >/dev/null 2>&1 && break; sleep 0.2; done
streams >/dev/null || { cat "$W/server.log" >&2; echo "FAIL: whip-server not up" >&2; exit 1; }
expect_stream() { # path, codecs (sorted, comma separated)
  local line tracks
  line=$(streams | grep "^$1 " || true)
  echo "   hub: $line"
  tracks=${line#*tracks=}; tracks=$(echo "${tracks%% *}" | tr , '\n' | sort | paste -sd, -)
  [ "$tracks" = "$2" ] || { echo "FAIL: $1 has tracks $tracks, want $2" >&2; exit 1; }
  local n=${line##*packets=}; n=${n%% *}
  [ "$n" -gt 20 ] || { echo "FAIL: $1 has $n packets" >&2; exit 1; }
}
probe() { # url, expected codec names (sorted, comma separated)
  local got
  got=$(timeout 15 "$FFPROBE" -v error -show_entries stream=codec_name -of csv=p=0 "$1" | sort | paste -sd, -)
  echo "   ffprobe $1: $got"
  [ "$got" = "$2" ] || { echo "FAIL: $1: $got, want $2" >&2; exit 1; }
}

echo "== ffmpeg WHIP (H.264 + Opus) -> hub -> RTMP, HTTP-FLV"
"$FFMPEG" -hide_banner -loglevel error -re -stream_loop -1 -i "$SRC" -t 12 \
  -c:v libx264 -bf 0 -g 50 -c:a libopus -ar 48000 -ac 2 \
  -f whip "http://$HTTP/whip/live/ff" >"$W/ffmpeg-whip.log" 2>&1 & FF=$!
sleep 4
expect_stream live/ff H264,Opus
probe "rtmp://$RTMP/live/ff" h264,opus
probe "http://$HTTP/live/ff.flv" h264,opus
wait $FF || true
# ffmpeg 9 logs "Failed to read response from DELETE" for an empty 200 body; only that is allowed.
if grep -v "DELETE\|dispose" "$W/ffmpeg-whip.log" | grep -qi .; then
  cat "$W/ffmpeg-whip.log" >&2; echo "FAIL: ffmpeg WHIP errors" >&2; exit 1
fi
sleep 1
streams | grep -q "^live/ff .*packets" && { echo "FAIL: live/ff still published" >&2; exit 1; }

echo "== pion WHIP (H.264 + Opus) -> hub -> pion WHEP, PLI round trip"
"$FFMPEG" -hide_banner -loglevel error -stream_loop 4 -i "$SRC" -an -t 10 -r 25 \
  -c:v libx264 -profile:v baseline -bf 0 -g 250 -keyint_min 250 -sc_threshold 0 \
  -bsf:v h264_mp4toannexb -f h264 "$W/in.h264"
"$FFMPEG" -hide_banner -loglevel error -stream_loop 4 -i "$SRC" -vn -t 10 \
  -c:a libopus -ar 48000 -ac 2 -page_duration 20000 "$W/in.ogg"
$GO whip "http://$HTTP/whip/live/p" "$W/in.h264" "$W/in.ogg" 12 2 & PW=$!
sleep 3
expect_stream live/p H264,Opus
$GO whep "http://$HTTP/whep/live/p" "$W/out.h264" 6 pli
wait $PW
frames=$("$FFPROBE" -v error -count_frames -select_streams v -show_entries stream=codec_name,nb_read_frames -of csv=p=0 "$W/out.h264")
echo "   received H.264: $frames"
case "$frames" in h264,*) ;; *) echo "FAIL: out.h264: $frames" >&2; exit 1 ;; esac
[ "${frames#h264,}" -gt 50 ] || { echo "FAIL: too few frames" >&2; exit 1; }
if "$FFMPEG" -v error -i "$W/out.h264" -f null - 2>&1 | grep -q .; then
  echo "FAIL: out.h264 does not decode cleanly" >&2; exit 1
fi

echo "== ffmpeg RTMP (H.264 + G.711 A-law) -> hub -> pion WHEP"
"$FFMPEG" -hide_banner -loglevel error -re -stream_loop -1 -i "$SRC" -t 12 \
  -c:v libx264 -bf 0 -g 25 -c:a pcm_alaw -ar 8000 -ac 1 \
  -f flv "rtmp://$RTMP/live/r" >"$W/ffmpeg-rtmp.log" 2>&1 & FF=$!
sleep 3
expect_stream live/r H264,PCMA
$GO whep "http://$HTTP/whep/live/r" "$W/rtmp.h264" 4 | tee "$W/whep-r.log"
grep -qi "audio/pcma" "$W/whep-r.log" || { echo "FAIL: PCMA not received" >&2; exit 1; }
kill $FF 2>/dev/null || true

echo "webrtc media interop: all passed"
