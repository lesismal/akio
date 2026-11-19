#!/usr/bin/env bash
# only-dtls <-> OpenSSL 4.1 and wolfSSL 5.8: DTLS 1.3 (RFC 9147) both directions, version
# negotiation and downgrade, HelloRetryRequest (cookie and group), small MTUs (fragments and
# ACKs), KeyUpdate, connection IDs (RFC 9146 in DTLS 1.2, DTLS 1.3 CIDs), external PSKs,
# session resumption (DTLS 1.3 and DTLS 1.2 tickets), DTLS-SRTP keys compared byte for byte;
# early data (0-RTT) and post-handshake client authentication both ways with wolfSSL (ADR-045).
#   dtls13.sh <dtls-interop binary> <work dir>
# run.sh calls it inside the image built from ./Dockerfile (OpenSSL 4.1 and wolfSSL 5.8.4 built
# with DTLS 1.3 and CIDs; Debian's OpenSSL 3.5 has no DTLS 1.3).
set -eu
BIN=$1
W=$2
mkdir -p "$W"
cd "$W"
rm -f ./*.log
PIDS=""
trap 'kill $PIDS 2>/dev/null || true' EXIT
fail() {
  echo "FAIL: $*"
  for f in "$W"/*.log; do echo "--- $f"; grep -av "Entering\|Leaving" "$f" | tail -25; done
  exit 1
}
openssl version
WOLF=/opt/wolfssl

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout ec.key \
  -out ec.pem -days 30 -subj /CN=openssl-ec 2>/dev/null
openssl req -x509 -newkey rsa:2048 -nodes -keyout rsa.key -out rsa.pem -days 30 \
  -subj /CN=openssl-rsa 2>/dev/null
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout only.key \
  -out only.pem -days 30 -subj /CN=only 2>/dev/null
fp() { echo "sha-256 $(openssl x509 -in "$1" -noout -fingerprint -sha256 | cut -d= -f2)"; }
openssl_material() { grep -aA3 'Keying material exporter' "$1" | sed -n 's/.*Keying material: *//p' | head -1; }
ours() { sed -n 's/^SRTP_MATERIAL //p' "$1" | head -1; }
suite() { sed -n 's/^CONNECTED suite=\([^ ]*\).*/\1/p' "$1" | head -1; }
infos() { grep "^INFO" "$1" | tr '\n' ' '; }
want() { grep -q -- "$2" "$1" || fail "$3: '$2' missing in $1"; }
same_material() {
  local a=$1 b=$2
  [ -n "$a" ] && [ "$a" = "$b" ] || fail "$3: keying material '$a' vs '$b'"
}
PSK=00112233445566778899aabbccddeeff
# A CID as wolfSSL's examples print it: each byte with %x (no zero padding).
wolfhex() { for b in $(echo "$1" | sed 's/../& /g'); do printf '%x' "0x$b"; done; }
port=26430
next() { port=$((port + 1)); }
# Background helpers. s_server is started inline with its stdin from `sleep` (a background
# job in a function would read /dev/null, and s_server quits at EOF).
start() { "$@" & PIDS="$PIDS $!"; sleep 0.5; }
started() { PIDS="$PIDS $!"; sleep 0.5; }
OFP=$(fp only.pem)

echo "== OpenSSL $(openssl version | cut -d' ' -f2) s_server <- only-dtls client"
# DTLS 1.3, ECDSA, SRTP keys, mutual authentication; the server's HelloRetryRequest for P-256
# (we send an X25519 share).
for c in "srtp-ecdsa:ec:SRTP_AEAD_AES_128_GCM:56:" "hrr-group-p256:ec:SRTP_AES128_CM_SHA1_80:60:-groups P-256" \
  "rsa-chacha-mtu300:rsa:SRTP_AEAD_AES_256_GCM:88:-ciphersuites TLS_CHACHA20_POLY1305_SHA256 -mtu 300"; do
  IFS=: read -r name kind srtp len extra <<<"$c"
  next
  # shellcheck disable=SC2086
  openssl s_server -dtls1_3 -accept "127.0.0.1:$port" -naccept 1 -cert "$kind.pem" \
    -key "$kind.key" -use_srtp "$srtp" -keymatexport EXTRACTOR-dtls_srtp -keymatexportlen "$len" \
    -Verify 1 -CAfile only.pem -verify_return_error $extra >"s-$name.log" 2>&1 < <(sleep 8) &
  started
  "$BIN" client "127.0.0.1:$port" --versions 1.3 --cert only.pem --key only.key --srtp "$srtp" \
    --fingerprint "$(fp "$kind.pem")" --mtu 300 --oneway >"c-$name.log" 2>&1 || fail "$name: client"
  sleep 0.5
  same_material "$(ours "c-$name.log")" "$(openssl_material "s-$name.log")" "$name"
  want "s-$name.log" "^hello from only-dtls" "$name"
  want "c-$name.log" "version=1.3" "$name"
  echo "ok   s_server -dtls1_3 <- only-dtls: $name ($(suite "c-$name.log"))"
done

# KeyUpdate (asking for the server's) between two messages.
next
openssl s_server -dtls1_3 -accept "127.0.0.1:$port" -naccept 1 -cert ec.pem -key ec.key \
  >s-keyupdate.log 2>&1 < <(sleep 8) &
started
"$BIN" client "127.0.0.1:$port" --versions 1.3 --key-update --oneway >c-keyupdate.log 2>&1 ||
  fail "keyupdate: client"
sleep 0.3
want c-keyupdate.log "^SENT_AFTER_UPDATE" keyupdate
# The message before the update and the one on the new keys.
[ "$(grep -c "hello from only-dtls" s-keyupdate.log)" -ge 2 ] || fail "keyupdate: data lost"
echo "ok   s_server -dtls1_3 <- only-dtls: KeyUpdate"

# Version negotiation: s_server any version (1.3), 1.2 only, 1.2 with HelloVerifyRequest.
for c in "any:-dtls:1.3" "dtls12:-dtls1_2:1.2" "dtls12-hvr:-dtls1_2 -listen:1.2"; do
  IFS=: read -r name sargs v <<<"$c"
  next
  # shellcheck disable=SC2086
  openssl s_server $sargs -accept "127.0.0.1:$port" -naccept 1 -cert ec.pem -key ec.key \
    >"s-v-$name.log" 2>&1 < <(sleep 8) &
  started
  "$BIN" client "127.0.0.1:$port" --versions 1.3,1.2 --oneway >"c-v-$name.log" 2>&1 ||
    fail "version $name: client"
  sleep 0.3
  want "c-v-$name.log" "version=$v" "version $name"
  want "s-v-$name.log" "^hello from only-dtls" "version $name"
  echo "ok   s_server $sargs <- only-dtls offering 1.3,1.2: DTLS $v"
done

# Resumption: DTLS 1.3 NewSessionTicket, DTLS 1.2 RFC 5077 ticket.
for v in 1.3 1.2; do
  next
  openssl s_server "-dtls1_${v#1.}" -accept "127.0.0.1:$port" -naccept 2 -cert ec.pem \
    -key ec.key >"s-resume-$v.log" 2>&1 < <(sleep 10) &
  started
  "$BIN" client "127.0.0.1:$port" --versions "$v" --resume --oneway >"c-resume-$v.log" 2>&1 ||
    fail "resume $v: client"
  sleep 0.3
  want "c-resume-$v.log" "NEW_SESSION ticket=true" "resume $v"
  [ "$(grep "^INFO" "c-resume-$v.log" | sed -n 2p)" != "" ] || fail "resume $v: no second connection"
  grep "^INFO" "c-resume-$v.log" | sed -n 2p | grep -q "resumed=true" || fail "resume $v: not resumed"
  echo "ok   s_server -dtls1_${v#1.} <- only-dtls: resumed DTLS $v session"
done

# External PSKs, no certificates.
for c in "1.3:-dtls1_3:TLS_AES_128_GCM_SHA256" "1.2:-dtls1_2 -cipher PSK-AES128-GCM-SHA256:TLS_PSK_WITH_AES_128_GCM_SHA256" \
  "1.2:-dtls1_2 -cipher ECDHE-PSK-CHACHA20-POLY1305:TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256"; do
  IFS=: read -r v sargs want_suite <<<"$c"
  next
  # shellcheck disable=SC2086
  openssl s_server $sargs -accept "127.0.0.1:$port" -naccept 1 -nocert -psk "$PSK" \
    -psk_identity only-psk >"s-psk-$want_suite.log" 2>&1 < <(sleep 8) &
  started
  "$BIN" client "127.0.0.1:$port" --versions "$v" --psk "only-psk:$PSK" --oneway \
    >"c-psk-$want_suite.log" 2>&1 || fail "psk $want_suite: client"
  sleep 0.3
  [ "$(suite "c-psk-$want_suite.log")" = "$want_suite" ] || fail "psk: suite $(suite "c-psk-$want_suite.log")"
  want "s-psk-$want_suite.log" "^hello from only-dtls" "psk $want_suite"
  echo "ok   s_server $sargs -psk <- only-dtls: $want_suite"
done

echo "== OpenSSL s_client -> only-dtls server"
for c in "default:ec:SRTP_AES128_CM_SHA1_80:60:" "mtu300-rsa:rsa:SRTP_AEAD_AES_128_GCM:56:-mtu 300" \
  "aes256:ec:SRTP_AEAD_AES_256_GCM:88:-ciphersuites TLS_AES_256_GCM_SHA384" \
  "no-cookie:ec:SRTP_AES128_CM_SHA1_80:60:"; do
  IFS=: read -r name kind srtp len extra <<<"$c"
  next
  sflags=()
  [ "$name" = no-cookie ] && sflags=(--no-cookie)
  [ "$name" = mtu300-rsa ] && sflags=(--mtu 300 --cert rsa.pem --key rsa.key)
  start "$BIN" server "127.0.0.1:$port" --versions 1.3 --srtp "$srtp" --fingerprint "$(fp ec.pem)" \
    "${sflags[@]}" >"S-$name.log" 2>&1
  # shellcheck disable=SC2086
  (echo "hello from openssl"; sleep 2) | openssl s_client -dtls1_3 -connect "127.0.0.1:$port" \
    -cert ec.pem -key ec.key -use_srtp "$srtp" -keymatexport EXTRACTOR-dtls_srtp \
    -keymatexportlen "$len" $extra >"C-$name.log" 2>&1 || true
  sleep 0.3
  same_material "$(ours "S-$name.log")" "$(openssl_material "C-$name.log")" "$name"
  want "S-$name.log" "^RECV hello from openssl" "$name"
  want "C-$name.log" "^hello from openssl" "$name"
  want "S-$name.log" "version=1.3" "$name"
  echo "ok   s_client -dtls1_3 -> only-dtls: $name ($(suite "S-$name.log"))"
done

# KeyUpdate from s_client ('K': update and request ours), then data.
next
start "$BIN" server "127.0.0.1:$port" --versions 1.3 --no-client-cert >S-keyupdate.log 2>&1
(sleep 0.8; echo K; sleep 0.5; echo "after update"; sleep 2) | openssl s_client -dtls1_3 \
  -connect "127.0.0.1:$port" >C-keyupdate.log 2>&1 || true
want S-keyupdate.log "^RECV after update" keyupdate
want C-keyupdate.log "KEYUPDATE" keyupdate
want C-keyupdate.log "^after update" keyupdate
echo "ok   s_client -dtls1_3 -> only-dtls: KeyUpdate both ways"

# Version negotiation from the client side.
for c in "dtls12:-dtls1_2:1.2" "any:-dtls:1.3"; do
  IFS=: read -r name cargs v <<<"$c"
  next
  start "$BIN" server "127.0.0.1:$port" --versions 1.3,1.2 --no-client-cert >"S-v-$name.log" 2>&1
  # shellcheck disable=SC2086
  (echo "hello from openssl"; sleep 2) | openssl s_client $cargs -connect "127.0.0.1:$port" \
    >"C-v-$name.log" 2>&1 || true
  want "S-v-$name.log" "version=$v" "client version $name"
  want "C-v-$name.log" "^hello from openssl" "client version $name"
  echo "ok   s_client $cargs -> only-dtls (1.3,1.2): DTLS $v"
done

# Resumption: s_client saves the session, then resumes it.
for v in 1.3 1.2; do
  next
  start "$BIN" server "127.0.0.1:$port" --versions "$v" --resumption --accept 2 --no-client-cert \
    >"S-resume-$v.log" 2>&1
  (echo hello; sleep 1.5) | openssl s_client "-dtls1_${v#1.}" -connect "127.0.0.1:$port" \
    -sess_out "sess-$v.pem" >"C-resume1-$v.log" 2>&1 || true
  (echo hello; sleep 1.5) | openssl s_client "-dtls1_${v#1.}" -connect "127.0.0.1:$port" \
    -sess_in "sess-$v.pem" >"C-resume2-$v.log" 2>&1 || true
  want "C-resume2-$v.log" "^Reused" "client resume $v"
  grep "^INFO" "S-resume-$v.log" | sed -n 2p | grep -q "resumed=true" || fail "client resume $v: not resumed"
  echo "ok   s_client -dtls1_${v#1.} -sess_in -> only-dtls: resumed DTLS $v session"
done

# PSK from s_client.
for c in "1.3:-dtls1_3" "1.2:-dtls1_2 -cipher ECDHE-PSK-AES128-CBC-SHA256:PSK-AES128-GCM-SHA256"; do
  IFS=: read -r v cargs <<<"$c"
  next
  start "$BIN" server "127.0.0.1:$port" --versions "$v" --psk "only-psk:$PSK" >"S-psk-$v.log" 2>&1
  # shellcheck disable=SC2086
  (echo "hello from openssl"; sleep 2) | openssl s_client $cargs -connect "127.0.0.1:$port" \
    -psk "$PSK" -psk_identity only-psk >"C-psk-$v.log" 2>&1 || true
  want "S-psk-$v.log" "psk=only-psk" "client psk $v"
  want "C-psk-$v.log" "^hello from openssl" "client psk $v"
  echo "ok   s_client $cargs -psk -> only-dtls: $(suite "S-psk-$v.log")"
done

echo "== wolfSSL $(strings "$(command -v wolfssl-client)" | grep -m1 -o '5\.[0-9]*\.[0-9]*' || true)"
# Connection IDs both ways, DTLS 1.3 and DTLS 1.2.
for v in 1.3 1.2; do
  wv=4
  [ "$v" = 1.2 ] && wv=3
  next
  start sh -c "cd $WOLF && exec wolfssl-server -u -v $wv -p $port -d --cid wxyz" >"ws-cid-$v.log" 2>&1
  "$BIN" client "127.0.0.1:$port" --versions "$v" --cid 4 --message hi >"oc-cid-$v.log" 2>&1 ||
    fail "wolf cid $v: client"
  sleep 1 # wolfSSL's example server flushes its log on exit
  want "oc-cid-$v.log" "peer_cid=7778797A" "wolf cid $v"
  want "oc-cid-$v.log" "^RECV I hear you" "wolf cid $v"
  local_cid=$(wolfhex "$(sed -n 's/.*local_cid=\([0-9A-F]*\).*/\1/p' "oc-cid-$v.log")")
  want "ws-cid-$v.log" "Sending CID is $local_cid" "wolf cid $v"
  echo "ok   wolfssl-server -v $wv --cid <- only-dtls --cid: DTLS $v, CIDs both ways"
  sleep 0.5
  next
  start "$BIN" server "127.0.0.1:$port" --versions "$v" --cid 6 --no-client-cert >"os-cid-$v.log" 2>&1
  (cd "$WOLF" && timeout 8 wolfssl-client -u -v "$wv" -p "$port" -d --cid abc) >"wc-cid-$v.log" 2>&1 || true
  want "os-cid-$v.log" "peer_cid=616263" "wolf client cid $v"
  want "os-cid-$v.log" "^RECV hello wolfssl" "wolf client cid $v"
  local_cid=$(wolfhex "$(sed -n 's/.*local_cid=\([0-9A-F]*\).*/\1/p' "os-cid-$v.log")")
  want "wc-cid-$v.log" "Sending CID is $local_cid" "wolf client cid $v"
  echo "ok   wolfssl-client -v $wv --cid -> only-dtls --cid: DTLS $v, CIDs both ways"
done

# wolfSSL client: HelloRetryRequest for the group (-J), KeyUpdate before data (-I),
# resumption (-r). (Its example client sends no pre_shared_key in DTLS 1.3 with -s, so PSKs
# are covered by OpenSSL above and pion in run.sh.)
for c in "hrr:-J" "keyupdate:-I" "resume:-r"; do
  IFS=: read -r name wargs <<<"$c"
  next
  sflags=(--no-client-cert)
  [ "$name" = resume ] && sflags+=(--resumption --accept 2)
  start "$BIN" server "127.0.0.1:$port" --versions 1.3 "${sflags[@]}" >"os-$name.log" 2>&1
  # shellcheck disable=SC2086
  (cd "$WOLF" && timeout 10 wolfssl-client -u -v 4 -p "$port" -d $wargs) >"wc-$name.log" 2>&1 || true
  want "os-$name.log" "^RECV hello wolfssl" "wolf $name"
  case $name in
  resume) grep "^INFO" "os-$name.log" | sed -n 2p | grep -q "resumed=true" || fail "wolf resume: not resumed" ;;
  esac
  echo "ok   wolfssl-client -v 4 $wargs -> only-dtls: $name ($(suite "os-$name.log"))"
done
# wolfSSL server: resumption and KeyUpdate from our side.
next
start sh -c "cd $WOLF && exec wolfssl-server -u -v 4 -p $port -d -C 2" >ws-resume.log 2>&1
"$BIN" client "127.0.0.1:$port" --versions 1.3 --resume --message hi >oc-resume.log 2>&1 ||
  fail "wolf server resume: client"
grep "^INFO" oc-resume.log | sed -n 2p | grep -q "resumed=true" || fail "wolf server resume: not resumed"
echo "ok   wolfssl-server -v 4 <- only-dtls: resumed DTLS 1.3 session"
next
start sh -c "cd $WOLF && exec wolfssl-server -u -v 4 -p $port -d" >ws-ku.log 2>&1
"$BIN" client "127.0.0.1:$port" --versions 1.3 --key-update --message hi >oc-ku.log 2>&1 ||
  fail "wolf server keyupdate: client"
want oc-ku.log "^KEY_UPDATE" "wolf server keyupdate"
echo "ok   wolfssl-server -v 4 <- only-dtls: KeyUpdate"

# Early data (0-RTT) with resumption, both ways. wolfSSL's client sends "A drop of info" as
# early data on its resumed connection (-r -0); its server reads early data with -0 and needs
# -J n (no HelloRetryRequest cookie: early data is rejected after a HelloRetryRequest).
for cookie in on off; do
  next
  sflags=(--versions 1.3 --resumption --early-data 16384 --accept 2 --no-client-cert)
  [ "$cookie" = off ] && sflags+=(--no-cookie)
  start "$BIN" server "127.0.0.1:$port" "${sflags[@]}" >"os-early-$cookie.log" 2>&1
  (cd "$WOLF" && timeout 10 wolfssl-client -u -v 4 -p "$port" -d -r -0) >"wc-early-$cookie.log" 2>&1 || true
  want "os-early-$cookie.log" "^EARLY_RECV A drop of info" "wolf client early data, cookies $cookie"
  grep "^EARLY accepted" "os-early-$cookie.log" | sed -n 2p | grep -q "accepted=true" ||
    fail "wolf client early data, cookies $cookie: not accepted"
  grep "^INFO" "os-early-$cookie.log" | sed -n 2p | grep -q "resumed=true" ||
    fail "wolf client early data, cookies $cookie: not resumed"
  echo "ok   wolfssl-client -v 4 -r -0 -> only-dtls --early-data: accepted (cookies $cookie)"
done
next
# stdbuf: the example prints the early data with printf; line-buffer it for the log.
start sh -c "cd $WOLF && exec timeout 15 stdbuf -oL wolfssl-server -u -v 4 -p $port -d -C 2 -r -0 -J n" >ws-early.log 2>&1
"$BIN" client "127.0.0.1:$port" --versions 1.3 --resume --early-data 1 --message hi >oc-early.log 2>&1 ||
  fail "wolf server early data: client"
want oc-early.log "^EARLY_SENT" "wolf server early data"
grep "^EARLY accepted" oc-early.log | sed -n 2p | grep -q "accepted=true" || fail "wolf server early data: not accepted"
sleep 1
want ws-early.log "Early Data Client message: early: hi" "wolf server early data"
echo "ok   wolfssl-server -v 4 -r -0 <- only-dtls --resume --early-data: accepted, read by wolfSSL"
# The same against wolfSSL's default HelloRetryRequest cookie: rejected, resent as 1-RTT data.
next
start sh -c "cd $WOLF && exec timeout 15 wolfssl-server -u -v 4 -p $port -d -C 2 -r -0" >ws-early-hrr.log 2>&1
"$BIN" client "127.0.0.1:$port" --versions 1.3 --resume --early-data 1 --message hi >oc-early-hrr.log 2>&1 ||
  fail "wolf server early data after HRR: client"
grep "^EARLY accepted" oc-early-hrr.log | sed -n 2p | grep -q "accepted=false" ||
  fail "wolf server early data after HRR: accepted"
grep "^INFO" oc-early-hrr.log | sed -n 2p | grep -q "resumed=true" || fail "wolf server early data after HRR: not resumed"
echo "ok   wolfssl-server -v 4 -r -0 (HRR cookie) <- only-dtls --early-data: rejected, resumed"

# Post-handshake client authentication (RFC 8446 §4.6.2), both ways.
next
start sh -c "cd $WOLF && exec timeout 15 wolfssl-server -u -v 4 -p $port -Q" >ws-pha.log 2>&1
"$BIN" client "127.0.0.1:$port" --versions 1.3 --pha --cert "$WOLF/certs/client-cert.pem" \
  --key "$WOLF/certs/client-key.pem" --message hi >oc-pha.log 2>&1 || fail "wolf server pha: client"
sleep 1
want oc-pha.log "^RECV I hear you" "wolf server pha"
want ws-pha.log "Successfully requested post-hs certificate" "wolf server pha"
want ws-pha.log "Verified Peer's cert" "wolf server pha"
sed -n '/Successfully requested post-hs/,$p' ws-pha.log | grep -q "processing finished" ||
  fail "wolf server pha: no post-handshake Finished processed"
if sed -n '/Successfully requested post-hs/,$p' ws-pha.log | grep -a "SendAlert:" | grep -qv close_notify; then
  fail "wolf server pha: alert"
fi
echo "ok   wolfssl-server -v 4 -Q <- only-dtls --pha: certificate, CertificateVerify, Finished verified"
next
start "$BIN" server "127.0.0.1:$port" --versions 1.3 --no-client-cert --request-cert >os-pha.log 2>&1
(cd "$WOLF" && timeout 10 wolfssl-client -u -v 4 -p "$port" -d -Q) >wc-pha.log 2>&1 || true
want os-pha.log "^CLIENT_CERT $(fp "$WOLF/certs/client-cert.pem")" "wolf client pha"
echo "ok   wolfssl-client -v 4 -Q -> only-dtls --request-cert: client certificate after the handshake"
# NewConnectionId / RequestConnectionId (RFC 9147 §9): neither OpenSSL 4.1 nor wolfSSL 5.8
# implements them; only-dtls against itself over UDP, with CIDs both ways.
next
start "$BIN" server "127.0.0.1:$port" --versions 1.3 --cid 4 --no-client-cert >os-rotate.log 2>&1
"$BIN" client "127.0.0.1:$port" --versions 1.3 --cid 5 --rotate-cid --message hi >oc-rotate.log 2>&1 ||
  fail "rotate: client"
want oc-rotate.log "^ROTATED true" "rotate"
[ "$(grep -c '^RECV hi' oc-rotate.log)" = 2 ] || fail "rotate: no echo on the new CID"
new_cid=$(sed -n 's/^ROTATED true peer_cid=//p' oc-rotate.log)
want os-rotate.log "^LOCAL_CIDS $new_cid" "rotate: old CID retired"
echo "ok   only-dtls --rotate-cid -> only-dtls: RequestConnectionId, NewConnectionId, rotation"
echo "dtls13 interop: all passed"
