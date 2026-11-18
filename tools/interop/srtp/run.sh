#!/usr/bin/env bash
# only-srtp cross-check against libsrtp: builds libsrtp (main at $LIBSRTP_REV, OpenSSL backend
# for AES-GCM) in a scratch directory, compiles vec.c against it and compares its packets with
# crates/only-srtp/testdata/libsrtp.txt, which `cargo test -p only-srtp libsrtp_cross_check`
# checks byte for byte both ways. UPDATE=1 rewrites the test data instead.
#   Needs git, a C compiler, make and OpenSSL 3 headers (OPENSSL_DIR=<prefix> if not system-wide;
#   a prefix with include/ and lib/, as an extracted libssl-dev package gives).
set -eu
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
LIBSRTP_REV=${LIBSRTP_REV:-052aa2965e2c26f737087492d37a31c3ee09ddba}
W=${WORK:-$(mktemp -d)}
DATA="$ROOT/crates/only-srtp/testdata/libsrtp.txt"
if [ ! -d "$W/libsrtp" ]; then
  git clone -q https://github.com/cisco/libsrtp.git "$W/libsrtp"
fi
cd "$W/libsrtp"
git checkout -q "$LIBSRTP_REV"
FLAGS=""
LIBS="-lcrypto"
if [ -n "${OPENSSL_DIR:-}" ]; then
  FLAGS="-I$OPENSSL_DIR/include -I$OPENSSL_DIR/include/$(gcc -dumpmachine)"
  LIBS="$(ls "$OPENSSL_DIR"/lib/*/libcrypto.a "$OPENSSL_DIR"/lib/libcrypto.a 2>/dev/null | head -1)"
fi
crypto_CFLAGS="$FLAGS" crypto_LIBS="$LIBS" CPPFLAGS="$FLAGS" \
  ./configure -q --with-crypto-library=openssl ${OPENSSL_DIR:+--with-openssl-dir=$OPENSSL_DIR}
make -s -j"$(nproc 2>/dev/null || echo 4)" libsrtp3.a
cc -O1 -o "$W/vec" "$ROOT/tools/interop/srtp/vec.c" -Iinclude -Icrypto/include -I. libsrtp3.a \
  $LIBS -lpthread -ldl
"$W/vec" > "$W/vectors.txt"
if [ "${UPDATE:-0}" = 1 ]; then
  { grep '^#' "$DATA"; cat "$W/vectors.txt"; } > "$W/new.txt" && mv "$W/new.txt" "$DATA"
  echo "updated $DATA ($(wc -l < "$W/vectors.txt") packets)"
else
  diff <(grep -v '^#' "$DATA") "$W/vectors.txt" && echo "libsrtp vectors match ($(wc -l < "$W/vectors.txt") packets)"
fi
