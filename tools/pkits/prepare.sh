#!/bin/sh
# Downloads NIST PKITS (the Public Key Interoperability Test Suite, 2011 edition) into $1 and
# extracts each test's certificates from its signed S/MIME message into $1/paths/<Test>.pem,
# for `crates/akio-x509/tests/pkits.rs`:
#
#   tools/pkits/prepare.sh /tmp/pkits
#   PKITS_DIR=/tmp/pkits cargo test -p akio-x509 --test pkits -- --ignored --nocapture
#
# Needs curl, unzip and openssl.
set -eu
dir=${1:?usage: prepare.sh <dir>}
mkdir -p "$dir"
cd "$dir"
if [ ! -d certs ]; then
    curl -fsSL -o PKITS_data.zip \
        https://csrc.nist.gov/CSRC/media/Projects/PKI-Testing/documents/PKITS_data.zip
    unzip -q -o PKITS_data.zip
fi
mkdir -p paths
for m in smime/Signed*.eml; do
    name=$(basename "$m" .eml)
    name=${name#Signed}
    openssl smime -pk7out -in "$m" 2>/dev/null |
        openssl pkcs7 -print_certs 2>/dev/null |
        sed -n '/BEGIN CERTIFICATE/,/END CERTIFICATE/p' >"paths/$name.pem" || true
done
echo "PKITS ready in $dir ($(ls paths | wc -l) paths)"
