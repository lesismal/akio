#!/bin/sh
# The certificate signing requests of tests/interop.rs (csr_*), made with OpenSSL 4.1 from
# the keys in this directory. Run here; the outputs are checked in.
set -e
openssl req -new -key leaf_rsa.key -subj "/CN=openssl.test/O=akio" \
  -addext "subjectAltName=DNS:openssl.test,DNS:*.openssl.test,IP:192.0.2.7" \
  -addext "extendedKeyUsage=serverAuth" -out req_rsa.pem
openssl req -new -key leaf_ed25519.key -config /dev/stdin -out req_ed25519.pem <<'CNF'
[req]
prompt=no
distinguished_name=dn
attributes=attrs
[dn]
CN=ed.test
[attrs]
challengePassword=hunter22
CNF
