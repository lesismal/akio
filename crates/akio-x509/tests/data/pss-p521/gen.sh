#!/bin/sh
# Regenerates the RSA-PSS-key and P-521 fixtures (test-only keys) with OpenSSL 3.2 or later:
#   cd crates/only-x509/tests/data/pss-p521 && sh gen.sh
# - pss_root: a self-signed root whose key is id-RSASSA-PSS restricted to SHA-256 (salt >= 32),
#   signed with RSA-PSS SHA-256; pss_leaf: an id-RSASSA-PSS key without parameters, a
#   serverAuth certificate for pss.test signed by pss_root.
# - p521_root: a self-signed P-521 root (ecdsa-with-SHA512); p521_leaf: a P-521 serverAuth
#   certificate for p521.test and 127.0.0.1 signed by it.
set -eu
days=36500
openssl genpkey -algorithm RSA-PSS -pkeyopt rsa_keygen_bits:2048 \
    -pkeyopt rsa_pss_keygen_md:sha256 -pkeyopt rsa_pss_keygen_mgf1_md:sha256 \
    -pkeyopt rsa_pss_keygen_saltlen:32 -out pss_root.key
openssl req -x509 -new -key pss_root.key -subj "/CN=PSS Test Root" -days $days \
    -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -out pss_root.pem
openssl genpkey -algorithm RSA-PSS -pkeyopt rsa_keygen_bits:2048 -out pss_leaf.key
openssl req -new -key pss_leaf.key -subj "/CN=pss.test" -out pss_leaf.csr
printf 'subjectAltName=DNS:pss.test\nextendedKeyUsage=serverAuth,clientAuth\nkeyUsage=critical,digitalSignature\n' >leaf.ext
openssl x509 -req -in pss_leaf.csr -CA pss_root.pem -CAkey pss_root.key -CAcreateserial \
    -days $days -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 \
    -extfile leaf.ext -out pss_leaf.pem
openssl ecparam -name secp521r1 -genkey -noout | openssl pkey -out p521_root.key
openssl req -x509 -new -key p521_root.key -subj "/CN=P-521 Test Root" -days $days -sha512 \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -out p521_root.pem
openssl ecparam -name secp521r1 -genkey -noout -out p521_leaf_sec1.key
openssl pkey -in p521_leaf_sec1.key -out p521_leaf.key
openssl req -new -key p521_leaf.key -subj "/CN=p521.test" -out p521_leaf.csr
printf 'subjectAltName=DNS:p521.test,IP:127.0.0.1\nextendedKeyUsage=serverAuth,clientAuth\nkeyUsage=critical,digitalSignature\n' >leaf.ext
openssl x509 -req -in p521_leaf.csr -CA p521_root.pem -CAkey p521_root.key -CAcreateserial \
    -days $days -sha512 -extfile leaf.ext -out p521_leaf.pem
printf 'only-x509 fixture message\n' >msg.bin
openssl dgst -sha512 -sign p521_leaf.key -out p521_sha512.sig msg.bin
openssl dgst -sha256 -sign pss_leaf.key -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 \
    -out pss_sha256.sig msg.bin
rm -f *.csr *.srl leaf.ext
