#!/bin/sh
# Regenerates the Ed448 and DSA test data with OpenSSL 3 or later (test-only keys):
# an Ed448 root and leaf, an Ed448 signature, a DSA (2048/256) root signing a P-256 leaf with
# dsa_with_SHA256 and a CRL revoking a second leaf.
set -eu
cd "$(dirname "$0")"
rm -rf work && mkdir work
cat >work/ext.cnf <<'CNF'
[ca]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
[leaf]
basicConstraints = critical, CA:FALSE
subjectAltName = DNS:ed448.test, DNS:dsa.test
extendedKeyUsage = serverAuth
CNF
days=7300

# Ed448
openssl genpkey -algorithm ed448 -out ed448_root.key
openssl req -new -x509 -key ed448_root.key -subj "/CN=Ed448 Test Root" -days $days \
    -config work/ext.cnf -extensions ca -out ed448_root.pem
openssl genpkey -algorithm ed448 -out ed448_leaf.key
openssl req -new -key ed448_leaf.key -subj "/CN=ed448.test" -out work/leaf.csr
openssl x509 -req -in work/leaf.csr -CA ed448_root.pem -CAkey ed448_root.key -days $days \
    -set_serial 2 -extfile work/ext.cnf -extensions leaf -out ed448_leaf.pem
printf 'Ed448 message signed by OpenSSL' >msg.bin
openssl pkeyutl -sign -inkey ed448_leaf.key -rawin -in msg.bin -out ed448.sig

# DSA 2048/256 root; P-256 leaves signed with dsa_with_SHA256.
openssl genpkey -genparam -algorithm DSA -pkeyopt dsa_paramgen_bits:2048 \
    -pkeyopt dsa_paramgen_q_bits:256 -pkeyopt dsa_paramgen_md:sha256 -out work/dsa.param
openssl genpkey -paramfile work/dsa.param -out work/dsa_root.key
openssl req -new -x509 -key work/dsa_root.key -sha256 -subj "/CN=DSA Test Root" -days $days \
    -config work/ext.cnf -extensions ca -out dsa_root.pem
for n in 3 4; do
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out work/leaf$n.key
    openssl req -new -key work/leaf$n.key -subj "/CN=dsa.test" -out work/leaf$n.csr
    openssl x509 -req -in work/leaf$n.csr -CA dsa_root.pem -CAkey work/dsa_root.key -sha256 \
        -days $days -set_serial $n -extfile work/ext.cnf -extensions leaf -out dsa_leaf$n.pem
done
# A CRL from the DSA root revoking leaf 4.
mkdir -p work/ca && : >work/ca/index.txt && echo 01 >work/ca/crlnumber
cat >work/ca.cnf <<CNF
[ca]
default_ca = d
[d]
database = work/ca/index.txt
crlnumber = work/ca/crlnumber
default_md = sha256
default_crl_days = $days
CNF
openssl ca -config work/ca.cnf -keyfile work/dsa_root.key -cert dsa_root.pem -revoke dsa_leaf4.pem \
    -crl_reason keyCompromise 2>/dev/null
openssl ca -config work/ca.cnf -keyfile work/dsa_root.key -cert dsa_root.pem -gencrl \
    -out dsa_root.crl.pem 2>/dev/null
rm -rf work
