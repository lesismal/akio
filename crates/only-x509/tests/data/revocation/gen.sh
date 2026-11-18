#!/usr/bin/env bash
# Regenerates the CRL and OCSP fixtures of tests/revocation.rs with OpenSSL 3 (made with 3.0.13
# on Ubuntu 24.04). Run from this directory: ./gen.sh. Keys are test-only.
#
#   root (RSA-2048) -> ca (P-256, keyCertSign + cRLSign) -> good, revoked, hold, unlisted
#                                                         -> responder (OCSPSigning)
#                                                         -> rogue (no OCSPSigning EKU)
#                   -> outsider (OCSPSigning, issued by root, not by ca)
set -eu
cd "$(dirname "$0")"
rm -rf work && mkdir work
cat > work/ca.cnf <<'CNF'
[ca]
default_ca = ca_sect
[ca_sect]
dir = work
database = work/index.txt
new_certs_dir = work
serial = work/serial
crlnumber = work/crlnumber
default_md = sha256
default_days = 3650
default_crl_days = 30
policy = pol
unique_subject = no
copy_extensions = none
[pol]
commonName = supplied
[leaf_ext]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost
crlDistributionPoints = URI:http://crl.only.test/ca.crl
authorityInfoAccess = OCSP;URI:http://ocsp.only.test/,caIssuers;URI:http://ca.only.test/ca.der
[responder_ext]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = OCSPSigning
noCheck = ignored
[rogue_ext]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
[ca_ext]
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
[crl_ext]
authorityKeyIdentifier = keyid
[crl_idp_ext]
authorityKeyIdentifier = keyid
issuingDistributionPoint = critical,@idp
[idp]
fullname = URI:http://crl.only.test/ca.crl
onlyuser = TRUE
[crl_delta_ext]
authorityKeyIdentifier = keyid
2.5.29.27 = critical,ASN1:INTEGER:1
CNF
c() { openssl "$@" >/dev/null 2>&1; }
# Root, self-signed.
c req -x509 -newkey rsa:2048 -nodes -keyout root.key -out root.pem -days 3650 -subj "/CN=Revocation Root" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign"
# Intermediate CA, signed by the root.
c req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout ca.key -out work/ca.csr -subj "/CN=Revocation CA"
cat > work/ca.ext <<'X'
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
X
c x509 -req -in work/ca.csr -CA root.pem -CAkey root.key -set_serial 0x1001 -days 3650 -sha256 -extfile work/ca.ext -out ca.pem
# A second intermediate (same root) to be revoked by the root's CRL.
c req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout ca2.key -out work/ca2.csr -subj "/CN=Revocation CA 2"
c x509 -req -in work/ca2.csr -CA root.pem -CAkey root.key -set_serial 0x1002 -days 3650 -sha256 -extfile work/ca.ext -out ca2.pem
: > work/index.txt
echo 1000 > work/serial
echo 01 > work/crlnumber
issue() { # name ext [subject]
    c req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$1.key" -out "work/$1.csr" -subj "/CN=$1"
    c ca -batch -config work/ca.cnf -cert ca.pem -keyfile ca.key -extensions "$2" -in "work/$1.csr" -out "$1.pem" -notext
}
issue good leaf_ext
issue revoked leaf_ext
issue hold leaf_ext
issue responder responder_ext
issue rogue rogue_ext
# Issued by ca but not in its database: OCSP says "unknown".
c req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout unlisted.key -out work/unlisted.csr -subj "/CN=unlisted"
c x509 -req -in work/unlisted.csr -CA ca.pem -CAkey ca.key -set_serial 0x7777 -days 3650 -sha256 \
    -extfile <(printf 'basicConstraints=critical,CA:FALSE\nsubjectAltName=DNS:localhost\n') -out unlisted.pem
# OCSP signer issued by the root, not by ca.
c req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout outsider.key -out work/outsider.csr -subj "/CN=outsider"
c x509 -req -in work/outsider.csr -CA root.pem -CAkey root.key -set_serial 0x1003 -days 3650 -sha256 \
    -extfile <(printf 'basicConstraints=critical,CA:FALSE\nextendedKeyUsage=OCSPSigning\n') -out outsider.pem

# CRL 1: complete, nothing revoked.
c ca -config work/ca.cnf -cert ca.pem -keyfile ca.key -gencrl -crlexts crl_ext -out work/empty.crl.pem
openssl crl -in work/empty.crl.pem -outform DER -out ca_empty.crl
# Revoke two (keyCompromise; certificateHold) and issue CRL 2, plus a PEM copy.
c ca -config work/ca.cnf -cert ca.pem -keyfile ca.key -revoke revoked.pem -crl_reason keyCompromise
c ca -config work/ca.cnf -cert ca.pem -keyfile ca.key -revoke hold.pem -crl_hold holdInstructionReject
c ca -config work/ca.cnf -cert ca.pem -keyfile ca.key -gencrl -crlexts crl_ext -out ca.crl.pem
openssl crl -in ca.crl.pem -outform DER -out ca.crl
# CRL 3: a delta on top of CRL 1 (base number 1), listing the same revocations.
c ca -config work/ca.cnf -cert ca.pem -keyfile ca.key -gencrl -crlexts crl_delta_ext -out work/delta.crl.pem
openssl crl -in work/delta.crl.pem -outform DER -out ca_delta.crl
# CRL 4: with an issuingDistributionPoint (onlyContainsUserCerts, the leaves' CRL DP).
c ca -config work/ca.cnf -cert ca.pem -keyfile ca.key -gencrl -crlexts crl_idp_ext -out work/idp.crl.pem
openssl crl -in work/idp.crl.pem -outform DER -out ca_idp.crl
# Root CRLs: ca2 revoked (cessationOfOperation).
printf 'R\t351231235959Z\t%s,cessationOfOperation\t1002\tunknown\t/CN=Revocation CA 2\n' \
    "$(date -u +%y%m%d%H%M%SZ)" > work/rindex.txt
echo 01 > work/rcrlnumber
sed -e 's#work/index.txt#work/rindex.txt#' -e 's#work/crlnumber#work/rcrlnumber#' work/ca.cnf > work/root.cnf
c ca -config work/root.cnf -cert root.pem -keyfile root.key -gencrl -crlexts crl_ext -out work/root.crl.pem
openssl crl -in work/root.crl.pem -outform DER -out root.crl

# OCSP responses (7 days).
ocsp_req() { openssl ocsp -issuer ca.pem -cert "$1.pem" -reqout "work/$1.req" "${@:2}" >/dev/null 2>&1; }
ocsp_resp() { # out req signer-cert signer-key [extra]
    local out=$1 req=$2 sc=$3 sk=$4
    shift 4
    openssl ocsp -index work/index.txt -CA ca.pem -rsigner "$sc" -rkey "$sk" -reqin "work/$req.req" \
        -respout "$out" "$@" >/dev/null 2>&1
}
ocsp_req good -no_nonce
ocsp_req revoked -no_nonce
ocsp_req hold -no_nonce
ocsp_req unlisted -no_nonce
openssl ocsp -issuer ca.pem -cert good.pem -reqout work/good_nonce.req -nonce >/dev/null 2>&1
openssl ocsp -sha256 -issuer ca.pem -cert good.pem -reqout work/good_sha256.req -no_nonce >/dev/null 2>&1
openssl ocsp -issuer ca.pem -cert good.pem -cert revoked.pem -reqout work/multi.req -no_nonce >/dev/null 2>&1
cp work/good_nonce.req ocsp_good_nonce_req.der
ocsp_resp ocsp_good_delegated.der good responder.pem responder.key -ndays 7
ocsp_resp ocsp_good_by_ca.der good ca.pem ca.key -ndays 7
ocsp_resp ocsp_good_by_key.der good responder.pem responder.key -ndays 7 -resp_key_id
ocsp_resp ocsp_good_no_next.der good responder.pem responder.key
ocsp_resp ocsp_good_nonce.der good_nonce responder.pem responder.key -ndays 7
ocsp_resp ocsp_good_sha256.der good_sha256 responder.pem responder.key -ndays 7
ocsp_resp ocsp_revoked.der revoked responder.pem responder.key -ndays 7
ocsp_resp ocsp_hold.der hold responder.pem responder.key -ndays 7
ocsp_resp ocsp_unknown.der unlisted responder.pem responder.key -ndays 7
ocsp_resp ocsp_multi.der multi responder.pem responder.key -ndays 7
ocsp_resp ocsp_rogue.der good rogue.pem rogue.key -ndays 7
ocsp_resp ocsp_outsider.der good outsider.pem outsider.key -ndays 7
openssl ocsp -index work/index.txt -CA ca.pem -rsigner responder.pem -rkey responder.key -resp_no_certs \
    -reqin work/good.req -respout ocsp_good_no_certs.der -ndays 7 >/dev/null 2>&1
# Sanity: OpenSSL's own view.
openssl ocsp -respin ocsp_good_delegated.der -issuer ca.pem -CAfile root.pem -cert good.pem -no_nonce 2>&1 | head -3
openssl crl -in ca.crl -inform DER -noout -text | head -30
rm -rf work
