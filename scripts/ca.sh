#!/usr/bin/env bash
# The offline parts of docs/operations.md: the private CA that signs the
# client certificates reviewers and operators present to admin.DOMAIN, the
# certificates themselves, their SHA-256 for the principals table, and the
# truststore API Gateway pins. Nothing here talks to AWS. The CA directory
# holds private keys: keep it off any machine that is not the operator's.
#
#   scripts/ca.sh init <ca dir> [name]                 create the CA (ca.key, ca.pem, truststore/ca.pem)
#   scripts/ca.sh issue <ca dir> <principal> [days]    issue a client certificate under clients/<principal>/
#   scripts/ca.sh fingerprint <certificate.pem>        the SHA-256 the principals table stores
#   scripts/ca.sh truststore <ca dir>                  rebuild truststore/ca.pem from ca.pem and ca-next.pem
#   scripts/ca.sh rotate <ca dir> [name]               start a rotation: new CA as ca-next, truststore with both
#   scripts/ca.sh retire <ca dir>                      finish it: ca-next becomes ca, truststore with the new one only
set -euo pipefail

usage() { sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }

ca_key() {
    # P-256 in PKCS#8: what openssl writes by default and what rustls reads.
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1"
    chmod 600 "$1"
}

ca_cert() { # key cert name
    openssl req -x509 -new -key "$1" -sha256 -days 3650 -subj "/CN=$3" -out "$2" \
        -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" \
        -addext "subjectKeyIdentifier=hash"
}

build_truststore() { # ca dir
    mkdir -p "$1/truststore"
    cat "$1/ca.pem" > "$1/truststore/ca.pem"
    [ -f "$1/ca-next.pem" ] && cat "$1/ca-next.pem" >> "$1/truststore/ca.pem"
    echo "truststore: $1/truststore/ca.pem ($(grep -c 'BEGIN CERTIFICATE' "$1/truststore/ca.pem") certificate(s))"
}

fingerprint() { # certificate.pem -> lowercase hex SHA-256 of the DER, no colons
    openssl x509 -in "$1" -outform DER | openssl dgst -sha256 -r | cut -d' ' -f1
}

cmd=${1:-}; shift || true
case "$cmd" in
    init)
        dir=${1:?ca dir}; name=${2:-AXLR registry CA}
        [ -e "$dir/ca.key" ] && { echo "$dir/ca.key exists; refusing to overwrite a CA" >&2; exit 1; }
        mkdir -p "$dir/clients"; chmod 700 "$dir"
        ca_key "$dir/ca.key"
        ca_cert "$dir/ca.key" "$dir/ca.pem" "$name"
        echo 1000 > "$dir/serial"
        build_truststore "$dir"
        echo "CA: $dir/ca.pem (key in $dir/ca.key, never uploaded)"
        ;;
    issue)
        dir=${1:?ca dir}; principal=${2:?principal id}; days=${3:-365}
        [[ "$principal" =~ ^[a-z0-9][a-z0-9._-]{0,63}$ ]] || { echo "principal: lowercase letters, digits, . _ -" >&2; exit 1; }
        out="$dir/clients/$principal"
        [ -e "$out/key.pem" ] && { echo "$out exists; issue under a new id or move the old one away" >&2; exit 1; }
        mkdir -p "$out"
        # Sign with the newest CA so the certificate survives a rotation in progress.
        signer=ca; [ -f "$dir/ca-next.pem" ] && signer=ca-next
        ca_key "$out/key.pem"
        openssl req -new -key "$out/key.pem" -subj "/CN=$principal" -out "$out/request.csr"
        openssl x509 -req -in "$out/request.csr" -CA "$dir/$signer.pem" -CAkey "$dir/$signer.key" \
            -CAserial "$dir/serial" -sha256 -days "$days" -out "$out/cert.pem" \
            -extfile <(printf 'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n') 2>/dev/null
        rm -f "$out/request.csr"
        # cert then key, the file reqwest's Identity::from_pem and the CLI's --cert read.
        cat "$out/cert.pem" "$out/key.pem" > "$out/identity.pem"; chmod 600 "$out/identity.pem"
        echo "certificate: $out/cert.pem (identity with key: $out/identity.pem)"
        echo "sha256: $(fingerprint "$out/cert.pem")"
        ;;
    fingerprint)
        fingerprint "${1:?certificate.pem}"
        ;;
    truststore)
        build_truststore "${1:?ca dir}"
        ;;
    rotate)
        dir=${1:?ca dir}; name=${2:-AXLR registry CA}
        [ -e "$dir/ca-next.key" ] && { echo "a rotation is in progress; retire it first" >&2; exit 1; }
        ca_key "$dir/ca-next.key"
        ca_cert "$dir/ca-next.key" "$dir/ca-next.pem" "$name"
        build_truststore "$dir"
        echo "new CA: $dir/ca-next.pem; upload the truststore, deploy, reissue every client, then retire"
        ;;
    retire)
        dir=${1:?ca dir}
        [ -f "$dir/ca-next.key" ] || { echo "no rotation in progress" >&2; exit 1; }
        mkdir -p "$dir/retired"
        stamp=$(date -u +%Y%m%dT%H%M%SZ)
        mv "$dir/ca.key" "$dir/retired/ca-$stamp.key"; mv "$dir/ca.pem" "$dir/retired/ca-$stamp.pem"
        mv "$dir/ca-next.key" "$dir/ca.key"; mv "$dir/ca-next.pem" "$dir/ca.pem"
        build_truststore "$dir"
        echo "old CA moved to $dir/retired/; upload the truststore and deploy, then delete the retired key"
        ;;
    *) usage ;;
esac
