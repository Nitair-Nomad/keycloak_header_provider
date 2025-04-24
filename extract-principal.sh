#!/bin/bash
CERT_FILE=$(mktemp)
trap "rm -f $CERT_FILE" EXIT

cat > "$CERT_FILE"

PRINCIPAL=$(openssl x509 -in "$CERT_FILE" -noout -text |
    grep -A1 "Subject Alternative Name" |
    grep -oP 'Principal Name=\K[^,\s]+')

if [[ -n "$PRINCIPAL" ]]; then
    echo "X-Principal-Name: $PRINCIPAL"
fi
