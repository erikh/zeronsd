#!/bin/bash

set -xeou pipefail

HOSTNAME="zt-$(sudo zerotier-cli info | awk '{ print $3 }').home.arpa"

openssl genrsa -out test-ca.key 2048
openssl req -x509 -new -subj "/C=US/ST=California/L=Irvine/OU=A Test Suite/O=Zerotier" -nodes -key test-ca.key -sha512 -days 365 -out test-ca.pem
openssl genrsa -out test-key.pem 2048
openssl req -new -addext "subjectAltName = DNS:${HOSTNAME}" -subj "/C=US/ST=California/L=Irvine/OU=A Test Suite/O=Zerotier/CN=${HOSTNAME}" -key test-key.pem -nodes -out test-cert.csr -sha512
openssl x509 -req -in test-cert.csr -CA test-ca.pem -CAkey test-ca.key -CAcreateserial -out test-cert.pem -sha512 -days 365 -extfile /dev/null

sudo cp test-ca.pem /usr/local/share/ca-certificates/zeronsd-test-ca.crt
sudo cp test-cert.pem /usr/local/share/ca-certificates/zeronsd-test-cert.crt
sudo grep -q zeronsd-test-ca /etc/ca-certificates.conf || (echo zeronsd-test-ca | sudo tee -a /etc/ca-certificates.conf)
sudo grep -q zeronsd-test-cert /etc/ca-certificates.conf || (echo zeronsd-test-cert | sudo tee -a /etc/ca-certificates.conf)
sudo update-ca-certificates -f
