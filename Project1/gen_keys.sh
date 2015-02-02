#!/bin/sh
# generate u's certificate pub and pri
openssl genrsa -out SALSCFu.pri 1024
openssl rsa -in SALSCFu.pri -pubout > SALSCFu.pub
openssl req -new -x509 -key SALSCFu.pri -out SALSCFu.pem -days 1095

# generate v's certificate pub and pri
openssl genrsa -out SALSCFt.pri 1024
openssl rsa -in SALSCFt.pri -pubout > SALSCFt.pub

# generate aes key
openssl rand 128 > key1.bin
openssl rand 128 > key2.bin
cat key1.bin key2.bin >> SALSCF.symm
rm key1.bin key2.bin
