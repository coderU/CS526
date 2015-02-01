#!/bin/sh

openssl genrsa -out proj3.pri 1024
openssl rsa -in proj3.pri -pubout > proj3.pub
openssl enc -aes-256-cbc -k secret -P -md sha1
