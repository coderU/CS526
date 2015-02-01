#!/bin/sh

openssl genrsa -out proj3.pri 1024
openssl rsa -in proj3.pri -pubout > proj3.pub
openssl rand -out proj3.symm 20
