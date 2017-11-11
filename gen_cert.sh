#!/bin/sh

openssl req -x509 -newkey rsa:2048 -nodes -keyout server-key.pem -out server-cert.pem -config openssl.cnf
