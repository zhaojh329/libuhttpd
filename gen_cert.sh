#!/bin/sh

openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -subj "/C=CZ/O=Acme Inc./OU=ACME/CN=ACME-DEV-123"
