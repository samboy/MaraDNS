#!/bin/sh

# This is run with run.certbot.sh

PATH=${PATH}:/usr/local/bin
export PATH
DOMAIN=${CERTBOT_DOMAIN}
DOMAIN=$( echo $DOMAIN | tr '.' '-' | tr 'A-Z' 'a-z' )

t-add $DOMAIN ${CERTBOT_VALIDATION}
service maradns restart
echo MaraDNS should have restarted
echo Record should be ${CERTBOT_VALIDATION}
askmara T_acme-challenge.${CERTBOT_DOMAIN}. 8.8.8.8
