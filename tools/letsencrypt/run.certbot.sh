#!/bin/sh

if [ -z "$1" ] ; then
	DOMAIN="example.com"
else
	DOMAIN="$1"
fi
TDOMAIN=$( echo $DOMAIN | tr '.' '-' | tr 'A-Z' 'a-z' )

PATH=${PATH}:/usr/local/bin
export PATH

t-zap ${TDOMAIN}

certbot certonly --manual --manual-public-ip-logging-ok \
        --preferred-challenges=dns --manual-auth-hook=/root/certbot/hook.sh \
	-d ${DOMAIN} -d '*.'${DOMAIN}
