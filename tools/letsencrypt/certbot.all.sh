#!/bin/sh

PATH=$PATH:/root/certbot
export PATH

for a in example.org example.com \
	example.net ; do
		ps auxw | grep certbot | grep -v grep | grep -v all | awk '
			{print "kill " $2}' | sh
		sleep 5
		run.certbot.sh $a
		echo DOMAIN $a updated
done
