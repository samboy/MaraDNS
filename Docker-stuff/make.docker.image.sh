#!/bin/sh

## CENTOS 8 NOTE ##
# Add these lines to /etc/security/limits.conf (without hashtag) so this
# works
#*       soft    nofile  131072
#*       hard    nofile  131072
#*       soft    nproc   131072
#*       hard    nproc   131072

docker build -t maradns-$( date +%Y-%m-%d ) .
