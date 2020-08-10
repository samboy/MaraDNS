#!/bin/sh

# This makes a Docker/Podman image where we run the tests.  This
# image does not have to be frequently updated; it has stable
# versions of all the programs the MaraDNS automated tests use
# during testing, but MaraDNS itself is pulled from GitHub in
# the image to run the actual tests.

## CENTOS 8 NOTE ##
# Add these lines to /etc/security/limits.conf (without hashtag) so this
# works
#*       soft    nofile  131072
#*       hard    nofile  131072
#*       soft    nproc   131072
#*       hard    nproc   131072

docker build -t maradns-$( date +%Y-%m-%d ) .
