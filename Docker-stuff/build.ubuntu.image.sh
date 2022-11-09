#!/bin/sh

# This makes a Docker/Podman image where we run the tests.  This
# image does not have to be frequently updated; it has stable
# versions of all the programs the MaraDNS automated tests use
# during testing, but MaraDNS itself is pulled from GitHub in
# the image to run the actual tests.

docker build -t maradns-$( date +%Y-%m-%d ) .
