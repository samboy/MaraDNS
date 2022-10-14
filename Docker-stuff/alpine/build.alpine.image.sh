#!/bin/sh

# Build an alpine image which can test MaraDNS

cp ../rg32hash.tar.gz .
cp ../run.tests.sh .
docker build -t alpine-$( date +%Y-%m-%d ) .
rm -f rg32hash.tar.gz run.tests.sh

# Work in progress: We still need to add the testing scripts, etc.
