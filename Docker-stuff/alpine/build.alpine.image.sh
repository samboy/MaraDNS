#!/bin/sh

# Build an alpine image which can test MaraDNS

cp ../rg32hash.tar.gz .
cp ../maramake-2022-11-01.tar.gz .
cp ../run.tests.sh .
docker build -t alpine-$( date +%Y-%m-%d ) .
rm -f rg32hash.tar.gz run.tests.sh maramake-2022-11-01.tar.gz

# Work in progress: We still need to add the testing scripts, etc.
