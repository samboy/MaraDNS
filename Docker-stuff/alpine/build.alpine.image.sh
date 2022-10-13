#!/bin/sh

# Build an alpine image which can test MaraDNS

docker build -t alpine-$( date +%Y-%m-%d ) .

# Work in progress: We still need to add the testing scripts, etc.
