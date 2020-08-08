#!/bin/sh

# With only one file, I will not bother with a Makefile

cd ../../lunacy/
make 
cd ../tools/coLunacyDNS/
FLAGS=-Os
gcc $FLAGS -c -o coLunacyDNS.o coLunacyDNS.c
gcc $FLAGS -o coLunacyDNS coLunacyDNS.o ../../lunacy/liblua.a -lm
gcc $FLAGS -c -o sipHash.o sipHash.c
gcc $FLAGS -o sipHash sipHash.o ../../lunacy/liblua.a -lm
