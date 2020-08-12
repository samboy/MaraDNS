#!/bin/sh

# With only one file, I will not bother with a Makefile

cd ../../lunacy/
make 
cd ../tools/coLunacyDNS/
FLAGS="-Os -Wall"
gcc $FLAGS -c -o coLunacyDNS.o coLunacyDNS.c
gcc $FLAGS -o coLunacyDNS coLunacyDNS.o ../../lunacy/liblua.a -lm
gcc $FLAGS -c -o HalfSipHash1-3.o halfSipHash1-3.c
gcc $FLAGS -o HalfSipHash1-3 HalfSipHash1-3.o ../../lunacy/liblua.a -lm
