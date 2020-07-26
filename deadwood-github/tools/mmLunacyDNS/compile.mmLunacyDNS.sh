#!/bin/sh

# With only one file, I will not bother with a Makefile

cd ../../lunacy/
make 
cd ../tools/mmLunacyDNS/
gcc -Os -c -o mmLunacyDNS.o mmLunacyDNS.c
gcc -Os -o mmLunacyDNS mmLunacyDNS.o ../../lunacy/liblua.a -lm
