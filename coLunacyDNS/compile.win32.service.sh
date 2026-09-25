#!/bin/sh

if [ ! -e /mingw ] ; then
	echo Only run this in Mingw
	exit 1
fi

# No symlinks
rm -f lauxlib.h lua.h luaconf.h lualib.h

for a in lauxlib.h lua.h luaconf.h lualib.h ; do
	cp lunacy/$a .
done

cd lunacy/
export CC="gcc"
make -f Makefile
cd ..
echo $CC -std=c99 -Wall -O3 -DMINGW -c -o coLunacyDNS.o coLunacyDNS.c
$CC -std=c99 -Wall -O3 -DMINGW -c -o coLunacyDNS.o coLunacyDNS.c
$CC -std=c99 -O3 -o coLunacyDNS.exe coLunacyDNS.o lunacy/liblua.a -lm -lwsock32
