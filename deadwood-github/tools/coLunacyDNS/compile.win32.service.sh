#!/bin/sh

if [ ! -e /mingw ] ; then
	echo Only run this in Mingw
	exit 1
fi

# No symlinks
rm -f lauxlib.h lua.h luaconf.h lualib.h

for a in lauxlib.h lua.h luaconf.h lualib.h ; do
	cp ../../lunacy/$a .
done

cd ../../lunacy/
make
cd ../tools/mmLunacyDNS/
gcc -Os -DMINGW -c -o coLunacyDNS.o coLunacyDNS.c
gcc -Os -o coLunacyDNS coLunacyDNS.o ../../lunacy/liblua.a -lm -lwsock32
