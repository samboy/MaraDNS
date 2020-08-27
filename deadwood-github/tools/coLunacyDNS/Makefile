# To use another CC, invoke as "make CC=clang" or some such
CC = gcc
# To use other flags, invoke as "make CFLAGS=-g" or some such
CFLAGS = -O3

all: coLunacyDNS HalfSipHash1-3 

clean: 
	rm -f *.o *.exe coLunacyDNS sipHash HalfSipHash1-3 \
    *.gcda *.gcno *.gcov ; \
    cd ../../lunacy ; make clean

../../lunacy/liblua.a:
	cd ../../lunacy ; make CC="${CC}" CFLAGS="${CFLAGS}" ; \
    cd ../tools/coLunacyDNS

coLunacyDNS.o: coLunacyDNS.c
	${CC} ${CFLAGS} -c -Wall -o coLunacyDNS.o coLunacyDNS.c 	

coLunacyDNS: coLunacyDNS.o ../../lunacy/liblua.a
	rm -f ../../lunacy/lua.o ../../lunacy/luac.o ; \
    ${CC} ${CFLAGS} -Wall -o coLunacyDNS coLunacyDNS.o \
    ../../lunacy/*.o -lm

HalfSipHash1-3.o: HalfSipHash1-3.c 
	${CC} ${CFLAGS} -c -Wall -o  HalfSipHash1-3.o HalfSipHash1-3.c

HalfSipHash1-3: HalfSipHash1-3.o ../../lunacy/liblua.a
	${CC} ${CFLAGS} -Wall -o HalfSipHash1-3 HalfSipHash1-3.o \
    ../../lunacy/liblua.a -lm
