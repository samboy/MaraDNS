# To use other flags, invoke as "make CFLAGS=-g" or some such
CFLAGS = -O3

all: coLunacyDNS HalfSipHash13 

clean: 
	rm -f *.o *.exe coLunacyDNS sipHash HalfSipHash1-3 \
    HalfSipHash13 *.gcda *.gcno *.gcov liblua.a ; \
    cd lunacy ; make clean

liblua.a:
	cd lunacy ; make CC="${CC}" CFLAGS="${CFLAGS}" ; \
    cp liblua.a .. ; cd ..

coLunacyDNS.o: coLunacyDNS.c
	${CC} ${CFLAGS} -c -Wall -o coLunacyDNS.o coLunacyDNS.c 	

coLunacyDNS: coLunacyDNS.o liblua.a
	rm -f lunacy/lua.o lunacy/luac.o ; \
    ${CC} ${CFLAGS} -Wall -o coLunacyDNS coLunacyDNS.o \
    lunacy/*.o -lm

HalfSipHash13.o: HalfSipHash13.c 
	${CC} ${CFLAGS} -c -Wall -o  HalfSipHash13.o HalfSipHash13.c

HalfSipHash13: HalfSipHash13.o liblua.a
	${CC} ${CFLAGS} -Wall -o HalfSipHash1-3 HalfSipHash13.o \
    lunacy/liblua.a -lm ; \
    ${CC} ${CFLAGS} -Wall -o HalfSipHash13 HalfSipHash13.o lunacy/liblua.a -lm
