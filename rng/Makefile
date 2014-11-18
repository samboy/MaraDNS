# Written because some makes (such as NetBSD's make) do not like the Makefile
# the original Rijndael code came with.

ROBJECTS=rng-alg-fst.o rng-api-fst.o
OBJECTS=$(ROBJECTS)
TABLES=rng-32bit-tables.h

#FLAGS = -g -Wall
#FLAGS = -g

all: $(ROBJECTS) 

# We don't delete the tables so that people compiling to embedded systems
# don't have to deal with a special CC to make the tables.
clean:
	rm -f $(ROBJECTS) core make_32bit_tables *.exe

superclean:
	rm -f $(ROBJECTS) core make_32bit_tables $(TABLES)

rng-alg-fst.o: rng-alg-fst.c rng-alg-fst.h $(TABLES)
	$(CC) -c $(FLAGS) -o rng-alg-fst.o rng-alg-fst.c

rng-api-fst.o: rng-alg-fst.o rng-api-fst.h 
	$(CC) -c $(FLAGS) -o rng-api-fst.o rng-api-fst.c

make_32bit_tables: make_32bit_tables.c
	$(CC) -o make_32bit_tables make_32bit_tables.c

rng-32bit-tables.h: make_32bit_tables
	./make_32bit_tables > rng-32bit-tables.h

