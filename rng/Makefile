# Written because some makes (such as NetBSD's make) do not like the Makefile
# the original Rijndael code came with.

ROBJECTS=rngalgfst.o rngapifst.o
OBJECTS=$(ROBJECTS)
TABLES=rng32bittables.h

# If cross-compiling, change the next line
HOSTCC=$(CC)

#FLAGS = -g -Wall
#FLAGS = -g

all: $(ROBJECTS) 

# We don't delete the tables so that people compiling to embedded systems
# don't have to deal with a special CC to make the tables.
clean:
	rm -f $(ROBJECTS) core make_32bit_tables *.exe

superclean:
	rm -f $(ROBJECTS) core make_32bit_tables $(TABLES)

rngalgfst.o: rngalgfst.c rngalgfst.h $(TABLES)
	$(CC) -c $(FLAGS) -o rngalgfst.o rngalgfst.c

rngapifst.o: rngalgfst.o rngapifst.h 
	$(CC) -c $(FLAGS) -o rngapifst.o rngapifst.c

make_32bit_tables: make_32bit_tables.c
	$(HOSTCC) -o make_32bit_tables make_32bit_tables.c

rng32bittables.h: make_32bit_tables
	./make_32bit_tables > rng-32bit-tables.h ; \
    ./make_32bit_tables > rng32bittables.h

