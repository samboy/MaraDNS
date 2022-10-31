ROBJECTS=../../rng/rngalgfst.o ../../rng/rngapifst.o
EXECS=marahash mqhash rg32hash

FLAGS = -g
#FLAGS = -g

all: $(EXECS)

clean:
	rm -f core $(EXECS)

marahash: $(ROBJECTS) rnghash.c
	$(CC) $(FLAGS) -o marahash rnghash.c $(ROBJECTS) 

mqhash: $(ROBJECTS) mqhash.c
	$(CC) $(FLAGS) -o mqhash mqhash.c $(ROBJECTS) 

rg32hash: rg32hash.c
	$(CC) $(FLAGS) -o rg32hash rg32hash.c

