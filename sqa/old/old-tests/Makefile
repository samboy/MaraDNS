JOBJS=../libs/JsStr.o ../libs/JsStrOS.o ../libs/JsStrCP.o 
MHOBJS=../libs/MaraHash.o
DOBJECTS=../dns/Queries.o ../dns/Compress.o ../dns/bobbit.o \
         ../dns/Decompress.o ../server/timestamp.o
POBJECTS=../parse/ParseMaraRc.o ../parse/ParseCsv1.o ../parse/ParseIpAcl.o
ROBJECTS=../rng/rng-alg-fst.o ../rng/rng-api-fst.o
OBJECTS=$(JOBJS) $(MHOBJS) $(DOBJECTS) $(POBJECTS)
EXECS=rtest csv1test compress.test show.charnum ipacltest rngtest cst \
      timestamp compress_new.test test_zoneserver test_getzone duende-test 

FLAGS = -g $(DEBUG)
#FLAGS = -g $(DEBUG)

all: $(EXECS)

clean:
	rm -f core $(EXECS) 

libs/tests:
	cd libs ; make

duende-test: duende-test.c
	$(CC) $(FLAGS) -o duende-test duende-test.c -lpthread

rngtest: rngtest.c $(ROBJECTS)
	$(CC) $(FLAGS) -o rngtest rngtest.c $(ROBJECTS)

rtest: rtest.c $(OBJECTS)
	$(CC) $(FLAGS) -o rtest rtest.c $(OBJECTS)

csv1test: csv1test.c $(OBJECTS) 
	$(CC) $(FLAGS) -o csv1test csv1test.c $(OBJECTS)

compress.test: compress.test.c $(OBJECTS)
	$(CC) $(FLAGS) -o compress.test compress.test.c $(OBJECTS)

compress_new.test: compress_new.test.c $(OBJECTS)
	$(CC) $(FLAGS) -o compress_new.test compress_new.test.c $(OBJECTS)

show.charnum: show.charnum.c 
	$(CC) $(FLAGS) -o show.charnum show.charnum.c 

ipacltest: ipacltest.c $(OBJECTS)
	$(CC) $(FLAGS) -o ipacltest ipacltest.c $(OBJECTS)

cst: cst.c $(OBJECTS)
	$(CC) $(FLAGS) -o cst cst.c $(OBJECTS)

timestamp: timestamp.c $(OBJECTS)
	$(CC) $(FLAGS) -o timestamp timestamp.c $(OBJECTS)

test_zoneserver: test_zoneserver.c $(OBJECTS)
	$(CC) $(FLAGS) -o test_zoneserver test_zoneserver.c $(OBJECTS)

test_getzone: test_getzone.c $(OBJECTS)
	$(CC) $(FLAGS) -o test_getzone test_getzone.c $(OBJECTS)

