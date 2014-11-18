JOBJS=../libs/JsStr.o ../libs/JsStrOS.o ../libs/JsStrCP.o 
MHOBJS=../libs/MaraHash.o 
DOBJECTS=../dns/Queries.o ../dns/Compress.o ../dns/bobbit.o ../dns/Decompress.o 
POBJECTS=../parse/ParseMaraRc.o ../parse/ParseCsv1.o ../parse/ParseIpAcl.o
ROBJECTS=../rng/rng-api-fst.o ../rng/rng-alg-fst.o
SOBJECTS=../server/timestamp.o
OBJECTS=$(JOBJS) $(MHOBJS) $(DOBJECTS) $(ROBJECTS) $(POBJECTS) $(SOBJECTS)
EXECS=asktest qr.test aaaatest dead_host_simulate sendudp sendnoise

FLAGS = -g $(DEBUG)
#FLAGS = -g -DDEBUG

all: $(EXECS)

clean:
	rm -f core $(EXECS)

asktest: asktest.c ../tools/askmara_labels_en.h $(OBJECTS) 
	$(CC) $(FLAGS) -o asktest asktest.c $(OBJECTS) 

sendudp: sendudp.c ../tools/askmara_labels_en.h $(OBJECTS) 
	$(CC) $(FLAGS) -o sendudp sendudp.c $(OBJECTS) 

sendnoise: sendnoise.c ../tools/askmara_labels_en.h $(OBJECTS) 
	$(CC) $(FLAGS) -o sendnoise sendnoise.c $(OBJECTS) 

qr.test: qr.test.c ../tools/askmara_labels_en.h $(OBJECTS) 
	$(CC) $(FLAGS) -o qr.test qr.test.c $(OBJECTS) 

aaaatest: aaaatest.c ../tools/askmara_labels_en.h $(OBJECTS) 
	$(CC) $(FLAGS) -o aaaatest aaaatest.c $(OBJECTS) 

dead_host_simulate: dead_host_simulate.c $(OBJECTS) 
	$(CC) $(FLAGS) -o dead_host_simulate dead_host_simulate.c $(OBJECTS) 

