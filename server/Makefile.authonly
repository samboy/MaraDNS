SOBJECTS=MaraBigHash.o timestamp.o read_kvars.o MaraAnyChain.o udpsuccess.o
JOBJS=../libs/JsStr.o ../libs/JsStrOS.o ../libs/JsStrCP.o 
MHOBJS=../libs/MaraHash.o
MJOBJS=../qual/qual_timestamp.o
POBJ6=../parse/Csv2_rr_wks.o
POBJ5=../parse/Csv2_database.o ../parse/Csv2_rr_txt.o ../parse/Csv2_esc_txt.o
POBJ3=../parse/Csv2_rr_soa.o ../parse/Csv2_rr_aaaa.o ../parse/Csv2_rr_a.o
POBJ2=../parse/Csv2_read.o ../parse/Csv2_main.o ../parse/Csv2_parse.o $(POBJ3)
POBJ4=../parse/ParseIpAcl.o ../parse/Parse_ipv6.o $(POBJ2) $(POBJ6)
POBJECTS=../parse/ParseMaraRc.o ../parse/ParseCsv1.o $(POBJ4) $(POBJ5)
DOBJECTS=../dns/Queries.o ../dns/Compress.o ../dns/bobbit.o ../dns/Decompress.o
ROBJECTS=../rng/rng-api-fst.o ../rng/rng-alg-fst.o
OBJECTS=$(JOBJS) $(MHOBJS) $(MJOBJS) $(SOBJECTS) $(DOBJECTS) $(POBJECTS) $(ROBJECTS)
EXECS=maradns

FLAGS = -DAUTHONLY

all: $(EXECS)

clean:
	rm -f $(SOBJECTS) recursive.o core $(EXECS) simple maradns *.exe

libs/tests:
	cd libs ; make

read_kvars.o: read_kvars.c ../libs/JsStr.h ../libs/MaraHash.h ../MaraDns.h
	$(CC) -c $(FLAGS) -o read_kvars.o read_kvars.c

MaraBigHash.o: MaraBigHash.c ../libs/JsStr.h ../libs/MaraHash.h ../MaraDns.h MaraBigHash_locale.h
	$(CC) -c $(FLAGS) -o MaraBigHash.o MaraBigHash.c 

timestamp.o: timestamp.c MaraDNS_locale.h
	$(CC) -c $(FLAGS) -o timestamp.o timestamp.c

MaraAnyChain.o: MaraAnyChain.c
	$(CC) -c $(FLAGS) -o MaraAnyChain.o MaraAnyChain.c

udpsuccess.o: udpsuccess.c
	$(CC) -c $(FLAGS) -o udpsuccess.o udpsuccess.c

maradns: MaraDNS.c $(OBJECTS) MaraDNS_locale.h
	$(CC) $(FLAGS) -DVERSION=\"$(VERSION)\" -DCOMPILED=\"$(COMPILED)\" -o maradns MaraDNS.c $(OBJECTS) 

simple: MaraDNS.c $(OBJECTS) MaraDNS_locale.h
	$(CC) $(FLAGS) -DVERSION=\"$(VERSION)\" -DCOMPILED=\"$(COMPILED)\" -o simple simple.c $(OBJECTS) 

