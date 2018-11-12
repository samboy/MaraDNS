JOBJS=../libs/JsStr.o ../libs/JsStrOS.o ../libs/JsStrCP.o 
MJOBJS=../qual/qual_timestamp.o
MHOBJS=../libs/MaraHash.o
DOBJECTS=../dns/Queries.o ../dns/Compress.o ../dns/bobbit.o ../dns/Decompress.o
POBJ6=../parse/Csv2_rr_wks.o
POBJ5=../parse/Csv2_database.o ../parse/Csv2_rr_txt.o ../parse/Csv2_esc_txt.o
POBJ3=../parse/Csv2_rr_soa.o ../parse/Csv2_rr_aaaa.o ../parse/Csv2_rr_a.o
POBJ2=../parse/Csv2_read.o ../parse/Csv2_main.o ../parse/Csv2_parse.o $(POBJ3)
POBJ4=../parse/ParseIpAcl.o ../parse/Parse_ipv6.o $(POBJ2) $(POBJ6)
POBJECTS=../parse/ParseMaraRc.o ../parse/ParseCsv1.o $(POBJ4) $(POBJ5)
OBJECTS=../parse/ParseCsv1.o ../parse/ParseMaraRc.o ../parse/ParseIpAcl.o
SOBJECTS=../server/timestamp.o ../server/MaraBigHash.o ../server/read_kvars.o \
	 ../server/MaraAnyChain.o
RNGOBJS=../rng/rng-api-fst.o ../rng/rng-alg-fst.o
TCPOBJS=libtcp.o
OBJECTS=$(JOBJS) $(MHOBJS) $(MJOBJS) $(DOBJECTS) $(POBJECTS) $(SOBJECTS) \
	$(TCPOBJS)
EXECS=getzone zoneserver fetchzone

FLAGS = -DAUTHONLY

all: $(EXECS)

clean:
	rm -f core $(EXECS) $(TCPOBJS) *.exe

getzone: getzone.c $(OBJECTS) 
	$(CC) $(FLAGS) -o getzone getzone.c $(OBJECTS)

fetchzone: fetchzone.c $(OBJECTS) 
	$(CC) $(FLAGS) -o fetchzone fetchzone.c $(OBJECTS) 

zoneserver: zoneserver.c zoneserver_en.h $(OBJECTS)
	$(CC) $(FLAGS) -DVERSION=\"$(VERSION)\" -o zoneserver zoneserver.c $(OBJECTS) $(RNGOBJS)

