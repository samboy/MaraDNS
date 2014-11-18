JOBJS=../libs/JsStr.o ../libs/JsStrOS.o ../libs/JsStrCP.o 
MHOBJS=../libs/MaraHash.o
POBJ3=Csv2_rr_soa.o Csv2_database.o Csv2_rr_txt.o Csv2_rr_wks.o
POBJ2=Csv2_read.o Csv2_main.o Csv2_parse.o Csv2_rr_a.o Csv2_rr_aaaa.o $(POBJ3)
OUTOBJ=Csv2_esc_txt.o
POBJECTS=ParseMaraRc.o ParseCsv1.o ParseIpAcl.o Parse_ipv6.o $(POBJ2)
DOBJECTS=../dns/Queries.o ../dns/Compress.o ../dns/bobbit.o ../dns/Decompress.o
OBJECTS=$(JOBJS) $(MHOBJS) $(POBJECTS) $(DOBJECTS) $(OUTOBJ)
EXECS=parsetest parsetest2

#FLAGS = -g -Wall $(DEBUG)
#FLAGS = -g $(DEBUG)

all: $(POBJECTS) $(OUTOBJ)

clean:
	rm -f $(POBJECTS) core $(EXECS) $(OUTOBJ)

../libs/tests:
	cd libs ; make

ParseMaraRc.o: ParseMaraRc.c ../libs/JsStr.h ../libs/MaraHash.h ../MaraDns.h ParseMaraRc_en.h
	$(CC) -c $(FLAGS) -o ParseMaraRc.o ParseMaraRc.c 

ParseCsv1.o: ParseCsv1.c ../libs/JsStr.h ../libs/MaraHash.h ../MaraDns.h
	$(CC) -c $(FLAGS) -o ParseCsv1.o ParseCsv1.c 

ParseIpAcl.o: ParseIpAcl.c ../libs/JsStr.h ../libs/MaraHash.h ../MaraDns.h
	$(CC) -c $(FLAGS) -o ParseIpAcl.o ParseIpAcl.c

Parse_ipv6.o: Parse_ipv6.c ../libs/MaraHash.h
	$(CC) -c $(FLAGS) -o Parse_ipv6.o Parse_ipv6.c

Csv2_esc_txt.o: Csv2_esc_txt.c ../libs/JsStr.h
	$(CC) -c $(FLAGS) -o Csv2_esc_txt.o Csv2_esc_txt.c

Csv2_main.o: Csv2_main.c ../libs/JsStr.h Csv2_read.h
	$(CC) -c $(FLAGS) -o Csv2_main.o Csv2_main.c

Csv2_read.o: Csv2_read.c ../libs/JsStr.h Csv2_read.h
	$(CC) -c $(FLAGS) -o Csv2_read.o Csv2_read.c

Csv2_parse.o: Csv2_parse.c ../libs/JsStr.h Csv2_read.h
	$(CC) -c $(FLAGS) -o Csv2_parse.o Csv2_parse.c

Csv2_rr_aaaa.o: Csv2_rr_aaaa.c ../libs/JsStr.h Csv2_read.h
	$(CC) -c $(FLAGS) -o Csv2_rr_aaaa.o Csv2_rr_aaaa.c

Csv2_rr_wks.o: Csv2_rr_wks.c ../libs/JsStr.h Csv2_read.h
	$(CC) -c $(FLAGS) -o Csv2_rr_wks.o Csv2_rr_wks.c

Csv2_rr_a.o: Csv2_rr_a.c ../libs/JsStr.h Csv2_read.h
	$(CC) -c $(FLAGS) -o Csv2_rr_a.o Csv2_rr_a.c

Csv2_rr_soa.o: Csv2_rr_soa.c ../libs/JsStr.h Csv2_read.h
	$(CC) -c $(FLAGS) -o Csv2_rr_soa.o Csv2_rr_soa.c

Csv2_rr_txt.o: Csv2_rr_txt.c ../libs/JsStr.h Csv2_read.h
	$(CC) -c $(FLAGS) -o Csv2_rr_txt.o Csv2_rr_txt.c

Csv2_database.o: Csv2_database.c ../libs/JsStr.h Csv2_read.h
	$(CC) -c $(FLAGS) -o Csv2_database.o Csv2_database.c

parsetest: parsetest.c $(OBJECTS) 
	$(CC) $(FLAGS) -o parsetest parsetest.c $(OBJECTS) 

parsetest2: parsetest2.c $(OBJECTS) 
	$(CC) $(FLAGS) -o parsetest2 parsetest2.c $(OBJECTS) 

