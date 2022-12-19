all: maradns.8 mararc.5 askmara.1 getzone.1 zoneserver.8 csv1.5 duende.8 \
	csv2.5 csv2_txt.5 fetchzone.1 mqhash.1 Deadwood.1 coLunacyDNS.1 \
	blockHashMake.1

clean:
	rm -f maradns.8 mararc.5 askmara.1 getzone.1 zoneserver.8 csv1.5 \
	maradns.ps mararc.ps askmara.ps getzone.ps zoneserver.ps csv1.ps \
	csv2.5 csv2_txt.5 Deadwood.1 coLunacyDNS.1 blockHashMake.1

blockHashMake.1: ../source/blockHashMake.ej
	../../../tools/ej/ej2man ../source/blockHashMake.ej > blockHashMake.1

Deadwood.1: ../source/Deadwood.ej
	../../../tools/ej/ej2man ../source/Deadwood.ej > Deadwood.1

coLunacyDNS.1: ../source/coLunacyDNS.ej
	../../../tools/ej/ej2man ../source/coLunacyDNS.ej > coLunacyDNS.1

duende.8: ../source/duende.ej 
	../../../tools/ej/ej2man ../source/duende.ej > duende.8

maradns.8: ../source/maradns.ej ../source/faq.embed ../source/credits.embed
	../../../tools/ej/ej2man ../source/maradns.ej > maradns.8

mararc.5: ../source/mararc.ej ../source/example_mararc
	../../../tools/ej/ej2man ../source/mararc.ej > mararc.5

askmara.1: ../source/askmara.ej
	../../../tools/ej/ej2man ../source/askmara.ej > askmara.1

getzone.1: ../source/getzone.ej
	../../../tools/ej/ej2man ../source/getzone.ej > getzone.1

fetchzone.1: ../source/fetchzone.ej
	../../../tools/ej/ej2man ../source/fetchzone.ej > fetchzone.1

zoneserver.8: ../source/zoneserver.ej
	../../../tools/ej/ej2man ../source/zoneserver.ej > zoneserver.8

csv1.5: ../source/csv1.ej ../examples/example_csv1
	../../../tools/ej/ej2man ../source/csv1.ej > csv1.5

csv2.5: ../source/csv2.ej ../examples/example_csv2
	../../../tools/ej/ej2man ../source/csv2.ej > csv2.5

csv2_txt.5: ../source/csv2_txt.ej 
	../../../tools/ej/ej2man ../source/csv2_txt.ej > csv2_txt.5

mqhash.1: ../source/mqhash.ej
	../../../tools/ej/ej2man ../source/mqhash.ej > mqhash.1

