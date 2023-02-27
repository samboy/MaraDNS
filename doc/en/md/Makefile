all: maradns.md mararc.md askmara.md getzone.md zoneserver.md \
	csv1.md duende.md \
	csv2.md csv2_txt.md fetchzone.md mqhash.md Deadwood.md \
	coLunacyDNS.md \
	blockHashMake.md blockHashRead.md

clean:
	rm -f *md

blockHashRead.md: ../source/blockHashRead.ej
	../../../tools/ej/ej2md ../source/blockHashRead.ej > blockHashRead.md

blockHashMake.md: ../source/blockHashMake.ej
	../../../tools/ej/ej2md ../source/blockHashMake.ej > blockHashMake.md

Deadwood.md: ../source/Deadwood.ej
	../../../tools/ej/ej2md ../source/Deadwood.ej > Deadwood.md

coLunacyDNS.md: ../source/coLunacyDNS.ej
	../../../tools/ej/ej2md ../source/coLunacyDNS.ej > coLunacyDNS.md

duende.md: ../source/duende.ej 
	../../../tools/ej/ej2md ../source/duende.ej > duende.md

maradns.md: ../source/maradns.ej ../source/faq.embed ../source/credits.embed
	../../../tools/ej/ej2md ../source/maradns.ej > maradns.md

mararc.md: ../source/mararc.ej ../source/example_mararc
	../../../tools/ej/ej2md ../source/mararc.ej > mararc.md

askmara.md: ../source/askmara.ej
	../../../tools/ej/ej2md ../source/askmara.ej > askmara.md

getzone.md: ../source/getzone.ej
	../../../tools/ej/ej2md ../source/getzone.ej > getzone.md

fetchzone.md: ../source/fetchzone.ej
	../../../tools/ej/ej2md ../source/fetchzone.ej > fetchzone.md

zoneserver.md: ../source/zoneserver.ej
	../../../tools/ej/ej2md ../source/zoneserver.ej > zoneserver.md

csv1.md: ../source/csv1.ej ../examples/example_csv1
	../../../tools/ej/ej2md ../source/csv1.ej > csv1.md

csv2.md: ../source/csv2.ej ../examples/example_csv2
	../../../tools/ej/ej2md ../source/csv2.ej > csv2.md

csv2_txt.md: ../source/csv2_txt.ej 
	../../../tools/ej/ej2md ../source/csv2_txt.ej > csv2_txt.md

mqhash.md: ../source/mqhash.ej
	../../../tools/ej/ej2md ../source/mqhash.ej > mqhash.md

