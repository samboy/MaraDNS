all: tutorial.txt \
     authoritative.txt compile.txt convert.txt recursive.txt \
     glossary.txt recordtypes.txt dangling.txt default_zonefile.txt \
     dnstcp.txt man.duende.txt dnsmaster.txt man.csv2_txt.txt \
     man.csv2.txt dnsslave.txt update.txt man.askmara.txt \
     man.fetchzone.txt man.zoneserver.txt man.maradns.txt \
     man.mararc.txt quick_start.txt dnsintro.txt \
     win_service.txt troubleshoot.txt bind2csv2.txt coding_style.txt

clean:
	rm -f *.txt 

man.maradns.txt: ../source/maradns.ej ../source/faq.embed
	../../../tools/ej/ej2txt ../source/maradns.ej > man.maradns.txt

man.mararc.txt: ../source/mararc.ej
	../../../tools/ej/ej2txt ../source/mararc.ej > man.mararc.txt

man.fetchzone.txt: ../source/fetchzone.ej
	../../../tools/ej/ej2txt ../source/fetchzone.ej > \
	    man.fetchzone.txt

man.zoneserver.txt: ../source/zoneserver.ej
	../../../tools/ej/ej2txt ../source/zoneserver.ej > \
	    man.zoneserver.txt

man.askmara.txt: ../source/askmara.ej
	../../../tools/ej/ej2txt ../source/askmara.ej > man.askmara.txt

man.csv2.txt: ../source/csv2.ej
	../../../tools/ej/ej2txt ../source/csv2.ej > man.csv2.txt

man.csv2_txt.txt: ../source/csv2.ej
	../../../tools/ej/ej2txt ../source/csv2_txt.ej > man.csv2_txt.txt

man.duende.txt: ../source/duende.ej
	../../../tools/ej/ej2txt ../source/duende.ej > man.duende.txt

tutorial.txt: ../source/tutorial.ej
	../../../tools/ej/ej2txt ../source/tutorial.ej > tutorial.txt

authoritative.txt: ../source/authoritative.ej
	../../../tools/ej/ej2txt ../source/authoritative.ej > \
	    authoritative.txt

compile.txt: ../source/compile.ej
	../../../tools/ej/ej2txt ../source/compile.ej > compile.txt

convert.txt: ../source/convert.ej
	../../../tools/ej/ej2txt ../source/convert.ej > convert.txt

recursive.txt: ../source/recursive.ej
	../../../tools/ej/ej2txt ../source/recursive.ej > \
	  recursive.txt

glossary.txt: ../source/glossary.ej
	../../../tools/ej/ej2txt ../source/glossary.ej > \
	  glossary.txt

recordtypes.txt: ../source/recordtypes.ej
	../../../tools/ej/ej2txt ../source/recordtypes.ej > \
	  recordtypes.txt

dangling.txt: ../source/dangling.ej
	../../../tools/ej/ej2txt ../source/dangling.ej > \
	  dangling.txt

default_zonefile.txt: ../source/default_zonefile.ej
	../../../tools/ej/ej2txt ../source/default_zonefile.ej > \
	  default_zonefile.txt

dnstcp.txt: ../source/dnstcp.ej
	../../../tools/ej/ej2txt ../source/dnstcp.ej > \
	  dnstcp.txt

dnsmaster.txt: ../source/dnsmaster.ej
	../../../tools/ej/ej2txt ../source/dnsmaster.ej > \
	  dnsmaster.txt

dnsslave.txt: ../source/dnsslave.ej
	../../../tools/ej/ej2txt ../source/dnsslave.ej > \
	  dnsslave.txt

update.txt: ../source/update.ej
	../../../tools/ej/ej2txt ../source/update.ej > update.txt

dnsintro.txt: ../source/dnsintro.ej
	../../../tools/ej/ej2txt ../source/dnsintro.ej > dnsintro.txt

quick_start.txt: ../source/quick_start.ej
	../../../tools/ej/ej2txt ../source/quick_start.ej > \
	    quick_start.txt

win_service.txt: ../source/win_service.ej
	../../../tools/ej/ej2txt ../source/win_service.ej > win_service.txt

bind2csv2.txt: ../source/bind2csv2.ej
	../../../tools/ej/ej2txt ../source/bind2csv2.ej > bind2csv2.txt

troubleshoot.txt: ../source/troubleshoot.ej
	../../../tools/ej/ej2txt ../source/troubleshoot.ej > troubleshoot.txt

coding_style.txt: ../source/coding_style.ej
	../../../tools/ej/ej2txt ../source/coding_style.ej > \
	    coding_style.txt

