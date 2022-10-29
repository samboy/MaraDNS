all: tutorial.html \
     authoritative.html compile.html convert.html recursive.html \
     glossary.html recordtypes.html dangling.html default_zonefile.html \
     dnstcp.html man.duende.html dnsmaster.html man.csv2_txt.html \
     man.csv2.html dnsslave.html update.html man.askmara.html \
     man.fetchzone.html man.zoneserver.html man.maradns.html \
     man.mararc.html quick_start.html dnsintro.html \
     win_service.html troubleshoot.html coding_style.html \
     man.csv1.html

clean:
	rm -f *.html 

man.maradns.html: ../source/maradns.ej ../source/faq.embed
	../../../tools/ej/ej2html ../source/maradns.ej > man.maradns.html

man.mararc.html: ../source/mararc.ej
	../../../tools/ej/ej2html ../source/mararc.ej > man.mararc.html

man.fetchzone.html: ../source/fetchzone.ej
	../../../tools/ej/ej2html ../source/fetchzone.ej > \
	    man.fetchzone.html

man.zoneserver.html: ../source/zoneserver.ej
	../../../tools/ej/ej2html ../source/zoneserver.ej > \
	    man.zoneserver.html

man.askmara.html: ../source/askmara.ej
	../../../tools/ej/ej2html ../source/askmara.ej > man.askmara.html

man.csv1.html: ../source/csv1.ej
	../../../tools/ej/ej2html ../source/csv1.ej > man.csv1.html

man.csv2.html: ../source/csv2.ej
	../../../tools/ej/ej2html ../source/csv2.ej > man.csv2.html

man.csv2_txt.html: ../source/csv2.ej
	../../../tools/ej/ej2html ../source/csv2_txt.ej > man.csv2_txt.html

man.duende.html: ../source/duende.ej
	../../../tools/ej/ej2html ../source/duende.ej > man.duende.html

tutorial.html: ../source/tutorial.ej
	../../../tools/ej/ej2html ../source/tutorial.ej > tutorial.html

authoritative.html: ../source/authoritative.ej
	../../../tools/ej/ej2html ../source/authoritative.ej > \
	    authoritative.html

compile.html: ../source/compile.ej
	../../../tools/ej/ej2html ../source/compile.ej > compile.html

convert.html: ../source/convert.ej
	../../../tools/ej/ej2html ../source/convert.ej > convert.html

recursive.html: ../source/recursive.ej
	../../../tools/ej/ej2html ../source/recursive.ej > \
	  recursive.html

glossary.html: ../source/glossary.ej
	../../../tools/ej/ej2html ../source/glossary.ej > \
	  glossary.html

recordtypes.html: ../source/recordtypes.ej
	../../../tools/ej/ej2html ../source/recordtypes.ej > \
	  recordtypes.html

dangling.html: ../source/dangling.ej
	../../../tools/ej/ej2html ../source/dangling.ej > \
	  dangling.html

default_zonefile.html: ../source/default_zonefile.ej
	../../../tools/ej/ej2html ../source/default_zonefile.ej > \
	  default_zonefile.html

dnstcp.html: ../source/dnstcp.ej
	../../../tools/ej/ej2html ../source/dnstcp.ej > \
	  dnstcp.html

dnsmaster.html: ../source/dnsmaster.ej
	../../../tools/ej/ej2html ../source/dnsmaster.ej > \
	  dnsmaster.html

dnsslave.html: ../source/dnsslave.ej
	../../../tools/ej/ej2html ../source/dnsslave.ej > \
	  dnsslave.html

update.html: ../source/update.ej
	../../../tools/ej/ej2html ../source/update.ej > update.html

dnsintro.html: ../source/dnsintro.ej
	../../../tools/ej/ej2html ../source/dnsintro.ej > dnsintro.html

quick_start.html: ../source/quick_start.ej
	../../../tools/ej/ej2html ../source/quick_start.ej > \
	    quick_start.html

win_service.html: ../source/win_service.ej
	../../../tools/ej/ej2html ../source/win_service.ej > win_service.html

troubleshoot.html: ../source/troubleshoot.ej
	../../../tools/ej/ej2html ../source/troubleshoot.ej > troubleshoot.html

coding_style.html: ../source/coding_style.ej
	../../../tools/ej/ej2html ../source/coding_style.ej > \
	    coding_style.html

