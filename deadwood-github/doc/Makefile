all: Duende.1 Duende.txt Deadwood.1 Deadwood.txt FAQ.txt FAQ.html \
	Deadwood.html Recursive-algorithm.txt

clean:
	rm -f Duende.1 Duende.txt Deadwood.1 Deadwood.txt FAQ.txt

Duende.1: Duende.ej
	../tools/ej/ej2man Duende.ej > Duende.1

Duende.txt: Duende.ej
	../tools/ej/ej2txt Duende.ej > Duende.txt ;\
	echo >> Duende.txt ;\
	unix2dos Duende.txt

Deadwood.1: Deadwood.ej
	../tools/ej/ej2man Deadwood.ej > Deadwood.1

Deadwood.txt: Deadwood.ej
	../tools/ej/ej2txt Deadwood.ej > Deadwood.txt ;\
	echo >> Deadwood.txt;\
	unix2dos Deadwood.txt

Deadwood.html: Deadwood.ej
	../tools/ej/ej2html Deadwood.ej > Deadwood.html

FAQ.txt: FAQ.ej
	../tools/ej/ej2txt FAQ.ej > FAQ.txt ;\
	echo >> FAQ.txt ;\
	unix2dos FAQ.txt

FAQ.html: FAQ.ej
	../tools/ej/ej2html FAQ.ej > FAQ.html

Recursive-algorithm.txt: Recursive-algorithm.ej
	../tools/ej/ej2txt Recursive-algorithm.ej > Recursive-algorithm.txt ;\
	echo >> Recursive-algorithm.txt ;\
	unix2dos Recursive-algorithm.txt

