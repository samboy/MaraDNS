all: Deadwood.1 Deadwood.txt FAQ.txt FAQ.html \
	Deadwood.html Recursive_algorithm.txt blockHashMake.1 \
	blockHashMake.txt blockHashMake.html \
	blockHashRead.1 blockHashRead.txt blockHashRead.html \
	Deadwood.md blockHashMake.md blockHashRead.md

clean:
	rm -f Duende.1 Duende.txt Deadwood.1 Deadwood.txt FAQ.txt \
	blockHashMake.1 blockHashMake.txt blockHashMake.html \
	blockHashRead.1 blockHashRead.txt blockHashRead.html

blockHashRead.1: blockHashRead.ej
	../../tools/ej/ej2man blockHashRead.ej > blockHashRead.1

blockHashRead.txt: blockHashRead.ej
	../../tools/ej/ej2txt blockHashRead.ej > blockHashRead.txt ;\
	unix2dos blockHashRead.txt

blockHashRead.html: blockHashRead.ej
	../../tools/ej/ej2html blockHashRead.ej > blockHashRead.html

blockHashRead.md: blockHashRead.ej
	../../tools/ej/ej2md blockHashRead.ej > blockHashRead.md

blockHashMake.1: blockHashMake.ej
	../../tools/ej/ej2man blockHashMake.ej > blockHashMake.1

blockHashMake.txt: blockHashMake.ej
	../../tools/ej/ej2txt blockHashMake.ej > blockHashMake.txt ;\
	unix2dos blockHashMake.txt

blockHashMake.html: blockHashMake.ej
	../../tools/ej/ej2html blockHashMake.ej > blockHashMake.html

blockHashMake.md: blockHashMake.ej
	../../tools/ej/ej2md blockHashMake.ej > blockHashMake.md

Duende.1: Duende.ej
	../../tools/ej/ej2man Duende.ej > Duende.1

Duende.txt: Duende.ej
	../../tools/ej/ej2txt Duende.ej > Duende.txt ;\
	echo >> Duende.txt ;\
	unix2dos Duende.txt

Deadwood.1: Deadwood.ej
	../../tools/ej/ej2man Deadwood.ej > Deadwood.1

Deadwood.txt: Deadwood.ej
	../../tools/ej/ej2txt Deadwood.ej > Deadwood.txt ;\
	echo >> Deadwood.txt;\
	unix2dos Deadwood.txt

Deadwood.html: Deadwood.ej
	../../tools/ej/ej2html Deadwood.ej > Deadwood.html

Deadwood.md: Deadwood.ej
	../../tools/ej/ej2md Deadwood.ej > Deadwood.md

FAQ.txt: FAQ.ej
	../../tools/ej/ej2txt FAQ.ej > FAQ.txt ;\
	echo >> FAQ.txt ;\
	unix2dos FAQ.txt

FAQ.html: FAQ.ej
	../../tools/ej/ej2html FAQ.ej > FAQ.html

Recursive_algorithm.txt: Recursive_algorithm.ej
	../../tools/ej/ej2txt Recursive_algorithm.ej > \
	Recursive_algorithm.txt ;\
	echo >> Recursive_algorithm.txt ;\
	unix2dos Recursive_algorithm.txt 

