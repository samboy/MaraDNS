all: tutorial.pdf authoritative.pdf compile.pdf convert.pdf recursive.pdf \
     glossary.pdf recordtypes.pdf 

clean:
	rm -f *.ps *.pdf

authoritative.ps: ../source/authoritative.ej
	../../../tools/ej/ej2ps ../source/authoritative.ej > \
	    authoritative.ps

authoritative.pdf: authoritative.ps
	ps2pdf authoritative.ps authoritative.pdf

tutorial.ps: ../source/tutorial.ej
	../../../tools/ej/ej2ps ../source/tutorial.ej > tutorial.ps

tutorial.pdf: tutorial.ps
	ps2pdf tutorial.ps tutorial.pdf

compile.ps: ../source/compile.ej
	../../../tools/ej/ej2ps ../source/compile.ej > compile.ps

compile.pdf: compile.ps
	ps2pdf compile.ps compile.pdf

convert.ps: ../source/convert.ej
	../../../tools/ej/ej2ps ../source/convert.ej > convert.ps

convert.pdf: convert.ps
	ps2pdf convert.ps convert.pdf

recursive.ps: ../source/recursive.ej
	../../../tools/ej/ej2ps ../source/recursive.ej > \
	  recursive.ps

recursive.pdf: recursive.ps
	ps2pdf recursive.ps recursive.pdf

glossary.ps: ../source/glossary.ej
	../../../tools/ej/ej2ps ../source/glossary.ej > \
	  glossary.ps

glossary.pdf: glossary.ps
	ps2pdf glossary.ps glossary.pdf

recordtypes.ps: ../source/recordtypes.ej
	../../../tools/ej/ej2ps ../source/recordtypes.ej > \
	  recordtypes.ps

recordtypes.pdf: recordtypes.ps
	ps2pdf recordtypes.ps recordtypes.pdf

changelog.ps: ../source/changelog.ej ../source/changelog.embed
	../../../tools/ej/ej2ps ../source/changelog.ej > \
	  changelog.ps

changelog.pdf: changelog.ps
	ps2pdf changelog.ps changelog.pdf

