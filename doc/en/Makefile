all: faq.txt faq.html QuickStart credits.txt files.txt 

clean:
	rm -f faq.txt faq.html QuickStart changelog.txt changelog.html \
	files.txt

faq.html: source/faq.ej source/faq.embed
	../../tools/ej/ej2html source/faq.ej > faq.html

faq.txt: source/faq.ej source/faq.embed
	../../tools/ej/ej2txt source/faq.ej > faq.txt

QuickStart: source/quick_start.ej
	../../tools/ej/ej2txt source/quick_start.ej > QuickStart

credits.txt: source/credits.ej source/credits.embed
	../../tools/ej/ej2txt source/credits.ej > credits.txt

files.txt: source/files.ej
	../../tools/ej/ej2txt source/files.ej > files.txt

