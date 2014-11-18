all: faq.txt faq.html QuickStart credits.txt changelog.txt files.txt 

clean:
	rm -f faq.txt faq.html QuickStart changelog.txt changelog.html \
	files.txt

faq.html: source/faq.ej source/faq.embed
	../../tools/ej/ej2html source/faq.ej > faq.html

faq.txt: source/faq.ej source/faq.embed
	../../tools/ej/ej2txt source/faq.ej > faq.txt

# For this file, the older ej2txt tools makes a nicer text file
QuickStart: source/quick_start.ej
	../../tools/ej/ej2txt.old source/quick_start.ej > QuickStart

credits.txt: source/credits.ej source/credits.embed
	../../tools/ej/ej2txt source/credits.ej > credits.txt

changelog.html: source/changelog.ej source/changelog.embed
	../../tools/ej/ej2html source/changelog.ej > changelog.html

changelog.txt: source/changelog.ej source/changelog.embed
	../../tools/ej/ej2txt source/changelog.ej > changelog.txt

files.txt: source/files.ej
	../../tools/ej/ej2txt source/files.ej > files.txt

download.html: source/download.ej
	../../tools/ej/ej2html source/download.ej > download.html

