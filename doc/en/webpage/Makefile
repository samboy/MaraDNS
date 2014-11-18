all: changelog.html contact.html dns_software.html download.html \
	faq-1.0.html faq.html index.html license.html notes.html \
	sponsors.html security.html advocacy.html debian.html \
	products.html search.html

changelog.html: changelog.embed maradns-1.2-top.html maradns-1.2-bottom.html
	./make.page changelog.embed

contact.html: contact.embed maradns-1.2-top.html maradns-1.2-bottom.html
	./make.page contact.embed

products.html: products.embed maradns-1.2-top.html maradns-1.2-bottom.html
	./make.page products.embed

dns_software.html: dns_software.embed maradns-1.2-top.html maradns-1.2-bottom.html
	./make.page dns_software.embed

download.html: download.embed maradns-1.2-top.html maradns-1.2-bottom.html
	./make.page download.embed

faq-1.0.html: faq-1.0.embed maradns-1.2-top.html maradns-1.2-bottom.html
	./make.page faq-1.0.embed

faq.html: faq.embed maradns-1.2-top.html maradns-1.2-bottom.html
	./make.page faq.embed

index.html: index.embed maradns-1.2-top.html maradns-1.2-bottom.html
	./make.page index.embed

license.html: license.embed maradns-1.2-top.html maradns-1.2-bottom.html
	./make.page license.embed

notes.html: notes.embed maradns-1.2-top.html maradns-1.2-bottom.html
	./make.page notes.embed

# Removed 2009.02.07: Out of date and replaced with sponsors page;
# current MaraDNS information is at the MaraDNS blog
roadmap.html: roadmap.embed maradns-1.2-top.html maradns-1.2-bottom.html
	./make.page roadmap.embed

security.html: security.embed maradns-1.2-top.html maradns-1.2-bottom.html
	./make.page security.embed

# Added 2011.03.18: Make it easier for users to search the docs
search.html: security.embed maradns-1.2-top.html maradns-1.2-bottom.html
	./make.page search.embed

advocacy.html: advocacy.embed maradns-1.2-top.html maradns-1.2-bottom.html
	./make.page advocacy.embed

# Added 2007.09.22: Web page tell Debian users to upgrade their version
# of MaraDNS
debian.html: debian.embed maradns-1.2-top.html maradns-1.2-bottom.html
	./make.page debian.embed

# Added 2009.02.07: Web page thanking people for sponsoring MaraDNS
sponsors.html: sponsors.embed maradns-1.2-top.html maradns-1.2-bottom.html
	./make.page sponsors.embed

