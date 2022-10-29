all: coLunacyDNS.1 coLunacyDNS.txt

clean:
	rm -f coLunacyDNS.1 coLunacyDNS.txt

coLunacyDNS.1: coLunacyDNS.ej
	../../tools/ej/ej2man coLunacyDNS.ej > coLunacyDNS.1

coLunacyDNS.txt: coLunacyDNS.ej
	../../tools/ej/ej2txt coLunacyDNS.ej > coLunacyDNS.txt

