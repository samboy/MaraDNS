# This is a wrapper that runs "./configure ; make"
all:
	./configure ; make

debug:
	./configure ; make debug

clean:
	./configure ; make clean

uninstall:
	./configure ; make uninstall

install:
	echo Please compile MaraDNS first
