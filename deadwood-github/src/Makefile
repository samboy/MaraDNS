# Makefile for Deadwood-3 (CentOS 5; may work with other other Linux and
# *NIX systems)

# The compiler that makes programs designed to run on the machine 
# compiling.  When cross-compiling, we still need to compile and
# run programs on the build machine, so change the next line when
# cross-compiling.
HOSTCC=$(CC)

OBJS=DwStr.o \
	DwMararc.o \
	DwRadioGatun.o \
	DwSocket.o \
	DwUdpSocket.o \
	DwTcpSocket.o \
	DwSys.o \
	DwHash.o \
	DwCompress.o \
	DwDnsStr.o \
	DwRecurse.o \
	DwDict.o

all:	Deadwood version.h

# Since some systems may not have /dev/urandom (Windows, *cough* *cough*), we 
# keep a randomly generated prime around 

#		Makefile \
#

clean:
	rm -f Test DwMain DwTcp *.exe *.o a.out RandomPrime writehash_test* \
		Deadwood foo* dw_cache DwHash DwCompress *stackdump \
		core ; \
		./make.version.h ; if [ -e /dev/urandom ] ; \
			then rm DwRandPrime.h  ; \
			cc RandomPrime.c ; ./a.out > DwRandPrime.h ; rm a.out \
		; fi 

version.h:	
	./make.version.h
	
DwStr.o:	DwStr.c DwStr.h
	$(CC) $(FLAGS) -DIPV6 -Wall -c -o DwStr.o DwStr.c

DwCompress.o:	DwCompress.c DwStr.h
	$(CC) $(FLAGS) -DIPV6 -Wall -c -o DwCompress.o DwCompress.c

DwDnsStr.o:	DwDnsStr.c DwStr.h DwRecurse.h
	$(CC) $(FLAGS) -DIPV6 -Wall -c -o DwDnsStr.o DwDnsStr.c

DwMararc.o:	DwMararc.c DwMararc.h 
	$(CC) $(FLAGS) -DIPV6 -Wall -c -o DwMararc.o DwMararc.c

DwRadioGatun.o:	DwRadioGatun.c DwRadioGatun.h DwStr.h
	$(CC) $(FLAGS) -DIPV6 -Wall -c -o DwRadioGatun.o DwRadioGatun.c

DwTcpSocket.o:	DwTcpSocket.c DwStr.h DwSocket.h
	$(CC) $(FLAGS) -DIPV6 -Wall -c -o DwTcpSocket.o DwTcpSocket.c

DwUdpSocket.o:	DwUdpSocket.c DwStr.h DwSocket.h
	$(CC) $(FLAGS) -DIPV6 -Wall -c -o DwUdpSocket.o DwUdpSocket.c

DwSocket.o:	DwSocket.c DwStr.h DwSocket.h
	$(CC) $(FLAGS) -DIPV6 -Wall -c -o DwSocket.o DwSocket.c

DwSys.o:	DwSys.c DwStr.h
	$(CC) $(FLAGS) -DIPV6 -Wall -c -o DwSys.o DwSys.c

RandomPrime:	RandomPrime.c
	$(CC) -O3 -o RandomPrime RandomPrime.c

DwRandPrime.h: RandomPrime
	if [ -e /dev/urandom ] ; then ./RandomPrime > DwRandPrime.h ; fi

DwHash.o:	DwHash.c DwStr.h DwRandPrime.h DwHash.h
	$(CC) $(FLAGS) -DIPV6 -Wall -c -o DwHash.o DwHash.c

DwRecurse.o:	DwRecurse.c DwRecurse.h
	$(CC) $(FLAGS) -DIPV6 -Wall -c -o DwRecurse.o DwRecurse.c

DwDict.o:	DwDict.c DwStr.h DwRandPrime.h DwDict.h
	$(CC) $(FLAGS) -DIPV6 -Wall -c -o DwDict.o DwDict.c

Test:		Test.c DwStr.o DwStr.h DwStr_functions.h $(OBJS)
	$(CC) $(FLAGS) -Wall -o Test Test.c $(OBJS)

Deadwood:	DwMain.c $(OBJS) DwStr_functions.h version.h
	$(CC) $(FLAGS) -DIPV6 -Wall -o Deadwood DwMain.c $(OBJS) -lrt

