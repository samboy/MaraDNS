all: blockHashMake blockHashRead

clean:
	rm -f blockHashMake blockHashRead *.exe

blockHashMake: blockHashMake.c
	$(CC) -std=c99 $(CFLAGS) -o blockHashMake blockHashMake.c

blockHashRead: blockHashRead.c
	$(CC) -std=c99 $(CFLAGS) -o blockHashRead blockHashRead.c
