all: blockHashMake blockHashRead

clean:
	rm -f blockHashMake blockHashRead *.exe

blockHashMake: blockHashMake.c
	$(CC) $(CFLAGS) -o blockHashMake blockHashMake.c

blockHashRead: blockHashRead.c
	$(CC) $(CFLAGS) -o blockHashRead blockHashRead.c
