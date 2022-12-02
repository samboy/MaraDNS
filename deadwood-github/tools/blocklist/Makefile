all: blockListMake blockListRead

clean:
	rm -f blockListMake blockListRead *.exe

blockListMake: blockListMake.c
	$(CC) $(CFLAGS) -o blockListMake blockListMake.c

blockListRead: blockListRead.c
	$(CC) $(CFLAGS) -o blockListRead blockListRead.c
