DOBJECTS=Queries.o Compress.o bobbit.o Decompress.o
JOBJS=../libs/JsStr.o ../libs/JsStrOS.o ../libs/JsStrCP.o 
MHOBJS=../libs/MaraHash.o
OBJECTS=$(DOBJECTS) $(JOBJS) $(MHOBJS)

FLAGS = -DAUTHONLY

all: Queries.o Compress.o bobbit.o Decompress.o

clean:
	rm -f Queries.o Compress.o bobbit.o Decompress.o

Queries.o: Queries.c ../libs/JsStr.h ../libs/MaraHash.h ../MaraDns.h
	$(CC) -c $(FLAGS) -o Queries.o Queries.c 

Compress.o: Compress.c ../libs/JsStr.h ../libs/MaraHash.h ../MaraDns.h
	$(CC) -c $(FLAGS) -o Compress.o Compress.c 

Decompress.o: Decompress.c ../libs/JsStr.h ../libs/MaraHash.h ../MaraDns.h
	$(CC) -c $(FLAGS) -o Decompress.o Decompress.c 

bobbit.o: bobbit.c ../libs/JsStr.h ../libs/MaraHash.h ../MaraDns.h
	$(CC) -c $(FLAGS) -o bobbit.o bobbit.c 

