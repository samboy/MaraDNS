DOBJECTS=qual_timestamp.o 
JOBJS=../libs/JsStr.o ../libs/JsStrOS.o ../libs/JsStrCP.o 
OBJECTS=$(DOBJECTS)

FLAGS = -DAUTHONLY

all: qual_timestamp.o

clean:
	rm -f qual_timestamp.o

qual_timestamp.o: qual_timestamp.c ../libs/JsStr.h ../libs/MaraHash.h ../MaraDns.h
	$(CC) -c $(FLAGS) -o qual_timestamp.o qual_timestamp.c 

