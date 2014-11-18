UOBJECTS=Utf8.o
JOBJS=../libs/JsStr.o ../libs/JsStrOS.o ../libs/JsStrCP.o 
MHOBJS=../libs/MaraHash.o
OBJECTS=$(UOBJECTS) $(JOBJS) $(MHOBJS)
EXECS=utf8test l1toutf8 utf8tol1 lcol

FLAGS = -g $(DEBUG)
#FLAGS = -g $(DEBUG)

all: $(EXECS)

clean:
	rm -f $(UOBJECTS) core $(EXECS)

Utf8.o: Utf8.c ../libs/JsStr.h ../libs/MaraHash.h ../MaraDns.h
	$(CC) -c $(FLAGS) -o Utf8.o Utf8.c 

utf8test: utf8test.c $(OBJECTS) 
	$(CC) $(FLAGS) -o utf8test utf8test.c $(OBJECTS) 

l1toutf8: l1toutf8.c
	$(CC) $(FLAGS) -o l1toutf8 l1toutf8.c

utf8tol1: utf8tol1.c
	$(CC) $(FLAGS) -o utf8tol1 utf8tol1.c

lcol: lcol.c
	$(CC) $(FLAGS) -o lcol lcol.c

