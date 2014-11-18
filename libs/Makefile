OBJECTS = JsStr.o JsStrOS.o JsStrCP.o MaraHash.o
#FLAGS = -Wall $(DEBUG)
#FLAGS = -g -DDEBUG -DTHREADS
#FLAGS = -g $(DEBUG)

all: tests mtest

clean:
	rm -f core $(OBJECTS) tests mtest *.exe

MaraHash.o: JsStr.h MaraHash.c
	$(CC) -c $(FLAGS) -o MaraHash.o MaraHash.c 

JsStr.o: JsStr.h JsStr.c
	$(CC) -c $(FLAGS) -o JsStr.o JsStr.c 

JsStrOS.o: JsStr.h JsStrOS.c
	$(CC) -c $(FLAGS) -o JsStrOS.o JsStrOS.c 

JsStrCP.o: JsStr.h JsStrCP.c
	$(CC) -c $(FLAGS) -o JsStrCP.o JsStrCP.c 

mtest: mtest.c $(OBJECTS)
	$(CC) $(FLAGS) -o mtest mtest.c $(OBJECTS)

tests: tests.c $(OBJECTS)
	$(CC) $(FLAGS) -o tests tests.c $(OBJECTS)

#onetime: $(OBJECTS) kiwi.h config.h onetime.c do_scramble.o cryptdate.o
#	$(CC) $(FLAGS) -o onetime onetime.c do_scramble.o cryptdate.o

