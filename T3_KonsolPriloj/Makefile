all: crypter


crypter: crypter.o generator.o protocol_funcs.o
	gcc -g -Wall crypter.o generator.o protocol_funcs.o -lssl -lcrypto -o crypter

generator.o:
	gcc -c generator.c

protocol_funcs.o:
	gcc -c protocol_funcs.c

crypter.o:
	gcc -c crypter.c

clean:
	rm -rf *.o crypter


