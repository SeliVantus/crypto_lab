all: verifier generator cracker

verifier:
	gcc -g -Wall ver.c -lssl -lcrypto -o verifier

cracker: crack.o cracker.o protocol_funcs.o generator.o
	gcc -g -Wall crack.o cracker.o protocol_funcs.o generator.o -lssl -lcrypto -o cracker

generator: gen.o generator.o protocol_funcs.o
	gcc -g -Wall gen.o generator.o protocol_funcs.o -lssl -lcrypto -o generator


gen.o:
	gcc -c gen.c

generator.o:
	gcc -c generator.c

protocol_funcs.o:
	gcc -c protocol_funcs.c

crack.o:
	gcc -c crack.c

cracker.o:
	gcc -c cracker.c

clean:
	rm -rf *.o verifier generator
