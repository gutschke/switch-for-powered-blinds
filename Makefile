all: switch

switch: switch.c jsmn/jsmn.h libjsmn.a
	gcc -DNDEBUG -D_GNU_SOURCE -DJSMN_ITERATORS -DWIRING --std=gnu11 -g -Wall -Werror -O0 -o switch switch.c libjsmn.a -lwiringPi -lpthread

libjsmn.a: jsmn.o
	ar rc libjsmn.a jsmn.o

jsmn.o: jsmn/jsmn.c jsmn/jsmn.h
	gcc  -DJSMN_ITERATORS -g -O0 -c jsmn/jsmn.c -o jsmn.o

clean:
	rm -f switch jsmn.o libjsmn.a
