CC=gcc
MPICC=mpicc
CFLAGS=-Wno-unused-parameter -Wno-format-overflow -Wall -Wextra -Werror -g -rdynamic -O3 -msse4.2

all: crypter lab4

crypter: crypter.o
	$(CC) -o crypter crypter.o -lcrypto

lab4: lab4.c
	$(MPICC) $(CFLAGS) -c lab4.o lab4.c
	$(MPICC) -o $@ lab4.o -lcrypto -lm

clean:
	rm -f *.o lab4 crypter
