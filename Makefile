CC=gcc
CFLAGS=

all: encrypter decrypter

encrypter: src/crypter.c src/mt19937ar.c src/mt19937ar.h
	$(CC) -o encrypter -DDECRYPTER=0 src/crypter.c src/mt19937ar.c

decrypter: src/crypter.c src/mt19937ar.c src/mt19937ar.h
	$(CC) -o decrypter -DDECRYPTER=1 src/crypter.c src/mt19937ar.c
