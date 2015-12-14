CC=gcc
CFLAGS=-std=c99

all: encrypter decrypter dll

encrypter: src/crypter.c src/mt19937ar.c src/mt19937ar.h
	$(CC) $(CFLAGS) -o encrypter -DDECRYPTER=0 src/crypter.c src/mt19937ar.c

decrypter: src/crypter.c src/mt19937ar.c src/mt19937ar.h
	$(CC) $(CFLAGS) -o decrypter -DDECRYPTER=1 src/crypter.c src/mt19937ar.c

dll: src/crypter.c src/mt19937ar.c src/mt19937ar.h
	$(CC) $(CFLAGS) -DDLL=1 -c src/crypter.c src/mt19937ar.c
	$(CC) $(CFLAGS) -shared -o cygpes16decrypter.dll \
		-Wl,--out-implib=libpes16decrypter.dll.a \
		-Wl,--export-all-symbols \
		-Wl,--enable-auto-import \
		-Wl,--whole-archive crypter.o mt19937ar.o \
		-Wl,--no-whole-archive
