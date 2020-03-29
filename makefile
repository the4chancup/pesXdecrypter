OBJ = crypt.o masterkey.o mt19937ar.o
#Define _WIN32 and BUILDING_LIBRARY for preprocessor
DFLAGS = -DBUILDING_LIBRARY -D_WIN32

libpesXcrypter.dll: $(OBJ)
	gcc -std=c99 -shared -o $@ $(OBJ)

crypt.o: crypt.h masterkey.h mt19937ar.h
	gcc -c crypt.c $(DFLAGS)

masterkey.o: masterkey.h
	gcc -c masterkey.c $(DFLAGS)

mt19937ar.o: mt19937ar.h
	gcc -c mt19937ar.c $(DFLAGS)

clean:
	rm $(OBJ)
