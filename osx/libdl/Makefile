CC=i686-apple-darwin10-gcc
CFLAGS= -fPIC -DPIC
CFLAGS+= -I../../include
CFLAGS+= -Os

all: i386
	

debug: all

clean:
	rm -rf libdl-*

i386:	
	$(CC) -dynamiclib -o libdl-32.dylib $(CFLAGS) -march=i386 -m32 libdl.c

x86-64:
	$(CC) -ldl -shared -dynamiclib -o libdl-64.dylib $(CFLAGS) -march=x86-64 -m64 libdl.c

test:
	$(CC) -ldl -march=i386 -m32 $(CFLAGS) dltest.c -o dltest -L.