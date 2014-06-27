framework_dir = ../metasploit-framework/

OUTPUT=.
CFLAGS=-g -Wall -fasm-blocks
CC=i686-apple-darwin10-gcc
 
CFLAGS+= -I metsrv/ -I common/ -I libdl/
CFLAGS+= -I ../include

all: run-bundle-all inject-bundle-all i386

i386:
	$(MAKE) -C libdl && [ -f libdl/libdl-32.dylib ]
	cp libdl/libdl-32.dylib $(OUTPUT)/libdl-32.dylib

	$(MAKE) -C common && [ -f common/libsupport.dylib ]
	cp common/libsupport.dylib $(OUTPUT)/libsupport.dylib

	$(MAKE) -C metsrv && [ -f metsrv/libmetsrv.dylib ]
	cp metsrv/libmetsrv.dylib $(OUTPUT)/libmetsrv.dylib

x86-64:

inject-bundle-all: inject-bundle-32

inject-bundle-32:
	$(CC) -I ./include -m32 -march=i386 inject-bundle.c -o inject-bundle

inject-bundle-64:
	$(CC) -I ./include -m64 -march=x86-64 inject-bundle.c -o inject-bundle

run-bundle-all: run-bundle-32
	
run-bundle-32:
	$(CC) -I ./include -m32 -march=i386 run-bundle.c -o run-bundle-32

run-bundle-64:
	$(CC) -I ./include -m64 -march=x86-64 run-bundle.c -o run-bundle-64

clean:
	$(MAKE) clean -C libdl
	$(MAKE) clean -C common
	$(MAKE) clean -C metsrv
	rm -rf inject-bundle-* run-bundle-*

test:
	rm -rf reverse_tcp
	$(CC) -m32 -march=i386 -L. -I./metsrv -lmetsrv reverse_tcp.c -o reverse_tcp

install:
	rm -rf /usr/lib/libmetsrv.dylib
	rm -rf /usr/lib/libsupport.dylib
	rm -rf /usr/lib/libdl-32.dylib
	cp libmetsrv.dylib /usr/lib/libmetsrv.dylib
	cp libsupport.dylib /usr/lib/libsupport.dylib
	cp libdl-32.dylib /usr/lib/libdl-32.dylib