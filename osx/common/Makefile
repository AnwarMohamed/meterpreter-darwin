.SUFFIXES: .S .c

SOURCEPATH=.
SSL_PATH=../openssl/include
XOR_PATH=./crypto
ZLIB_PATH=./zlib

CFLAGS= -D_BYTE_ORDER=_LITTLE_ENDIAN -D_SIZE_T_DECLARED
CFLAGS+= -fno-builtin
CFLAGS+= -I$(SOURCEPATH) -I$(XOR_PATH) -I$(ZLIB_PATH) -I$(SSL_PATH)
CFLAGS+= -I.
CFLAGS+= -march=i386 -m32 -g -fPIC -Os -DPIC

objects = args.o base.o base_dispatch.o base_dispatch_common.o buffer.o \
	channel.o common.o core.o list.o remote.o thread.o xor.o zlib.o

CFLAGS+= -fno-stack-protector

BASEVPATH=.:./crypto:./arch/posix:./zlib:
OSVPATH=./arch/posix
ARCHVPATH=./arch/posix
VPATH=$(BASEVPATH):$(OSVPATH):$(ARCHVPATH)

CFLAGS+= -I$(ARCHVPATH)

all: libsupport.dylib

libsupport.dylib: $(objects)
	$(CC) $(CFLAGS) -dynamiclib $(objects) -L../../lib -lc -lssl -lcrypto -o $@

clean:
	$(RM) -f *.o *.a *.dylib zlib/zlib.o

.PHONY: clean

