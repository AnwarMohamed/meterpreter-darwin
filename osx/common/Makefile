.SUFFIXES: .S .c

SOURCEPATH=.
SSL_PATH=../openssl/include
XOR_PATH=./crypto
ZLIB_PATH=./zlib
DARWIN_PATH=../../include
GCC_PATH=../../include/gcc

CFLAGS=-nostdinc -nostdlib
#CFLAGS+= -I ../../test/source/bionic/libc/include 
#CFLAGS+= -I ../../test/source/bionic/libc/kernel/common/linux/ 
#CFLAGS+= -I ../../test/source/bionic/libc/kernel/common/ 
#CFLAGS+= -I ../../test/source/bionic/libc/arch-x86/include/
#CFLAGS+= -I ../../test/source/bionic/libc/kernel/arch-x86/ 

CFLAGS+= -I$(SSL_PATH)
CFLAGS+= -D_BYTE_ORDER=_LITTLE_ENDIAN -D_SIZE_T_DECLARED
#CFLAGS+= -Dwchar_t="char" 
CFLAGS+= -fno-builtin
#-DElf_Size="u_int32_t" 
CFLAGS+= -I$(SOURCEPATH) -I$(XOR_PATH) -I$(ZLIB_PATH) -I$(SSL_PATH) -I$(DARWIN_PATH)
#CFLAGS+=  -D__linux__ -D__DARWIN__ -DMALLOC_PRODUCTION 
CFLAGS+= -I.
CFLAGS+= -march=i386 -m32 -g -fPIC -Os -DPIC

#CC=gcc
CC=i686-apple-darwin10-gcc
AR=i686-apple-darwin10-ar
LD=i686-apple-darwin10-ld
RM=rm

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
	$(CC) $(CFLAGS) -dynamiclib $(objects) -lc -lssl -lcrypto -o $@ 

clean:
	$(RM) -f *.o *.a *.dylib zlib/zlib.o

.PHONY: clean

