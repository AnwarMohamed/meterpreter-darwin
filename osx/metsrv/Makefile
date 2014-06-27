
BASEVPATH=.:./posix/
OPENSSL=../openssl/include
COMMON=../common
SERVER=./

CFLAGS=-fno-stack-protector -nostdinc -nostdlib 
#CFLAGS+=-D_UNIX -D__linux__ 
CFLAGS+=-I${COMMON} -I${SERVER} -I${OPENSSL}

#CFLAGS+= -I ../../test/source/bionic/libc/include 
#CFLAGS+= -I ../../test/source/bionic/libc/kernel/common/linux/ 
#CFLAGS+= -I ../../test/source/bionic/libc/kernel/common/ 
#CFLAGS+= -I ../../test/source/bionic/libc/arch-x86/include/
#CFLAGS+= -I ../../test/source/bionic/libc/kernel/arch-x86/ 
#CFLAGS+= -Dwchar_t="char"
CFLAGS+= -I ../../include
CFLAGS+= -fno-builtin -D_SIZE_T_DECLARED
#CFLAGS+= -DElf_Size="u_int32_t" 
CFLAGS+= -D_BYTE_ORDER=_LITTLE_ENDIAN
#CFLAGS+= -lgcc

CFLAGS+= -march=i386 -m32

CC=i686-apple-darwin10-gcc
AR=i686-apple-darwin10-ar
LD=i686-apple-darwin10-ld

OSVPATH=../common/arch/posix:../metsrv/linux/
ARCHVPATH=$(OSVPATH)/$(RARCH):$(ELFARCHPATH)
VPATH=$(BASEVPATH):$(OSVPATH):$(ARCHVPATH)

objects= metsrv.o scheduler.o 
objects+= server_setup.o remote_dispatch_common.o remote_dispatch.o
#objects+= netlink.o

all:  libmetsrv.dylib

debug: CFLAGS+=-ggdb
debug: all

libmetsrv.dylib: $(objects)
	$(CC) -Wl -dynamiclib $(CFLAGS) -o $@ $(objects) -L../../lib -L.. -lc -lcrypto -lssl -ldl -ldl-32 -lsupport

clean:
	$(RM) -f *.o *.so *.gz *~ *.a libmetsrv.dylib
	$(RM) metsrv_test.bundle

.PHONY: clean

test: all
	$(CC) $(CFLAGS) -bundle -o metsrv_test.bundle -L../../lib -L.. -lmetsrv posix/metsrv_test.c -lc -ldl