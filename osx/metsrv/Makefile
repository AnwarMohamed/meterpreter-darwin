
BASEVPATH=.:./posix/
OPENSSL=../openssl/include
COMMON=../common
SERVER=./

CFLAGS=-fno-stack-protector
CFLAGS+= -I${COMMON} -I${SERVER} -I${OPENSSL}
CFLAGS+= -fno-builtin -D_SIZE_T_DECLARED
CFLAGS+= -D_BYTE_ORDER=_LITTLE_ENDIAN
CFLAGS+= -march=i386 -m32

OSVPATH=../common/arch/posix
ARCHVPATH=$(OSVPATH)/$(RARCH):$(ELFARCHPATH)
VPATH=$(BASEVPATH):$(OSVPATH):$(ARCHVPATH)

objects= metsrv.o scheduler.o 
objects+= server_setup.o remote_dispatch_common.o remote_dispatch.o

all:  libmetsrv.dylib

libmetsrv.dylib: $(objects)
	$(CC) -dynamiclib -shared $(CFLAGS) -o $@ $(objects) -L../../lib -L.. -lc -lcrypto -lssl -ldl -lsupport

clean:
	$(RM) -f *.o *.gz *~ *.a *.dylib

.PHONY: clean
