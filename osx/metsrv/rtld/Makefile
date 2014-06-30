
CFLAGS+= -I ../../../test/source/bionic/libc/include 
CFLAGS+= -I ../../../test/source/bionic/libc/kernel/common/linux/ 
CFLAGS+= -I ../../../test/source/bionic/libc/kernel/common/ 
CFLAGS+= -I ../../../test/source/bionic/libc/arch-x86/include/
CFLAGS+= -I ../../../test/source/bionic/libc/kernel/arch-x86/ 

CFLAGS+= -fPIC -DPIC
CFLAGS+= -nostdinc -nostdlib -Dwchar_t="char" -fno-builtin -D_SIZE_T_DECLARED -DElf_Size="u_int32_t" -DANDROID_X86_LINKER
CFLAGS+= -DMETSRV_RTLD -D_BYTE_ORDER=_LITTLE_ENDIAN

CFLAGS+= -march=i386 -m32

OBJ=msflinker.o basic_libc.o syscall.o linker_format.o dlfcn.o zlib.o metsrv_rtld.o

compiled=../../bionic/compiled

# These are all generated from their .so counterparts below
HEADERS=libc.h       \
	libm.h           \
	libcrypto.h      \
	libssl.h         \
	libsupport.h     \
	libmetsrv_main.h \
	libpcap.h

CC=i686-apple-darwin10-gcc
AR=i686-apple-darwin10-ar
LD=i686-apple-darwin10-ld

all: msflinker msflinker.bin rtldtest

debug: DEBUG=true
debug: CFLAGS+=-ggdb
debug: all

%.h: $(compiled)/%.so
	([ "$(DEBUG)" != "true" ] && strip --strip-debug $<) || true
	(export SO=$<; perl ../../../tools/so2h.pl $< $$(basename $${SO%.so}))

msflinker: $(OBJ)
	$(CC) -Wl,-script=script -Wl,--hash-style=sysv $(CFLAGS) -o msflinker $(OBJ) -lgcc
	([ "$(DEBUG)" != "true" ] && strip $@) || true

# elf2bin only has to run on the build machine, don't bother with CFLAGS
msflinker.bin: msflinker elf2bin.c
	$(CC) -march=i386 -m32 -o elf2bin elf2bin.c
	./elf2bin msflinker msflinker.bin

metsrv_rtld.o: $(HEADERS)

rtldtest: rtldtest.c msflinker
	$(CC) -march=i386 -m32 -o rtldtest rtldtest.c -DEP=`objdump -f msflinker | grep start | awk '{ print $$3 }'`

.S.o:
	$(CC) $(CFLAGS) -c $<

.c.o:
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f $(HEADERS)
	rm -f *.o
	rm -f msflinker msflinker.bin msflinker.so
	rm -f rtldtest elf2bin

.PHONY: clean

