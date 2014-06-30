framework_dir =../../metasploit-framework

OUTPUT=.
 
CFLAGS=-g -Wall -fasm-blocks
CFLAGS+= -I metsrv/ -I common/
CFLAGS+= -fno-stack-protector
CFLAGS+= -fno-builtin -D_SIZE_T_DECLARED
CFLAGS+= -D_BYTE_ORDER=_LITTLE_ENDIAN
CFLAGS+= -march=i386 -m32

all: osx bin
osx:
	$(MAKE) -C common && [ -f common/libsupport.dylib ]
	cp common/libsupport.dylib $(OUTPUT)/libsupport.dylib

	$(MAKE) -C metsrv && [ -f metsrv/libmetsrv.dylib ]
	cp metsrv/libmetsrv.dylib $(OUTPUT)/libmetsrv.dylib

	$(MAKE) -C extensions/stdapi && [ -f extensions/stdapi/ext_server_stdapi.dylib ]
	cp extensions/stdapi/ext_server_stdapi.dylib $(OUTPUT)/ext_server_stdapi.dylib

bin:
	$(CC) -m32 -march=i386 -ldl payloads/reverse_tcp_x86.c -o payloads/reverse_tcp_x86.bin

clean:
	$(MAKE) clean -C common
	$(MAKE) clean -C metsrv
	$(MAKE) clean -C extensions/stdapi
	rm -rf *.dylib payloads/reverse_tcp_x86.bin

install:
	rm -rf $(framework_dir)/data/meterpreter/ext_server_stdapi.dylib
	rm -rf $(framework_dir)/data/osx/libmetsrv.dylib
	rm -rf $(framework_dir)/data/osx/libsupport.dylib

	cp $(OUTPUT)/ext_server_stdapi.dylib $(framework_dir)/data/meterpreter/ext_server_stdapi.dylib
	cp $(OUTPUT)/libmetsrv.dylib $(framework_dir)/data/osx/libmetsrv.dylib
	cp $(OUTPUT)/libsupport.dylib $(framework_dir)/data/osx/libsupport.dylib
	cp payloads/reverse_tcp_x86.bin $(framework_dir)/data/osx/reverse_tcp_x86.bin