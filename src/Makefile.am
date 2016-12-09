AUTOMAKE_OPTIONS = subdir-objects

AM_CFLAGS=-I asm/ -I asm/src/

lib_LIBRARIES = libreverse.a
libreverse_a_SOURCES = instrument.c \
		       gotplt.c \
		       revwin/reverse.c \
		       lend/ld.c \
		       asm/src/x86/x86-dis.c
