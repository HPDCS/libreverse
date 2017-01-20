AUTOMAKE_OPTIONS = subdir-objects

AM_CFLAGS=-I asm/ -I asm/src/ -I reverse -I reverse/src

lib_LIBRARIES = libreverse.a
libreverse_a_SOURCES = instrument.c \
		       gotplt.c \
		       mm/slab.c \
		       reverse/reverse.c \
		       reverse/fmap.c \
		       reverse/ralloc.c \
		       lend/ld.c \
		       asm/src/x86/x86-dis.c \
		       dl_selector.S
