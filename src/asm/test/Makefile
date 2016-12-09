# Invoke as 'make TARGET=arm' to generate bytestreams in arm subfolder.
# This supposes that you are generating the bytestreams on TARGET

all:
	gcc -c queue.c -o obj.o
	objcopy --dump-section .text=$(TARGET)/queue.bin obj.o
	gcc -c cube.c -lm -o obj.o
	objcopy --dump-section .text=$(TARGET)/cube.bin obj.o
	gcc -c bubblesort.c -o obj.o
	objcopy --dump-section .text=$(TARGET)/bubblesort.bin obj.o
	gcc -c binarysearch.c -o obj.o
	objcopy --dump-section .text=$(TARGET)/binarysearch.bin obj.o
	gcc -c circle.c -lm -o obj.o
	objcopy --dump-section .text=$(TARGET)/circle.bin obj.o
	unlink obj.o
