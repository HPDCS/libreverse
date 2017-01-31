# Makefile

CC = gcc
INCLUDES = -I$(HOME)/git/libreverse/src

CFLAGS = -g3 -rdynamic -O0 -Wall $(INCLUDES)
LFLAGS = -L$(LIBDIR) $(LIBS)

LIBDIR = $(HOME)/git/libreverse/usr/lib
LIBS = -lreverse -lpthread -lm

HIJACKER = $(HOME)/git/hijacker/usr/bin/hijacker

SRCS = hash.c utils.c
OBJS = $(SRCS:.c=.o)

TESTS = test test1

GDB = gdb --tui --args


all: $(TESTS)


test: $(OBJS) test.o
	#$(HIJACKER) -c conf.xml -i $@.o -o $@_instrumented.o #-vvvvv
	$(CC) $@.o $(OBJS) $(LFLAGS) -o $@
	@echo "${@} generated!"

test1: $(OBJS) test1.o
	$(CC) $@.o $(OBJS) $(LFLAGS) -o $@
	@echo "${@} generated!"

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@	 

.PHONY: clean list
list:
	@echo $(TESTS)

clean:
	@rm -f *.o gmon.out graphdump.txt $(TESTS)
