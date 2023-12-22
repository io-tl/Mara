CC = musl-gcc
CFLAGS = -std=gnu99 -Wall -Wextra -pedantic -O3
AR = ar
ARFLAGS = rcs
RANLIB = ranlib


all: libctty.a ctty

libctty.a: libctty.c libctty.h
	$(CC) $(CFLAGS) -c libctty.c
	$(AR) $(ARFLAGS) libctty.a libctty.o
	$(RANLIB) libctty.a

ctty: libctty.o ctty.c
	$(CC) $(CFLAGS) -L. -o ctty ctty.c -lctty

clean: 
	rm libctty.o libctty.a ctty
