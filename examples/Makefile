# A simple Makefile to build the examples in this directory.
#
# This example file is released to the public domain.

CC = gcc
PKG_CONFIG = pkg-config
CFLAGS = -g -Wall $(shell $(PKG_CONFIG) --cflags libserialport)
LIBS = $(shell $(PKG_CONFIG) --libs libserialport)

SOURCES = $(wildcard *.c)

BINARIES = $(SOURCES:.c=)

%: %.c
	$(CC) $(CFLAGS) $< $(LIBS) -o $@

all: $(BINARIES)

clean:
	rm $(BINARIES)
