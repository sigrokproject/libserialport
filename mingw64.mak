# mingw64.mak: build libserialport.dll using MinGW64-w64

# Program for compiling C programs
CC = gcc

# Extra flags to give to the C preprocessor
CPPFLAGS =
CPPFLAGS += -DLIBSERIALPORT_MINGW64BUILD
# CPPFLAGS += -DLIBSERIALPORT_MSBUILD
# CPPFLAGS += -DLIBSERIALPORT_ATBUILD
# CPPFLAGS += -DHAVE_CONFIG_H

# Extra flags to give to the C compiler.
CFLAGS =
CFLAGS += -I. -std=c99
CFLAGS += -Wall -Wextra -pedantic -Wmissing-prototypes -Wshadow
CFLAGS += -g -O2

# Extra flags when invoking the linker
LDFLAGS = -s -shared -Wl,--subsystem,windows

# Library flags or names when invoking the linker
LDLIBS = -lsetupapi

# Command to remove a file
RM = rm -f

H_FILES = libserialport_internal.h libserialport.h
O_FILES = serialport.o timing.o windows.o

all: libserialport.dll

libserialport.dll: $(O_FILES)
	gcc -o libserialport.dll $(O_FILES) $(LDFLAGS) $(LDLIBS)

serialport.o: serialport.c $(H_FILES)
	$(CC) -c $(CPPFLAGS) $(CFLAGS) -o $@ $<

timing.o: timing.c $(H_FILES)
	$(CC) -c $(CPPFLAGS) $(CFLAGS) -o $@ $<

windows.o: windows.c $(H_FILES)
	$(CC) -c $(CPPFLAGS) $(CFLAGS) -o $@ $<

install:
	@echo "install is not yet implemented"
	exit 1

clean:
	$(RM) libserialport.dll
	$(RM) *.o

.PHONY: all install clean
