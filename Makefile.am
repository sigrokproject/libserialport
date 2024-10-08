##
## This file is part of the libserialport project.
##
## Copyright (C) 2010-2012 Bert Vermeulen <bert@biot.com>
## Copyright (C) 2013 Martin Ling <martin-libserialport@earth.li>
##
## This program is free software: you can redistribute it and/or modify
## it under the terms of the GNU Lesser General Public License as
## published by the Free Software Foundation, either version 3 of the
## License, or (at your option) any later version.
##
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##
## You should have received a copy of the GNU Lesser General Public License
## along with this program.  If not, see <http://www.gnu.org/licenses/>.
##

ACLOCAL_AMFLAGS = -I autostuff
AM_LIBTOOLFLAGS = --silent
GNUMAKEFLAGS = --no-print-directory

# Enable more compiler warnings.
AM_CFLAGS = -std=c99 -Wall -Wextra -pedantic -Wmissing-prototypes -Wshadow
# Set flag used in libserialport.h to indicate we are building the library
# using autotools.
AM_CFLAGS += -DLIBSERIALPORT_ATBUILD

lib_LTLIBRARIES = libserialport.la

libserialport_la_SOURCES = serialport.c timing.c libserialport_internal.h
if LINUX
libserialport_la_SOURCES += linux.c linux_termios.c linux_termios.h
endif
if WIN32
libserialport_la_SOURCES += windows.c
endif
if MACOSX
libserialport_la_SOURCES += macosx.c
endif
if FREEBSD
libserialport_la_SOURCES += freebsd.c
endif

libserialport_la_LIBADD = $(SP_LIBS)

libserialport_la_LDFLAGS = -version-info $(SP_LIB_VERSION) -no-undefined
if MACOSX
libserialport_la_LDFLAGS += -framework IOKit -framework CoreFoundation
endif

library_includedir = $(includedir)
library_include_HEADERS = libserialport.h

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libserialport.pc

TESTS = test_timing
check_PROGRAMS = test_timing
test_timing_SOURCES = timing.c test_timing.c
test_timing_CFLAGS = $(AM_CFLAGS)

EXTRA_DIST = Doxyfile \
	examples/Makefile \
	examples/README \
	examples/list_ports.c \
	examples/port_info.c \
	examples/port_config.c \
	examples/await_events.c \
	examples/handle_errors.c \
	examples/send_receive.c \
	examples/examples.sln \
	examples/projects

DISTCLEANFILES = ChangeLog

.PHONY: ChangeLog doc

ChangeLog:
	git --git-dir '$(top_srcdir)/.git' log >$@ || touch $@

dist-hook: ChangeLog

doc: $(nodist_include_HEADERS) $(top_srcdir)/Doxyfile
	doxygen $(top_srcdir)/Doxyfile
