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

AM_CPPFLAGS = -I$(top_srcdir)

# Enable more compiler warnings.
AM_CFLAGS = -std=c99 -Wall -Wextra -pedantic -Wmissing-prototypes -Wshadow

lib_LTLIBRARIES = libserialport.la

libserialport_la_SOURCES = serialport.c libserialport_internal.h
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

libserialport_la_LIBADD = $(LIBOBJS)
if WIN32
libserialport_la_LIBADD += $(SP_LIBS)
endif

libserialport_la_LDFLAGS = $(SP_LIB_LDFLAGS) -no-undefined
if MACOSX
libserialport_la_LDFLAGS += -framework IOKit -framework CoreFoundation
endif

library_includedir = $(includedir)
library_include_HEADERS = libserialport.h

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libserialport.pc

EXTRA_DIST = Doxyfile

MAINTAINERCLEANFILES = ChangeLog

.PHONY: ChangeLog
ChangeLog:
	git --git-dir $(top_srcdir)/.git log > ChangeLog || touch ChangeLog

dist-hook: ChangeLog

doc: $(library_include_HEADERS) $(top_srcdir)/Doxyfile
	doxygen $(top_srcdir)/Doxyfile
