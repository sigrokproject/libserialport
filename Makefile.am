## SPDX-License-Identifier: LGPL-3.0-or-later
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

# Cross-platform sources
libserialport_la_SOURCES = serialport.c timing.c libserialport_internal.h

# Win32 versus POSIX
if WIN32
libserialport_la_SOURCES += windows.c serialport_win32.c
else
libserialport_la_SOURCES	+= serialport_posix.c
nodist_libserialport_la_SOURCES	 = baudrates.h
BUILT_SOURCES			 = baudrates.h
endif

# Additional sources for specific POSIX systems
if LINUX
libserialport_la_SOURCES += linux.c linux_termios.c linux_termios.h
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

# Target-specific termios baud rate file. This is opportunistic; if
# $(CC) -E doesn't support any of the macro extraction options, the
# baudrates.sh script still includes an extensive fallback list of
# common constants.
#
# Garbage in the generated output is harmless; all that matters are
# #define Bxxx directives.

# List of options used by various compilers to extract macro definitions;
# these are tried in the order listed until the compiler exits successfully.
# -dM: gcc, clang and derived compilers, icc classic
# -xdumpmacros: Sun Studio (writes to stderr!)
# -qshowmacros: IBM XL classic
# -PD: MSVC (usable with a wrapper such as cccl from the SWIG project)
getmacopts = -dM -xdumpmacros -qshowmacros -PD

CLEANFILES			= baudrates.h

baudrates.h: termios.c config.h baudrates.sh
	$(AM_V_GEN)rm -f $@
	$(AM_V_at)( for opt in $(getmacopts); do \
			$(COMPILE) -E $$opt $< 2>&1 \
			  && break; \
		    done ) | $(SHELL) $(<D)/baudrates.sh $@t
	$(AM_V_at)chmod a-w $@t
	$(AM_V_at)mv $@t $@

library_includedir = $(includedir)
library_include_HEADERS = libserialport.h

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libserialport.pc

TESTS = test_timing test_feature_guards test_baud_termiox.sh
check_PROGRAMS = test_timing test_feature_guards
test_timing_SOURCES = timing.c test_timing.c
test_timing_CFLAGS = $(AM_CFLAGS)
test_feature_guards_SOURCES = test_feature_guards.c
test_feature_guards_CFLAGS = -std=c99 -Wall -Wextra -pedantic

EXTRA_DIST = Doxyfile \
	baudrates.sh \
	termios.c \
	test_baud_termiox.sh \
	tests/baud-termiox/config.h \
	tests/baud-termiox/linux/termios.h \
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
