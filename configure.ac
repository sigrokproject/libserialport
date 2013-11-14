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

# We require at least autoconf 2.63 (AC_INIT format changed there).
AC_PREREQ([2.63])

# libserialport package version number (NOT the same as shared lib version!).
m4_define([sp_package_version_major], [0])
m4_define([sp_package_version_minor], [1])
m4_define([sp_package_version], [sp_package_version_major.sp_package_version_minor])

AC_INIT([libserialport], [sp_package_version], [martin-libserialport@earth.li],
	[libserialport], [http://github.com/martinling/libserialport])
AC_CONFIG_MACRO_DIR([autostuff])
AC_CONFIG_AUX_DIR([autostuff])

AC_CANONICAL_TARGET

# We require at least automake 1.11 (needed for 'silent rules').
AM_INIT_AUTOMAKE([1.11 -Wall -Werror])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])

AH_TOP([#ifndef SP_CONFIG_H
#define SP_CONFIG_H    /* To stop multiple inclusions. */])
AH_BOTTOM([#endif /* SP_CONFIG_H */])

# Enable more compiler warnings via -Wall and -Wextra.
CFLAGS="$CFLAGS -Wall -Wextra"

# Checks for programs.
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S

# Required for per-target flags or subdir-objects with C sources.
AM_PROG_CC_C_O

# Initialize libtool.
LT_INIT

# Initialize pkg-config.
# We require at least 0.22, as "Requires.private" behaviour changed there.
PKG_PROG_PKG_CONFIG([0.22])

# Library version for libserialport (NOT the same as the package version).
# Carefully read the libtool docs before updating these numbers!
# The algorithm for determining which number to change (and how) is nontrivial!
# http://www.gnu.org/software/libtool/manual/libtool.html#Updating-version-info
SP_LIB_VERSION_CURRENT=0
SP_LIB_VERSION_REVISION=0
SP_LIB_VERSION_AGE=0
SP_LIB_VERSION="$SP_LIB_VERSION_CURRENT:$SP_LIB_VERSION_REVISION:$SP_LIB_VERSION_AGE"
SP_LIB_LDFLAGS="-version-info $SP_LIB_VERSION"
AC_SUBST(SP_LIB_VERSION_CURRENT)
AC_SUBST(SP_LIB_VERSION_REVISION)
AC_SUBST(SP_LIB_VERSION_AGE)
AC_SUBST(SP_LIB_VERSION)
AC_SUBST(SP_LIB_LDFLAGS)

# Checks for header files.
# These are already checked: inttypes.h dlfcn.h memory.h stdint.h stdlib.h
# string.h strings.h sys/types.h sys/stat.h unistd.h
AC_CHECK_HEADERS([errno.h fcntl.h stddef.h sys/ioctl.h termios.h])

case $target_os in
*linux*)
	# On Linux libudev is currently a hard requirement.
	PKG_CHECK_MODULES([libudev], [libudev >= 0],
		[CFLAGS="$CFLAGS $libudev_CFLAGS"; LIBS="$LIBS $libudev_LIBS"])
	;;
*darwin*)
	LDFLAGS="$LDFLAGS -Wl,-framework -Wl,IOKit -Wl,-framework -Wl,CoreFoundation"
	AC_CHECK_HEADER(IOKit/IOKitLib.h, [], [AC_MSG_ERROR([IOKit/IOKitLib.h not found])])
	;;
esac

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T

# Checks for library functions.
AC_CHECK_FUNCS([strerror])

AC_SUBST(MAKEFLAGS, '--no-print-directory')
AC_SUBST(AM_LIBTOOLFLAGS, '--silent')

SP_PACKAGE_VERSION_MAJOR=sp_package_version_major
SP_PACKAGE_VERSION_MINOR=sp_package_version_minor
SP_PACKAGE_VERSION=sp_package_version

AC_SUBST(SP_PACKAGE_VERSION_MAJOR)
AC_SUBST(SP_PACKAGE_VERSION_MINOR)
AC_SUBST(SP_PACKAGE_VERSION)

AC_CONFIG_FILES([Makefile libserialport.pc])

AC_OUTPUT

echo
echo "libserialport configuration summary:"
echo
echo "  - Package version (major.minor):          $SP_PACKAGE_VERSION"
echo "  - Library version (current:revision:age): $SP_LIB_VERSION"
echo "  - Prefix: $prefix"
echo "  - Building on: $build"
echo "  - Building for: $host"
echo
