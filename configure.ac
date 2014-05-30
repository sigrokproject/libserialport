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
m4_define([sp_package_version_micro], [0])
m4_define([sp_package_version], [sp_package_version_major.sp_package_version_minor.sp_package_version_micro])

AC_INIT([libserialport], [sp_package_version], [martin-libserialport@earth.li],
	[libserialport], [http://sigrok.org/wiki/Libserialport])
AC_CONFIG_MACRO_DIR([autostuff])
AC_CONFIG_AUX_DIR([autostuff])

AC_CANONICAL_TARGET

# We require at least automake 1.11 (needed for 'silent rules').
AM_INIT_AUTOMAKE([1.11 -Wall -Werror check-news])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])

# Enable more compiler warnings via -Wall and -Wextra.
CFLAGS="$CFLAGS -Wall -Wextra"

# Checks for programs.
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S

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

# Checks for libraries.

# This variable collects the pkg-config names of all detected libs.
# It is then used to construct the "Requires.private:" field in the
# libserialport.pc file.
SP_PKGLIBS=""

case $target_os in
*linux*)
	AM_CONDITIONAL([LINUX], true)
	;;
*darwin*)
	AM_CONDITIONAL([LINUX], false)
	LDFLAGS="$LDFLAGS -Wl,-framework -Wl,IOKit -Wl,-framework -Wl,CoreFoundation"
	AC_CHECK_HEADER(IOKit/IOKitLib.h, [], [AC_MSG_ERROR([IOKit/IOKitLib.h not found])])
	;;
*)
	AM_CONDITIONAL([LINUX], false)
esac

AC_SUBST(SP_PKGLIBS)

# Define size_t if not defined as standard.
AC_TYPE_SIZE_T

# Check for specific termios structures.
AC_CHECK_TYPE([struct termios2], [AC_DEFINE(HAVE_TERMIOS2, 1)], [], [[#include <linux/termios.h>]])
AC_CHECK_TYPE([struct termiox], [AC_DEFINE(HAVE_TERMIOX, 1)], [], [[#include <linux/termios.h>]])
AC_CHECK_MEMBERS([struct termios.c_ispeed, struct termios.c_ospeed],
	[AC_DEFINE(HAVE_TERMIOS_SPEED, 1)], [], [[#include <linux/termios.h>]])
AC_CHECK_MEMBERS([struct termios2.c_ispeed, struct termios2.c_ospeed],
	[AC_DEFINE(HAVE_TERMIOS2_SPEED, 1)], [], [[#include <linux/termios.h>]])

AC_SUBST(MAKEFLAGS, '--no-print-directory')
AC_SUBST(AM_LIBTOOLFLAGS, '--silent')

SP_PACKAGE_VERSION_MAJOR=sp_package_version_major
SP_PACKAGE_VERSION_MINOR=sp_package_version_minor
SP_PACKAGE_VERSION_MICRO=sp_package_version_micro
SP_PACKAGE_VERSION=sp_package_version

AC_SUBST(SP_PACKAGE_VERSION_MAJOR)
AC_SUBST(SP_PACKAGE_VERSION_MINOR)
AC_SUBST(SP_PACKAGE_VERSION_MICRO)
AC_SUBST(SP_PACKAGE_VERSION)

AC_CONFIG_FILES([Makefile libserialport.h libserialport.pc])

AC_OUTPUT

echo
echo "libserialport configuration summary:"
echo
echo "  - Package version (major.minor.micro):    $SP_PACKAGE_VERSION"
echo "  - Library version (current:revision:age): $SP_LIB_VERSION"
echo "  - Prefix: $prefix"
echo "  - Building on: $build"
echo "  - Building for: $host"
echo
