/* SPDX-License-Identifier: LGPL-3.0-or-later */

#ifndef TEST_LINUX_TERMIOS_H
#define TEST_LINUX_TERMIOS_H

struct termiox {
	unsigned short x_hflag;
	unsigned short x_cflag;
	unsigned short x_rflag[5];
	unsigned short x_sflag;
};

#define RTSXOFF 0x0001
#define CTSXON  0x0002
#define DTRXOFF 0x0004
#define DSRXON  0x0008

#endif
