/*
 * This file is part of the libserialport project.
 *
 * Copyright (C) 2013 Martin Ling <martin-libserialport@earth.li>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * At the time of writing, glibc does not support the Linux kernel interfaces
 * for setting non-standard baud rates and flow control. We therefore have to
 * prepare the correct ioctls ourselves, for which we need the declarations in
 * linux/termios.h.
 *
 * We can't include linux/termios.h in serialport.c however, because its
 * contents conflict with the termios.h provided by glibc. So this file exists
 * to isolate the bits of code which use the kernel termios declarations.
 *
 * The details vary by architecture. Some architectures have c_ispeed/c_ospeed
 * in struct termios, accessed with TCSETS/TCGETS. Others have these fields in
 * struct termios2, accessed with TCSETS2/TCGETS2. Some architectures have the
 * TCSETX/TCGETX ioctls used with struct termiox, others do not.
 */

#if defined(__linux__) && !defined(__ANDROID__)

#include <linux/termios.h>
#include "linux_termios.h"

int get_termios_get_ioctl(void)
{
#ifdef HAVE_TERMIOS2
	return TCGETS2;
#else
	return TCGETS;
#endif
}

int get_termios_set_ioctl(void)
{
#ifdef HAVE_TERMIOS2
	return TCSETS2;
#else
	return TCSETS;
#endif
}

int get_termios_size(void)
{
#ifdef HAVE_TERMIOS2
	return sizeof(struct termios2);
#else
	return sizeof(struct termios);
#endif
}

int get_termios_speed(void *data)
{
#ifdef HAVE_TERMIOS2
	struct termios2 *term = (struct termios2 *) data;
#else
	struct termios *term = (struct termios *) data;
#endif
	if (term->c_ispeed != term->c_ospeed)
		return -1;
	else
		return term->c_ispeed;
}

void set_termios_speed(void *data, int speed)
{
#ifdef HAVE_TERMIOS2
	struct termios2 *term = (struct termios2 *) data;
#else
	struct termios *term = (struct termios *) data;
#endif
	term->c_cflag &= ~CBAUD;
	term->c_cflag |= BOTHER;
	term->c_ispeed = term->c_ospeed = speed;
}

#ifdef HAVE_TERMIOX
int get_termiox_size(void)
{
	return sizeof(struct termiox);
}

int get_termiox_flow(void *data)
{
	struct termiox *termx = (struct termiox *) data;
	int flags = 0;

	if (termx->x_cflag & RTSXOFF)
		flags |= RTS_FLOW;
	if (termx->x_cflag & CTSXON)
		flags |= CTS_FLOW;
	if (termx->x_cflag & DTRXOFF)
		flags |= DTR_FLOW;
	if (termx->x_cflag & DSRXON)
		flags |= DSR_FLOW;

	return flags;
}

void set_termiox_flow(void *data, int flags)
{
	struct termiox *termx = (struct termiox *) data;

	termx->x_cflag &= ~(RTSXOFF | CTSXON | DTRXOFF | DSRXON);

	if (flags & RTS_FLOW)
		termx->x_cflag |= RTSXOFF;
	if (flags & CTS_FLOW)
		termx->x_cflag |= CTSXON;
	if (flags & DTR_FLOW)
		termx->x_cflag |= DTRXOFF;
	if (flags & DSR_FLOW)
		termx->x_cflag |= DSRXON;
}
#endif

#endif
