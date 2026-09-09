/*
 * SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * This file is part of the libserialport project.
 *
 * Copyright (C) 2010-2012 Bert Vermeulen <bert@biot.com>
 * Copyright (C) 2010-2015 Uwe Hermann <uwe@hermann-uwe.de>
 * Copyright (C) 2013-2015 Martin Ling <martin-libserialport@earth.li>
 * Copyright (C) 2013 Matthias Heidbrink <m-sigrok@heidbrink.biz>
 * Copyright (C) 2014 Aurelien Jacobs <aurel@gnuage.org>
 * Copyright (C) 2026 H. Peter Anvin <hpa@zytor.com>
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

#include "libserialport_internal.h"

#ifndef HAVE_CFSETOBAUD
#define MAKE_BAUD_TABLE std_baudrates
#include "baudrates.h"

#ifdef SPEED_T_IS_SANE
#define cfsetibaud cfsetispeed
#define cfsetobaud cfsetospeed
#define cfgetibaud cfgetispeed
#define cfgetobaud cfgetospeed
#define HAVE_CFSETOBAUD 1
#endif
#endif

SP_PRIV void sp_platform_init_port(struct sp_port *port)
{
	port->fd = -1;
}

SP_PRIV enum sp_return sp_platform_canonicalize_port_name(const char *portname,
	char **canonical_name)
{
#ifdef HAVE_REALPATH
	char pathbuf[PATH_MAX + 1];
	char *res;
	size_t len;

	res = realpath(portname, pathbuf);
	if (!res)
		return SP_ERR_ARG;

	len = strlen(pathbuf) + 1;
	if (!(*canonical_name = malloc(len)))
		return SP_ERR_MEM;
	memcpy(*canonical_name, pathbuf, len);
#else
	(void)portname;
	(void)canonical_name;
#endif

	return SP_OK;
}

SP_PRIV bool sp_platform_port_is_open(const struct sp_port *port)
{
	return port->fd >= 0;
}

SP_PRIV void sp_platform_free_port(struct sp_port *port)
{
	(void)port;
}

SP_PRIV enum sp_return sp_platform_open(struct sp_port *port, enum sp_mode flags)
{
	int flags_local = O_NONBLOCK | O_NOCTTY | O_CLOEXEC;

	/* Map 'flags' to the OS-specific settings. */
	if ((flags & SP_MODE_READ_WRITE) == SP_MODE_READ_WRITE)
		flags_local |= O_RDWR;
	else if (flags & SP_MODE_READ)
		flags_local |= O_RDONLY;
	else if (flags & SP_MODE_WRITE)
		flags_local |= O_WRONLY;

	if ((port->fd = open(port->name, flags_local)) < 0)
		RETURN_FAIL("open() failed");

	/*
	 * On POSIX in the default case the file descriptor of a serial port
	 * is not opened exclusively. Therefore the settings of a port are
	 * overwritten if the serial port is opened a second time. Windows
	 * opens all serial ports exclusively.
	 * So the idea is to open the serial ports alike in the exclusive mode.
	 *
	 * ioctl(*, TIOCEXCL) defines the file descriptor as exclusive. So all
	 * further open calls on the serial port will fail.
	 *
	 * There is a race condition if two processes open the same serial
	 * port. None of the processes will notice the exclusive ownership of
	 * the other process because ioctl() doesn't return an error code if
	 * the file descriptor is already marked as exclusive.
	 * This can be solved with flock(). It returns an error if the file
	 * descriptor is already locked by another process.
	 */
#ifdef HAVE_FLOCK
	if (flock(port->fd, LOCK_EX | LOCK_NB) < 0)
		RETURN_FAIL("flock() failed");
#endif

#ifdef TIOCEXCL
	/*
	 * Before Linux 3.8 ioctl(*, TIOCEXCL) was not implemented and could
	 * lead to EINVAL or ENOTTY.
	 * These errors aren't fatal and can be ignored.
	 */
	if (ioctl(port->fd, TIOCEXCL) < 0 && errno != EINVAL && errno != ENOTTY)
		RETURN_FAIL("ioctl() failed");
#endif

	RETURN_OK();
}

SP_PRIV enum sp_return sp_platform_set_default_config(struct sp_port *port,
	struct port_data *data)
{
	/* Set sane port settings. */
	(void)port;
	/* Turn off all fancy termios tricks, give us a raw channel. */
	data->term.c_iflag &= ~(IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR | ICRNL | IMAXBEL);
#ifdef IUCLC
	data->term.c_iflag &= ~IUCLC;
#endif
	data->term.c_oflag &= ~(OPOST | ONLCR | OCRNL | ONOCR | ONLRET);
#ifdef OLCUC
	data->term.c_oflag &= ~OLCUC;
#endif
#ifdef NLDLY
	data->term.c_oflag &= ~NLDLY;
#endif
#ifdef CRDLY
	data->term.c_oflag &= ~CRDLY;
#endif
#ifdef TABDLY
	data->term.c_oflag &= ~TABDLY;
#endif
#ifdef BSDLY
	data->term.c_oflag &= ~BSDLY;
#endif
#ifdef VTDLY
	data->term.c_oflag &= ~VTDLY;
#endif
#ifdef FFDLY
	data->term.c_oflag &= ~FFDLY;
#endif
#ifdef OFILL
	data->term.c_oflag &= ~OFILL;
#endif
	data->term.c_lflag &= ~(ISIG | ICANON | ECHO | IEXTEN);
	data->term.c_cc[VMIN] = 0;
	data->term.c_cc[VTIME] = 0;

	/* Ignore modem status lines; enable receiver; leave control lines alone on close. */
	data->term.c_cflag |= (CLOCAL | CREAD);
	data->term.c_cflag &= ~(HUPCL);
	RETURN_OK();
}

static enum sp_return add_handle(struct sp_event_set *event_set,
		event_handle handle, enum sp_event mask)
{
	void *new_handles;
	enum sp_event *new_masks;

	TRACE("%p, %d, %d", event_set, handle, mask);

	if (!(new_handles = realloc(event_set->handles,
			sizeof(event_handle) * (event_set->count + 1))))
		RETURN_ERROR(SP_ERR_MEM, "Handle array realloc() failed");

	event_set->handles = new_handles;

	if (!(new_masks = realloc(event_set->masks,
			sizeof(enum sp_event) * (event_set->count + 1))))
		RETURN_ERROR(SP_ERR_MEM, "Mask array realloc() failed");

	event_set->masks = new_masks;

	((event_handle *) event_set->handles)[event_set->count] = handle;
	event_set->masks[event_set->count] = mask;

	event_set->count++;

	RETURN_OK();
}

#ifdef USE_TERMIOS_SPEED
static enum sp_return get_baudrate(int fd, int *baudrate)
{
	void *data;

	TRACE("%d, %p", fd, baudrate);

	DEBUG("Getting baud rate");

	if (!(data = malloc(get_termios_size())))
		RETURN_ERROR(SP_ERR_MEM, "termios malloc failed");

	if (ioctl(fd, get_termios_get_ioctl(), data) < 0) {
		free(data);
		RETURN_FAIL("Getting termios failed");
	}

	*baudrate = get_termios_speed(data);

	free(data);

	RETURN_OK();
}

static enum sp_return set_baudrate(int fd, int baudrate)
{
	void *data;

	TRACE("%d, %d", fd, baudrate);

	DEBUG("Getting baud rate");

	if (!(data = malloc(get_termios_size())))
		RETURN_ERROR(SP_ERR_MEM, "termios malloc failed");

	if (ioctl(fd, get_termios_get_ioctl(), data) < 0) {
		free(data);
		RETURN_FAIL("Getting termios failed");
	}

	DEBUG("Setting baud rate");

	set_termios_speed(data, baudrate);

	if (ioctl(fd, get_termios_set_ioctl(), data) < 0) {
		free(data);
		RETURN_FAIL("Setting termios failed");
	}

	free(data);

	RETURN_OK();
}
#endif /* USE_TERMIOS_SPEED */

#ifdef USE_TERMIOX
static enum sp_return get_flow(int fd, struct port_data *data)
{
	void *termx;

	TRACE("%d, %p", fd, data);

	DEBUG("Getting advanced flow control");

	if (!(termx = malloc(get_termiox_size())))
		RETURN_ERROR(SP_ERR_MEM, "termiox malloc failed");

	if (ioctl(fd, TCGETX, termx) < 0) {
		free(termx);
		RETURN_FAIL("Getting termiox failed");
	}

	get_termiox_flow(termx, &data->rts_flow, &data->cts_flow,
			&data->dtr_flow, &data->dsr_flow);

	free(termx);

	RETURN_OK();
}

static enum sp_return set_flow(int fd, struct port_data *data)
{
	void *termx;

	TRACE("%d, %p", fd, data);

	DEBUG("Getting advanced flow control");

	if (!(termx = malloc(get_termiox_size())))
		RETURN_ERROR(SP_ERR_MEM, "termiox malloc failed");

	if (ioctl(fd, TCGETX, termx) < 0) {
		free(termx);
		RETURN_FAIL("Getting termiox failed");
	}

	DEBUG("Setting advanced flow control");

	set_termiox_flow(termx, data->rts_flow, data->cts_flow,
			data->dtr_flow, data->dsr_flow);

	if (ioctl(fd, TCSETX, termx) < 0) {
		free(termx);
		RETURN_FAIL("Setting termiox failed");
	}

	free(termx);

	RETURN_OK();
}
#endif /* USE_TERMIOX */

static enum sp_return get_config(struct sp_port *port, struct port_data *data,
	struct sp_port_config *config)
{
#if !defined(HAVE_CFSETOBAUD)
	unsigned int i;
#endif

	TRACE("%p, %p, %p", port, data, config);

	DEBUG_FMT("Getting configuration for port %s", port->name);


	if (tcgetattr(port->fd, &data->term) < 0)
		RETURN_FAIL("tcgetattr() failed");

	if (ioctl(port->fd, TIOCMGET, &data->controlbits) < 0)
		RETURN_FAIL("TIOCMGET ioctl failed");

#ifdef USE_TERMIOX
	int ret = get_flow(port->fd, data);

	if (ret == SP_ERR_FAIL && errno == EINVAL)
		data->termiox_supported = 0;
	else if (ret < 0)
		RETURN_CODEVAL(ret);
	else
		data->termiox_supported = 1;
#else
	data->termiox_supported = 0;
#endif

#ifdef HAVE_CFSETOBAUD
	config->baudrate = cfgetobaud(&data->term);
#else
	{
		speed_t speed = cfgetospeed(&data->term);
		for (i = 0; i < NUM_STD_BAUDRATES; i++) {
		    if (speed == std_baudrates[i].index) {
			    config->baudrate = std_baudrates[i].value;
			    break;
		    }
		}
	}

	if (i == NUM_STD_BAUDRATES) {
#ifdef __APPLE__
		config->baudrate = (int)data->term.c_ospeed;
#elif defined(USE_TERMIOS_SPEED)
		TRY(get_baudrate(port->fd, &config->baudrate));
#else
		config->baudrate = -1;
#endif
	}
#endif /* HAVE_CFSETOBAUD */

	switch (data->term.c_cflag & CSIZE) {
	case CS8:
		config->bits = 8;
		break;
	case CS7:
		config->bits = 7;
		break;
	case CS6:
		config->bits = 6;
		break;
	case CS5:
		config->bits = 5;
		break;
	default:
		config->bits = -1;
	}

	if (!(data->term.c_cflag & PARENB) && (data->term.c_iflag & IGNPAR))
		config->parity = SP_PARITY_NONE;
	else if (!(data->term.c_cflag & PARENB) || (data->term.c_iflag & IGNPAR))
		config->parity = -1;
#ifdef CMSPAR
	else if (data->term.c_cflag & CMSPAR)
		config->parity = (data->term.c_cflag & PARODD) ? SP_PARITY_MARK : SP_PARITY_SPACE;
#endif
	else
		config->parity = (data->term.c_cflag & PARODD) ? SP_PARITY_ODD : SP_PARITY_EVEN;

	config->stopbits = (data->term.c_cflag & CSTOPB) ? 2 : 1;

	if (data->term.c_cflag & CRTSCTS) {
		config->rts = SP_RTS_FLOW_CONTROL;
		config->cts = SP_CTS_FLOW_CONTROL;
	} else {
		if (data->termiox_supported && data->rts_flow)
			config->rts = SP_RTS_FLOW_CONTROL;
		else
			config->rts = (data->controlbits & TIOCM_RTS) ? SP_RTS_ON : SP_RTS_OFF;

		config->cts = (data->termiox_supported && data->cts_flow) ?
			SP_CTS_FLOW_CONTROL : SP_CTS_IGNORE;
	}

	if (data->termiox_supported && data->dtr_flow)
		config->dtr = SP_DTR_FLOW_CONTROL;
	else
		config->dtr = (data->controlbits & TIOCM_DTR) ? SP_DTR_ON : SP_DTR_OFF;

	config->dsr = (data->termiox_supported && data->dsr_flow) ?
		SP_DSR_FLOW_CONTROL : SP_DSR_IGNORE;

	if (data->term.c_iflag & IXOFF) {
		if (data->term.c_iflag & IXON)
			config->xon_xoff = SP_XONXOFF_INOUT;
		else
			config->xon_xoff = SP_XONXOFF_IN;
	} else {
		if (data->term.c_iflag & IXON)
			config->xon_xoff = SP_XONXOFF_OUT;
		else
			config->xon_xoff = SP_XONXOFF_DISABLED;
	}

	RETURN_OK();
}

static enum sp_return set_config(struct sp_port *port, struct port_data *data,
	const struct sp_port_config *config)
{
#if !defined(HAVE_CFSETOBAUD)
	size_t i;
#endif

#ifdef __APPLE__
	BAUD_TYPE baud_nonstd;

	baud_nonstd = B0;
#endif
#ifdef USE_TERMIOS_SPEED
	int baud_nonstd = 0;
#endif

	TRACE("%p, %p, %p", port, data, config);

	DEBUG_FMT("Setting configuration for port %s", port->name);


	int controlbits;

	if (config->baudrate >= 0) {
#ifdef HAVE_CFSETOBAUD
		if (cfsetobaud(&data->term, config->baudrate) < 0)
			RETURN_FAIL(STRING(cfsetobaud)"() failed");
		if (cfsetibaud(&data->term, config->baudrate) < 0)
			RETURN_FAIL(STRING(cfsetibaud)"() failed");
#else
		size_t l = 0;
		size_t h = NUM_STD_BAUDRATES;
		while (l < h) {
			size_t i = (l+h) >> 1;
			if (config->baudrate < std_baudrates[i].value) {
				h = i;
			} else if (config->baudrate == std_baudrates[i].value) {
				speed_t ix = std_baudrates[i].index;
				if (cfsetospeed(&data->term, ix) < 0)
					RETURN_FAIL("cfsetospeed() failed");
				if (cfsetispeed(&data->term, ix) < 0)
					RETURN_FAIL("cfsetispeed() failed");
				break;
			} else {
				l = i+1;
			}
		}

		/* Non-standard baud rate? */
		if (l >= h) {
#ifdef __APPLE__
			/* Set "dummy" baud rate. */
			if (cfsetspeed(&data->term, B9600) < 0)
				RETURN_FAIL("cfsetspeed() failed");
			baud_nonstd = config->baudrate;
#elif defined(USE_TERMIOS_SPEED)
			baud_nonstd = 1;
#else
			RETURN_ERROR(SP_ERR_SUPP, "Non-standard baudrate not supported");
#endif
		}
#endif /* HAVE_CFSETOBAUD */
	}

	if (config->bits >= 0) {
		data->term.c_cflag &= ~CSIZE;
		switch (config->bits) {
		case 8:
			data->term.c_cflag |= CS8;
			break;
		case 7:
			data->term.c_cflag |= CS7;
			break;
		case 6:
			data->term.c_cflag |= CS6;
			break;
		case 5:
			data->term.c_cflag |= CS5;
			break;
		default:
			RETURN_ERROR(SP_ERR_ARG, "Invalid data bits setting");
		}
	}

	if (config->parity >= 0) {
		data->term.c_iflag &= ~IGNPAR;
		data->term.c_cflag &= ~(PARENB | PARODD);
#ifdef CMSPAR
		data->term.c_cflag &= ~CMSPAR;
#endif
		switch (config->parity) {
		case SP_PARITY_NONE:
			data->term.c_iflag |= IGNPAR;
			break;
		case SP_PARITY_EVEN:
			data->term.c_cflag |= PARENB;
			break;
		case SP_PARITY_ODD:
			data->term.c_cflag |= PARENB | PARODD;
			break;
#ifdef CMSPAR
		case SP_PARITY_MARK:
			data->term.c_cflag |= PARENB | PARODD;
			data->term.c_cflag |= CMSPAR;
			break;
		case SP_PARITY_SPACE:
			data->term.c_cflag |= PARENB;
			data->term.c_cflag |= CMSPAR;
			break;
#else
		case SP_PARITY_MARK:
		case SP_PARITY_SPACE:
			RETURN_ERROR(SP_ERR_SUPP, "Mark/space parity not supported");
#endif
		default:
			RETURN_ERROR(SP_ERR_ARG, "Invalid parity setting");
		}
	}

	if (config->stopbits >= 0) {
		data->term.c_cflag &= ~CSTOPB;
		switch (config->stopbits) {
		case 1:
			data->term.c_cflag &= ~CSTOPB;
			break;
		case 2:
			data->term.c_cflag |= CSTOPB;
			break;
		default:
			RETURN_ERROR(SP_ERR_ARG, "Invalid stop bits setting");
		}
	}

	if (config->rts >= 0 || config->cts >= 0) {
		if (data->termiox_supported) {
			data->rts_flow = data->cts_flow = 0;
			switch (config->rts) {
			case SP_RTS_OFF:
			case SP_RTS_ON:
				controlbits = TIOCM_RTS;
				if (ioctl(port->fd, config->rts == SP_RTS_ON ? TIOCMBIS : TIOCMBIC, &controlbits) < 0)
					RETURN_FAIL("Setting RTS signal level failed");
				break;
			case SP_RTS_FLOW_CONTROL:
				data->rts_flow = 1;
				break;
			default:
				break;
			}
			if (config->cts == SP_CTS_FLOW_CONTROL)
				data->cts_flow = 1;

			if (data->rts_flow && data->cts_flow)
				data->term.c_iflag |= CRTSCTS;
			else
				data->term.c_iflag &= ~CRTSCTS;
		} else {
			/* Asymmetric use of RTS/CTS not supported. */
			if (data->term.c_iflag & CRTSCTS) {
				/* Flow control can only be disabled for both RTS & CTS together. */
				if (config->rts >= 0 && config->rts != SP_RTS_FLOW_CONTROL) {
					if (config->cts != SP_CTS_IGNORE)
						RETURN_ERROR(SP_ERR_SUPP, "RTS & CTS flow control must be disabled together");
				}
				if (config->cts >= 0 && config->cts != SP_CTS_FLOW_CONTROL) {
					if (config->rts <= 0 || config->rts == SP_RTS_FLOW_CONTROL)
						RETURN_ERROR(SP_ERR_SUPP, "RTS & CTS flow control must be disabled together");
				}
			} else {
				/* Flow control can only be enabled for both RTS & CTS together. */
				if (((config->rts == SP_RTS_FLOW_CONTROL) && (config->cts != SP_CTS_FLOW_CONTROL)) ||
					((config->cts == SP_CTS_FLOW_CONTROL) && (config->rts != SP_RTS_FLOW_CONTROL)))
					RETURN_ERROR(SP_ERR_SUPP, "RTS & CTS flow control must be enabled together");
			}

			if (config->rts >= 0) {
				if (config->rts == SP_RTS_FLOW_CONTROL) {
					data->term.c_iflag |= CRTSCTS;
				} else {
					controlbits = TIOCM_RTS;
					if (ioctl(port->fd, config->rts == SP_RTS_ON ? TIOCMBIS : TIOCMBIC,
							&controlbits) < 0)
						RETURN_FAIL("Setting RTS signal level failed");
				}
			}
		}
	}

	if (config->dtr >= 0 || config->dsr >= 0) {
		if (data->termiox_supported) {
			data->dtr_flow = data->dsr_flow = 0;
			switch (config->dtr) {
			case SP_DTR_OFF:
			case SP_DTR_ON:
				controlbits = TIOCM_DTR;
				if (ioctl(port->fd, config->dtr == SP_DTR_ON ? TIOCMBIS : TIOCMBIC, &controlbits) < 0)
					RETURN_FAIL("Setting DTR signal level failed");
				break;
			case SP_DTR_FLOW_CONTROL:
				data->dtr_flow = 1;
				break;
			default:
				break;
			}
			if (config->dsr == SP_DSR_FLOW_CONTROL)
				data->dsr_flow = 1;
		} else {
			/* DTR/DSR flow control not supported. */
			if (config->dtr == SP_DTR_FLOW_CONTROL || config->dsr == SP_DSR_FLOW_CONTROL)
				RETURN_ERROR(SP_ERR_SUPP, "DTR/DSR flow control not supported");

			if (config->dtr >= 0) {
				controlbits = TIOCM_DTR;
				if (ioctl(port->fd, config->dtr == SP_DTR_ON ? TIOCMBIS : TIOCMBIC,
						&controlbits) < 0)
					RETURN_FAIL("Setting DTR signal level failed");
			}
		}
	}

	if (config->xon_xoff >= 0) {
		data->term.c_iflag &= ~(IXON | IXOFF | IXANY);
		switch (config->xon_xoff) {
		case SP_XONXOFF_DISABLED:
			break;
		case SP_XONXOFF_IN:
			data->term.c_iflag |= IXOFF;
			break;
		case SP_XONXOFF_OUT:
			data->term.c_iflag |= IXON | IXANY;
			break;
		case SP_XONXOFF_INOUT:
			data->term.c_iflag |= IXON | IXOFF | IXANY;
			break;
		default:
			RETURN_ERROR(SP_ERR_ARG, "Invalid XON/XOFF setting");
		}
	}

	if (tcsetattr(port->fd, TCSANOW, &data->term) < 0)
		RETURN_FAIL("tcsetattr() failed");

#ifdef __APPLE__
	if (baud_nonstd != B0) {
		if (ioctl(port->fd, IOSSIOSPEED, &baud_nonstd) == -1)
			RETURN_FAIL("IOSSIOSPEED ioctl failed");
		/*
		 * Set baud rates in data->term to correct, but incompatible
		 * with tcsetattr() value, same as delivered by tcgetattr().
		 */
		if (cfsetspeed(&data->term, baud_nonstd) < 0)
			RETURN_FAIL("cfsetspeed() failed");
	}
#elif defined(__linux__)
#ifdef USE_TERMIOS_SPEED
	if (baud_nonstd)
		TRY(set_baudrate(port->fd, config->baudrate));
#endif
#ifdef USE_TERMIOX
	if (data->termiox_supported)
		TRY(set_flow(port->fd, data));
#endif
#endif


	RETURN_OK();
}

SP_PRIV enum sp_return sp_platform_get_config(struct sp_port *port,
	struct port_data *data, struct sp_port_config *config)
{
	return get_config(port, data, config);
}

SP_PRIV enum sp_return sp_platform_set_config(struct sp_port *port,
	struct port_data *data, const struct sp_port_config *config)
{
	return set_config(port, data, config);
}

SP_API enum sp_return sp_get_port_handle(const struct sp_port *port,
                                         void *result_ptr)
{
	TRACE("%p, %p", port, result_ptr);

	if (!port)
		RETURN_ERROR(SP_ERR_ARG, "Null port");
	if (!result_ptr)
		RETURN_ERROR(SP_ERR_ARG, "Null result pointer");

	int *fd_ptr = result_ptr;
	*fd_ptr = port->fd;

	RETURN_OK();
}

SP_API enum sp_return sp_close(struct sp_port *port)
{
	TRACE("%p", port);

	CHECK_OPEN_PORT();

	DEBUG_FMT("Closing port %s", port->name);

#ifdef TIOCNXCL
	ioctl(port->fd, TIOCNXCL);
#endif

	/* Returns 0 upon success, -1 upon failure. */
	if (close(port->fd) == -1)
		RETURN_FAIL("close() failed");
	port->fd = -1;

	RETURN_OK();
}

SP_API enum sp_return sp_flush(struct sp_port *port, enum sp_buffer buffers)
{
	TRACE("%p, 0x%x", port, buffers);

	CHECK_OPEN_PORT();

	if (buffers > SP_BUF_BOTH)
		RETURN_ERROR(SP_ERR_ARG, "Invalid buffer selection");

	const char *buffer_names[] = {"no", "input", "output", "both"};

	DEBUG_FMT("Flushing %s buffers on port %s",
		buffer_names[buffers], port->name);

	int flags = 0;
	if (buffers == SP_BUF_BOTH)
		flags = TCIOFLUSH;
	else if (buffers == SP_BUF_INPUT)
		flags = TCIFLUSH;
	else if (buffers == SP_BUF_OUTPUT)
		flags = TCOFLUSH;

	/* Returns 0 upon success, -1 upon failure. */
	if (tcflush(port->fd, flags) < 0)
		RETURN_FAIL("tcflush() failed");
	RETURN_OK();
}

SP_API enum sp_return sp_drain(struct sp_port *port)
{
	TRACE("%p", port);

	CHECK_OPEN_PORT();

	DEBUG_FMT("Draining port %s", port->name);

	while (1) {
		int result;
#ifdef HAVE_TCDRAIN
		/* Proper POSIX */
		result = tcdrain(port->fd);
#elif defined(TIOCDRAIN)
		/*
		 * No system is known which has TIOCDRAIN but is missing
		 * tcdrain(), however, this guards against any such system
		 * appearing and invoking the TCSBRK fallback, which might
		 * not work on such systems.
		 */
		result = ioctl(port->fd, TIOCDRAIN);
#elif defined(TCSBRK)
		/*
		 * Android only has tcdrain from platform 21 onwards.
		 * On previous API versions, use the ioctl directly.
		 *
		 * TCSBRK(1) behaves like tcdrain() on most systems;
		 * hopefully the ones that don't will actually have
		 * tcdrain() implemented, or will have TIOCDRAIN.
		 */
		result = ioctl(port->fd, TCSBRK, 1);
#else
		/* Need platform-specific code for this case. */
#error "Neither tcdrain() nor TCSBRK defined, send a bug report"
#endif
		if (result < 0) {
			if (errno == EINTR) {
				DEBUG("tcdrain() was interrupted");
				continue;
			} else {
				RETURN_FAIL("tcdrain() failed");
			}
		} else {
			RETURN_OK();
		}
	}
}

SP_API enum sp_return sp_blocking_write(struct sp_port *port, const void *buf,
                                        size_t count, unsigned int timeout_ms)
{
	TRACE("%p, %p, %d, %d", port, buf, count, timeout_ms);

	CHECK_OPEN_PORT();

	if (!buf)
		RETURN_ERROR(SP_ERR_ARG, "Null buffer");

	if (timeout_ms)
		DEBUG_FMT("Writing %d bytes to port %s, timeout %d ms",
			count, port->name, timeout_ms);
	else
		DEBUG_FMT("Writing %d bytes to port %s, no timeout",
			count, port->name);

	if (count == 0)
		RETURN_INT(0);

	size_t bytes_written = 0;
	unsigned char *ptr = (unsigned char *) buf;
	struct timeout timeout;
	fd_set fds;
	ssize_t result;

	timeout_start(&timeout, timeout_ms);

	FD_ZERO(&fds);
	FD_SET(port->fd, &fds);

	/* Loop until we have written the requested number of bytes. */
	while (bytes_written < count) {

		if (timeout_check(&timeout))
			break;

		result = select(port->fd + 1, NULL, &fds, NULL, timeout_timeval(&timeout));

		timeout_update(&timeout);

		if (result < 0) {
			if (errno == EINTR) {
				DEBUG("select() call was interrupted, repeating");
				continue;
			} else {
				RETURN_FAIL("select() failed");
			}
		} else if (result == 0) {
			/* Timeout has expired. */
			break;
		}

		/* Do write. */
		result = write(port->fd, ptr, count - bytes_written);

		if (result < 0) {
			if (errno == EAGAIN)
				/* This shouldn't happen because we did a select() first, but handle anyway. */
				continue;
			else
				/* This is an actual failure. */
				RETURN_FAIL("write() failed");
		}

		bytes_written += result;
		ptr += result;
	}

	if (bytes_written < count)
		DEBUG("Write timed out");

	RETURN_INT(bytes_written);
}

SP_API enum sp_return sp_nonblocking_write(struct sp_port *port,
                                           const void *buf, size_t count)
{
	TRACE("%p, %p, %d", port, buf, count);

	CHECK_OPEN_PORT();

	if (!buf)
		RETURN_ERROR(SP_ERR_ARG, "Null buffer");

	DEBUG_FMT("Writing up to %d bytes to port %s", count, port->name);

	if (count == 0)
		RETURN_INT(0);

	/* Returns the number of bytes written, or -1 upon failure. */
	ssize_t written = write(port->fd, buf, count);

	if (written < 0) {
		if (errno == EAGAIN)
			// Buffer is full, no bytes written.
			RETURN_INT(0);
		else
			RETURN_FAIL("write() failed");
	} else {
		RETURN_INT(written);
	}
}

SP_API enum sp_return sp_blocking_read(struct sp_port *port, void *buf,
                                       size_t count, unsigned int timeout_ms)
{
	TRACE("%p, %p, %d, %d", port, buf, count, timeout_ms);

	CHECK_OPEN_PORT();

	if (!buf)
		RETURN_ERROR(SP_ERR_ARG, "Null buffer");

	if (timeout_ms)
		DEBUG_FMT("Reading %d bytes from port %s, timeout %d ms",
			count, port->name, timeout_ms);
	else
		DEBUG_FMT("Reading %d bytes from port %s, no timeout",
			count, port->name);

	if (count == 0)
		RETURN_INT(0);

	size_t bytes_read = 0;
	unsigned char *ptr = (unsigned char *) buf;
	struct timeout timeout;
	fd_set fds;
	ssize_t result;

	timeout_start(&timeout, timeout_ms);

	FD_ZERO(&fds);
	FD_SET(port->fd, &fds);

	/* Loop until we have the requested number of bytes. */
	while (bytes_read < count) {

		if (timeout_check(&timeout))
			/* Timeout has expired. */
			break;

		result = select(port->fd + 1, &fds, NULL, NULL, timeout_timeval(&timeout));

		timeout_update(&timeout);

		if (result < 0) {
			if (errno == EINTR) {
				DEBUG("select() call was interrupted, repeating");
				continue;
			} else {
				RETURN_FAIL("select() failed");
			}
		} else if (result == 0) {
			/* Timeout has expired. */
			break;
		}

		/* Do read. */
		result = read(port->fd, ptr, count - bytes_read);

		if (result < 0) {
			if (errno == EAGAIN)
				/*
				 * This shouldn't happen because we did a
				 * select() first, but handle anyway.
				 */
				continue;
			else
				/* This is an actual failure. */
				RETURN_FAIL("read() failed");
		}

		bytes_read += result;
		ptr += result;
	}

	if (bytes_read < count)
		DEBUG("Read timed out");

	RETURN_INT(bytes_read);
}

SP_API enum sp_return sp_blocking_read_next(struct sp_port *port, void *buf,
                                            size_t count, unsigned int timeout_ms)
{
	TRACE("%p, %p, %d, %d", port, buf, count, timeout_ms);

	CHECK_OPEN_PORT();

	if (!buf)
		RETURN_ERROR(SP_ERR_ARG, "Null buffer");

	if (count == 0)
		RETURN_ERROR(SP_ERR_ARG, "Zero count");

	if (timeout_ms)
		DEBUG_FMT("Reading next max %d bytes from port %s, timeout %d ms",
			count, port->name, timeout_ms);
	else
		DEBUG_FMT("Reading next max %d bytes from port %s, no timeout",
			count, port->name);

	size_t bytes_read = 0;
	struct timeout timeout;
	fd_set fds;
	ssize_t result;

	timeout_start(&timeout, timeout_ms);

	FD_ZERO(&fds);
	FD_SET(port->fd, &fds);

	/* Loop until we have at least one byte, or timeout is reached. */
	while (bytes_read == 0) {

		if (timeout_check(&timeout))
			/* Timeout has expired. */
			break;

		result = select(port->fd + 1, &fds, NULL, NULL, timeout_timeval(&timeout));

		timeout_update(&timeout);

		if (result < 0) {
			if (errno == EINTR) {
				DEBUG("select() call was interrupted, repeating");
				continue;
			} else {
				RETURN_FAIL("select() failed");
			}
		} else if (result == 0) {
			/* Timeout has expired. */
			break;
		}

		/* Do read. */
		result = read(port->fd, buf, count);

		if (result < 0) {
			if (errno == EAGAIN)
				/* This shouldn't happen because we did a select() first, but handle anyway. */
				continue;
			else
				/* This is an actual failure. */
				RETURN_FAIL("read() failed");
		}

		bytes_read = result;
	}

	if (bytes_read == 0)
		DEBUG("Read timed out");

	RETURN_INT(bytes_read);
}

SP_API enum sp_return sp_nonblocking_read(struct sp_port *port, void *buf,
                                          size_t count)
{
	TRACE("%p, %p, %d", port, buf, count);

	CHECK_OPEN_PORT();

	if (!buf)
		RETURN_ERROR(SP_ERR_ARG, "Null buffer");

	DEBUG_FMT("Reading up to %d bytes from port %s", count, port->name);

	ssize_t bytes_read;

	/* Returns the number of bytes read, or -1 upon failure. */
	if ((bytes_read = read(port->fd, buf, count)) < 0) {
		if (errno == EAGAIN)
			/* No bytes available. */
			bytes_read = 0;
		else
			/* This is an actual failure. */
			RETURN_FAIL("read() failed");
	}
	RETURN_INT(bytes_read);
}

SP_API enum sp_return sp_input_waiting(struct sp_port *port)
{
	TRACE("%p", port);

	CHECK_OPEN_PORT();

	DEBUG_FMT("Checking input bytes waiting on port %s", port->name);

	int bytes_waiting;
	if (ioctl(port->fd, TIOCINQ, &bytes_waiting) < 0)
		RETURN_FAIL("TIOCINQ ioctl failed");
	RETURN_INT(bytes_waiting);
}

SP_API enum sp_return sp_output_waiting(struct sp_port *port)
{
	TRACE("%p", port);

#ifdef __CYGWIN__
	/* TIOCOUTQ is not defined in Cygwin headers */
	RETURN_ERROR(SP_ERR_SUPP,
			"Getting output bytes waiting is not supported on Cygwin");
#else
	CHECK_OPEN_PORT();

	DEBUG_FMT("Checking output bytes waiting on port %s", port->name);

	int bytes_waiting;
	if (ioctl(port->fd, TIOCOUTQ, &bytes_waiting) < 0)
		RETURN_FAIL("TIOCOUTQ ioctl failed");
	RETURN_INT(bytes_waiting);
#endif
}

SP_API enum sp_return sp_add_port_events(struct sp_event_set *event_set,
	const struct sp_port *port, enum sp_event mask)
{
	TRACE("%p, %p, %d", event_set, port, mask);

	if (!event_set)
		RETURN_ERROR(SP_ERR_ARG, "Null event set");

	if (!port)
		RETURN_ERROR(SP_ERR_ARG, "Null port");

	if (mask > (SP_EVENT_RX_READY | SP_EVENT_TX_READY | SP_EVENT_ERROR))
		RETURN_ERROR(SP_ERR_ARG, "Invalid event mask");

	if (!mask)
		RETURN_OK();

	TRY(add_handle(event_set, port->fd, mask));

	RETURN_OK();
}

SP_API enum sp_return sp_wait(struct sp_event_set *event_set,
                              unsigned int timeout_ms)
{
	TRACE("%p, %d", event_set, timeout_ms);

	if (!event_set)
		RETURN_ERROR(SP_ERR_ARG, "Null event set");

	struct timeout timeout;
	int poll_timeout;
	int result;
	struct pollfd *pollfds;
	unsigned int i;

	if (!(pollfds = malloc(sizeof(struct pollfd) * event_set->count)))
		RETURN_ERROR(SP_ERR_MEM, "pollfds malloc() failed");

	for (i = 0; i < event_set->count; i++) {
		pollfds[i].fd = ((int *)event_set->handles)[i];
		pollfds[i].events = 0;
		pollfds[i].revents = 0;
		if (event_set->masks[i] & SP_EVENT_RX_READY)
			pollfds[i].events |= POLLIN;
		if (event_set->masks[i] & SP_EVENT_TX_READY)
			pollfds[i].events |= POLLOUT;
		if (event_set->masks[i] & SP_EVENT_ERROR)
			pollfds[i].events |= POLLERR;
	}

	timeout_start(&timeout, timeout_ms);
	timeout_limit(&timeout, INT_MAX);

	/* Loop until an event occurs. */
	while (1) {

		if (timeout_check(&timeout)) {
			DEBUG("Wait timed out");
			break;
		}

		poll_timeout = (int) timeout_remaining_ms(&timeout);
		if (poll_timeout == 0)
			poll_timeout = -1;

		result = poll(pollfds, event_set->count, poll_timeout);

		timeout_update(&timeout);

		if (result < 0) {
			if (errno == EINTR) {
				DEBUG("poll() call was interrupted, repeating");
				continue;
			} else {
				free(pollfds);
				RETURN_FAIL("poll() failed");
			}
		} else if (result == 0) {
			DEBUG("poll() timed out");
			if (!timeout.overflow)
				break;
		} else {
			DEBUG("poll() completed");
			break;
		}
	}

	free(pollfds);
	RETURN_OK();
}

SP_API enum sp_return sp_get_signals(struct sp_port *port,
                                     enum sp_signal *signals)
{
	TRACE("%p, %p", port, signals);

	CHECK_OPEN_PORT();

	if (!signals)
		RETURN_ERROR(SP_ERR_ARG, "Null result pointer");

	DEBUG_FMT("Getting control signals for port %s", port->name);

	*signals = 0;
	int bits;
	if (ioctl(port->fd, TIOCMGET, &bits) < 0)
		RETURN_FAIL("TIOCMGET ioctl failed");
	if (bits & TIOCM_CTS)
		*signals |= SP_SIG_CTS;
	if (bits & TIOCM_DSR)
		*signals |= SP_SIG_DSR;
	if (bits & TIOCM_CAR)
		*signals |= SP_SIG_DCD;
	if (bits & TIOCM_RNG)
		*signals |= SP_SIG_RI;
	RETURN_OK();
}

SP_API enum sp_return sp_start_break(struct sp_port *port)
{
	TRACE("%p", port);

	CHECK_OPEN_PORT();
	if (ioctl(port->fd, TIOCSBRK, 1) < 0)
		RETURN_FAIL("TIOCSBRK ioctl failed");

	RETURN_OK();
}

SP_API enum sp_return sp_end_break(struct sp_port *port)
{
	TRACE("%p", port);

	CHECK_OPEN_PORT();
	if (ioctl(port->fd, TIOCCBRK, 1) < 0)
		RETURN_FAIL("TIOCCBRK ioctl failed");

	RETURN_OK();
}

SP_API int sp_last_error_code(void)
{
	TRACE_VOID();
	RETURN_INT(errno);
}

SP_API char *sp_last_error_message(void)
{
	TRACE_VOID();

	RETURN_STRING(strerror(errno));
}

SP_API void sp_free_error_message(char *message)
{
	TRACE("%s", message);

	(void)message;

	RETURN();
}
