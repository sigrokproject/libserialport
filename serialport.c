/*
 * This file is part of the libserialport project.
 *
 * Copyright (C) 2010-2012 Bert Vermeulen <bert@biot.com>
 * Copyright (C) 2010-2012 Uwe Hermann <uwe@hermann-uwe.de>
 * Copyright (C) 2013 Martin Ling <martin-libserialport@earth.li>
 * Copyright (C) 2013 Matthias Heidbrink <m-sigrok@heidbrink.biz>
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

#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#ifdef _WIN32
#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#else
#include <termios.h>
#include <sys/ioctl.h>
#endif
#ifdef __APPLE__
#include <IOKit/IOKitLib.h>
#include <IOKit/serial/IOSerialKeys.h>
#include <IOKit/serial/ioss.h>
#include <sys/syslimits.h>
#endif
#ifdef __linux__
#include "libudev.h"
#include "linux/serial.h"
#include "linux_termios.h"
#if defined(TCGETX) && defined(TCSETX) && defined(HAVE_TERMIOX)
#define USE_TERMIOX
#endif
#endif

#include "libserialport.h"

struct port_data {
#ifdef _WIN32
	DCB dcb;
#else
	struct termios term;
	int controlbits;
#ifdef USE_TERMIOX
	int flow;
#endif
#endif
};

/* Standard baud rates. */
#ifdef _WIN32
#define BAUD_TYPE DWORD
#define BAUD(n) {CBR_##n, n}
#else
#define BAUD_TYPE speed_t
#define BAUD(n) {B##n, n}
#endif

struct std_baudrate {
	BAUD_TYPE index;
	int value;
};

const struct std_baudrate std_baudrates[] = {
#ifdef _WIN32
	/*
	 * The baudrates 50/75/134/150/200/1800/230400/460800 do not seem to
	 * have documented CBR_* macros.
	 */
	BAUD(110), BAUD(300), BAUD(600), BAUD(1200), BAUD(2400), BAUD(4800),
	BAUD(9600), BAUD(14400), BAUD(19200), BAUD(38400), BAUD(57600),
	BAUD(115200), BAUD(128000), BAUD(256000),
#else
	BAUD(50), BAUD(75), BAUD(110), BAUD(134), BAUD(150), BAUD(200),
	BAUD(300), BAUD(600), BAUD(1200), BAUD(1800), BAUD(2400), BAUD(4800),
	BAUD(9600), BAUD(19200), BAUD(38400), BAUD(57600), BAUD(115200),
	BAUD(230400),
#if !defined(__APPLE__) && !defined(__OpenBSD__)
	BAUD(460800),
#endif
#endif
};

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))
#define NUM_STD_BAUDRATES ARRAY_SIZE(std_baudrates)

#define TRY(x) do { int ret = x; if (ret != SP_OK) return ret; } while (0)

/* Helper functions. */
static enum sp_return validate_port(struct sp_port *port);
static struct sp_port **list_append(struct sp_port **list, const char *portname);
static enum sp_return get_config(struct sp_port *port, struct port_data *data,
	struct sp_port_config *config);
static enum sp_return set_config(struct sp_port *port, struct port_data *data,
	const struct sp_port_config *config);

enum sp_return sp_get_port_by_name(const char *portname, struct sp_port **port_ptr)
{
	struct sp_port *port;
	int len;

	if (!port_ptr)
		return SP_ERR_ARG;

	*port_ptr = NULL;

	if (!portname)
		return SP_ERR_ARG;

	if (!(port = malloc(sizeof(struct sp_port))))
		return SP_ERR_MEM;

	len = strlen(portname) + 1;

	if (!(port->name = malloc(len))) {
		free(port);
		return SP_ERR_MEM;
	}

	memcpy(port->name, portname, len);

#ifdef _WIN32
	port->hdl = INVALID_HANDLE_VALUE;
#else
	port->fd = -1;
#endif

	*port_ptr = port;

	return SP_OK;
}

enum sp_return sp_copy_port(const struct sp_port *port, struct sp_port **copy_ptr)
{
	if (!copy_ptr)
		return SP_ERR_ARG;

	*copy_ptr = NULL;

	if (!port || !port->name)
		return SP_ERR_ARG;

	return sp_get_port_by_name(port->name, copy_ptr);
}

void sp_free_port(struct sp_port *port)
{
	if (!port)
		return;

	if (port->name)
		free(port->name);

	free(port);
}

static struct sp_port **list_append(struct sp_port **list, const char *portname)
{
	void *tmp;
	unsigned int count;

	for (count = 0; list[count]; count++);
	if (!(tmp = realloc(list, sizeof(struct sp_port *) * (count + 2))))
		goto fail;
	list = tmp;
	if (sp_get_port_by_name(portname, &list[count]) != SP_OK)
		goto fail;
	list[count + 1] = NULL;
	return list;

fail:
	sp_free_port_list(list);
	return NULL;
}

enum sp_return sp_list_ports(struct sp_port ***list_ptr)
{
	struct sp_port **list;
	int ret = SP_OK;

	if (!(list = malloc(sizeof(struct sp_port **))))
		return SP_ERR_MEM;

	list[0] = NULL;

#ifdef _WIN32
	HKEY key;
	TCHAR *value, *data;
	DWORD max_value_len, max_data_size, max_data_len;
	DWORD value_len, data_size, data_len;
	DWORD type, index = 0;
	char *name;
	int name_len;

	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, _T("HARDWARE\\DEVICEMAP\\SERIALCOMM"),
			0, KEY_QUERY_VALUE, &key) != ERROR_SUCCESS) {
		ret = SP_ERR_FAIL;
		goto out_done;
	}
	if (RegQueryInfoKey(key, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
				&max_value_len, &max_data_size, NULL, NULL) != ERROR_SUCCESS) {
		ret = SP_ERR_FAIL;
		goto out_close;
	}
	max_data_len = max_data_size / sizeof(TCHAR);
	if (!(value = malloc((max_value_len + 1) * sizeof(TCHAR)))) {
		ret = SP_ERR_MEM;
		goto out_close;
	}
	if (!(data = malloc((max_data_len + 1) * sizeof(TCHAR)))) {
		ret = SP_ERR_MEM;
		goto out_free_value;
	}
	while (
		value_len = max_value_len + 1,
		data_size = max_data_size,
		RegEnumValue(key, index, value, &value_len,
			NULL, &type, (LPBYTE)data, &data_size) == ERROR_SUCCESS)
	{
		data_len = data_size / sizeof(TCHAR);
		data[data_len] = '\0';
#ifdef UNICODE
		name_len = WideCharToMultiByte(CP_ACP, 0, data, -1, NULL, 0, NULL, NULL)
#else
		name_len = data_len + 1;
#endif
		if (!(name = malloc(name_len))) {
			ret = SP_ERR_MEM;
			goto out;
		}
#ifdef UNICODE
		WideCharToMultiByte(CP_ACP, 0, data, -1, name, name_len, NULL, NULL);
#else
		strcpy(name, data);
#endif
		if (type == REG_SZ && !(list = list_append(list, name))) {
			ret = SP_ERR_MEM;
			goto out;
		}
		index++;
	}
out:
	free(data);
out_free_value:
	free(value);
out_close:
	RegCloseKey(key);
out_done:
#endif
#ifdef __APPLE__
	mach_port_t master;
	CFMutableDictionaryRef classes;
	io_iterator_t iter;
	char *path;
	io_object_t port;
	CFTypeRef cf_path;
	Boolean result;

	if (IOMasterPort(MACH_PORT_NULL, &master) != KERN_SUCCESS) {
		ret = SP_ERR_FAIL;
		goto out_done;
	}

	if (!(classes = IOServiceMatching(kIOSerialBSDServiceValue))) {
		ret = SP_ERR_FAIL;
		goto out_done;
	}

	CFDictionarySetValue(classes,
			CFSTR(kIOSerialBSDTypeKey), CFSTR(kIOSerialBSDAllTypes));

	if (IOServiceGetMatchingServices(master, classes, &iter) != KERN_SUCCESS) {
		ret = SP_ERR_FAIL;
		goto out_done;
	}

	if (!(path = malloc(PATH_MAX))) {
		ret = SP_ERR_MEM;
		goto out_release;
	}

	while ((port = IOIteratorNext(iter))) {
		cf_path = IORegistryEntryCreateCFProperty(port,
				CFSTR(kIOCalloutDeviceKey), kCFAllocatorDefault, 0);
		if (cf_path) {
			result = CFStringGetCString(cf_path,
					path, PATH_MAX, kCFStringEncodingASCII);
			CFRelease(cf_path);
			if (result && !(list = list_append(list, path))) {
				ret = SP_ERR_MEM;
				IOObjectRelease(port);
				goto out;
			}
		}
		IOObjectRelease(port);
	}
out:
	free(path);
out_release:
	IOObjectRelease(iter);
out_done:
#endif
#ifdef __linux__
	struct udev *ud;
	struct udev_enumerate *ud_enumerate;
	struct udev_list_entry *ud_list;
	struct udev_list_entry *ud_entry;
	const char *path;
	struct udev_device *ud_dev, *ud_parent;
	const char *name;
	const char *driver;
	int fd, ioctl_result;
	struct serial_struct serial_info;

	ud = udev_new();
	ud_enumerate = udev_enumerate_new(ud);
	udev_enumerate_add_match_subsystem(ud_enumerate, "tty");
	udev_enumerate_scan_devices(ud_enumerate);
	ud_list = udev_enumerate_get_list_entry(ud_enumerate);
	udev_list_entry_foreach(ud_entry, ud_list) {
		path = udev_list_entry_get_name(ud_entry);
		ud_dev = udev_device_new_from_syspath(ud, path);
		/* If there is no parent device, this is a virtual tty. */
		ud_parent = udev_device_get_parent(ud_dev);
		if (ud_parent == NULL) {
			udev_device_unref(ud_dev);
			continue;
		}
		name = udev_device_get_devnode(ud_dev);
		/* The serial8250 driver has a hardcoded number of ports.
		 * The only way to tell which actually exist on a given system
		 * is to try to open them and make an ioctl call. */
		driver = udev_device_get_driver(ud_parent);
		if (driver && !strcmp(driver, "serial8250")) {
			if ((fd = open(name, O_RDWR | O_NONBLOCK | O_NOCTTY)) < 0)
				goto skip;
			ioctl_result = ioctl(fd, TIOCGSERIAL, &serial_info);
			close(fd);
			if (ioctl_result != 0)
				goto skip;
			if (serial_info.type == PORT_UNKNOWN)
				goto skip;
		}
		list = list_append(list, name);
skip:
		udev_device_unref(ud_dev);
		if (!list) {
			ret = SP_ERR_MEM;
			goto out;
		}
	}
out:
	udev_enumerate_unref(ud_enumerate);
	udev_unref(ud);
#endif

	if (ret == SP_OK) {
		*list_ptr = list;
	} else {
		if (list)
			sp_free_port_list(list);
		*list_ptr = NULL;
	}

	return ret;
}

void sp_free_port_list(struct sp_port **list)
{
	unsigned int i;

	for (i = 0; list[i]; i++)
		sp_free_port(list[i]);
	free(list);
}

static enum sp_return validate_port(struct sp_port *port)
{
	if (port == NULL)
		return 0;
#ifdef _WIN32
	if (port->hdl == INVALID_HANDLE_VALUE)
		return 0;
#else
	if (port->fd < 0)
		return 0;
#endif
	return 1;
}

#define CHECK_PORT() do { if (!validate_port(port)) return SP_ERR_ARG; } while (0)

enum sp_return sp_open(struct sp_port *port, enum sp_mode flags)
{
	if (!port)
		return SP_ERR_ARG;

#ifdef _WIN32
	DWORD desired_access = 0, flags_and_attributes = 0;
	char *escaped_port_name;

	/* Prefix port name with '\\.\' to work with ports above COM9. */
	if (!(escaped_port_name = malloc(strlen(port->name + 5))))
		return SP_ERR_MEM;
	sprintf(escaped_port_name, "\\\\.\\%s", port->name);

	/* Map 'flags' to the OS-specific settings. */
	flags_and_attributes = FILE_ATTRIBUTE_NORMAL;
	if (flags & SP_MODE_READ)
		desired_access |= GENERIC_READ;
	if (flags & SP_MODE_WRITE)
		desired_access |= GENERIC_WRITE;
	if (flags & SP_MODE_NONBLOCK)
		flags_and_attributes |= FILE_FLAG_OVERLAPPED;

	port->hdl = CreateFile(escaped_port_name, desired_access, 0, 0,
			 OPEN_EXISTING, flags_and_attributes, 0);

	free(escaped_port_name);

	if (port->hdl == INVALID_HANDLE_VALUE)
		return SP_ERR_FAIL;
#else
	int flags_local = 0;
	struct port_data data;
	struct sp_port_config config;
	int ret;

	/* Map 'flags' to the OS-specific settings. */
	if (flags & (SP_MODE_READ | SP_MODE_WRITE))
		flags_local |= O_RDWR;
	else if (flags & SP_MODE_READ)
		flags_local |= O_RDONLY;
	else if (flags & SP_MODE_WRITE)
		flags_local |= O_WRONLY;
	if (flags & SP_MODE_NONBLOCK)
		flags_local |= O_NONBLOCK;

	if ((port->fd = open(port->name, flags_local)) < 0)
		return SP_ERR_FAIL;

	ret = get_config(port, &data, &config);

	if (ret < 0) {
		sp_close(port);
		return ret;
	}

	/* Turn off all serial port cooking. */
	data.term.c_iflag &= ~(ISTRIP | INLCR | ICRNL);
	data.term.c_oflag &= ~(ONLCR | OCRNL | ONOCR);
#if !defined(__FreeBSD__) && !defined(__OpenBSD__) && !defined(__NetBSD__)
	data.term.c_oflag &= ~OFILL;
#endif
	/* Disable canonical mode, and don't echo input characters. */
	data.term.c_lflag &= ~(ICANON | ECHO);

	/* Ignore modem status lines; enable receiver */
	data.term.c_cflag |= (CLOCAL | CREAD);

	ret = set_config(port, &data, &config);

	if (ret < 0) {
		sp_close(port);
		return ret;
	}
#endif

	return SP_OK;
}

enum sp_return sp_close(struct sp_port *port)
{
	CHECK_PORT();

#ifdef _WIN32
	/* Returns non-zero upon success, 0 upon failure. */
	if (CloseHandle(port->hdl) == 0)
		return SP_ERR_FAIL;
	port->hdl = INVALID_HANDLE_VALUE;
#else
	/* Returns 0 upon success, -1 upon failure. */
	if (close(port->fd) == -1)
		return SP_ERR_FAIL;
	port->fd = -1;
#endif

	return SP_OK;
}

enum sp_return sp_flush(struct sp_port *port)
{
	CHECK_PORT();

#ifdef _WIN32
	/* Returns non-zero upon success, 0 upon failure. */
	if (PurgeComm(port->hdl, PURGE_RXCLEAR | PURGE_TXCLEAR) == 0)
		return SP_ERR_FAIL;
#else
	/* Returns 0 upon success, -1 upon failure. */
	if (tcflush(port->fd, TCIOFLUSH) < 0)
		return SP_ERR_FAIL;
#endif
	return SP_OK;
}

enum sp_return sp_write(struct sp_port *port, const void *buf, size_t count)
{
	CHECK_PORT();

	if (!buf)
		return SP_ERR_ARG;

#ifdef _WIN32
	DWORD written = 0;

	/* Returns non-zero upon success, 0 upon failure. */
	if (WriteFile(port->hdl, buf, count, &written, NULL) == 0)
		return SP_ERR_FAIL;
	return written;
#else
	/* Returns the number of bytes written, or -1 upon failure. */
	ssize_t written = write(port->fd, buf, count);

	if (written < 0)
		return SP_ERR_FAIL;
	else
		return written;
#endif
}

enum sp_return sp_read(struct sp_port *port, void *buf, size_t count)
{
	CHECK_PORT();

	if (!buf)
		return SP_ERR_ARG;

#ifdef _WIN32
	DWORD bytes_read = 0;

	/* Returns non-zero upon success, 0 upon failure. */
	if (ReadFile(port->hdl, buf, count, &bytes_read, NULL) == 0)
		return SP_ERR_FAIL;
	return bytes_read;
#else
	ssize_t bytes_read;

	/* Returns the number of bytes read, or -1 upon failure. */
	if ((bytes_read = read(port->fd, buf, count)) < 0)
		return SP_ERR_FAIL;
	return bytes_read;
#endif
}

#ifdef __linux__
static enum sp_return get_baudrate(int fd, int *baudrate)
{
	void *data;

	if (!(data = malloc(get_termios_size())))
		return SP_ERR_MEM;

	if (ioctl(fd, get_termios_get_ioctl(), data) < 0)
		return SP_ERR_FAIL;

	*baudrate = get_termios_speed(data);

	return SP_OK;
}

static enum sp_return set_baudrate(int fd, int baudrate)
{
	void *data;

	if (!(data = malloc(get_termios_size())))
		return SP_ERR_MEM;

	if (ioctl(fd, get_termios_get_ioctl(), data) < 0)
		return SP_ERR_FAIL;

	set_termios_speed(data, baudrate);

	if (ioctl(fd, get_termios_set_ioctl(), data) < 0)
		return SP_ERR_FAIL;

	return SP_OK;
}

#ifdef USE_TERMIOX
static enum sp_return get_flow(int fd, int *flow)
{
	void *data;

	if (!(data = malloc(get_termiox_size())))
		return SP_ERR_MEM;

	if (ioctl(fd, TCGETX, data) < 0)
		return SP_ERR_FAIL;

	*flow = get_termiox_flow(data);

	return SP_OK;
}

static enum sp_return set_flow(int fd, int flow)
{
	void *data;

	if (!(data = malloc(get_termiox_size())))
		return SP_ERR_MEM;

	if (ioctl(fd, TCGETX, data) < 0)
		return SP_ERR_FAIL;

	set_termiox_flow(data, flow);

	if (ioctl(fd, TCSETX, data) < 0)
		return SP_ERR_FAIL;

	return SP_OK;
}
#endif /* USE_TERMIOX */
#endif /* __linux__ */

static enum sp_return get_config(struct sp_port *port, struct port_data *data,
	struct sp_port_config *config)
{
	unsigned int i;

#ifdef _WIN32
	if (!GetCommState(port->hdl, &data->dcb))
		return SP_ERR_FAIL;

	for (i = 0; i < NUM_STD_BAUDRATES; i++) {
		if (data->dcb.BaudRate == std_baudrates[i].index) {
			config->baudrate = std_baudrates[i].value;
			break;
		}
	}

	if (i == NUM_STD_BAUDRATES)
		/* BaudRate field can be either an index or a custom baud rate. */
		config->baudrate = data->dcb.BaudRate;

	config->bits = data->dcb.ByteSize;

	if (data->dcb.fParity)
		switch (data->dcb.Parity) {
		case NOPARITY:
			config->parity = SP_PARITY_NONE;
			break;
		case EVENPARITY:
			config->parity = SP_PARITY_EVEN;
			break;
		case ODDPARITY:
			config->parity = SP_PARITY_ODD;
			break;
		default:
			config->parity = -1;
		}
	else
		config->parity = SP_PARITY_NONE;

	switch (data->dcb.StopBits) {
	case ONESTOPBIT:
		config->stopbits = 1;
		break;
	case TWOSTOPBITS:
		config->stopbits = 2;
		break;
	default:
		config->stopbits = -1;
	}

	switch (data->dcb.fRtsControl) {
	case RTS_CONTROL_DISABLE:
		config->rts = SP_RTS_OFF;
		break;
	case RTS_CONTROL_ENABLE:
		config->rts = SP_RTS_ON;
		break;
	case RTS_CONTROL_HANDSHAKE:
		config->rts = SP_RTS_FLOW_CONTROL;
		break;
	default:
		config->rts = -1;
	}

	config->cts = data->dcb.fOutxCtsFlow ? SP_CTS_FLOW_CONTROL : SP_CTS_IGNORE;

	switch (data->dcb.fDtrControl) {
	case DTR_CONTROL_DISABLE:
		config->dtr = SP_DTR_OFF;
		break;
	case DTR_CONTROL_ENABLE:
		config->dtr = SP_DTR_ON;
		break;
	case DTR_CONTROL_HANDSHAKE:
		config->dtr = SP_DTR_FLOW_CONTROL;
		break;
	default:
		config->dtr = -1;
	}

	config->dsr = data->dcb.fOutxDsrFlow ? SP_DSR_FLOW_CONTROL : SP_DSR_IGNORE;

	if (data->dcb.fInX) {
		if (data->dcb.fOutX)
			config->xon_xoff = SP_XONXOFF_INOUT;
		else
			config->xon_xoff = SP_XONXOFF_IN;
	} else {
		if (data->dcb.fOutX)
			config->xon_xoff = SP_XONXOFF_OUT;
		else
			config->xon_xoff = SP_XONXOFF_DISABLED;
	}

#else // !_WIN32

	if (tcgetattr(port->fd, &data->term) < 0)
		return SP_ERR_FAIL;

	if (ioctl(port->fd, TIOCMGET, &data->controlbits) < 0)
		return SP_ERR_FAIL;

#ifdef USE_TERMIOX
	TRY(get_flow(port->fd, &data->flow));
#endif

	for (i = 0; i < NUM_STD_BAUDRATES; i++) {
		if (cfgetispeed(&data->term) == std_baudrates[i].index) {
			config->baudrate = std_baudrates[i].value;
			break;
		}
	}

	if (i == NUM_STD_BAUDRATES) {
#ifdef __APPLE__
		config->baudrate = (int)data->term.c_ispeed;
#elif defined(__linux__)
		TRY(get_baudrate(port->fd, &config->baudrate));
#else
		config->baudrate = -1;
#endif
	}

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
	else
		config->parity = (data->term.c_cflag & PARODD) ? SP_PARITY_ODD : SP_PARITY_EVEN;

	config->stopbits = (data->term.c_cflag & CSTOPB) ? 2 : 1;

	if (data->term.c_cflag & CRTSCTS) {
		config->rts = SP_RTS_FLOW_CONTROL;
		config->cts = SP_CTS_FLOW_CONTROL;
	} else {
#ifdef USE_TERMIOX
		if (data->flow & RTS_FLOW)
			config->rts = SP_RTS_FLOW_CONTROL;
		else
			config->rts = (data->controlbits & TIOCM_RTS) ? SP_RTS_ON : SP_RTS_OFF;

		config->cts = (data->flow & CTS_FLOW) ? SP_CTS_FLOW_CONTROL : SP_CTS_IGNORE;
#else
		config->rts = (data->controlbits & TIOCM_RTS) ? SP_RTS_ON : SP_RTS_OFF;
		config->cts = SP_CTS_IGNORE;
#endif
	}

#ifdef USE_TERMIOX
	if (data->flow & DTR_FLOW)
		config->dtr = SP_DTR_FLOW_CONTROL;
	else
		config->dtr = (data->controlbits & TIOCM_DTR) ? SP_DTR_ON : SP_DTR_OFF;

	config->dsr = (data->flow & DSR_FLOW) ? SP_DSR_FLOW_CONTROL : SP_DSR_IGNORE;
#else
	config->dtr = (data->controlbits & TIOCM_DTR) ? SP_DTR_ON : SP_DTR_OFF;
	config->dsr = SP_DSR_IGNORE;
#endif

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
#endif

	return SP_OK;
}

static enum sp_return set_config(struct sp_port *port, struct port_data *data,
	const struct sp_port_config *config)
{
	unsigned int i;
#ifdef __APPLE__
	BAUD_TYPE baud_nonstd;

	baud_nonstd = B0;
#endif
#ifdef __linux__
	int baud_nonstd = 0;
#endif

#ifdef _WIN32
	if (config->baudrate >= 0) {
		for (i = 0; i < NUM_STD_BAUDRATES; i++) {
			if (config->baudrate == std_baudrates[i].value) {
				data->dcb.BaudRate = std_baudrates[i].index;
				break;
			}
		}

		if (i == NUM_STD_BAUDRATES)
			data->dcb.BaudRate = config->baudrate;
	}

	if (config->bits >= 0)
		data->dcb.ByteSize = config->bits;

	if (config->parity >= 0) {
		switch (config->parity) {
		/* Note: There's also SPACEPARITY, MARKPARITY (unneeded so far). */
		case SP_PARITY_NONE:
			data->dcb.Parity = NOPARITY;
			break;
		case SP_PARITY_EVEN:
			data->dcb.Parity = EVENPARITY;
			break;
		case SP_PARITY_ODD:
			data->dcb.Parity = ODDPARITY;
			break;
		default:
			return SP_ERR_ARG;
		}
	}

	if (config->stopbits >= 0) {
		switch (config->stopbits) {
		/* Note: There's also ONE5STOPBITS == 1.5 (unneeded so far). */
		case 1:
			data->dcb.StopBits = ONESTOPBIT;
			break;
		case 2:
			data->dcb.StopBits = TWOSTOPBITS;
			break;
		default:
			return SP_ERR_ARG;
		}
	}

	if (config->rts >= 0) {
		switch (config->rts) {
		case SP_RTS_OFF:
			data->dcb.fRtsControl = RTS_CONTROL_DISABLE;
			break;
		case SP_RTS_ON:
			data->dcb.fRtsControl = RTS_CONTROL_ENABLE;
			break;
		case SP_RTS_FLOW_CONTROL:
			data->dcb.fRtsControl = RTS_CONTROL_HANDSHAKE;
			break;
		default:
			return SP_ERR_ARG;
		}
	}

	if (config->cts >= 0) {
		switch (config->cts) {
		case SP_CTS_IGNORE:
			data->dcb.fOutxCtsFlow = FALSE;
			break;
		case SP_CTS_FLOW_CONTROL:
			data->dcb.fOutxCtsFlow = TRUE;
			break;
		default:
			return SP_ERR_ARG;
		}
	}

	if (config->dtr >= 0) {
		switch (config->dtr) {
		case SP_DTR_OFF:
			data->dcb.fDtrControl = DTR_CONTROL_DISABLE;
			break;
		case SP_DTR_ON:
			data->dcb.fDtrControl = DTR_CONTROL_ENABLE;
			break;
		case SP_DTR_FLOW_CONTROL:
			data->dcb.fDtrControl = DTR_CONTROL_HANDSHAKE;
			break;
		default:
			return SP_ERR_ARG;
		}
	}

	if (config->dsr >= 0) {
		switch (config->dsr) {
		case SP_DSR_IGNORE:
			data->dcb.fOutxDsrFlow = FALSE;
			break;
		case SP_DSR_FLOW_CONTROL:
			data->dcb.fOutxDsrFlow = TRUE;
			break;
		default:
			return SP_ERR_ARG;
		}
	}

	if (config->xon_xoff >= 0) {
		switch (config->xon_xoff) {
		case SP_XONXOFF_DISABLED:
			data->dcb.fInX = FALSE;
			data->dcb.fOutX = FALSE;
			break;
		case SP_XONXOFF_IN:
			data->dcb.fInX = TRUE;
			data->dcb.fOutX = FALSE;
			break;
		case SP_XONXOFF_OUT:
			data->dcb.fInX = FALSE;
			data->dcb.fOutX = TRUE;
			break;
		case SP_XONXOFF_INOUT:
			data->dcb.fInX = TRUE;
			data->dcb.fOutX = TRUE;
			break;
		default:
			return SP_ERR_ARG;
		}
	}

	if (!SetCommState(port->hdl, &data->dcb))
		return SP_ERR_FAIL;

#else /* !_WIN32 */

	int controlbits;

	if (config->baudrate >= 0) {
		for (i = 0; i < NUM_STD_BAUDRATES; i++) {
			if (config->baudrate == std_baudrates[i].value) {
				if (cfsetospeed(&data->term, std_baudrates[i].index) < 0)
					return SP_ERR_FAIL;

				if (cfsetispeed(&data->term, std_baudrates[i].index) < 0)
					return SP_ERR_FAIL;
				break;
			}
		}

		/* Non-standard baud rate */
		if (i == NUM_STD_BAUDRATES) {
#ifdef __APPLE__
			/* Set "dummy" baud rate */
			if (cfsetspeed(&data->term, B9600) < 0)
				return SP_ERR_FAIL;
			baud_nonstd = config->baudrate;
#elif defined(__linux__)
			baud_nonstd = 1;
#else
			return SP_ERR_ARG;
#endif
		}
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
			return SP_ERR_ARG;
		}
	}

	if (config->parity >= 0) {
		data->term.c_iflag &= ~IGNPAR;
		data->term.c_cflag &= ~(PARENB | PARODD);
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
		default:
			return SP_ERR_ARG;
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
			return SP_ERR_ARG;
		}
	}

	if (config->rts >= 0 || config->cts >= 0) {
#ifdef USE_TERMIOX
		data->flow &= ~(RTS_FLOW | CTS_FLOW);
		switch (config->rts) {
			case SP_RTS_OFF:
			case SP_RTS_ON:
				controlbits = TIOCM_RTS;
				if (ioctl(port->fd, config->rts == SP_RTS_ON ? TIOCMBIS : TIOCMBIC,
						&controlbits) < 0)
					return SP_ERR_FAIL;
				break;
			case SP_RTS_FLOW_CONTROL:
				data->flow |= RTS_FLOW;
				break;
			default:
				break;
		}
		if (config->cts == SP_CTS_FLOW_CONTROL)
			data->flow |= CTS_FLOW;

		if (data->flow & (RTS_FLOW | CTS_FLOW))
			data->term.c_iflag |= CRTSCTS;
		else
			data->term.c_iflag &= ~CRTSCTS;
#else
		/* Asymmetric use of RTS/CTS not supported. */
		if (data->term.c_iflag & CRTSCTS) {
			/* Flow control can only be disabled for both RTS & CTS together. */
			if (config->rts >= 0 && config->rts != SP_RTS_FLOW_CONTROL) {
				if (config->cts != SP_CTS_IGNORE)
					return SP_ERR_ARG;
			}
			if (config->cts >= 0 && config->cts != SP_CTS_FLOW_CONTROL) {
				if (config->rts <= 0 || config->rts == SP_RTS_FLOW_CONTROL)
					return SP_ERR_ARG;
			}
		} else {
			/* Flow control can only be enabled for both RTS & CTS together. */
			if (((config->rts == SP_RTS_FLOW_CONTROL) && (config->cts != SP_CTS_FLOW_CONTROL)) ||
				((config->cts == SP_CTS_FLOW_CONTROL) && (config->rts != SP_RTS_FLOW_CONTROL)))
				return SP_ERR_ARG;
		}

		if (config->rts >= 0) {
			if (config->rts == SP_RTS_FLOW_CONTROL) {
				data->term.c_iflag |= CRTSCTS;
			} else {
				controlbits = TIOCM_RTS;
				if (ioctl(port->fd, config->rts == SP_RTS_ON ? TIOCMBIS : TIOCMBIC,
						&controlbits) < 0)
					return SP_ERR_FAIL;
			}
		}
#endif
	}

	if (config->dtr >= 0 || config->dsr >= 0) {
#ifdef USE_TERMIOX
		data->flow &= ~(DTR_FLOW | DSR_FLOW);
		switch (config->dtr) {
			case SP_DTR_OFF:
			case SP_DTR_ON:
				controlbits = TIOCM_DTR;
				if (ioctl(port->fd, config->dtr == SP_DTR_ON ? TIOCMBIS : TIOCMBIC,
						&controlbits) < 0)
					return SP_ERR_FAIL;
				break;
			case SP_DTR_FLOW_CONTROL:
				data->flow |= DTR_FLOW;
				break;
			default:
				break;
		}
		if (config->dsr == SP_DSR_FLOW_CONTROL)
			data->flow |= DSR_FLOW;
#else
		/* DTR/DSR flow control not supported. */
		if (config->dtr == SP_DTR_FLOW_CONTROL || config->dsr == SP_DSR_FLOW_CONTROL)
			return SP_ERR_ARG;

		if (config->dtr >= 0) {
			controlbits = TIOCM_DTR;
			if (ioctl(port->fd, config->dtr == SP_DTR_ON ? TIOCMBIS : TIOCMBIC,
					&controlbits) < 0)
				return SP_ERR_FAIL;
		}
#endif
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
			return SP_ERR_ARG;
		}
	}

	if (tcsetattr(port->fd, TCSADRAIN, &data->term) < 0)
		return SP_ERR_FAIL;

#ifdef __APPLE__
	if (baud_nonstd != B0) {
		if (ioctl(port->fd, IOSSIOSPEED, &baud_nonstd) == -1)
			return SP_ERR_FAIL;
		/* Set baud rates in data->term to correct, but incompatible
		 * with tcsetattr() value, same as delivered by tcgetattr(). */
		if (cfsetspeed(&data->term, baud_nonstd) < 0)
			return SP_ERR_FAIL;
	}
#elif defined(__linux__)
	if (baud_nonstd)
		TRY(set_baudrate(port->fd, config->baudrate));
#ifdef USE_TERMIOX
	TRY(set_flow(port->fd, data->flow));
#endif
#endif

#endif /* !_WIN32 */

	return SP_OK;
}

enum sp_return sp_set_config(struct sp_port *port, const struct sp_port_config *config)
{
	struct port_data data;
	struct sp_port_config prev_config;

	CHECK_PORT();

	if (!config)
		return SP_ERR_ARG;

	TRY(get_config(port, &data, &prev_config));
	TRY(set_config(port, &data, config));

	return SP_OK;
}

#define CREATE_SETTER(x, type) int sp_set_##x(struct sp_port *port, type x) { \
	struct port_data data; \
	struct sp_port_config config; \
	CHECK_PORT(); \
	TRY(get_config(port, &data, &config)); \
	config.x = x; \
	TRY(set_config(port, &data, &config)); \
	return SP_OK; \
}

CREATE_SETTER(baudrate, int)
CREATE_SETTER(bits, int)
CREATE_SETTER(parity, enum sp_parity)
CREATE_SETTER(stopbits, int)
CREATE_SETTER(rts, enum sp_rts)
CREATE_SETTER(cts, enum sp_cts)
CREATE_SETTER(dtr, enum sp_dtr)
CREATE_SETTER(dsr, enum sp_dsr)
CREATE_SETTER(xon_xoff, enum sp_xonxoff)

enum sp_return sp_set_flowcontrol(struct sp_port *port, enum sp_flowcontrol flowcontrol)
{
	struct port_data data;
	struct sp_port_config config;

	CHECK_PORT();

	TRY(get_config(port, &data, &config));

	if (flowcontrol == SP_FLOWCONTROL_XONXOFF)
		config.xon_xoff = SP_XONXOFF_INOUT;
	else
		config.xon_xoff = SP_XONXOFF_DISABLED;

	if (flowcontrol == SP_FLOWCONTROL_RTSCTS) {
		config.rts = SP_RTS_FLOW_CONTROL;
		config.cts = SP_CTS_FLOW_CONTROL;
	} else {
		if (config.rts == SP_RTS_FLOW_CONTROL)
			config.rts = SP_RTS_ON;
		config.cts = SP_CTS_IGNORE;
	}

	if (flowcontrol == SP_FLOWCONTROL_DTRDSR) {
		config.dtr = SP_DTR_FLOW_CONTROL;
		config.dsr = SP_DSR_FLOW_CONTROL;
	} else {
		if (config.dtr == SP_DTR_FLOW_CONTROL)
			config.dtr = SP_DTR_ON;
		config.dsr = SP_DSR_IGNORE;
	}

	TRY(set_config(port, &data, &config));

	return SP_OK;
}

int sp_last_error_code(void)
{
#ifdef _WIN32
	return GetLastError();
#else
	return errno;
#endif
}

char *sp_last_error_message(void)
{
#ifdef _WIN32
	LPVOID message;
	DWORD error = GetLastError();

	FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		error,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR) &message,
		0, NULL );

	return message;
#else
	return strerror(errno);
#endif
}

void sp_free_error_message(char *message)
{
#ifdef _WIN32
	LocalFree(message);
#else
	(void)message;
#endif
}
