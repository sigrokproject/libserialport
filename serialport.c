/*
 * This file is part of the libserialport project.
 *
 * Copyright (C) 2010-2012 Bert Vermeulen <bert@biot.com>
 * Copyright (C) 2010-2012 Uwe Hermann <uwe@hermann-uwe.de>
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
#else
#include <termios.h>
#include <sys/ioctl.h>
#endif
#ifdef __APPLE__
#include <IOKitLib.h>
#include <serial/IOSerialKeys.h>
#endif
#ifdef __linux__
#include "libudev.h"
#endif

#include "serialport.h"

static char **sp_list_new(void)
{
	char **list;
	if ((list = malloc(sizeof(char *))))
		list[0] = NULL;
	return list;
}

static char **sp_list_append(char **list, void *data, size_t len)
{
	void *tmp;
	unsigned int count;
	for (count = 0; list[count]; count++);
	if (!(tmp = realloc(list, sizeof(char *) * (count + 2))))
		goto fail;
	list = tmp;
	if (!(list[count] = malloc(len)))
		goto fail;
	memcpy(list[count], data, len);
	list[count + 1] = NULL;
	return list;
fail:
	sp_free_port_list(list);
	return NULL;
}

/**
 * List the serial ports available on the system.
 *
 * @return A null-terminated array of port name strings.
 */
char **sp_list_ports(void)
{
	char **list = NULL;

#ifdef _WIN32
	HKEY key;
	TCHAR *name, *data;
	DWORD max_name_len, max_data_size, max_data_len;
	DWORD name_len, data_size, data_len;
	DWORD type, index = 0;

	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, _T("HARDWARE\\DEVICEMAP\\SERIALCOMM"),
			0, KEY_QUERY_VALUE, &key) != ERROR_SUCCESS)
		return NULL;
	if (RegQueryInfoKey(key, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
				&max_name_len, &max_data_size, NULL, NULL) != ERROR_SUCCESS)
		goto out_close;
	max_data_len = max_data_size / sizeof(TCHAR);
	if (!(name = malloc((max_name_len + 1) * sizeof(TCHAR))))
		goto out_close;
	if (!(data = malloc((max_data_len + 1) * sizeof(TCHAR))))
		goto out_free_name;
	if (!(list = sp_list_new()))
		goto out;
	while (
		name_len = max_name_len,
		data_size = max_data_size,
		RegEnumValue(key, index, name, &name_len,
			NULL, &type, (LPBYTE)data, &data_size) == ERROR_SUCCESS)
	{
		data_len = data_size / sizeof(TCHAR);
		data[data_len] = '\0';
		if (type == REG_SZ)
			if (!(list = sp_list_append(list,
					data, (data_len + 1) * sizeof(TCHAR))))
				goto out;
		index++;
	}
out:
	free(data);
out_free_name:
	free(name);
out_close:
	RegCloseKey(key);
	return list;
#endif
#ifdef __APPLE__
	mach_port_t master;
	CFMutableDictionaryRef classes;
	io_iterator_t iter;
	char *path;
	io_object_t port;
	CFTypeRef cf_path;
	Boolean result;

	if (IOMasterPort(MACH_PORT_NULL, &master) != KERN_SUCCESS)
		return NULL;

	if (!(classes = IOServiceMatching(kIOSerialBSDServiceValue)))
		return NULL;

	CFDictionarySetValue(classes,
			CFSTR(kIOSerialBSDTypeKey), CFSTR(kIOSerialBSDAllTypes));

	if (!(IOServiceGetMatchingServices(master, classes, &iter)))
		return NULL;

	if (!(path = malloc(PATH_MAX)))
		goto out_release;

	if (!(list = sp_list_new()))
		goto out;

	while (port = IOIteratorNext(iter)) {
		cf_path = IORegistryEntryCreateCFProperty(port,
				CFSTR(kIOCalloutDeviceKey), kCFAllocatorDefault, 0);
		if (cf_path) {
			result = CFStringGetCString(cf_path,
					path, PATH_MAX, kCFStringEncodingASCII);
			CFRelease(cf_path);
			if (result)
				if (!(list = sp_list_append(list, path, strlen(path) + 1)))
				{
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
	return list;
#endif
#ifdef __linux__
	struct udev *ud;
	struct udev_enumerate *ud_enumerate;
	struct udev_list_entry *ud_list;
	struct udev_list_entry *ud_entry;
	const char *path;
	struct udev_device *ud_dev;
	const char *name;

	ud = udev_new();
	ud_enumerate = udev_enumerate_new(ud);
	udev_enumerate_add_match_subsystem(ud_enumerate, "tty");
	udev_enumerate_scan_devices(ud_enumerate);
	ud_list = udev_enumerate_get_list_entry(ud_enumerate);
	if (!(list = sp_list_new()))
		goto out;
	udev_list_entry_foreach(ud_entry, ud_list)
	{
		path = udev_list_entry_get_name(ud_entry);
		ud_dev = udev_device_new_from_syspath(ud, path);
		name = udev_device_get_devnode(ud_dev);
		list = sp_list_append(list, (void *)name, strlen(name) + 1);
		udev_device_unref(ud_dev);
		if (!list)
			goto out;
	}
out:
	udev_enumerate_unref(ud_enumerate);
	udev_unref(ud);
	return list;
#endif
}

/**
 * Free a port list returned by sp_list_ports.
 */
void sp_free_port_list(char **list)
{
	unsigned int i;
	for (i = 0; list[i]; i++)
		free(list[i]);
	free(list);
}

static int sp_validate_port(struct sp_port *port)
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

#define CHECK_PORT() do { if (!sp_validate_port(port)) return SP_ERR_ARG; } while (0)

/**
 * Open the specified serial port.
 *
 * @param port Pointer to empty port structure allocated by caller.
 * @param portname Name of port to open.
 * @param flags Flags to use when opening the serial port. Possible flags
 *              are: SP_MODE_RDWR, SP_MODE_RDONLY, SP_MODE_NONBLOCK.
 *
 * @return SP_OK on success, SP_ERR_FAIL on failure,
 *         or SP_ERR_ARG if an invalid port or name is passed.
 */
int sp_open(struct sp_port *port, char *portname, int flags)
{
	if (!port)
		return SP_ERR_ARG;

	if (!portname)
		return SP_ERR_ARG;

	port->name = portname;

#ifdef _WIN32
	DWORD desired_access = 0, flags_and_attributes = 0;
	/* Map 'flags' to the OS-specific settings. */
	desired_access |= GENERIC_READ;
	flags_and_attributes = FILE_ATTRIBUTE_NORMAL;
	if (flags & SP_MODE_RDWR)
		desired_access |= GENERIC_WRITE;
	if (flags & SP_MODE_NONBLOCK)
		flags_and_attributes |= FILE_FLAG_OVERLAPPED;

	port->hdl = CreateFile(port->name, desired_access, 0, 0,
			 OPEN_EXISTING, flags_and_attributes, 0);
	if (port->hdl == INVALID_HANDLE_VALUE)
		return SP_ERR_FAIL;
#else
	int flags_local = 0;
	/* Map 'flags' to the OS-specific settings. */
	if (flags & SP_MODE_RDWR)
		flags_local |= O_RDWR;
	if (flags & SP_MODE_RDONLY)
		flags_local |= O_RDONLY;
	if (flags & SP_MODE_NONBLOCK)
		flags_local |= O_NONBLOCK;

	if ((port->fd = open(port->name, flags_local)) < 0)
		return SP_ERR_FAIL;
#endif

	return SP_OK;
}

/**
 * Close the specified serial port.
 *
 * @param port Pointer to port structure.
 *
 * @return SP_OK on success, SP_ERR_FAIL on failure,
 *         or SP_ERR_ARG if an invalid port is passed.
 */
int sp_close(struct sp_port *port)
{
	CHECK_PORT();

#ifdef _WIN32
	/* Returns non-zero upon success, 0 upon failure. */
	if (CloseHandle(port->hdl) == 0)
		return SP_ERR_FAIL;
#else
	/* Returns 0 upon success, -1 upon failure. */
	if (close(port->fd) == -1)
		return SP_ERR_FAIL;
#endif

	return SP_OK;
}

/**
 * Flush serial port buffers.
 *
 * @param port Pointer to port structure.
 *
 * @return SP_OK on success, SP_ERR_FAIL on failure,
 *         or SP_ERR_ARG if an invalid port is passed.
 */
int sp_flush(struct sp_port *port)
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

/**
 * Write a number of bytes to the specified serial port.
 *
 * @param port Pointer to port structure.
 * @param buf Buffer containing the bytes to write.
 * @param count Number of bytes to write.
 *
 * @return The number of bytes written, SP_ERR_FAIL on failure,
 *         or SP_ERR_ARG if an invalid port is passed.
 */
int sp_write(struct sp_port *port, const void *buf, size_t count)
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
		return written;;
#endif
}

/**
 * Read a number of bytes from the specified serial port.
 *
 * @param port Pointer to port structure.
 * @param buf Buffer where to store the bytes that are read.
 * @param count The number of bytes to read.
 *
 * @return The number of bytes read, SP_ERR_FAIL on failure,
 *         or SP_ERR_ARG if an invalid port is passed.
 */
int sp_read(struct sp_port *port, void *buf, size_t count)
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

/**
 * Set serial parameters for the specified serial port.
 *
 * @param port Pointer to port structure.
 * @param baudrate The baudrate to set.
 * @param bits The number of data bits to use.
 * @param parity The parity setting to use (0 = none, 1 = even, 2 = odd).
 * @param stopbits The number of stop bits to use (1 or 2).
 * @param flowcontrol The flow control settings to use (0 = none, 1 = RTS/CTS,
 *                    2 = XON/XOFF).
 *
 * @return The number of bytes read, SP_ERR_FAIL on failure,
 *         or SP_ERR_ARG if an invalid argument is passed.
 */
int sp_set_params(struct sp_port *port, int baudrate,
			      int bits, int parity, int stopbits,
			      int flowcontrol, int rts, int dtr)
{
	CHECK_PORT();

#ifdef _WIN32
	DCB dcb;

	if (!GetCommState(port->hdl, &dcb))
		return SP_ERR_FAIL;

	switch (baudrate) {
	/*
	 * The baudrates 50/75/134/150/200/1800/230400/460800 do not seem to
	 * have documented CBR_* macros.
	 */
	case 110:
		dcb.BaudRate = CBR_110;
		break;
	case 300:
		dcb.BaudRate = CBR_300;
		break;
	case 600:
		dcb.BaudRate = CBR_600;
		break;
	case 1200:
		dcb.BaudRate = CBR_1200;
		break;
	case 2400:
		dcb.BaudRate = CBR_2400;
		break;
	case 4800:
		dcb.BaudRate = CBR_4800;
		break;
	case 9600:
		dcb.BaudRate = CBR_9600;
		break;
	case 14400:
		dcb.BaudRate = CBR_14400; /* Not available on Unix? */
		break;
	case 19200:
		dcb.BaudRate = CBR_19200;
		break;
	case 38400:
		dcb.BaudRate = CBR_38400;
		break;
	case 57600:
		dcb.BaudRate = CBR_57600;
		break;
	case 115200:
		dcb.BaudRate = CBR_115200;
		break;
	case 128000:
		dcb.BaudRate = CBR_128000; /* Not available on Unix? */
		break;
	case 256000:
		dcb.BaudRate = CBR_256000; /* Not available on Unix? */
		break;
	default:
		return SP_ERR_ARG;
	}

	switch (stopbits) {
	/* Note: There's also ONE5STOPBITS == 1.5 (unneeded so far). */
	case 1:
		dcb.StopBits = ONESTOPBIT;
		break;
	case 2:
		dcb.StopBits = TWOSTOPBITS;
		break;
	default:
		return SP_ERR_ARG;
	}

	switch (parity) {
	/* Note: There's also SPACEPARITY, MARKPARITY (unneeded so far). */
	case SP_PARITY_NONE:
		dcb.Parity = NOPARITY;
		break;
	case SP_PARITY_EVEN:
		dcb.Parity = EVENPARITY;
		break;
	case SP_PARITY_ODD:
		dcb.Parity = ODDPARITY;
		break;
	default:
		return SP_ERR_ARG;
	}

	if (rts != -1) {
		if (rts)
			dcb.fRtsControl = RTS_CONTROL_ENABLE;
		else
			dcb.fRtsControl = RTS_CONTROL_DISABLE;
	}

	if (dtr != -1) {
		if (dtr)
			dcb.fDtrControl = DTR_CONTROL_ENABLE;
		else
			dcb.fDtrControl = DTR_CONTROL_DISABLE;
	}

	if (!SetCommState(port->hdl, &dcb))
		return SP_ERR_FAIL;
#else
	struct termios term;
	speed_t baud;
	int controlbits;

	if (tcgetattr(port->fd, &term) < 0)
		return SP_ERR_FAIL;

	switch (baudrate) {
	case 50:
		baud = B50;
		break;
	case 75:
		baud = B75;
		break;
	case 110:
		baud = B110;
		break;
	case 134:
		baud = B134;
		break;
	case 150:
		baud = B150;
		break;
	case 200:
		baud = B200;
		break;
	case 300:
		baud = B300;
		break;
	case 600:
		baud = B600;
		break;
	case 1200:
		baud = B1200;
		break;
	case 1800:
		baud = B1800;
		break;
	case 2400:
		baud = B2400;
		break;
	case 4800:
		baud = B4800;
		break;
	case 9600:
		baud = B9600;
		break;
	case 19200:
		baud = B19200;
		break;
	case 38400:
		baud = B38400;
		break;
	case 57600:
		baud = B57600;
		break;
	case 115200:
		baud = B115200;
		break;
	case 230400:
		baud = B230400;
		break;
#if !defined(__APPLE__) && !defined(__OpenBSD__)
	case 460800:
		baud = B460800;
		break;
#endif
	default:
		return SP_ERR_ARG;
	}

	if (cfsetospeed(&term, baud) < 0)
		return SP_ERR_FAIL;

	if (cfsetispeed(&term, baud) < 0)
		return SP_ERR_FAIL;

	term.c_cflag &= ~CSIZE;
	switch (bits) {
	case 8:
		term.c_cflag |= CS8;
		break;
	case 7:
		term.c_cflag |= CS7;
		break;
	default:
		return SP_ERR_ARG;
	}

	term.c_cflag &= ~CSTOPB;
	switch (stopbits) {
	case 1:
		term.c_cflag &= ~CSTOPB;
		break;
	case 2:
		term.c_cflag |= CSTOPB;
		break;
	default:
		return SP_ERR_ARG;
	}

	term.c_iflag &= ~(IXON | IXOFF);
	term.c_cflag &= ~CRTSCTS;
	switch (flowcontrol) {
	case 0:
		/* No flow control. */
		break;
	case 1:
		term.c_cflag |= CRTSCTS;
		break;
	case 2:
		term.c_iflag |= IXON | IXOFF;
		break;
	default:
		return SP_ERR_ARG;
	}

	term.c_iflag &= ~IGNPAR;
	term.c_cflag &= ~(PARODD | PARENB);
	switch (parity) {
	case SP_PARITY_NONE:
		term.c_iflag |= IGNPAR;
		break;
	case SP_PARITY_EVEN:
		term.c_cflag |= PARENB;
		break;
	case SP_PARITY_ODD:
		term.c_cflag |= PARENB | PARODD;
		break;
	default:
		return SP_ERR_ARG;
	}

	/* Turn off all serial port cooking. */
	term.c_iflag &= ~(ISTRIP | INLCR | ICRNL);
	term.c_oflag &= ~(ONLCR | OCRNL | ONOCR);
#if !defined(__FreeBSD__) && !defined(__OpenBSD__) && !defined(__NetBSD__)
	term.c_oflag &= ~OFILL;
#endif

	/* Disable canonical mode, and don't echo input characters. */
	term.c_lflag &= ~(ICANON | ECHO);

	/* Write the configured settings. */
	if (tcsetattr(port->fd, TCSADRAIN, &term) < 0)
		return SP_ERR_FAIL;

	if (rts != -1) {
		controlbits = TIOCM_RTS;
		if (ioctl(port->fd, rts ? TIOCMBIS : TIOCMBIC,
				&controlbits) < 0)
			return SP_ERR_FAIL;
	}

	if (dtr != -1) {
		controlbits = TIOCM_DTR;
		if (ioctl(port->fd, dtr ? TIOCMBIS : TIOCMBIC,
				&controlbits) < 0)
			return SP_ERR_FAIL;
	}
#endif

	return SP_OK;
}

/**
 * Get error code for failed operation.
 *
 * In order to obtain the correct result, this function should be called
 * straight after the failure, before executing any other system operations.
 *
 * @return The system's numeric code for the error that caused the last
 *         operation to fail.
 */
int sp_last_error_code(void)
{
#ifdef _WIN32
	return GetLastError();
#else
	return errno;
#endif
}

/**
 * Get error message for failed operation.
 *
 * In order to obtain the correct result, this function should be called
 * straight after the failure, before executing other system operations.
 *
 * @return The system's message for the error that caused the last
 *         operation to fail. This string may be allocated by the function,
 *         and can be freed after use by calling sp_free_error_message.
 */
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

/**
 * Free error message.
 *
 * This function can be used to free a string returned by the
 * sp_last_error_message function.
 */
void sp_free_error_message(char *message)
{
#ifdef _WIN32
	LocalFree(message);
#else
	(void)message;
#endif
}
