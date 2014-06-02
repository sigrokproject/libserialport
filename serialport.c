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
#include <stdio.h>
#include <stdarg.h>
#ifdef _WIN32
#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#else
#include <limits.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <limits.h>
#include <poll.h>
#endif
#ifdef __APPLE__
#include <IOKit/IOKitLib.h>
#include <IOKit/serial/IOSerialKeys.h>
#include <IOKit/serial/ioss.h>
#include <sys/syslimits.h>
#endif
#ifdef __linux__
#ifdef HAVE_LIBUDEV
#include "libudev.h"
#endif
#ifndef __ANDROID__
#include "linux/serial.h"
#endif
#include "linux_termios.h"

/* TCGETX/TCSETX is not available everywhere. */
#if defined(TCGETX) && defined(TCSETX) && defined(HAVE_TERMIOX)
#define USE_TERMIOX
#endif
#endif

/* TIOCINQ/TIOCOUTQ is not available everywhere. */
#if !defined(TIOCINQ) && defined(FIONREAD)
#define TIOCINQ FIONREAD
#endif
#if !defined(TIOCOUTQ) && defined(FIONWRITE)
#define TIOCOUTQ FIONWRITE
#endif

/* Non-standard baudrates are not available everywhere. */
#if defined(HAVE_TERMIOS_SPEED) || defined(HAVE_TERMIOS2_SPEED)
#define USE_TERMIOS_SPEED
#endif

#include "libserialport.h"

struct sp_port {
	char *name;
#ifdef _WIN32
	HANDLE hdl;
	COMMTIMEOUTS timeouts;
	OVERLAPPED write_ovl;
	OVERLAPPED read_ovl;
	OVERLAPPED wait_ovl;
	DWORD events;
	BYTE pending_byte;
	BOOL writing;
#else
	int fd;
#endif
};

struct sp_port_config {
	int baudrate;
	int bits;
	enum sp_parity parity;
	int stopbits;
	enum sp_rts rts;
	enum sp_cts cts;
	enum sp_dtr dtr;
	enum sp_dsr dsr;
	enum sp_xonxoff xon_xoff;
};

struct port_data {
#ifdef _WIN32
	DCB dcb;
#else
	struct termios term;
	int controlbits;
	int termiox_supported;
	int rts_flow;
	int cts_flow;
	int dtr_flow;
	int dsr_flow;
#endif
};

#ifdef _WIN32
typedef HANDLE event_handle;
#else
typedef int event_handle;
#endif

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

void (*sp_debug_handler)(const char *format, ...) = sp_default_debug_handler;

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))
#define NUM_STD_BAUDRATES ARRAY_SIZE(std_baudrates)

/* Debug output macros. */
#define DEBUG(fmt, ...) do { if (sp_debug_handler) sp_debug_handler(fmt ".\n", ##__VA_ARGS__); } while (0)
#define DEBUG_ERROR(err, fmt, ...) DEBUG("%s returning " #err ": " fmt, __func__, ##__VA_ARGS__)
#define DEBUG_FAIL(fmt, ...) do {               \
	char *errmsg = sp_last_error_message(); \
	DEBUG("%s returning SP_ERR_FAIL: "fmt": %s", __func__,##__VA_ARGS__,errmsg); \
	sp_free_error_message(errmsg); \
} while (0);
#define RETURN() do { DEBUG("%s returning", __func__); return; } while(0)
#define RETURN_CODE(x) do { DEBUG("%s returning " #x, __func__); return x; } while (0)
#define RETURN_CODEVAL(x) do { \
	switch (x) { \
		case SP_OK: RETURN_CODE(SP_OK); \
		case SP_ERR_ARG: RETURN_CODE(SP_ERR_ARG); \
		case SP_ERR_FAIL: RETURN_CODE(SP_ERR_FAIL); \
		case SP_ERR_MEM: RETURN_CODE(SP_ERR_MEM); \
		case SP_ERR_SUPP: RETURN_CODE(SP_ERR_SUPP); \
	} \
} while (0)
#define RETURN_OK() RETURN_CODE(SP_OK);
#define RETURN_ERROR(err, ...) do { DEBUG_ERROR(err, __VA_ARGS__); return err; } while (0)
#define RETURN_FAIL(...) do { DEBUG_FAIL(__VA_ARGS__); return SP_ERR_FAIL; } while (0)
#define RETURN_VALUE(fmt, x) do { \
	typeof(x) _x = x; \
	DEBUG("%s returning " fmt, __func__, _x); \
	return _x; \
} while (0)
#define SET_ERROR(val, err, msg) do { DEBUG_ERROR(err, msg); val = err; } while (0)
#define SET_FAIL(val, msg) do { DEBUG_FAIL(msg); val = SP_ERR_FAIL; } while (0)
#define TRACE(fmt, ...) DEBUG("%s(" fmt ") called", __func__, ##__VA_ARGS__)

#define TRY(x) do { int ret = x; if (ret != SP_OK) RETURN_CODEVAL(ret); } while (0)

/* Helper functions. */
static struct sp_port **list_append(struct sp_port **list, const char *portname);
static enum sp_return get_config(struct sp_port *port, struct port_data *data,
	struct sp_port_config *config);
static enum sp_return set_config(struct sp_port *port, struct port_data *data,
	const struct sp_port_config *config);

enum sp_return sp_get_port_by_name(const char *portname, struct sp_port **port_ptr)
{
	struct sp_port *port;
	int len;

	TRACE("%s, %p", portname, port_ptr);

	if (!port_ptr)
		RETURN_ERROR(SP_ERR_ARG, "Null result pointer");

	*port_ptr = NULL;

	if (!portname)
		RETURN_ERROR(SP_ERR_ARG, "Null port name");

	DEBUG("Building structure for port %s", portname);

	if (!(port = malloc(sizeof(struct sp_port))))
		RETURN_ERROR(SP_ERR_MEM, "Port structure malloc failed");

	len = strlen(portname) + 1;

	if (!(port->name = malloc(len))) {
		free(port);
		RETURN_ERROR(SP_ERR_MEM, "Port name malloc failed");
	}

	memcpy(port->name, portname, len);

#ifdef _WIN32
	port->hdl = INVALID_HANDLE_VALUE;
#else
	port->fd = -1;
#endif

	*port_ptr = port;

	RETURN_OK();
}

char *sp_get_port_name(const struct sp_port *port)
{
	TRACE("%p", port);

	if (!port)
		return NULL;

	RETURN_VALUE("%s", port->name);
}

enum sp_return sp_get_port_handle(const struct sp_port *port, void *result_ptr)
{
	TRACE("%p, %p", port, result_ptr);

	if (!port)
		RETURN_ERROR(SP_ERR_ARG, "Null port");

#ifdef _WIN32
	HANDLE *handle_ptr = result_ptr;
	*handle_ptr = port->hdl;
#else
	int *fd_ptr = result_ptr;
	*fd_ptr = port->fd;
#endif

	RETURN_OK();
}

enum sp_return sp_copy_port(const struct sp_port *port, struct sp_port **copy_ptr)
{
	TRACE("%p, %p", port, copy_ptr);

	if (!copy_ptr)
		RETURN_ERROR(SP_ERR_ARG, "Null result pointer");

	*copy_ptr = NULL;

	if (!port)
		RETURN_ERROR(SP_ERR_ARG, "Null port");

	if (!port->name)
		RETURN_ERROR(SP_ERR_ARG, "Null port name");

	DEBUG("Copying port structure");

	RETURN_VALUE("%p", sp_get_port_by_name(port->name, copy_ptr));
}

void sp_free_port(struct sp_port *port)
{
	TRACE("%p", port);

	if (!port) {
		DEBUG("Null port");
		RETURN();
	}

	DEBUG("Freeing port structure");

	if (port->name)
		free(port->name);

	free(port);

	RETURN();
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
	int ret = SP_ERR_SUPP;

	TRACE("%p", list_ptr);

	if (!list_ptr)
		RETURN_ERROR(SP_ERR_ARG, "Null result pointer");

	DEBUG("Enumerating ports");

	if (!(list = malloc(sizeof(struct sp_port **))))
		RETURN_ERROR(SP_ERR_MEM, "Port list malloc failed");

	list[0] = NULL;

#ifdef _WIN32
	HKEY key;
	TCHAR *value, *data;
	DWORD max_value_len, max_data_size, max_data_len;
	DWORD value_len, data_size, data_len;
	DWORD type, index = 0;
	char *name;
	int name_len;

	ret = SP_OK;

	DEBUG("Opening registry key");
	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, _T("HARDWARE\\DEVICEMAP\\SERIALCOMM"),
			0, KEY_QUERY_VALUE, &key) != ERROR_SUCCESS) {
		SET_FAIL(ret, "RegOpenKeyEx() failed");
		goto out_done;
	}
	DEBUG("Querying registry key value and data sizes");
	if (RegQueryInfoKey(key, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
				&max_value_len, &max_data_size, NULL, NULL) != ERROR_SUCCESS) {
		SET_FAIL(ret, "RegQueryInfoKey() failed");
		goto out_close;
	}
	max_data_len = max_data_size / sizeof(TCHAR);
	if (!(value = malloc((max_value_len + 1) * sizeof(TCHAR)))) {
		SET_ERROR(ret, SP_ERR_MEM, "registry value malloc failed");
		goto out_close;
	}
	if (!(data = malloc((max_data_len + 1) * sizeof(TCHAR)))) {
		SET_ERROR(ret, SP_ERR_MEM, "registry data malloc failed");
		goto out_free_value;
	}
	DEBUG("Iterating over values");
	while (
		value_len = max_value_len + 1,
		data_size = max_data_size,
		RegEnumValue(key, index, value, &value_len,
			NULL, &type, (LPBYTE)data, &data_size) == ERROR_SUCCESS)
	{
		data_len = data_size / sizeof(TCHAR);
		data[data_len] = '\0';
#ifdef UNICODE
		name_len = WideCharToMultiByte(CP_ACP, 0, data, -1, NULL, 0, NULL, NULL);
#else
		name_len = data_len + 1;
#endif
		if (!(name = malloc(name_len))) {
			SET_ERROR(ret, SP_ERR_MEM, "registry port name malloc failed");
			goto out;
		}
#ifdef UNICODE
		WideCharToMultiByte(CP_ACP, 0, data, -1, name, name_len, NULL, NULL);
#else
		strcpy(name, data);
#endif
		if (type == REG_SZ) {
			DEBUG("Found port %s", name);
			if (!(list = list_append(list, name))) {
				SET_ERROR(ret, SP_ERR_MEM, "list append failed");
				goto out;
			}
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

	ret = SP_OK;

	DEBUG("Getting IOKit master port");
	if (IOMasterPort(MACH_PORT_NULL, &master) != KERN_SUCCESS) {
		SET_FAIL(ret, "IOMasterPort() failed");
		goto out_done;
	}

	DEBUG("Creating matching dictionary");
	if (!(classes = IOServiceMatching(kIOSerialBSDServiceValue))) {
		SET_FAIL(ret, "IOServiceMatching() failed");
		goto out_done;
	}

	CFDictionarySetValue(classes,
			CFSTR(kIOSerialBSDTypeKey), CFSTR(kIOSerialBSDAllTypes));

	DEBUG("Getting matching services");
	if (IOServiceGetMatchingServices(master, classes, &iter) != KERN_SUCCESS) {
		SET_FAIL(ret, "IOServiceGetMatchingServices() failed");
		goto out_done;
	}

	if (!(path = malloc(PATH_MAX))) {
		SET_ERROR(ret, SP_ERR_MEM, "device path malloc failed");
		goto out_release;
	}

	DEBUG("Iterating over results");
	while ((port = IOIteratorNext(iter))) {
		cf_path = IORegistryEntryCreateCFProperty(port,
				CFSTR(kIOCalloutDeviceKey), kCFAllocatorDefault, 0);
		if (cf_path) {
			result = CFStringGetCString(cf_path,
					path, PATH_MAX, kCFStringEncodingASCII);
			CFRelease(cf_path);
			if (result) {
				DEBUG("Found port %s", path);
				if (!(list = list_append(list, path))) {
					SET_ERROR(ret, SP_ERR_MEM, "list append failed");
					IOObjectRelease(port);
					goto out;
				}
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
#if defined(__linux__) && defined(HAVE_LIBUDEV)
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

	ret = SP_OK;

	DEBUG("Enumerating tty devices");
	ud = udev_new();
	ud_enumerate = udev_enumerate_new(ud);
	udev_enumerate_add_match_subsystem(ud_enumerate, "tty");
	udev_enumerate_scan_devices(ud_enumerate);
	ud_list = udev_enumerate_get_list_entry(ud_enumerate);
	DEBUG("Iterating over results");
	udev_list_entry_foreach(ud_entry, ud_list) {
		path = udev_list_entry_get_name(ud_entry);
		DEBUG("Found device %s", path);
		ud_dev = udev_device_new_from_syspath(ud, path);
		/* If there is no parent device, this is a virtual tty. */
		ud_parent = udev_device_get_parent(ud_dev);
		if (ud_parent == NULL) {
			DEBUG("No parent device, assuming virtual tty");
			udev_device_unref(ud_dev);
			continue;
		}
		name = udev_device_get_devnode(ud_dev);
		/* The serial8250 driver has a hardcoded number of ports.
		 * The only way to tell which actually exist on a given system
		 * is to try to open them and make an ioctl call. */
		driver = udev_device_get_driver(ud_parent);
		if (driver && !strcmp(driver, "serial8250")) {
			DEBUG("serial8250 device, attempting to open");
			if ((fd = open(name, O_RDWR | O_NONBLOCK | O_NOCTTY)) < 0) {
				DEBUG("open failed, skipping");
				goto skip;
			}
			ioctl_result = ioctl(fd, TIOCGSERIAL, &serial_info);
			close(fd);
			if (ioctl_result != 0) {
				DEBUG("ioctl failed, skipping");
				goto skip;
			}
			if (serial_info.type == PORT_UNKNOWN) {
				DEBUG("port type is unknown, skipping");
				goto skip;
			}
		}
		DEBUG("Found port %s", name);
		list = list_append(list, name);
skip:
		udev_device_unref(ud_dev);
		if (!list) {
			SET_ERROR(ret, SP_ERR_MEM, "list append failed");
			goto out;
		}
	}
out:
	udev_enumerate_unref(ud_enumerate);
	udev_unref(ud);
#endif

	switch (ret) {
	case SP_OK:
		*list_ptr = list;
		RETURN_OK();
	case SP_ERR_SUPP:
		DEBUG_ERROR(SP_ERR_SUPP, "Enumeration not supported on this platform");
	default:
		if (list)
			sp_free_port_list(list);
		*list_ptr = NULL;
		return ret;
	}
}

void sp_free_port_list(struct sp_port **list)
{
	unsigned int i;

	TRACE("%p", list);

	if (!list) {
		DEBUG("Null list");
		RETURN();
	}

	DEBUG("Freeing port list");

	for (i = 0; list[i]; i++)
		sp_free_port(list[i]);
	free(list);

	RETURN();
}

#define CHECK_PORT() do { \
	if (port == NULL) \
		RETURN_ERROR(SP_ERR_ARG, "Null port"); \
	if (port->name == NULL) \
		RETURN_ERROR(SP_ERR_ARG, "Null port name"); \
} while (0)
#ifdef _WIN32
#define CHECK_PORT_HANDLE() do { \
	if (port->hdl == INVALID_HANDLE_VALUE) \
		RETURN_ERROR(SP_ERR_ARG, "Invalid port handle"); \
} while (0)
#else
#define CHECK_PORT_HANDLE() do { \
	if (port->fd < 0) \
		RETURN_ERROR(SP_ERR_ARG, "Invalid port fd"); \
} while (0)
#endif
#define CHECK_OPEN_PORT() do { \
	CHECK_PORT(); \
	CHECK_PORT_HANDLE(); \
} while (0)

enum sp_return sp_open(struct sp_port *port, enum sp_mode flags)
{
	struct port_data data;
	struct sp_port_config config;
	enum sp_return ret;

	TRACE("%p, 0x%x", port, flags);

	CHECK_PORT();

	if (flags > (SP_MODE_READ | SP_MODE_WRITE))
		RETURN_ERROR(SP_ERR_ARG, "Invalid flags");

	DEBUG("Opening port %s", port->name);

#ifdef _WIN32
	DWORD desired_access = 0, flags_and_attributes = 0, errors;
	char *escaped_port_name;
	COMSTAT status;

	/* Prefix port name with '\\.\' to work with ports above COM9. */
	if (!(escaped_port_name = malloc(strlen(port->name) + 5)))
		RETURN_ERROR(SP_ERR_MEM, "Escaped port name malloc failed");
	sprintf(escaped_port_name, "\\\\.\\%s", port->name);

	/* Map 'flags' to the OS-specific settings. */
	flags_and_attributes = FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED;
	if (flags & SP_MODE_READ)
		desired_access |= GENERIC_READ;
	if (flags & SP_MODE_WRITE)
		desired_access |= GENERIC_WRITE;

	port->hdl = CreateFile(escaped_port_name, desired_access, 0, 0,
			 OPEN_EXISTING, flags_and_attributes, 0);

	free(escaped_port_name);

	if (port->hdl == INVALID_HANDLE_VALUE)
		RETURN_FAIL("port CreateFile() failed");

	/* All timeouts initially disabled. */
	port->timeouts.ReadIntervalTimeout = 0;
	port->timeouts.ReadTotalTimeoutMultiplier = 0;
	port->timeouts.ReadTotalTimeoutConstant = 0;
	port->timeouts.WriteTotalTimeoutMultiplier = 0;
	port->timeouts.WriteTotalTimeoutConstant = 0;

	if (SetCommTimeouts(port->hdl, &port->timeouts) == 0) {
		sp_close(port);
		RETURN_FAIL("SetCommTimeouts() failed");
	}

	/* Prepare OVERLAPPED structures. */
#define INIT_OVERLAPPED(ovl) do { \
	memset(&port->ovl, 0, sizeof(port->ovl)); \
	port->ovl.hEvent = INVALID_HANDLE_VALUE; \
	if ((port->ovl.hEvent = CreateEvent(NULL, TRUE, TRUE, NULL)) \
			== INVALID_HANDLE_VALUE) { \
		sp_close(port); \
		RETURN_FAIL(#ovl "CreateEvent() failed"); \
	} \
} while (0)

	INIT_OVERLAPPED(read_ovl);
	INIT_OVERLAPPED(write_ovl);
	INIT_OVERLAPPED(wait_ovl);

	/* Set event mask for RX and error events. */
	if (SetCommMask(port->hdl, EV_RXCHAR | EV_ERR) == 0) {
		sp_close(port);
		RETURN_FAIL("SetCommMask() failed");
	}

	/* Start background operation for RX and error events. */
	if (WaitCommEvent(port->hdl, &port->events, &port->wait_ovl) == 0) {
		if (GetLastError() != ERROR_IO_PENDING) {
			sp_close(port);
			RETURN_FAIL("WaitCommEvent() failed");
		}
	}

	port->writing = FALSE;

#else
	int flags_local = O_NONBLOCK | O_NOCTTY;

	/* Map 'flags' to the OS-specific settings. */
	if (flags & (SP_MODE_READ | SP_MODE_WRITE))
		flags_local |= O_RDWR;
	else if (flags & SP_MODE_READ)
		flags_local |= O_RDONLY;
	else if (flags & SP_MODE_WRITE)
		flags_local |= O_WRONLY;

	if ((port->fd = open(port->name, flags_local)) < 0)
		RETURN_FAIL("open() failed");
#endif

	ret = get_config(port, &data, &config);

	if (ret < 0) {
		sp_close(port);
		RETURN_CODEVAL(ret);
	}

	/* Set sane port settings. */
#ifdef _WIN32
	data.dcb.fBinary = TRUE;
	data.dcb.fDsrSensitivity = FALSE;
	data.dcb.fErrorChar = FALSE;
	data.dcb.fNull = FALSE;
	data.dcb.fAbortOnError = TRUE;
#else
	/* Turn off all fancy termios tricks, give us a raw channel. */
	data.term.c_iflag &= ~(IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR | ICRNL | IMAXBEL);
#ifdef IUCLC
	data.term.c_iflag &= ~IUCLC;
#endif
	data.term.c_oflag &= ~(OPOST | ONLCR | OCRNL | ONOCR | ONLRET);
#ifdef OLCUC
	data.term.c_oflag &= ~OLCUC;
#endif
#ifdef NLDLY
	data.term.c_oflag &= ~NLDLY;
#endif
#ifdef CRDLY
	data.term.c_oflag &= ~CRDLY;
#endif
#ifdef TABDLY
	data.term.c_oflag &= ~TABDLY;
#endif
#ifdef BSDLY
	data.term.c_oflag &= ~BSDLY;
#endif
#ifdef VTDLY
	data.term.c_oflag &= ~VTDLY;
#endif
#ifdef FFDLY
	data.term.c_oflag &= ~FFDLY;
#endif
#ifdef OFILL
	data.term.c_oflag &= ~OFILL;
#endif
	data.term.c_lflag &= ~(ISIG | ICANON | ECHO | IEXTEN);
	data.term.c_cc[VMIN] = 0;
	data.term.c_cc[VTIME] = 0;

	/* Ignore modem status lines; enable receiver; leave control lines alone on close. */
	data.term.c_cflag |= (CLOCAL | CREAD | HUPCL);
#endif

#ifdef _WIN32
	if (ClearCommError(port->hdl, &errors, &status) == 0)
		RETURN_FAIL("ClearCommError() failed");
#endif

	ret = set_config(port, &data, &config);

	if (ret < 0) {
		sp_close(port);
		RETURN_CODEVAL(ret);
	}

	RETURN_OK();
}

enum sp_return sp_close(struct sp_port *port)
{
	TRACE("%p", port);

	CHECK_OPEN_PORT();

	DEBUG("Closing port %s", port->name);

#ifdef _WIN32
	/* Returns non-zero upon success, 0 upon failure. */
	if (CloseHandle(port->hdl) == 0)
		RETURN_FAIL("port CloseHandle() failed");
	port->hdl = INVALID_HANDLE_VALUE;

	/* Close event handles for overlapped structures. */
#define CLOSE_OVERLAPPED(ovl) do { \
	if (port->ovl.hEvent != INVALID_HANDLE_VALUE && \
		CloseHandle(port->ovl.hEvent) == 0) \
		RETURN_FAIL(# ovl "event CloseHandle() failed"); \
} while (0)
	CLOSE_OVERLAPPED(read_ovl);
	CLOSE_OVERLAPPED(write_ovl);
	CLOSE_OVERLAPPED(wait_ovl);

#else
	/* Returns 0 upon success, -1 upon failure. */
	if (close(port->fd) == -1)
		RETURN_FAIL("close() failed");
	port->fd = -1;
#endif

	RETURN_OK();
}

enum sp_return sp_flush(struct sp_port *port, enum sp_buffer buffers)
{
	TRACE("%p, 0x%x", port, buffers);

	CHECK_OPEN_PORT();

	if (buffers > SP_BUF_BOTH)
		RETURN_ERROR(SP_ERR_ARG, "Invalid buffer selection");

	const char *buffer_names[] = {"no", "input", "output", "both"};

	DEBUG("Flushing %s buffers on port %s", buffer_names[buffers], port->name);

#ifdef _WIN32
	DWORD flags = 0;
	if (buffers & SP_BUF_INPUT)
		flags |= PURGE_RXCLEAR;
	if (buffers & SP_BUF_OUTPUT)
		flags |= PURGE_TXCLEAR;

	/* Returns non-zero upon success, 0 upon failure. */
	if (PurgeComm(port->hdl, flags) == 0)
		RETURN_FAIL("PurgeComm() failed");
#else
	int flags = 0;
	if (buffers & SP_BUF_BOTH)
		flags = TCIOFLUSH;
	else if (buffers & SP_BUF_INPUT)
		flags = TCIFLUSH;
	else if (buffers & SP_BUF_OUTPUT)
		flags = TCOFLUSH;

	/* Returns 0 upon success, -1 upon failure. */
	if (tcflush(port->fd, flags) < 0)
		RETURN_FAIL("tcflush() failed");
#endif
	RETURN_OK();
}

enum sp_return sp_drain(struct sp_port *port)
{
	TRACE("%p", port);

	CHECK_OPEN_PORT();

	DEBUG("Draining port %s", port->name);

#ifdef _WIN32
	/* Returns non-zero upon success, 0 upon failure. */
	if (FlushFileBuffers(port->hdl) == 0)
		RETURN_FAIL("FlushFileBuffers() failed");
	RETURN_OK();
#else
	int result;
	while (1) {
#ifdef __ANDROID__
		int arg = 1;
		result = ioctl(port->fd, TCSBRK, &arg);
#else
		result = tcdrain(port->fd);
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
#endif
}

enum sp_return sp_blocking_write(struct sp_port *port, const void *buf, size_t count, unsigned int timeout)
{
	TRACE("%p, %p, %d, %d", port, buf, count, timeout);

	CHECK_OPEN_PORT();

	if (!buf)
		RETURN_ERROR(SP_ERR_ARG, "Null buffer");

	if (timeout)
		DEBUG("Writing %d bytes to port %s, timeout %d ms", count, port->name, timeout);
	else
		DEBUG("Writing %d bytes to port %s, no timeout", count, port->name);

	if (count == 0)
		RETURN_VALUE("0", 0);

#ifdef _WIN32
	DWORD bytes_written = 0;
	BOOL result;

	/* Wait for previous non-blocking write to complete, if any. */
	if (port->writing) {
		DEBUG("Waiting for previous write to complete");
		result = GetOverlappedResult(port->hdl, &port->write_ovl, &bytes_written, TRUE);
		port->writing = 0;
		if (!result)
			RETURN_FAIL("Previous write failed to complete");
		DEBUG("Previous write completed");
	}

	/* Set timeout. */
	port->timeouts.WriteTotalTimeoutConstant = timeout;
	if (SetCommTimeouts(port->hdl, &port->timeouts) == 0)
		RETURN_FAIL("SetCommTimeouts() failed");

	/* Start write. */
	if (WriteFile(port->hdl, buf, count, NULL, &port->write_ovl) == 0) {
		if (GetLastError() == ERROR_IO_PENDING) {
			DEBUG("Waiting for write to complete");
			GetOverlappedResult(port->hdl, &port->write_ovl, &bytes_written, TRUE);
			DEBUG("Write completed, %d/%d bytes written", bytes_written, count);
			RETURN_VALUE("%d", bytes_written);
		} else {
			RETURN_FAIL("WriteFile() failed");
		}
	} else {
		DEBUG("Write completed immediately");
		RETURN_VALUE("%d", count);
	}
#else
	size_t bytes_written = 0;
	unsigned char *ptr = (unsigned char *) buf;
	struct timeval start, delta, now, end = {0, 0};
	fd_set fds;
	int result;

	if (timeout) {
		/* Get time at start of operation. */
		gettimeofday(&start, NULL);
		/* Define duration of timeout. */
		delta.tv_sec = timeout / 1000;
		delta.tv_usec = (timeout % 1000) * 1000;
		/* Calculate time at which we should give up. */
		timeradd(&start, &delta, &end);
	}

	/* Loop until we have written the requested number of bytes. */
	while (bytes_written < count)
	{
		/* Wait until space is available. */
		FD_ZERO(&fds);
		FD_SET(port->fd, &fds);
		if (timeout) {
			gettimeofday(&now, NULL);
			if (timercmp(&now, &end, >)) {
				DEBUG("write timed out");
				RETURN_VALUE("%d", bytes_written);
			}
			timersub(&end, &now, &delta);
		}
		result = select(port->fd + 1, NULL, &fds, NULL, timeout ? &delta : NULL);
		if (result < 0) {
			if (errno == EINTR) {
				DEBUG("select() call was interrupted, repeating");
				continue;
			} else {
				RETURN_FAIL("select() failed");
			}
		} else if (result == 0) {
			DEBUG("write timed out");
			RETURN_VALUE("%d", bytes_written);
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

	RETURN_VALUE("%d", bytes_written);
#endif
}

enum sp_return sp_nonblocking_write(struct sp_port *port, const void *buf, size_t count)
{
	TRACE("%p, %p, %d", port, buf, count);

	CHECK_OPEN_PORT();

	if (!buf)
		RETURN_ERROR(SP_ERR_ARG, "Null buffer");

	DEBUG("Writing up to %d bytes to port %s", count, port->name);

	if (count == 0)
		RETURN_VALUE("0", 0);

#ifdef _WIN32
	DWORD written = 0;
	BYTE *ptr = (BYTE *) buf;

	/* Check whether previous write is complete. */
	if (port->writing) {
		if (HasOverlappedIoCompleted(&port->write_ovl)) {
			DEBUG("Previous write completed");
			port->writing = 0;
		} else {
			DEBUG("Previous write not complete");
			/* Can't take a new write until the previous one finishes. */
			RETURN_VALUE("0", 0);
		}
	}

	/* Set timeout. */
	port->timeouts.WriteTotalTimeoutConstant = 0;
	if (SetCommTimeouts(port->hdl, &port->timeouts) == 0)
		RETURN_FAIL("SetCommTimeouts() failed");

	/* Keep writing data until the OS has to actually start an async IO for it.
	 * At that point we know the buffer is full. */
	while (written < count)
	{
		/* Copy first byte of user buffer. */
		port->pending_byte = *ptr++;

		/* Start asynchronous write. */
		if (WriteFile(port->hdl, &port->pending_byte, 1, NULL, &port->write_ovl) == 0) {
			if (GetLastError() == ERROR_IO_PENDING) {
				if (HasOverlappedIoCompleted(&port->write_ovl)) {
					DEBUG("Asynchronous write completed immediately");
					port->writing = 0;
					written++;
					continue;
				} else {
					DEBUG("Asynchronous write running");
					port->writing = 1;
					RETURN_VALUE("%d", ++written);
				}
			} else {
				/* Actual failure of some kind. */
				RETURN_FAIL("WriteFile() failed");
			}
		} else {
			DEBUG("Single byte written immediately");
			written++;
		}
	}

	DEBUG("All bytes written immediately");

	RETURN_VALUE("%d", written);
#else
	/* Returns the number of bytes written, or -1 upon failure. */
	ssize_t written = write(port->fd, buf, count);

	if (written < 0)
		RETURN_FAIL("write() failed");
	else
		RETURN_VALUE("%d", written);
#endif
}

enum sp_return sp_blocking_read(struct sp_port *port, void *buf, size_t count, unsigned int timeout)
{
	TRACE("%p, %p, %d, %d", port, buf, count, timeout);

	CHECK_OPEN_PORT();

	if (!buf)
		RETURN_ERROR(SP_ERR_ARG, "Null buffer");

	if (timeout)
		DEBUG("Reading %d bytes from port %s, timeout %d ms", count, port->name, timeout);
	else
		DEBUG("Reading %d bytes from port %s, no timeout", count, port->name);

	if (count == 0)
		RETURN_VALUE("0", 0);

#ifdef _WIN32
	DWORD bytes_read = 0;

	/* Set timeout. */
	port->timeouts.ReadIntervalTimeout = 0;
	port->timeouts.ReadTotalTimeoutConstant = timeout;
	if (SetCommTimeouts(port->hdl, &port->timeouts) == 0)
		RETURN_FAIL("SetCommTimeouts() failed");

	/* Start read. */
	if (ReadFile(port->hdl, buf, count, NULL, &port->read_ovl) == 0) {
		if (GetLastError() == ERROR_IO_PENDING) {
			DEBUG("Waiting for read to complete");
			GetOverlappedResult(port->hdl, &port->read_ovl, &bytes_read, TRUE);
			DEBUG("Read completed, %d/%d bytes read", bytes_read, count);
		} else {
			RETURN_FAIL("ReadFile() failed");
		}
	} else {
		DEBUG("Read completed immediately");
		bytes_read = count;
	}

	/* Start background operation for subsequent events. */
	if (WaitCommEvent(port->hdl, &port->events, &port->wait_ovl) == 0) {
		if (GetLastError() != ERROR_IO_PENDING)
			RETURN_FAIL("WaitCommEvent() failed");
	}

	RETURN_VALUE("%d", bytes_read);

#else
	size_t bytes_read = 0;
	unsigned char *ptr = (unsigned char *) buf;
	struct timeval start, delta, now, end = {0, 0};
	fd_set fds;
	int result;

	if (timeout) {
		/* Get time at start of operation. */
		gettimeofday(&start, NULL);
		/* Define duration of timeout. */
		delta.tv_sec = timeout / 1000;
		delta.tv_usec = (timeout % 1000) * 1000;
		/* Calculate time at which we should give up. */
		timeradd(&start, &delta, &end);
	}

	/* Loop until we have the requested number of bytes. */
	while (bytes_read < count)
	{
		/* Wait until data is available. */
		FD_ZERO(&fds);
		FD_SET(port->fd, &fds);
		if (timeout) {
			gettimeofday(&now, NULL);
			if (timercmp(&now, &end, >))
				/* Timeout has expired. */
				RETURN_VALUE("%d", bytes_read);
			timersub(&end, &now, &delta);
		}
		result = select(port->fd + 1, &fds, NULL, NULL, timeout ? &delta : NULL);
		if (result < 0) {
			if (errno == EINTR) {
				DEBUG("select() call was interrupted, repeating");
				continue;
			} else {
				RETURN_FAIL("select() failed");
			}
		} else if (result == 0) {
			DEBUG("read timed out");
			RETURN_VALUE("%d", bytes_read);
		}

		/* Do read. */
		result = read(port->fd, ptr, count - bytes_read);

		if (result < 0) {
			if (errno == EAGAIN)
				/* This shouldn't happen because we did a select() first, but handle anyway. */
				continue;
			else
				/* This is an actual failure. */
				RETURN_FAIL("read() failed");
		}

		bytes_read += result;
		ptr += result;
	}

	RETURN_VALUE("%d", bytes_read);
#endif
}

enum sp_return sp_nonblocking_read(struct sp_port *port, void *buf, size_t count)
{
	TRACE("%p, %p, %d", port, buf, count);

	CHECK_OPEN_PORT();

	if (!buf)
		RETURN_ERROR(SP_ERR_ARG, "Null buffer");

	DEBUG("Reading up to %d bytes from port %s", count, port->name);

#ifdef _WIN32
	DWORD bytes_read;

	/* Set timeout. */
	port->timeouts.ReadIntervalTimeout = MAXDWORD;
	port->timeouts.ReadTotalTimeoutConstant = 0;
	if (SetCommTimeouts(port->hdl, &port->timeouts) == 0)
		RETURN_FAIL("SetCommTimeouts() failed");

	/* Do read. */
	if (ReadFile(port->hdl, buf, count, NULL, &port->read_ovl) == 0)
		RETURN_FAIL("ReadFile() failed");

	/* Get number of bytes read. */
	if (GetOverlappedResult(port->hdl, &port->read_ovl, &bytes_read, TRUE) == 0)
		RETURN_FAIL("GetOverlappedResult() failed");

	if (bytes_read > 0) {
		/* Start background operation for subsequent events. */
		if (WaitCommEvent(port->hdl, &port->events, &port->wait_ovl) == 0) {
			if (GetLastError() != ERROR_IO_PENDING)
				RETURN_FAIL("WaitCommEvent() failed");
		}
	}

	RETURN_VALUE("%d", bytes_read);
#else
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
	RETURN_VALUE("%d", bytes_read);
#endif
}

enum sp_return sp_input_waiting(struct sp_port *port)
{
	TRACE("%p", port);

	CHECK_OPEN_PORT();

	DEBUG("Checking input bytes waiting on port %s", port->name);

#ifdef _WIN32
	DWORD errors;
	COMSTAT comstat;

	if (ClearCommError(port->hdl, &errors, &comstat) == 0)
		RETURN_FAIL("ClearCommError() failed");
	RETURN_VALUE("%d", comstat.cbInQue);
#else
	int bytes_waiting;
	if (ioctl(port->fd, TIOCINQ, &bytes_waiting) < 0)
		RETURN_FAIL("TIOCINQ ioctl failed");
	RETURN_VALUE("%d", bytes_waiting);
#endif
}

enum sp_return sp_output_waiting(struct sp_port *port)
{
	TRACE("%p", port);

	CHECK_OPEN_PORT();

	DEBUG("Checking output bytes waiting on port %s", port->name);

#ifdef _WIN32
	DWORD errors;
	COMSTAT comstat;

	if (ClearCommError(port->hdl, &errors, &comstat) == 0)
		RETURN_FAIL("ClearCommError() failed");
	RETURN_VALUE("%d", comstat.cbOutQue);
#else
	int bytes_waiting;
	if (ioctl(port->fd, TIOCOUTQ, &bytes_waiting) < 0)
		RETURN_FAIL("TIOCOUTQ ioctl failed");
	RETURN_VALUE("%d", bytes_waiting);
#endif
}

enum sp_return sp_new_event_set(struct sp_event_set **result_ptr)
{
	struct sp_event_set *result;

	TRACE("%p", result_ptr);

	if (!result_ptr)
		RETURN_ERROR(SP_ERR_ARG, "Null result");

	*result_ptr = NULL;

	if (!(result = malloc(sizeof(struct sp_event_set))))
		RETURN_ERROR(SP_ERR_MEM, "sp_event_set malloc() failed");

	memset(result, 0, sizeof(struct sp_event_set));

	*result_ptr = result;

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
		RETURN_ERROR(SP_ERR_MEM, "handle array realloc() failed");

	if (!(new_masks = realloc(event_set->masks,
			sizeof(enum sp_event) * (event_set->count + 1))))
		RETURN_ERROR(SP_ERR_MEM, "mask array realloc() failed");

	event_set->handles = new_handles;
	event_set->masks = new_masks;

	((event_handle *) event_set->handles)[event_set->count] = handle;
	event_set->masks[event_set->count] = mask;

	event_set->count++;

	RETURN_OK();
}

enum sp_return sp_add_port_events(struct sp_event_set *event_set,
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

#ifdef _WIN32
	enum sp_event handle_mask;
	if ((handle_mask = mask & SP_EVENT_TX_READY))
		TRY(add_handle(event_set, port->write_ovl.hEvent, handle_mask));
	if ((handle_mask = mask & (SP_EVENT_RX_READY | SP_EVENT_ERROR)))
		TRY(add_handle(event_set, port->wait_ovl.hEvent, handle_mask));
#else
	TRY(add_handle(event_set, port->fd, mask));
#endif

	RETURN_OK();
}

void sp_free_event_set(struct sp_event_set *event_set)
{
	TRACE("%p", event_set);

	if (!event_set) {
		DEBUG("Null event set");
		RETURN();
	}

	DEBUG("Freeing event set");

	if (event_set->handles)
		free(event_set->handles);
	if (event_set->masks)
		free(event_set->masks);

	free(event_set);

	RETURN();
}

enum sp_return sp_wait(struct sp_event_set *event_set, unsigned int timeout)
{
	TRACE("%p, %d", event_set, timeout);

	if (!event_set)
		RETURN_ERROR(SP_ERR_ARG, "Null event set");

#ifdef _WIN32
	if (WaitForMultipleObjects(event_set->count, event_set->handles, FALSE,
			timeout ? timeout : INFINITE) == WAIT_FAILED)
		RETURN_FAIL("WaitForMultipleObjects() failed");

	RETURN_OK();
#else
	struct timeval start, delta, now, end = {0, 0};
	int result, timeout_remaining;
	struct pollfd *pollfds;
	unsigned int i;

	if (!(pollfds = malloc(sizeof(struct pollfd) * event_set->count)))
		RETURN_ERROR(SP_ERR_MEM, "pollfds malloc() failed");

	for (i = 0; i < event_set->count; i++) {
		pollfds[i].fd = ((int *) event_set->handles)[i];
		pollfds[i].events = 0;
		pollfds[i].revents = 0;
		if (event_set->masks[i] & SP_EVENT_RX_READY)
			pollfds[i].events |= POLLIN;
		if (event_set->masks[i] & SP_EVENT_TX_READY)
			pollfds[i].events |= POLLOUT;
		if (event_set->masks[i] & SP_EVENT_ERROR)
			pollfds[i].events |= POLLERR;
	}

	if (timeout) {
		/* Get time at start of operation. */
		gettimeofday(&start, NULL);
		/* Define duration of timeout. */
		delta.tv_sec = timeout / 1000;
		delta.tv_usec = (timeout % 1000) * 1000;
		/* Calculate time at which we should give up. */
		timeradd(&start, &delta, &end);
	}

	/* Loop until an event occurs. */
	while (1)
	{
		if (timeout) {
			gettimeofday(&now, NULL);
			if (timercmp(&now, &end, >)) {
				DEBUG("wait timed out");
				break;
			}
			timersub(&end, &now, &delta);
			timeout_remaining = delta.tv_sec * 1000 + delta.tv_usec / 1000;
		}

		result = poll(pollfds, event_set->count, timeout ? timeout_remaining : -1);

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
			break;
		} else {
			DEBUG("poll() completed");
			break;
		}
	}

	free(pollfds);
	RETURN_OK();
#endif
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
		RETURN_FAIL("getting termios failed");
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
		RETURN_FAIL("getting termios failed");
	}

	DEBUG("Setting baud rate");

	set_termios_speed(data, baudrate);

	if (ioctl(fd, get_termios_set_ioctl(), data) < 0) {
		free(data);
		RETURN_FAIL("setting termios failed");
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
		RETURN_FAIL("getting termiox failed");
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
		RETURN_FAIL("getting termiox failed");
	}

	DEBUG("Setting advanced flow control");

	set_termiox_flow(termx, data->rts_flow, data->cts_flow,
			data->dtr_flow, data->dsr_flow);

	if (ioctl(fd, TCSETX, termx) < 0) {
		free(termx);
		RETURN_FAIL("setting termiox failed");
	}

	free(termx);

	RETURN_OK();
}
#endif /* USE_TERMIOX */

static enum sp_return get_config(struct sp_port *port, struct port_data *data,
	struct sp_port_config *config)
{
	unsigned int i;

	TRACE("%p, %p, %p", port, data, config);

	DEBUG("Getting configuration for port %s", port->name);

#ifdef _WIN32
	if (!GetCommState(port->hdl, &data->dcb))
		RETURN_FAIL("GetCommState() failed");

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
		case ODDPARITY:
			config->parity = SP_PARITY_ODD;
			break;
		case EVENPARITY:
			config->parity = SP_PARITY_EVEN;
			break;
		case MARKPARITY:
			config->parity = SP_PARITY_MARK;
			break;
		case SPACEPARITY:
			config->parity = SP_PARITY_SPACE;
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

	for (i = 0; i < NUM_STD_BAUDRATES; i++) {
		if (cfgetispeed(&data->term) == std_baudrates[i].index) {
			config->baudrate = std_baudrates[i].value;
			break;
		}
	}

	if (i == NUM_STD_BAUDRATES) {
#ifdef __APPLE__
		config->baudrate = (int)data->term.c_ispeed;
#elif defined(USE_TERMIOS_SPEED)
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
#endif

	RETURN_OK();
}

static enum sp_return set_config(struct sp_port *port, struct port_data *data,
	const struct sp_port_config *config)
{
	unsigned int i;
#ifdef __APPLE__
	BAUD_TYPE baud_nonstd;

	baud_nonstd = B0;
#endif
#ifdef USE_TERMIOS_SPEED
	int baud_nonstd = 0;
#endif

	TRACE("%p, %p, %p", port, data, config);

	DEBUG("Setting configuration for port %s", port->name);

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
		case SP_PARITY_NONE:
			data->dcb.Parity = NOPARITY;
			break;
		case SP_PARITY_ODD:
			data->dcb.Parity = ODDPARITY;
			break;
		case SP_PARITY_EVEN:
			data->dcb.Parity = EVENPARITY;
			break;
		case SP_PARITY_MARK:
			data->dcb.Parity = MARKPARITY;
			break;
		case SP_PARITY_SPACE:
			data->dcb.Parity = SPACEPARITY;
			break;
		default:
			RETURN_ERROR(SP_ERR_ARG, "Invalid parity setting");
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
			RETURN_ERROR(SP_ERR_ARG, "Invalid stop bit setting");
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
			RETURN_ERROR(SP_ERR_ARG, "Invalid RTS setting");
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
			RETURN_ERROR(SP_ERR_ARG, "Invalid CTS setting");
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
			RETURN_ERROR(SP_ERR_ARG, "Invalid DTR setting");
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
			RETURN_ERROR(SP_ERR_ARG, "Invalid DSR setting");
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
			RETURN_ERROR(SP_ERR_ARG, "Invalid XON/XOFF setting");
		}
	}

	if (!SetCommState(port->hdl, &data->dcb))
		RETURN_FAIL("SetCommState() failed");

#else /* !_WIN32 */

	int controlbits;

	if (config->baudrate >= 0) {
		for (i = 0; i < NUM_STD_BAUDRATES; i++) {
			if (config->baudrate == std_baudrates[i].value) {
				if (cfsetospeed(&data->term, std_baudrates[i].index) < 0)
					RETURN_FAIL("cfsetospeed() failed");

				if (cfsetispeed(&data->term, std_baudrates[i].index) < 0)
					RETURN_FAIL("cfsetispeed() failed");
				break;
			}
		}

		/* Non-standard baud rate */
		if (i == NUM_STD_BAUDRATES) {
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
		/* Set baud rates in data->term to correct, but incompatible
		 * with tcsetattr() value, same as delivered by tcgetattr(). */
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

#endif /* !_WIN32 */

	RETURN_OK();
}

enum sp_return sp_new_config(struct sp_port_config **config_ptr)
{
	struct sp_port_config *config;

	TRACE("%p", config_ptr);

	if (!config_ptr)
		RETURN_ERROR(SP_ERR_ARG, "Null result pointer");

	*config_ptr = NULL;

	if (!(config = malloc(sizeof(struct sp_port_config))))
		RETURN_ERROR(SP_ERR_MEM, "config malloc failed");

	config->baudrate = -1;
	config->bits = -1;
	config->parity = -1;
	config->stopbits = -1;
	config->rts = -1;
	config->cts = -1;
	config->dtr = -1;
	config->dsr = -1;

	*config_ptr = config;

	RETURN_OK();
}

void sp_free_config(struct sp_port_config *config)
{
	TRACE("%p", config);

	if (!config)
		DEBUG("Null config");
	else
		free(config);

	RETURN();
}

enum sp_return sp_get_config(struct sp_port *port, struct sp_port_config *config)
{
	struct port_data data;

	TRACE("%p, %p", port, config);

	CHECK_OPEN_PORT();

	if (!config)
		RETURN_ERROR(SP_ERR_ARG, "Null config");

	TRY(get_config(port, &data, config));

	RETURN_OK();
}

enum sp_return sp_set_config(struct sp_port *port, const struct sp_port_config *config)
{
	struct port_data data;
	struct sp_port_config prev_config;

	TRACE("%p, %p", port, config);

	CHECK_OPEN_PORT();

	if (!config)
		RETURN_ERROR(SP_ERR_ARG, "Null config");

	TRY(get_config(port, &data, &prev_config));
	TRY(set_config(port, &data, config));

	RETURN_OK();
}

#define CREATE_ACCESSORS(x, type) \
enum sp_return sp_set_##x(struct sp_port *port, type x) { \
	struct port_data data; \
	struct sp_port_config config; \
	TRACE("%p, %d", port, x); \
	CHECK_OPEN_PORT(); \
	TRY(get_config(port, &data, &config)); \
	config.x = x; \
	TRY(set_config(port, &data, &config)); \
	RETURN_OK(); \
} \
enum sp_return sp_get_config_##x(const struct sp_port_config *config, type *x) { \
	TRACE("%p, %p", config, x); \
	if (!config) \
		RETURN_ERROR(SP_ERR_ARG, "Null config"); \
	*x = config->x; \
	RETURN_OK(); \
} \
enum sp_return sp_set_config_##x(struct sp_port_config *config, type x) { \
	TRACE("%p, %d", config, x); \
	if (!config) \
		RETURN_ERROR(SP_ERR_ARG, "Null config"); \
	config->x = x; \
	RETURN_OK(); \
}

CREATE_ACCESSORS(baudrate, int)
CREATE_ACCESSORS(bits, int)
CREATE_ACCESSORS(parity, enum sp_parity)
CREATE_ACCESSORS(stopbits, int)
CREATE_ACCESSORS(rts, enum sp_rts)
CREATE_ACCESSORS(cts, enum sp_cts)
CREATE_ACCESSORS(dtr, enum sp_dtr)
CREATE_ACCESSORS(dsr, enum sp_dsr)
CREATE_ACCESSORS(xon_xoff, enum sp_xonxoff)

enum sp_return sp_set_config_flowcontrol(struct sp_port_config *config, enum sp_flowcontrol flowcontrol)
{
	if (!config)
		RETURN_ERROR(SP_ERR_ARG, "Null configuration");

	if (flowcontrol > SP_FLOWCONTROL_DTRDSR)
		RETURN_ERROR(SP_ERR_ARG, "Invalid flow control setting");

	if (flowcontrol == SP_FLOWCONTROL_XONXOFF)
		config->xon_xoff = SP_XONXOFF_INOUT;
	else
		config->xon_xoff = SP_XONXOFF_DISABLED;

	if (flowcontrol == SP_FLOWCONTROL_RTSCTS) {
		config->rts = SP_RTS_FLOW_CONTROL;
		config->cts = SP_CTS_FLOW_CONTROL;
	} else {
		if (config->rts == SP_RTS_FLOW_CONTROL)
			config->rts = SP_RTS_ON;
		config->cts = SP_CTS_IGNORE;
	}

	if (flowcontrol == SP_FLOWCONTROL_DTRDSR) {
		config->dtr = SP_DTR_FLOW_CONTROL;
		config->dsr = SP_DSR_FLOW_CONTROL;
	} else {
		if (config->dtr == SP_DTR_FLOW_CONTROL)
			config->dtr = SP_DTR_ON;
		config->dsr = SP_DSR_IGNORE;
	}

	RETURN_OK();
}

enum sp_return sp_set_flowcontrol(struct sp_port *port, enum sp_flowcontrol flowcontrol)
{
	struct port_data data;
	struct sp_port_config config;

	TRACE("%p, %d", port, flowcontrol);

	CHECK_OPEN_PORT();

	TRY(get_config(port, &data, &config));

	TRY(sp_set_config_flowcontrol(&config, flowcontrol));

	TRY(set_config(port, &data, &config));

	RETURN_OK();
}

enum sp_return sp_get_signals(struct sp_port *port, enum sp_signal *signals)
{
	TRACE("%p, %p", port, signals);

	CHECK_OPEN_PORT();

	if (!signals)
		RETURN_ERROR(SP_ERR_ARG, "Null result pointer");

	DEBUG("Getting control signals for port %s", port->name);

	*signals = 0;
#ifdef _WIN32
	DWORD bits;
	if (GetCommModemStatus(port->hdl, &bits) == 0)
		RETURN_FAIL("GetCommModemStatus() failed");
	if (bits & MS_CTS_ON)
		*signals |= SP_SIG_CTS;
	if (bits & MS_DSR_ON)
		*signals |= SP_SIG_DSR;
	if (bits & MS_RLSD_ON)
		*signals |= SP_SIG_DCD;
	if (bits & MS_RING_ON)
		*signals |= SP_SIG_RI;
#else
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
#endif
	RETURN_OK();
}

enum sp_return sp_start_break(struct sp_port *port)
{
	TRACE("%p", port);

	CHECK_OPEN_PORT();
#ifdef _WIN32
	if (SetCommBreak(port->hdl) == 0)
		RETURN_FAIL("SetCommBreak() failed");
#else
	if (ioctl(port->fd, TIOCSBRK, 1) < 0)
		RETURN_FAIL("TIOCSBRK ioctl failed");
#endif

	RETURN_OK();
}

enum sp_return sp_end_break(struct sp_port *port)
{
	TRACE("%p", port);

	CHECK_OPEN_PORT();
#ifdef _WIN32
	if (ClearCommBreak(port->hdl) == 0)
		RETURN_FAIL("ClearCommBreak() failed");
#else
	if (ioctl(port->fd, TIOCCBRK, 1) < 0)
		RETURN_FAIL("TIOCCBRK ioctl failed");
#endif

	RETURN_OK();
}

int sp_last_error_code(void)
{
	TRACE("");
#ifdef _WIN32
	RETURN_VALUE("%d", GetLastError());
#else
	RETURN_VALUE("%d", errno);
#endif
}

char *sp_last_error_message(void)
{
	TRACE("");

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

	RETURN_VALUE("%s", message);
#else
	RETURN_VALUE("%s", strerror(errno));
#endif
}

void sp_free_error_message(char *message)
{
	TRACE("%s", message);

#ifdef _WIN32
	LocalFree(message);
#else
	(void)message;
#endif

	RETURN();
}

void sp_set_debug_handler(void (*handler)(const char *format, ...))
{
	TRACE("%p", handler);

	sp_debug_handler = handler;

	RETURN();
}

void sp_default_debug_handler(const char *format, ...)
{
	va_list args;
	va_start(args, format);
	if (getenv("LIBSERIALPORT_DEBUG")) {
		fputs("sp: ", stderr);
		vfprintf(stderr, format, args);
	}
	va_end(args);
}

int sp_get_major_package_version(void)
{
	return SP_PACKAGE_VERSION_MAJOR;
}

int sp_get_minor_package_version(void)
{
	return SP_PACKAGE_VERSION_MINOR;
}

int sp_get_micro_package_version(void)
{
	return SP_PACKAGE_VERSION_MICRO;
}

const char *sp_get_package_version_string(void)
{
	return SP_PACKAGE_VERSION_STRING;
}

int sp_get_current_lib_version(void)
{
	return SP_LIB_VERSION_CURRENT;
}

int sp_get_revision_lib_version(void)
{
	return SP_LIB_VERSION_REVISION;
}

int sp_get_age_lib_version(void)
{
	return SP_LIB_VERSION_AGE;
}

const char *sp_get_lib_version_string(void)
{
	return SP_LIB_VERSION_STRING;
}

/** @} */
