/*
 * This file is part of the libserialport project.
 *
 * Copyright (C) 2014 Martin Ling <martin-libserialport@earth.li>
 * Copyright (C) 2014 Aurelien Jacobs <aurel@gnuage.org>
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
#include <setupapi.h>
#include <cfgmgr32.h>
#include <usbioctl.h>
#else
#include <limits.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <limits.h>
#include <poll.h>
#endif
#ifdef __APPLE__
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/serial/IOSerialKeys.h>
#include <IOKit/serial/ioss.h>
#include <sys/syslimits.h>
#endif
#ifdef __linux__
#include <dirent.h>
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

struct sp_port {
	char *name;
	char *description;
	enum sp_transport transport;
	int usb_bus;
	int usb_address;
	int usb_vid;
	int usb_pid;
	char *usb_manufacturer;
	char *usb_product;
	char *usb_serial;
	char *bluetooth_address;
#ifdef _WIN32
	char *usb_path;
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

extern const struct std_baudrate std_baudrates[];

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))
#define NUM_STD_BAUDRATES ARRAY_SIZE(std_baudrates)

extern void (*sp_debug_handler)(const char *format, ...);

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

SP_PRIV struct sp_port **list_append(struct sp_port **list, const char *portname);

/* OS-specific Helper functions. */
SP_PRIV enum sp_return get_port_details(struct sp_port *port);
SP_PRIV enum sp_return list_ports(struct sp_port ***list);
