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

void (*sp_debug_handler)(const char *format, ...) = sp_default_debug_handler;

SP_API enum sp_return sp_get_port_by_name(const char *portname, struct sp_port **port_ptr)
{
	struct sp_port *port;
	char *canonical_name = NULL;
	enum sp_return ret;
	size_t len;

	TRACE("%s, %p", portname, port_ptr);

	if (!port_ptr)
		RETURN_ERROR(SP_ERR_ARG, "Null result pointer");

	*port_ptr = NULL;

	if (!portname)
		RETURN_ERROR(SP_ERR_ARG, "Null port name");

	DEBUG_FMT("Building structure for port %s", portname);

	ret = sp_platform_canonicalize_port_name(portname, &canonical_name);
	if (ret == SP_ERR_ARG)
		RETURN_ERROR(SP_ERR_ARG, "Could not retrieve realpath behind port name");
	if (ret != SP_OK)
		RETURN_CODEVAL(ret);
	if (canonical_name)
		portname = canonical_name;

	if (!(port = malloc(sizeof(struct sp_port)))) {
		free(canonical_name);
		RETURN_ERROR(SP_ERR_MEM, "Port structure malloc failed");
	}

	len = strlen(portname) + 1;

	if (!(port->name = malloc(len))) {
		free(canonical_name);
		free(port);
		RETURN_ERROR(SP_ERR_MEM, "Port name malloc failed");
	}

	memcpy(port->name, portname, len);
	free(canonical_name);

	sp_platform_init_port(port);

	port->description = NULL;
	port->transport = SP_TRANSPORT_NATIVE;
	port->usb_bus = -1;
	port->usb_address = -1;
	port->usb_vid = -1;
	port->usb_pid = -1;
	port->usb_manufacturer = NULL;
	port->usb_product = NULL;
	port->usb_serial = NULL;
	port->bluetooth_address = NULL;

#ifndef NO_PORT_METADATA
	if ((ret = get_port_details(port)) != SP_OK) {
		sp_free_port(port);
		return ret;
	}
#endif

	*port_ptr = port;

	RETURN_OK();
}

SP_API char *sp_get_port_name(const struct sp_port *port)
{
	TRACE("%p", port);

	if (!port)
		return NULL;

	RETURN_STRING(port->name);
}

SP_API char *sp_get_port_description(const struct sp_port *port)
{
	TRACE("%p", port);

	if (!port || !port->description)
		return NULL;

	RETURN_STRING(port->description);
}

SP_API enum sp_transport sp_get_port_transport(const struct sp_port *port)
{
	TRACE("%p", port);

	RETURN_INT(port ? port->transport : SP_TRANSPORT_NATIVE);
}

SP_API enum sp_return sp_get_port_usb_bus_address(const struct sp_port *port,
                                                  int *usb_bus,int *usb_address)
{
	TRACE("%p", port);

	if (!port)
		RETURN_ERROR(SP_ERR_ARG, "Null port");
	if (port->transport != SP_TRANSPORT_USB)
		RETURN_ERROR(SP_ERR_ARG, "Port does not use USB transport");
	if (port->usb_bus < 0 || port->usb_address < 0)
		RETURN_ERROR(SP_ERR_SUPP, "Bus and address values are not available");

	if (usb_bus)
		*usb_bus = port->usb_bus;
	if (usb_address)
		*usb_address = port->usb_address;

	RETURN_OK();
}

SP_API enum sp_return sp_get_port_usb_vid_pid(const struct sp_port *port,
                                              int *usb_vid, int *usb_pid)
{
	TRACE("%p", port);

	if (!port)
		RETURN_ERROR(SP_ERR_ARG, "Null port");
	if (port->transport != SP_TRANSPORT_USB)
		RETURN_ERROR(SP_ERR_ARG, "Port does not use USB transport");
	if (port->usb_vid < 0 || port->usb_pid < 0)
		RETURN_ERROR(SP_ERR_SUPP, "VID:PID values are not available");

	if (usb_vid)
		*usb_vid = port->usb_vid;
	if (usb_pid)
		*usb_pid = port->usb_pid;

	RETURN_OK();
}

SP_API char *sp_get_port_usb_manufacturer(const struct sp_port *port)
{
	TRACE("%p", port);

	if (!port || port->transport != SP_TRANSPORT_USB || !port->usb_manufacturer)
		return NULL;

	RETURN_STRING(port->usb_manufacturer);
}

SP_API char *sp_get_port_usb_product(const struct sp_port *port)
{
	TRACE("%p", port);

	if (!port || port->transport != SP_TRANSPORT_USB || !port->usb_product)
		return NULL;

	RETURN_STRING(port->usb_product);
}

SP_API char *sp_get_port_usb_serial(const struct sp_port *port)
{
	TRACE("%p", port);

	if (!port || port->transport != SP_TRANSPORT_USB || !port->usb_serial)
		return NULL;

	RETURN_STRING(port->usb_serial);
}

SP_API char *sp_get_port_bluetooth_address(const struct sp_port *port)
{
	TRACE("%p", port);

	if (!port || port->transport != SP_TRANSPORT_BLUETOOTH
	    || !port->bluetooth_address)
		return NULL;

	RETURN_STRING(port->bluetooth_address);
}

SP_API enum sp_return sp_copy_port(const struct sp_port *port,
                                   struct sp_port **copy_ptr)
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

	RETURN_INT(sp_get_port_by_name(port->name, copy_ptr));
}

SP_API void sp_free_port(struct sp_port *port)
{
	TRACE("%p", port);

	if (!port) {
		DEBUG("Null port");
		RETURN();
	}

	DEBUG("Freeing port structure");

	if (port->name)
		free(port->name);
	if (port->description)
		free(port->description);
	if (port->usb_manufacturer)
		free(port->usb_manufacturer);
	if (port->usb_product)
		free(port->usb_product);
	if (port->usb_serial)
		free(port->usb_serial);
	if (port->bluetooth_address)
		free(port->bluetooth_address);

	sp_platform_free_port(port);
	free(port);

	RETURN();
}

SP_PRIV struct sp_port **list_append(struct sp_port **list,
                                     const char *portname)
{
	void *tmp;
	size_t count;

	for (count = 0; list[count]; count++)
		;
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

SP_API enum sp_return sp_list_ports(struct sp_port ***list_ptr)
{
#ifndef NO_ENUMERATION
	struct sp_port **list;
	int ret;
#endif

	TRACE("%p", list_ptr);

	if (!list_ptr)
		RETURN_ERROR(SP_ERR_ARG, "Null result pointer");

	*list_ptr = NULL;

#ifdef NO_ENUMERATION
	RETURN_ERROR(SP_ERR_SUPP, "Enumeration not supported on this platform");
#else
	DEBUG("Enumerating ports");

	if (!(list = malloc(sizeof(struct sp_port *))))
		RETURN_ERROR(SP_ERR_MEM, "Port list malloc failed");

	list[0] = NULL;

	ret = list_ports(&list);

	if (ret == SP_OK) {
		*list_ptr = list;
	} else {
		sp_free_port_list(list);
		*list_ptr = NULL;
	}

	RETURN_CODEVAL(ret);
#endif
}

SP_API void sp_free_port_list(struct sp_port **list)
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

SP_API enum sp_return sp_open(struct sp_port *port, enum sp_mode flags)
{
	struct port_data data;
	struct sp_port_config config;
	enum sp_return ret;

	TRACE("%p, 0x%x", port, flags);

	CHECK_PORT();

	if (flags > SP_MODE_READ_WRITE)
		RETURN_ERROR(SP_ERR_ARG, "Invalid flags");

	DEBUG_FMT("Opening port %s", port->name);

	ret = sp_platform_open(port, flags);
	if (ret < 0)
		RETURN_CODEVAL(ret);

	ret = sp_platform_get_config(port, &data, &config);
	if (ret < 0) {
		sp_close(port);
		RETURN_CODEVAL(ret);
	}

	/*
	 * Assume a default baudrate if the OS does not provide one.
	 * Cannot assign -1 here since Windows holds the baudrate in
	 * the DCB and does not configure the rate individually.
	 */
	if (config.baudrate == 0)
		config.baudrate = 9600;

	ret = sp_platform_set_default_config(port, &data);
	if (ret < 0)
		RETURN_CODEVAL(ret);

	ret = sp_platform_set_config(port, &data, &config);
	if (ret < 0) {
		sp_close(port);
		RETURN_CODEVAL(ret);
	}

	RETURN_OK();
}

SP_API enum sp_return sp_new_event_set(struct sp_event_set **result_ptr)
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

SP_API void sp_free_event_set(struct sp_event_set *event_set)
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

SP_API enum sp_return sp_new_config(struct sp_port_config **config_ptr)
{
	struct sp_port_config *config;

	TRACE("%p", config_ptr);

	if (!config_ptr)
		RETURN_ERROR(SP_ERR_ARG, "Null result pointer");

	*config_ptr = NULL;

	if (!(config = malloc(sizeof(struct sp_port_config))))
		RETURN_ERROR(SP_ERR_MEM, "Config malloc failed");

	config->baudrate = -1;
	config->bits = -1;
	config->parity = -1;
	config->stopbits = -1;
	config->rts = -1;
	config->cts = -1;
	config->dtr = -1;
	config->dsr = -1;
	config->xon_xoff = -1;

	*config_ptr = config;

	RETURN_OK();
}

SP_API void sp_free_config(struct sp_port_config *config)
{
	TRACE("%p", config);

	if (!config)
		DEBUG("Null config");
	else
		free(config);

	RETURN();
}

SP_API enum sp_return sp_get_config(struct sp_port *port,
                                    struct sp_port_config *config)
{
	struct port_data data;

	TRACE("%p, %p", port, config);

	CHECK_OPEN_PORT();

	if (!config)
		RETURN_ERROR(SP_ERR_ARG, "Null config");

	TRY(sp_platform_get_config(port, &data, config));

	RETURN_OK();
}

SP_API enum sp_return sp_set_config(struct sp_port *port,
                                    const struct sp_port_config *config)
{
	struct port_data data;
	struct sp_port_config prev_config;

	TRACE("%p, %p", port, config);

	CHECK_OPEN_PORT();

	if (!config)
		RETURN_ERROR(SP_ERR_ARG, "Null config");

	TRY(sp_platform_get_config(port, &data, &prev_config));
	TRY(sp_platform_set_config(port, &data, config));

	RETURN_OK();
}

#define CREATE_ACCESSORS(x, type) \
SP_API enum sp_return sp_set_##x(struct sp_port *port, type x) { \
	struct port_data data; \
	struct sp_port_config config; \
	TRACE("%p, %d", port, x); \
	CHECK_OPEN_PORT(); \
	TRY(sp_platform_get_config(port, &data, &config)); \
	config.x = x; \
	TRY(sp_platform_set_config(port, &data, &config)); \
	RETURN_OK(); \
} \
SP_API enum sp_return sp_get_config_##x(const struct sp_port_config *config, \
                                        type *x) { \
	TRACE("%p, %p", config, x); \
	if (!x) \
		RETURN_ERROR(SP_ERR_ARG, "Null result pointer"); \
	if (!config) \
		RETURN_ERROR(SP_ERR_ARG, "Null config"); \
	*x = config->x; \
	RETURN_OK(); \
} \
SP_API enum sp_return sp_set_config_##x(struct sp_port_config *config, \
                                        type x) { \
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


SP_API enum sp_return sp_set_config_flowcontrol(struct sp_port_config *config,
                                                enum sp_flowcontrol flowcontrol)
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

SP_API enum sp_return sp_set_flowcontrol(struct sp_port *port,
                                         enum sp_flowcontrol flowcontrol)
{
	struct port_data data;
	struct sp_port_config config;

	TRACE("%p, %d", port, flowcontrol);

	CHECK_OPEN_PORT();

	TRY(sp_platform_get_config(port, &data, &config));

	TRY(sp_set_config_flowcontrol(&config, flowcontrol));

	TRY(sp_platform_set_config(port, &data, &config));

	RETURN_OK();
}

SP_API void sp_set_debug_handler(void (*handler)(const char *format, ...))
{
	TRACE("%p", handler);

	sp_debug_handler = handler;

	RETURN();
}

SP_API void sp_default_debug_handler(const char *format, ...)
{
	va_list args;
	va_start(args, format);
	if (getenv("LIBSERIALPORT_DEBUG")) {
		fputs("sp: ", stderr);
		vfprintf(stderr, format, args);
	}
	va_end(args);
}

SP_API int sp_get_major_package_version(void)
{
	return SP_PACKAGE_VERSION_MAJOR;
}

SP_API int sp_get_minor_package_version(void)
{
	return SP_PACKAGE_VERSION_MINOR;
}

SP_API int sp_get_micro_package_version(void)
{
	return SP_PACKAGE_VERSION_MICRO;
}

SP_API const char *sp_get_package_version_string(void)
{
	return SP_PACKAGE_VERSION_STRING;
}

SP_API int sp_get_current_lib_version(void)
{
	return SP_LIB_VERSION_CURRENT;
}

SP_API int sp_get_revision_lib_version(void)
{
	return SP_LIB_VERSION_REVISION;
}

SP_API int sp_get_age_lib_version(void)
{
	return SP_LIB_VERSION_AGE;
}

SP_API const char *sp_get_lib_version_string(void)
{
	return SP_LIB_VERSION_STRING;
}

/** @} */
