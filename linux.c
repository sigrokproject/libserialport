/*
 * SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * This file is part of the libserialport project.
 *
 * Copyright (C) 2013 Martin Ling <martin-libserialport@earth.li>
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

#include <config.h>
#include "libserialport.h"
#include "libserialport_internal.h"

/*
 * The 'e' modifier for O_CLOEXEC is glibc >= 2.7 only, hence not
 * portable, so provide an own wrapper for this functionality.
 */
static FILE *fopen_cloexec_rdonly(const char *pathname)
{
	int fd;
	if ((fd = open(pathname, O_RDONLY | O_CLOEXEC)) < 0)
		return NULL;
	return fdopen(fd, "r");
}

SP_PRIV enum sp_return get_port_details(struct sp_port *port)
{
	/*
	 * Description limited to 127 char, anything longer
	 * would not be user friendly anyway.
	 */
	char description[128];
	int bus, address;
	unsigned int vid, pid;
	char manufacturer[128], product[128], serial[128];
	char baddr[32];
	const char dir_name[] = "/sys/class/tty/%s/device/%s%s";
	char sub_dir[32] = "", link_name[PATH_MAX], file_name[PATH_MAX];
	char *ptr, *dev = port->name + 5;
	FILE *file;
	int i, count;

	if (strncmp(port->name, "/dev/", 5))
		RETURN_ERROR(SP_ERR_ARG, "Device name not recognized");

	snprintf(link_name, sizeof(link_name), "/sys/class/tty/%s", dev);
	ptr = link_name + sizeof("/sys/class/tty"); /* sizeof() will return length+1 */
	/* Escape slashes in the device name as ! */
	while ((ptr = strchr(ptr, '/')))
		*ptr++ = '!';
	count = readlink(link_name, file_name, sizeof(file_name));
	if (count == -1 && errno == EINVAL) {
		/* Not a symbolic link */
		count = snprintf(file_name, sizeof(file_name), "%s/device", link_name);
	} else if ((size_t)count >= sizeof(file_name)-1) {
		RETURN_ERROR(SP_ERR_ARG, "Device not found");
	}
	file_name[count] = 0;
	if (strstr(file_name, "bluetooth"))
		port->transport = SP_TRANSPORT_BLUETOOTH;
	else if (strstr(file_name, "usb"))
		port->transport = SP_TRANSPORT_USB;

	if (port->transport == SP_TRANSPORT_USB) {
		for (i = 0; i < 5; i++) {
			strcat(sub_dir, "../");

			snprintf(file_name, sizeof(file_name), dir_name, dev, sub_dir, "busnum");
			if (!(file = fopen_cloexec_rdonly(file_name)))
				continue;
			count = fscanf(file, "%d", &bus);
			fclose(file);
			if (count != 1)
				continue;

			snprintf(file_name, sizeof(file_name), dir_name, dev, sub_dir, "devnum");
			if (!(file = fopen_cloexec_rdonly(file_name)))
				continue;
			count = fscanf(file, "%d", &address);
			fclose(file);
			if (count != 1)
				continue;

			snprintf(file_name, sizeof(file_name), dir_name, dev, sub_dir, "idVendor");
			if (!(file = fopen_cloexec_rdonly(file_name)))
				continue;
			count = fscanf(file, "%4x", &vid);
			fclose(file);
			if (count != 1)
				continue;

			snprintf(file_name, sizeof(file_name), dir_name, dev, sub_dir, "idProduct");
			if (!(file = fopen_cloexec_rdonly(file_name)))
				continue;
			count = fscanf(file, "%4x", &pid);
			fclose(file);
			if (count != 1)
				continue;

			port->usb_bus = bus;
			port->usb_address = address;
			port->usb_vid = vid;
			port->usb_pid = pid;

			snprintf(file_name, sizeof(file_name), dir_name, dev, sub_dir, "product");
			if ((file = fopen_cloexec_rdonly(file_name))) {
				if ((ptr = fgets(description, sizeof(description), file))) {
					ptr = description + strlen(description) - 1;
					if (ptr >= description && *ptr == '\n')
						*ptr = 0;
					port->description = strdup(description);
				}
				fclose(file);
			}
			if (!file || !ptr)
				port->description = strdup(dev);

			snprintf(file_name, sizeof(file_name), dir_name, dev, sub_dir, "manufacturer");
			if ((file = fopen_cloexec_rdonly(file_name))) {
				if ((ptr = fgets(manufacturer, sizeof(manufacturer), file))) {
					ptr = manufacturer + strlen(manufacturer) - 1;
					if (ptr >= manufacturer && *ptr == '\n')
						*ptr = 0;
					port->usb_manufacturer = strdup(manufacturer);
				}
				fclose(file);
			}

			snprintf(file_name, sizeof(file_name), dir_name, dev, sub_dir, "product");
			if ((file = fopen_cloexec_rdonly(file_name))) {
				if ((ptr = fgets(product, sizeof(product), file))) {
					ptr = product + strlen(product) - 1;
					if (ptr >= product && *ptr == '\n')
						*ptr = 0;
					port->usb_product = strdup(product);
				}
				fclose(file);
			}

			snprintf(file_name, sizeof(file_name), dir_name, dev, sub_dir, "serial");
			if ((file = fopen_cloexec_rdonly(file_name))) {
				if ((ptr = fgets(serial, sizeof(serial), file))) {
					ptr = serial + strlen(serial) - 1;
					if (ptr >= serial && *ptr == '\n')
						*ptr = 0;
					port->usb_serial = strdup(serial);
				}
				fclose(file);
			}

			/* If present, add serial to description for better identification. */
			if (port->usb_serial && strlen(port->usb_serial)) {
				snprintf(description, sizeof(description),
					"%s - %s", port->description, port->usb_serial);
				if (port->description)
					free(port->description);
				port->description = strdup(description);
			}

			break;
		}
	} else {
		port->description = strdup(dev);

		if (port->transport == SP_TRANSPORT_BLUETOOTH) {
			snprintf(file_name, sizeof(file_name), dir_name, dev, "", "address");
			if ((file = fopen_cloexec_rdonly(file_name))) {
				if ((ptr = fgets(baddr, sizeof(baddr), file))) {
					ptr = baddr + strlen(baddr) - 1;
					if (ptr >= baddr && *ptr == '\n')
						*ptr = 0;
					port->bluetooth_address = strdup(baddr);
				}
				fclose(file);
			}
		}
	}

	RETURN_OK();
}

SP_PRIV enum sp_return list_ports(struct sp_port ***list)
{
	char name[PATH_MAX], sysname[PATH_MAX + 10 + 7];
	struct dirent *entry;
	DIR *dir;
	int ret = SP_OK;

	DEBUG("Enumerating tty devices");
	if (!(dir = opendir("/sys/class/tty")))
		RETURN_FAIL("Could not open /sys/class/tty");

	DEBUG("Iterating over results");
	while ((entry = readdir(dir))) {
		char *p;
		struct stat statbuf;
		FILE *typefh;

		if ((size_t)snprintf(name, sizeof(name), "/dev/%s", entry->d_name)
		    >= sizeof(name))
			continue;

		/* sysfs by necessity escapes slashes as ! in pathnames */
		p = name+5;
		while ((p = strchr(p, '!')))
			*p++ = '/';

		if (stat(name, &statbuf) || !S_ISCHR(statbuf.st_mode))
			continue;

		p = sysname + snprintf(sysname, sizeof(sysname),
				       "/sys/class/tty/%s/device", entry->d_name);
		p -= 6;		/* Point to the first character of "device" */

		/*
		 * If this is a real physical device, it will have a link to its
		 * physical device description directory.
		 */
		if (stat(sysname, &statbuf) || !S_ISDIR(statbuf.st_mode))
			continue;

		DEBUG_FMT("Found device %s", name);
		/*
		 * The serial8250 driver has a hardcoded number of ports.
		 * If the "type" file entry exists in the sysfs directory
		 * and it contains 0, it is a placeholder and should be
		 * ignored. If the "type" entry doesn't exist, it is not
		 * an 8250 serial port.
		 *
		 * Earlier versions of this library tried to open all
		 * ports and call TIOCGSERIAL, this would result in
		 * RTS and DTR being pulsed on every port!
		 */
		strcpy(p, "type");
		DEBUG("checking if serial type is enumerated");
		typefh = fopen_cloexec_rdonly(sysname);
		if (typefh) {
			int type;
			int rv = fscanf(typefh, "%i", &type);
			fclose(typefh);
			if (rv == 1 && type == 0) {
				/* PORT_UNKNOWN, it is a placeholder port */
				DEBUG("serial type 0, skipping port");
				continue;
			}
		}

		DEBUG_FMT("Found port %s", name);
		*list = list_append(*list, name);
		if (!*list) {
			SET_ERROR(ret, SP_ERR_MEM, "List append failed");
			break;
		}
	}
	closedir(dir);

	return ret;
}
