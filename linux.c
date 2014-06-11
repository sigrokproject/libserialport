/*
 * This file is part of the libserialport project.
 *
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

#include "libserialport.h"
#include "libserialport_internal.h"

enum sp_return get_port_details(struct sp_port *port)
{
	/* Description limited to 127 char,
	   anything longer would not be user friendly anyway */
	char description[128];
	int bus, address, vid, pid = -1;
	char manufacturer[128], product[128], serial[128];
	char baddr[32];
	const char dir_name[] = "/sys/class/tty/%s/device/%s%s";
	char sub_dir[32] = "", file_name[PATH_MAX];
	char *ptr, *dev = port->name + 5;
	FILE *file;
	int i, count;

	if (strncmp(port->name, "/dev/", 5))
		RETURN_ERROR(SP_ERR_ARG, "Device name not recognized (%s)", port->name);

	snprintf(file_name, sizeof(file_name), "/sys/class/tty/%s", dev);
	count = readlink(file_name, file_name, sizeof(file_name));
	if (count <= 0 || count >= (int) sizeof(file_name)-1)
		RETURN_ERROR(SP_ERR_ARG, "Device not found (%s)", port->name);
	file_name[count] = 0;
	if (strstr(file_name, "bluetooth"))
		port->transport = SP_TRANSPORT_BLUETOOTH;
	else if (strstr(file_name, "usb"))
		port->transport = SP_TRANSPORT_USB;

	if (port->transport == SP_TRANSPORT_USB) {
		for (i=0; i<5; i++) {
			strcat(sub_dir, "../");

			snprintf(file_name, sizeof(file_name), dir_name, dev, sub_dir, "busnum");
			if (!(file = fopen(file_name, "r")))
				continue;
			count = fscanf(file, "%d", &bus);
			fclose(file);
			if (count != 1)
				continue;

			snprintf(file_name, sizeof(file_name), dir_name, dev, sub_dir, "devnum");
			if (!(file = fopen(file_name, "r")))
				continue;
			count = fscanf(file, "%d", &address);
			fclose(file);
			if (count != 1)
				continue;

			snprintf(file_name, sizeof(file_name), dir_name, dev, sub_dir, "idVendor");
			if (!(file = fopen(file_name, "r")))
				continue;
			count = fscanf(file, "%4x", &vid);
			fclose(file);
			if (count != 1)
				continue;

			snprintf(file_name, sizeof(file_name), dir_name, dev, sub_dir, "idProduct");
			if (!(file = fopen(file_name, "r")))
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
			if ((file = fopen(file_name, "r"))) {
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
			if ((file = fopen(file_name, "r"))) {
				if ((ptr = fgets(manufacturer, sizeof(manufacturer), file))) {
					ptr = manufacturer + strlen(manufacturer) - 1;
					if (ptr >= manufacturer && *ptr == '\n')
						*ptr = 0;
					port->usb_manufacturer = strdup(manufacturer);
				}
				fclose(file);
			}

			snprintf(file_name, sizeof(file_name), dir_name, dev, sub_dir, "product");
			if ((file = fopen(file_name, "r"))) {
				if ((ptr = fgets(product, sizeof(product), file))) {
					ptr = product + strlen(product) - 1;
					if (ptr >= product && *ptr == '\n')
						*ptr = 0;
					port->usb_product = strdup(product);
				}
				fclose(file);
			}

			snprintf(file_name, sizeof(file_name), dir_name, dev, sub_dir, "serial");
			if ((file = fopen(file_name, "r"))) {
				if ((ptr = fgets(serial, sizeof(serial), file))) {
					ptr = serial + strlen(serial) - 1;
					if (ptr >= serial && *ptr == '\n')
						*ptr = 0;
					port->usb_serial = strdup(serial);
				}
				fclose(file);
			}

			break;
		}
	} else {
		port->description = strdup(dev);

		if (port->transport == SP_TRANSPORT_BLUETOOTH) {
			snprintf(file_name, sizeof(file_name), dir_name, dev, "", "address");
			if ((file = fopen(file_name, "r"))) {
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
