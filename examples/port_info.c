#include <libserialport.h>
#include <stdio.h>

/* Example of how to get information about a serial port.
 *
 * This example file is released to the public domain. */

int main(int argc, char **argv)
{
	/* Get the port name from the command line. */
	if (argc != 2) {
		printf("Usage: %s <port name>\n", argv[0]);
		return -1;
	}
	char *port_name = argv[1];

	/* A pointer to a struct sp_port, which will refer to
	 * the port found. */
	struct sp_port *port;

	printf("Looking for port %s.\n", port_name);

	/* Call sp_get_port_by_name() to find the port. The port
	 * pointer will be updated to refer to the port found. */
	enum sp_return result = sp_get_port_by_name(port_name, &port);

	if (result != SP_OK) {
		printf("sp_get_port_by_name() failed!\n");
		return -1;
	}

	/* Display some basic information about the port. */
	printf("Port name: %s\n", sp_get_port_name(port));
	printf("Description: %s\n", sp_get_port_description(port));

	/* Identify the transport which this port is connected through,
	 * e.g. native port, USB or Bluetooth. */
	enum sp_transport transport = sp_get_port_transport(port);

	if (transport == SP_TRANSPORT_NATIVE) {
		/* This is a "native" port, usually directly connected
		 * to the system rather than some external interface. */
		printf("Type: Native\n");
	} else if (transport == SP_TRANSPORT_USB) {
		/* This is a USB to serial converter of some kind. */
		printf("Type: USB\n");

		/* Display string information from the USB descriptors. */
		printf("Manufacturer: %s\n", sp_get_port_usb_manufacturer(port));
		printf("Product: %s\n", sp_get_port_usb_product(port));
		printf("Serial: %s\n", sp_get_port_usb_serial(port));

		/* Display USB vendor and product IDs. */
		int usb_vid, usb_pid;
		sp_get_port_usb_vid_pid(port, &usb_vid, &usb_pid);
		printf("VID: %04X PID: %04X\n", usb_vid, usb_pid);

		/* Display bus and address. */
		int usb_bus, usb_address;
		sp_get_port_usb_bus_address(port, &usb_bus, &usb_address);
		printf("Bus: %d Address: %d\n", usb_bus, usb_address);
	} else if (transport == SP_TRANSPORT_BLUETOOTH) {
		/* This is a Bluetooth serial port. */
		printf("Type: Bluetooth\n");

		/* Display Bluetooth MAC address. */
		printf("MAC: %s\n", sp_get_port_bluetooth_address(port));
	}

	printf("Freeing port.\n");

	/* Free the port structure created by sp_get_port_by_name(). */
	sp_free_port(port);

	/* Note that this will also free the port name and other
	 * strings retrieved from the port structure. If you want
	 * to keep these, copy them before freeing the port. */

	return 0;
}
