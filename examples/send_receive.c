#include <libserialport.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Example of how to send and receive data.
 *
 * This example file is released to the public domain. */

/* Helper function for error handling. */
int check(enum sp_return result);

int main(int argc, char **argv)
{
	/* This example can be used with one or two ports. With one port, it
	 * will send data and try to receive it on the same port. This can be
	 * done by connecting a single wire between the TX and RX pins of the
	 * port.
	 *
	 * Alternatively it can be used with two serial ports connected to each
	 * other, so that data can be sent on one and received on the other.
	 * This can be done with two ports with TX/RX cross-connected, e.g. by
	 * a "null modem" cable, or with a pair of interconnected virtual ports,
	 * such as those created by com0com on Windows or tty0tty on Linux. */

	/* Get the port names from the command line. */
	if (argc < 2 || argc > 3) {
		printf("Usage: %s <port 1> [<port 2>]\n", argv[0]);
		return -1;
	}
	int num_ports = argc - 1;
	char **port_names = argv + 1;

	/* The ports we will use. */
	struct sp_port *ports[2];

	/* Open and configure each port. */
	for (int i = 0; i < num_ports; i++) {
		printf("Looking for port %s.\n", port_names[i]);
		check(sp_get_port_by_name(port_names[i], &ports[i]));

		printf("Opening port.\n");
		check(sp_open(ports[i], SP_MODE_READ_WRITE));

		printf("Setting port to 9600 8N1, no flow control.\n");
		check(sp_set_baudrate(ports[i], 9600));
		check(sp_set_bits(ports[i], 8));
		check(sp_set_parity(ports[i], SP_PARITY_NONE));
		check(sp_set_stopbits(ports[i], 1));
		check(sp_set_flowcontrol(ports[i], SP_FLOWCONTROL_NONE));
	}

	/* Now send some data on each port and receive it back. */
	for (int tx = 0; tx < num_ports; tx++) {
		/* Get the ports to send and receive on. */
		int rx = num_ports == 1 ? 0 : ((tx == 0) ? 1 : 0);
		struct sp_port *tx_port = ports[tx];
		struct sp_port *rx_port = ports[rx];

		/* The data we will send. */
		char *data = "Hello!";
		int size = strlen(data);

		/* We'll allow a 1 second timeout for send and receive. */
		unsigned int timeout = 1000;

		/* On success, sp_blocking_write() and sp_blocking_read()
		 * return the number of bytes sent/received before the
		 * timeout expired. We'll store that result here. */
		int result;

		/* Send data. */
		printf("Sending '%s' (%d bytes) on port %s.\n",
				data, size, sp_get_port_name(tx_port));
		result = check(sp_blocking_write(tx_port, data, size, timeout));

		/* Check whether we sent all of the data. */
		if (result == size)
			printf("Sent %d bytes successfully.\n", size);
		else
			printf("Timed out, %d/%d bytes sent.\n", result, size);

		/* Allocate a buffer to receive data. */
		char *buf = malloc(size + 1);

		/* Try to receive the data on the other port. */
		printf("Receiving %d bytes on port %s.\n",
				size, sp_get_port_name(rx_port));
		result = check(sp_blocking_read(rx_port, buf, size, timeout));

		/* Check whether we received the number of bytes we wanted. */
		if (result == size)
			printf("Received %d bytes successfully.\n", size);
		else
			printf("Timed out, %d/%d bytes received.\n", result, size);

		/* Check if we received the same data we sent. */
		buf[result] = '\0';
		printf("Received '%s'.\n", buf);

		/* Free receive buffer. */
		free(buf);
	}

	/* Close ports and free resources. */
	for (int i = 0; i < num_ports; i++) {
		check(sp_close(ports[i]));
		sp_free_port(ports[i]);
	}

	return 0;
}

/* Helper function for error handling. */
int check(enum sp_return result)
{
	/* For this example we'll just exit on any error by calling abort(). */
	char *error_message;

	switch (result) {
	case SP_ERR_ARG:
		printf("Error: Invalid argument.\n");
		abort();
	case SP_ERR_FAIL:
		error_message = sp_last_error_message();
		printf("Error: Failed: %s\n", error_message);
		sp_free_error_message(error_message);
		abort();
	case SP_ERR_SUPP:
		printf("Error: Not supported.\n");
		abort();
	case SP_ERR_MEM:
		printf("Error: Couldn't allocate memory.\n");
		abort();
	case SP_OK:
	default:
		return result;
	}
}
