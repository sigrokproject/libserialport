#include <libserialport.h>
#include <stdio.h>
#include <stdlib.h>

/* Example of how to wait for events on multiple ports.
 *
 * This example file is released to the public domain. */

/* Helper function for error handling. */
int check(enum sp_return result);

int main(int argc, char **argv)
{
	/* Get the port names from the command line. */
	if (argc < 2) {
		printf("Usage: %s <port name>...\n", argv[0]);
		return -1;
	}
	int num_ports = argc - 1;
	char **port_names = argv + 1;

	/* The ports we will use. */
	struct sp_port **ports = malloc(num_ports * sizeof(struct sp_port *));
	if (!ports)
		abort();

	/* The set of events we will wait for. */
	struct sp_event_set *event_set;

	/* Allocate the event set. */
	check(sp_new_event_set(&event_set));

	/* Open and configure each port, and then add its RX event
	 * to the event set. */
	for (int i = 0; i < num_ports; i++) {
		printf("Looking for port %s.\n", port_names[i]);
		check(sp_get_port_by_name(port_names[i], &ports[i]));

		printf("Opening port.\n");
		check(sp_open(ports[i], SP_MODE_READ));

		printf("Setting port to 9600 8N1, no flow control.\n");
		check(sp_set_baudrate(ports[i], 9600));
		check(sp_set_bits(ports[i], 8));
		check(sp_set_parity(ports[i], SP_PARITY_NONE));
		check(sp_set_stopbits(ports[i], 1));
		check(sp_set_flowcontrol(ports[i], SP_FLOWCONTROL_NONE));

		printf("Adding port RX event to event set.\n");
		check(sp_add_port_events(event_set, ports[i], SP_EVENT_RX_READY));
	}

	/* Now we can call sp_wait() to await any event in the set.
	 * It will return when an event occurs, or the timeout elapses. */
	printf("Waiting up to 5 seconds for RX on any port...\n");
	check(sp_wait(event_set, 5000));

	/* Iterate over ports to see which have data waiting. */
	for (int i = 0; i < num_ports; i++) {
		/* Get number of bytes waiting. */
		int bytes_waiting = check(sp_input_waiting(ports[i]));
		printf("Port %s: %d bytes received.\n",
				sp_get_port_name(ports[i]), bytes_waiting);
	}

	/* Close ports and free resources. */
	sp_free_event_set(event_set);
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
