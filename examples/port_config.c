#include <libserialport.h>
#include <stdio.h>
#include <stdlib.h>

/* Example of how to configure a serial port.
 *
 * This example file is released to the public domain. */

/* Helper function for error handling. */
int check(enum sp_return result);

/* Helper function to give a name for each parity mode. */
const char *parity_name(enum sp_parity parity);

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
	check(sp_get_port_by_name(port_name, &port));

	/* Display some basic information about the port. */
	printf("Port name: %s\n", sp_get_port_name(port));
	printf("Description: %s\n", sp_get_port_description(port));

	/* The port must be open to access its configuration. */
	printf("Opening port.\n");
	check(sp_open(port, SP_MODE_READ_WRITE));

	/* There are two ways to access a port's configuration:
	 *
	 * 1. You can read and write a whole configuration (all settings at
	 *    once) using sp_get_config() and sp_set_config(). This is handy
	 *    if you want to change between some preset combinations, or save
	 *    and restore an existing configuration. It also ensures the
	 *    changes are made together, via an efficient set of calls into
	 *    the OS - in some cases a single system call can be used.
	 *
	 *    Use accessor functions like sp_get_config_baudrate() and
	 *    sp_set_config_baudrate() to get and set individual settings
	 *    from a configuration.
	 *
	 *    Configurations are allocated using sp_new_config() and freed
	 *    with sp_free_config(). You need to manage them yourself.
	 *
	 * 2. As a shortcut, you can set individual settings on a port
	 *    directly by calling functions like sp_set_baudrate() and
	 *    sp_set_parity(). This saves you the work of allocating
	 *    a temporary config, setting it up, applying it to a port
	 *    and then freeing it.
	 *
	 * In this example we'll do a bit of both: apply some initial settings
	 * to the port, read out that config and display it, then switch to a
	 * different configuration and back using sp_set_config(). */

	/* First let's set some initial settings directly on the port.
	 *
	 * You should always configure all settings before using a port.
	 * There are no "default" settings applied by libserialport.
	 * When you open a port it has the defaults from the OS or driver,
	 * or the settings left over by the last program to use it. */
	printf("Setting port to 115200 8N1, no flow control.\n");
	check(sp_set_baudrate(port, 115200));
	check(sp_set_bits(port, 8));
	check(sp_set_parity(port, SP_PARITY_NONE));
	check(sp_set_stopbits(port, 1));
	check(sp_set_flowcontrol(port, SP_FLOWCONTROL_NONE));

	/* A pointer to a struct sp_port_config, which we'll use for the config
	 * read back from the port. The pointer will be set by sp_new_config(). */
	struct sp_port_config *initial_config;

	/* Allocate a configuration for us to read the port config into. */
	check(sp_new_config(&initial_config));

	/* Read the current config from the port into that configuration. */
	check(sp_get_config(port, initial_config));

	/* Display some of the settings read back from the port. */
	int baudrate, bits, stopbits;
	enum sp_parity parity;
	check(sp_get_config_baudrate(initial_config, &baudrate));
	check(sp_get_config_bits(initial_config, &bits));
	check(sp_get_config_stopbits(initial_config, &stopbits));
	check(sp_get_config_parity(initial_config, &parity));
	printf("Baudrate: %d, data bits: %d, parity: %s, stop bits: %d\n",
			baudrate, bits, parity_name(parity), stopbits);

	/* Create a different configuration to have ready for use. */
	printf("Creating new config for 9600 7E2, XON/XOFF flow control.\n");
	struct sp_port_config *other_config;
	check(sp_new_config(&other_config));
	check(sp_set_config_baudrate(other_config, 9600));
	check(sp_set_config_bits(other_config, 7));
	check(sp_set_config_parity(other_config, SP_PARITY_EVEN));
	check(sp_set_config_stopbits(other_config, 2));
	check(sp_set_config_flowcontrol(other_config, SP_FLOWCONTROL_XONXOFF));

	/* We can apply the new config to the port in one call. */
	printf("Applying new configuration.\n");
	check(sp_set_config(port, other_config));

	/* And now switch back to our original config. */
	printf("Setting port back to previous config.\n");
	check(sp_set_config(port, initial_config));

	/* Now clean up by closing the port and freeing structures. */
	check(sp_close(port));
	sp_free_port(port);
	sp_free_config(initial_config);
	sp_free_config(other_config);

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

/* Helper function to give a name for each parity mode. */
const char *parity_name(enum sp_parity parity)
{
	switch (parity) {
	case SP_PARITY_INVALID:
		return "(Invalid)";
	case SP_PARITY_NONE:
		return "None";
	case SP_PARITY_ODD:
		return "Odd";
	case SP_PARITY_EVEN:
		return "Even";
	case SP_PARITY_MARK:
		return "Mark";
	case SP_PARITY_SPACE:
		return "Space";
	default:
		return NULL;
	}
}
