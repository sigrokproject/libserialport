#include <libserialport.h>
#include <stdio.h>

/* Example of how to get a list of serial ports on the system.
 *
 * This example file is released to the public domain. */

int main(int argc, char **argv)
{
	/* A pointer to a null-terminated array of pointers to
	 * struct sp_port, which will contain the ports found.*/
	struct sp_port **port_list;

	printf("Getting port list.\n");

	/* Call sp_list_ports() to get the ports. The port_list
	 * pointer will be updated to refer to the array created. */
	enum sp_return result = sp_list_ports(&port_list);

	if (result != SP_OK) {
		printf("sp_list_ports() failed!\n");
		return -1;
	}

	/* Iterate through the ports. When port_list[i] is NULL
	 * this indicates the end of the list. */
	int i;
	for (i = 0; port_list[i] != NULL; i++) {
		struct sp_port *port = port_list[i];

		/* Get the name of the port. */
		char *port_name = sp_get_port_name(port);

		printf("Found port: %s\n", port_name);
	}

	printf("Found %d ports.\n", i);

	printf("Freeing port list.\n");

	/* Free the array created by sp_list_ports(). */
	sp_free_port_list(port_list);

	/* Note that this will also free all the sp_port structures
	 * it points to. If you want to keep one of them (e.g. to
	 * use that port in the rest of your program), take a copy
	 * of it first using sp_copy_port(). */

	return 0;
}
