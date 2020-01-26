#include <libserialport.h>
#include <stdio.h>
#include <stdlib.h>

/* Example of how to handle errors from libserialport.
 *
 * This example file is released to the public domain. */

/* Pointers used in the program to resources that may need to be freed. */
struct sp_port **port_list = NULL;
struct sp_port_config *config = NULL;
struct sp_port *port = NULL;

/* Example of a function to clean up and exit the program with a given return code. */
void end_program(int return_code)
{
	/* Free any structures we allocated. */
	if (port_list != NULL)
		sp_free_port_list(port_list);
	if (config != NULL)
		sp_free_config(config);
	if (port != NULL)
		sp_free_port(port);

	/* Exit with the given return code. */
	exit(return_code);
}

/* Example of a helper function for error handling. */
int check(enum sp_return result)
{
	int error_code;
	char *error_message;

	switch (result) {

		/* Handle each of the four negative error codes that can be returned.
		 *
		 * In this example, we will end the program on any error, using
		 * a different return code for each possible class of error. */

	case SP_ERR_ARG:
		/* When SP_ERR_ARG is returned, there was a problem with one
		 * or more of the arguments passed to the function, e.g. a null
		 * pointer or an invalid value. This generally implies a bug in
		 * the calling code. */
		printf("Error: Invalid argument.\n");
		end_program(1);

	case SP_ERR_FAIL:
		/* When SP_ERR_FAIL is returned, there was an error from the OS,
		 * which we can obtain the error code and message for. These
		 * calls must be made in the same thread as the call that
		 * returned SP_ERR_FAIL, and before any other system functions
		 * are called in that thread, or they may not return the
		 * correct results. */
		error_code = sp_last_error_code();
		error_message = sp_last_error_message();
		printf("Error: Failed: OS error code: %d, message: '%s'\n",
			error_code, error_message);
		/* The error message should be freed after use. */
		sp_free_error_message(error_message);
		end_program(2);

	case SP_ERR_SUPP:
		/* When SP_ERR_SUPP is returned, the function was asked to do
		 * something that isn't supported by the current OS or device,
		 * or that libserialport doesn't know how to do in the current
		 * version. */
		printf("Error: Not supported.\n");
		end_program(3);

	case SP_ERR_MEM:
		/* When SP_ERR_MEM is returned, libserialport wasn't able to
		 * allocate some memory it needed. Since the library doesn't
		 * normally use any large data structures, this probably means
		 * the system is critically low on memory and recovery will
		 * require very careful handling. The library itself will
		 * always try to handle any allocation failure safely.
		 *
		 * In this example, we'll just try to exit gracefully without
		 * calling printf, which might need to allocate further memory. */
		end_program(4);

	case SP_OK:
	default:
		/* A return value of SP_OK, defined as zero, means that the
		 * operation succeeded. */
		printf("Operation succeeded.\n");

		/* Some fuctions can also return a value greater than zero to
		 * indicate a numeric result, such as the number of bytes read by
		 * sp_blocking_read(). So when writing an error handling wrapper
		 * function like this one, it's helpful to return the result so
		 * that it can be used. */
		return result;
	}
}

int main(int argc, char **argv)
{
	/* Call some functions that should not result in errors. */

	printf("Getting list of ports.\n");
	check(sp_list_ports(&port_list));

	printf("Creating a new port configuration.\n");
	check(sp_new_config(&config));

	/* Now make a function call that will result in an error. */

	printf("Trying to find a port that doesn't exist.\n");
	check(sp_get_port_by_name("NON-EXISTENT-PORT", &port));

	/* We could now clean up and exit normally if an error hadn't occured. */
	end_program(0);
}
