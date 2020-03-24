include(CheckFunctionExists)

check_function_exists("clock_gettime" HAVE_CLOCK_GETTIME)
check_function_exists("realpath" HAVE_REALPATH)
