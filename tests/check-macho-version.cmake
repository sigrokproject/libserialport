# SPDX-License-Identifier: LGPL-3.0-or-later

find_program(otool NAMES otool)
execute_process(
    COMMAND "${otool}" -L "${LIBRARY}"
    RESULT_VARIABLE result
    OUTPUT_VARIABLE output
    ERROR_VARIABLE error
)
if(NOT result EQUAL 0)
    message(FATAL_ERROR "Cannot read Mach-O versions: ${error}")
endif()

# Match Libtool's 1:1:1 version mapping without changing the install name.
if(NOT output MATCHES
    "@rpath/libserialport\\.0\\.dylib \\(compatibility version 2\\.0\\.0, current version 2\\.1\\.0\\)"
)
    message(FATAL_ERROR "Unexpected Mach-O versions or install name:\n${output}")
endif()
