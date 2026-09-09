# SPDX-License-Identifier: LGPL-3.0-or-later

# Run this test after installation on macOS or Linux.
cmake_minimum_required(VERSION 3.17)
find_program(pkg_config NAMES pkg-config)
find_program(compiler NAMES cc)
if(NOT pkg_config OR NOT compiler)
    message(FATAL_ERROR "This test requires pkg-config and a C compiler")
endif()
if(NOT EXISTS "${PREFIX}/lib/pkgconfig/libserialport.pc")
    message(FATAL_ERROR "The installation has no libserialport.pc")
endif()

# Use a path with spaces to check relocation and flag quoting.
set(relocated "${BINARY_DIR}/relocated install")
file(REMOVE_RECURSE "${relocated}")
file(MAKE_DIRECTORY "${relocated}")
file(COPY "${PREFIX}/" DESTINATION "${relocated}")
set(ENV{PKG_CONFIG_PATH} "${relocated}/lib/pkgconfig:$ENV{PKG_CONFIG_PATH}")

function(query_pkg_config output)
    execute_process(
        COMMAND "${pkg_config}" ${ARGN} libserialport
        RESULT_VARIABLE result
        OUTPUT_VARIABLE value
        ERROR_VARIABLE error
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    if(NOT result EQUAL 0)
        message(FATAL_ERROR "pkg-config failed: ${error}")
    endif()
    set(${output} "${value}" PARENT_SCOPE)
endfunction()

query_pkg_config(version --modversion)
if(NOT version STREQUAL "0.1.3")
    message(FATAL_ERROR "Unexpected package version: ${version}")
endif()
query_pkg_config(package_prefix --variable=prefix)
# pkgconf escapes spaces in pcfiledir, including in variable queries.
string(REPLACE "\\ " " " package_prefix "${package_prefix}")
get_filename_component(package_prefix "${package_prefix}" REALPATH)
get_filename_component(expected_prefix "${relocated}" REALPATH)
if(NOT package_prefix STREQUAL expected_prefix)
    message(FATAL_ERROR "pkg-config selected the wrong prefix: ${package_prefix}")
endif()

set(mode)
if(NOT SHARED)
    set(mode --static)
endif()
query_pkg_config(cflags ${mode} --cflags)
query_pkg_config(libs ${mode} --libs)
separate_arguments(cflags UNIX_COMMAND "${cflags}")
separate_arguments(libs UNIX_COMMAND "${libs}")
set(consumer "${BINARY_DIR}/consumer")
execute_process(
    COMMAND "${compiler}" ${cflags}
        "${SOURCE_DIR}/tests/cmake-package/main.c"
        -o "${consumer}" "-Wl,-rpath,${relocated}/lib" ${libs}
    RESULT_VARIABLE result
    OUTPUT_VARIABLE output
    ERROR_VARIABLE error
)
if(NOT result EQUAL 0)
    message(FATAL_ERROR "Cannot build the pkg-config consumer:\n${output}${error}")
endif()
execute_process(
    COMMAND "${consumer}"
    RESULT_VARIABLE result
    OUTPUT_VARIABLE output
    ERROR_VARIABLE error
)
if(NOT result EQUAL 0)
    message(FATAL_ERROR "The pkg-config consumer failed:\n${output}${error}")
endif()
message(STATUS "The relocated pkg-config consumer passed (shared=${SHARED})")
