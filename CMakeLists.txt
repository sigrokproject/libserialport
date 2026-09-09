# SPDX-License-Identifier: LGPL-3.0-or-later
#
# Copyright (C) 2026 H. Peter Anvin <hpa@zytor.com>

cmake_minimum_required(VERSION 3.17)

project(libserialport VERSION 0.1.3 LANGUAGES C)

include(CheckCSourceCompiles)
include(CheckIncludeFile)
include(CheckStructHasMember)
include(CheckSymbolExists)
include(CMakePackageConfigHelpers)
include(CTest)

option(LIBSERIALPORT_BUILD_EXAMPLES "Build libserialport examples" OFF)

add_library(libserialport)
add_library(libserialport::libserialport ALIAS libserialport)

target_sources(libserialport PRIVATE serialport.c timing.c libserialport_internal.h)
target_include_directories(libserialport
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        $<INSTALL_INTERFACE:include>
)
target_compile_features(libserialport PUBLIC c_std_99)
set_target_properties(libserialport PROPERTIES
    C_EXTENSIONS OFF
    POSITION_INDEPENDENT_CODE ON
    PREFIX ""
    IMPORT_PREFIX ""
    VERSION 0.1.3
    SOVERSION 0
)

set(SP_API "")
set(SP_PRIV "")
set(LIBSERIALPORT_NEEDS_LIBUSB OFF)
set(LIBSERIALPORT_PC_LIBRARY serialport)
set(LIBSERIALPORT_PC_LIBS_PRIVATE "")
set(LIBSERIALPORT_PC_REQUIRES_PRIVATE "")
set(LIBSERIALPORT_PC_CFLAGS "")

if(NOT MSVC)
    target_compile_definitions(libserialport PRIVATE LIBSERIALPORT_ATBUILD)
    target_include_directories(libserialport BEFORE PRIVATE
        "${CMAKE_CURRENT_BINARY_DIR}"
    )

    set(libserialport_saved_required_flags "${CMAKE_REQUIRED_FLAGS}")
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        string(APPEND CMAKE_REQUIRED_FLAGS " -Werror")
    endif()
    check_c_source_compiles(
        "__attribute__((visibility(\"hidden\"))) void f(void) {}\nint main(void) { f(); return 0; }"
        LIBSERIALPORT_HAS_VISIBILITY_ATTRIBUTE
    )
    if(LIBSERIALPORT_HAS_VISIBILITY_ATTRIBUTE)
        set(SP_API "__attribute__((visibility(\"default\")))")
        set(SP_PRIV "__attribute__((visibility(\"hidden\")))")
    else()
        check_c_source_compiles(
            "__declspec(dllexport) void f(void) {}\nint main(void) { f(); return 0; }"
            LIBSERIALPORT_HAS_DECLSPEC
        )
        if(LIBSERIALPORT_HAS_DECLSPEC)
            set(SP_API "__declspec(dllexport)")
        endif()
    endif()
    set(CMAKE_REQUIRED_FLAGS "${libserialport_saved_required_flags}")
endif()

if(UNIX)
    # Magic definitions needed to enable extensions on various systems
    list(APPEND CMAKE_REQUIRED_DEFINITIONS
      -D_GNU_SOURCE=1 -D_DEFAULT_SOURCE=1 -D_ALL_SOURCE=1
      -D_BSD_SOURCE -D_NETBSD_SOURCE=1 -D_OPENBSD_SOURCE=1
      -D__EXTENSIONS__=1 -D_XOPEN_SOURCE=700 -D_POSIX_C_SOURCE=202405L
      -D_TIME_BITS=64 -D_FILE_OFFSET_BITS=64
      -D_REENTRANT=1 -D_THREAD_SAFE=1
    )

    check_include_file("sys/file.h" HAVE_SYS_FILE_H)
    check_symbol_exists(realpath "stdlib.h" HAVE_REALPATH)
    check_symbol_exists(flock "sys/file.h" HAVE_FLOCK)
    check_symbol_exists(clock_gettime "time.h" HAVE_CLOCK_GETTIME)
    check_symbol_exists(tcdrain "termios.h" HAVE_TCDRAIN)

    check_symbol_exists(cfsetobaud "termios.h" HAVE_CFSETOBAUD)

    set(libserialport_baudrates
        50 75 110 134 150 200 300 600 1200 1800 2400 4800 7200 9600
        14400 19200 28800 33600 38400 57600 76800 115200 128000 153600
        230400 256000 307200 460800 500000 576000 614400 921600 1000000
        1152000 1500000 2000000 2500000 3000000 3500000 4000000 5000000
        10000000
    )
    set(libserialport_termios_source
        "${CMAKE_CURRENT_BINARY_DIR}/libserialport-termios.c"
    )
    file(WRITE "${libserialport_termios_source}"
        "#include <sys/types.h>\n"
        "#include <termios.h>\n"
        "#include <sys/ioctl.h>\n"
    )
    foreach(libserialport_macro_option IN ITEMS
        -dM -xdumpmacros -qshowmacros -PD
    )
        execute_process(
            COMMAND "${CMAKE_C_COMPILER}" ${CMAKE_C_COMPILER_ARG1}
                -E "${libserialport_macro_option}"
                "${libserialport_termios_source}"
            RESULT_VARIABLE libserialport_macro_result
            OUTPUT_VARIABLE libserialport_macro_output
            ERROR_QUIET
        )
        if(libserialport_macro_result EQUAL 0)
            string(REGEX MATCHALL
                "#[ \t]*define[ \t]+B[1-9][0-9]*"
                libserialport_baudrate_definitions
                "${libserialport_macro_output}"
            )
            foreach(libserialport_baudrate_definition IN LISTS
                libserialport_baudrate_definitions
            )
                string(REGEX REPLACE
                    ".*B([1-9][0-9]*)$"
                    "\\1"
                    libserialport_baudrate
                    "${libserialport_baudrate_definition}"
                )
                list(APPEND libserialport_baudrates
                    "${libserialport_baudrate}"
                )
            endforeach()
            break()
        endif()
    endforeach()
    list(REMOVE_DUPLICATES libserialport_baudrates)
    list(SORT libserialport_baudrates COMPARE NATURAL)
    set(libserialport_baud_condition "")
    set(libserialport_baud_table "")
    foreach(baudrate IN LISTS libserialport_baudrates)
        string(APPEND libserialport_baud_condition
            " \\\n\t&& (!defined(B${baudrate}) || (B${baudrate} == ${baudrate}))")
        string(APPEND libserialport_baud_table
            "#ifdef B${baudrate}\n\t{ B${baudrate}, ${baudrate} },\n#endif\n")
    endforeach()
    configure_file(cmake/baudrates.h.in baudrates.h @ONLY)
    target_sources(libserialport PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/baudrates.h")
endif()

if(WIN32 AND NOT CYGWIN)
    target_sources(libserialport PRIVATE windows.c serialport_win32.c)
    target_link_libraries(libserialport PRIVATE setupapi cfgmgr32)
    set(LIBSERIALPORT_PC_LIBS_PRIVATE "-lsetupapi -lcfgmgr32")

    if(MSVC)
        set(LIBSERIALPORT_PC_LIBRARY libserialport)
        target_compile_definitions(libserialport PRIVATE LIBSERIALPORT_MSBUILD)
        if(NOT BUILD_SHARED_LIBS)
            target_compile_definitions(libserialport PUBLIC LIBSERIALPORT_STATIC)
            set(LIBSERIALPORT_PC_CFLAGS "-DLIBSERIALPORT_STATIC")
        endif()
    elseif(BUILD_SHARED_LIBS)
        set_target_properties(libserialport PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS ON)
    endif()
else()
    target_sources(libserialport PRIVATE serialport_posix.c)
endif()

if(APPLE)
    # Match Libtool's 1:1:1 Mach-O versions, not its ELF version mapping.
    set_target_properties(libserialport PROPERTIES
        MACHO_COMPATIBILITY_VERSION 2.0.0
        MACHO_CURRENT_VERSION 2.1.0
    )
    target_sources(libserialport PRIVATE macosx.c)
    find_library(COREFOUNDATION_FRAMEWORK CoreFoundation REQUIRED)
    find_library(IOKIT_FRAMEWORK IOKit REQUIRED)
    target_link_libraries(libserialport PRIVATE
        "${COREFOUNDATION_FRAMEWORK}"
        "${IOKIT_FRAMEWORK}"
    )
    set(LIBSERIALPORT_PC_LIBS_PRIVATE
        "-framework CoreFoundation -framework IOKit"
    )
elseif(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
    target_sources(libserialport PRIVATE freebsd.c)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(LIBUSB REQUIRED IMPORTED_TARGET libusb-2.0)
    target_link_libraries(libserialport PRIVATE PkgConfig::LIBUSB)
    set(LIBSERIALPORT_NEEDS_LIBUSB ON)
    set(LIBSERIALPORT_PC_REQUIRES_PRIVATE libusb-2.0)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_sources(libserialport PRIVATE linux.c linux_termios.c linux_termios.h)

    set(libserialport_saved_required_definitions "${CMAKE_REQUIRED_DEFINITIONS}")

    check_struct_has_member(
        "struct serial_struct" flags "linux/serial.h"
        HAVE_STRUCT_SERIAL_STRUCT LANGUAGE C
    )
    check_c_source_compiles(
        "#include <linux/termios.h>\nint main(void) { struct termios2 value; (void)value; return 0; }"
        HAVE_STRUCT_TERMIOS2
    )
    check_struct_has_member(
        "struct termios" c_ispeed "linux/termios.h"
        HAVE_STRUCT_TERMIOS_C_ISPEED LANGUAGE C
    )
    check_struct_has_member(
        "struct termios" c_ospeed "linux/termios.h"
        HAVE_STRUCT_TERMIOS_C_OSPEED LANGUAGE C
    )
    check_struct_has_member(
        "struct termios2" c_ispeed "linux/termios.h"
        HAVE_STRUCT_TERMIOS2_C_ISPEED LANGUAGE C
    )
    check_struct_has_member(
        "struct termios2" c_ospeed "linux/termios.h"
        HAVE_STRUCT_TERMIOS2_C_OSPEED LANGUAGE C
    )
    check_c_source_compiles(
        "#include <linux/termios.h>\nint main(void) { struct termiox value; (void)value; return 0; }"
        HAVE_STRUCT_TERMIOX
    )
    check_symbol_exists(BOTHER "linux/termios.h" HAVE_DECL_BOTHER)

    if(HAVE_STRUCT_TERMIOS_C_ISPEED AND HAVE_STRUCT_TERMIOS_C_OSPEED)
        set(HAVE_TERMIOS_SPEED 1)
    endif()
    if(HAVE_STRUCT_TERMIOS2_C_ISPEED AND HAVE_STRUCT_TERMIOS2_C_OSPEED)
        set(HAVE_TERMIOS2_SPEED 1)
    endif()

    set(CMAKE_REQUIRED_DEFINITIONS "${libserialport_saved_required_definitions}")
elseif(NOT WIN32)
    set(NO_ENUMERATION 1)
    set(NO_PORT_METADATA 1)
endif()

configure_file(cmake/config.h.in config.h)

if(LIBSERIALPORT_BUILD_EXAMPLES)
    foreach(example IN ITEMS
        list_ports port_info port_config await_events handle_errors send_receive
    )
        add_executable(${example} "examples/${example}.c")
        target_link_libraries(${example} PRIVATE libserialport)
    endforeach()
endif()

if(BUILD_TESTING)
    add_executable(test_timing test_timing.c timing.c)
    target_include_directories(test_timing PRIVATE
        "${CMAKE_CURRENT_BINARY_DIR}"
        "${CMAKE_CURRENT_SOURCE_DIR}"
    )
    target_compile_features(test_timing PRIVATE c_std_99)
    if(MSVC)
        target_compile_definitions(test_timing PRIVATE
            LIBSERIALPORT_MSBUILD LIBSERIALPORT_STATIC
        )
    else()
        target_compile_definitions(test_timing PRIVATE LIBSERIALPORT_ATBUILD)
    endif()
    add_test(NAME timing COMMAND test_timing)

    add_executable(test_feature_guards test_feature_guards.c)
    target_include_directories(test_feature_guards PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}"
    )
    target_compile_features(test_feature_guards PRIVATE c_std_99)
    add_test(NAME feature_guards COMMAND test_feature_guards)

    if(APPLE AND BUILD_SHARED_LIBS)
        add_test(NAME macho_version COMMAND "${CMAKE_COMMAND}"
            "-DLIBRARY=$<TARGET_FILE:libserialport>"
            -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/check-macho-version.cmake"
        )
    endif()
endif()

install(TARGETS libserialport
    EXPORT libserialportTargets
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
    INCLUDES DESTINATION include
)
install(FILES libserialport.h DESTINATION include)
configure_file(cmake/libserialport.pc.in libserialport.pc @ONLY)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/libserialport.pc"
    DESTINATION lib/pkgconfig
)
install(EXPORT libserialportTargets
    FILE libserialportTargets.cmake
    NAMESPACE libserialport::
    DESTINATION lib/cmake/libserialport
)
write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/libserialportConfigVersion.cmake"
    VERSION "${PROJECT_VERSION}"
    COMPATIBILITY SameMajorVersion
)
configure_package_config_file(
    cmake/libserialportConfig.cmake.in
    "${CMAKE_CURRENT_BINARY_DIR}/libserialportConfig.cmake"
    INSTALL_DESTINATION lib/cmake/libserialport
)
install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/libserialportConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/libserialportConfigVersion.cmake"
    DESTINATION lib/cmake/libserialport
)
