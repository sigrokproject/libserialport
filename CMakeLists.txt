cmake_minimum_required(VERSION 3.12)

# Disable in-source builds to prevent source tree corruption.
if("${CMAKE_SOURCE_DIR}" STREQUAL "${CMAKE_BINARY_DIR}")
    message(FATAL_ERROR "FATAL: In-source builds are not allowed.
    You should create a separate directory for build files.")
endif()

project(
    libserialport
	VERSION 0.1.1
	DESCRIPTION "cross-platform library for accessing serial ports."
	HOMEPAGE_URL "https://sigrok.org/wiki/libserialport"
	LANGUAGES C
)

# Custom modules
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

set(PACKAGE_NAME              ${PROJECT_NAME})
set(PACKAGE_BUGREPORT         "martin-libserialport@earth.li")
set(RESOURCE_FILE_LICENSE     "${CMAKE_CURRENT_SOURCE_DIR}/COPYING")
set(PACKAGE_VERSION_MAJOR     ${PROJECT_VERSION_MAJOR})
set(PACKAGE_VERSION_MINOR     ${PROJECT_VERSION_MINOR})
set(PACKAGE_VERSION_PATCH     ${PROJECT_VERSION_PATCH})

set(LIB_VERSION_AGE         1)
set(LIB_VERSION_CURRENT     1)
set(LIB_VERSION_REVISION    0)
set(LIB_VERSION_STRING
    "${LIB_VERSION_CURRENT}:${LIB_VERSION_REVISION}:${LIB_VERSION_AGE}")

# Include check modules
include(CheckSys)
include(CheckTypes)
include(CheckIncludes)
include(CheckFunctions)
include(CheckAttributes)
include(CheckDeclarations)

configure_file(
    "${CMAKE_MODULE_PATH}/config.h.in"
    "${CMAKE_CURRENT_SOURCE_DIR}/config.h"
    @ONLY
)

include(GNUInstallDirs)

add_definitions(-D_GNU_SOURCE)
add_definitions(-DLIBSERIALPORT_ATBUILD)
add_compile_options(-Wall -Wextra -pedantic -Wno-unused-parameter)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

set(
    LIBRARY_OUTPUT_PATH ${CMAKE_BINARY_DIR}/lib
)

set(
    LSP_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/serialport.c
    ${CMAKE_CURRENT_SOURCE_DIR}/timing.c
)

set(
    LSP_HEADER
    ${CMAKE_CURRENT_SOURCE_DIR}/libserialport_internal.h
    ${CMAKE_CURRENT_SOURCE_DIR}/libserialport.h
)

if(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    set(
        LSP_SOURCES ${LSP_SOURCES}
        ${CMAKE_CURRENT_SOURCE_DIR}/linux.c
        ${CMAKE_CURRENT_SOURCE_DIR}/linux_termios.c
    )

    set(
        LSP_HEADER ${LSP_HEADER}
        ${CMAKE_CURRENT_SOURCE_DIR}/linux_termios.h
    )
elseif(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
    set(
        LSP_SOURCES ${LSP_SOURCES}
        ${CMAKE_CURRENT_SOURCE_DIR}/windows.c
    )
elseif(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
    set(
        LSP_SOURCES ${LSP_SOURCES}
        ${CMAKE_CURRENT_SOURCE_DIR}/macosx.c
    )
elseif(${CMAKE_SYSTEM_NAME} MATCHES "FreeBSD")
    set(
        LSP_SOURCES ${LSP_SOURCES}
        ${CMAKE_CURRENT_SOURCE_DIR}/freebsd.c
    )
else()
    message(
        FATAL_ERROR
        "
        No support for ${CMAKE_SYSTEM_NAME} operating system.
        Only available for [Linux, Darwin, FreeBSD, Windows].
        "
    )
endif()

string(REPLACE "lib" "" LIBRARY_NAME ${PROJECT_NAME})

add_library(
    ${LIBRARY_NAME} SHARED
    ${LSP_SOURCES} ${LSP_HEADER}
)

add_library(
    ${LIBRARY_NAME}_static STATIC
    ${LSP_SOURCES} ${LSP_HEADER}
)

target_include_directories(
    ${LIBRARY_NAME}
    INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}
)

target_include_directories(
    ${LIBRARY_NAME}_static
    INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}
)

if (UNIX)
    set_target_properties(
        ${LIBRARY_NAME}_static
        PROPERTIES OUTPUT_NAME ${LIBRARY_NAME}
    )

    configure_file(
        ${CMAKE_MODULE_PATH}/libserialport.pc.in
        ${CMAKE_CURRENT_BINARY_DIR}/libserialport.pc
        @ONLY
    )

    install(
        FILES ${CMAKE_CURRENT_BINARY_DIR}/libserialport.pc
        DESTINATION ${CMAKE_INSTALL_PREFIX}/pkgconfig
    )
endif()

set_target_properties(
    ${LIBRARY_NAME}
    PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
)

set_target_properties(
    ${LIBRARY_NAME}_static
    PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
)

if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
    target_link_libraries(${LIBRARY_NAME} setupapi)
    target_link_libraries(${LIBRARY_NAME}_static setupapi)
elseif(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
    find_library(IOKit IOKit)
    find_library(CoreFoundation CoreFoundation)
    target_link_libraries(${LIBRARY_NAME} ${IOKit} ${CoreFoundation})
    target_link_libraries(${LIBRARY_NAME}_static ${IOKit} ${CoreFoundation})
endif()

install(
    TARGETS ${LIBRARY_NAME}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

install(
    TARGETS ${LIBRARY_NAME}_static
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

install(
    FILES ${CMAKE_CURRENT_SOURCE_DIR}/libserialport.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

if(NOT TARGET uninstall)
    configure_file(
        ${CMAKE_MODULE_PATH}/cmake_uninstall.cmake.in
        ${CMAKE_BINARY_DIR}/cmake_uninstall.cmake
        IMMEDIATE @ONLY
    )

    add_custom_target(
        uninstall
        COMMAND ${CMAKE_COMMAND} -P ${CMAKE_BINARY_DIR}/cmake_uninstall.cmake
    )
endif()

add_subdirectory(examples)
