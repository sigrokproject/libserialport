if(NOT ${CMAKE_SYSTEM_NAME} MATCHES "Linux|Darwin|Windows|FreeBSD")
    set(NO_ENUMERATION true)
    set(NO_PORT_METADATA true)
endif()
