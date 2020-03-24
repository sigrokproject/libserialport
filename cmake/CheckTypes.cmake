include(CheckCSourceCompiles)

macro(check_type_exists type header var)
    check_c_source_compiles(
        "
        #include <${header}>
        void foo(${type} test);
        int main(void) {return 0;}
        "
        ${var}
    )
endmacro()

macro(check_type_member_exists type member header var)
    check_c_source_compiles(
        "
        #include <${header}>
        int main(void) {((${type} *)0)->${member}; return 0; }
        "
        ${var}
    )
endmacro()

function(setnot var res)
    if(${var})
        set(${res} false PARENT_SCOPE)
    else()
        set(${res} true  PARENT_SCOPE)
    endif()
endfunction()

check_type_exists(
    "size_t" "sys/types.h" HAVE_SIZE_T
)
setnot(HAVE_SIZE_T size_t)

check_type_exists(
    "struct termiox" "linux/termios.h" HAVE_STRUCT_TERMIOX
)

check_type_exists(
    "struct termios2" "linux/termios.h" HAVE_STRUCT_TERMIOS2
)

check_type_exists(
    "struct serial_struct" "linux/serial.h" HAVE_STRUCT_SERIAL_STRUCT
)

check_type_member_exists(
    "struct termios" "c_ispeed" "linux/termios.h" HAVE_STRUCT_TERMIOS_C_ISPEED
)

check_type_member_exists(
    "struct termios" "c_ospeed" "linux/termios.h" HAVE_STRUCT_TERMIOS_C_OSPEED
)

check_type_member_exists(
    "struct termios2" "c_ispeed" "linux/termios.h" HAVE_STRUCT_TERMIOS2_C_ISPEED
)

check_type_member_exists(
    "struct termios2" "c_ospeed" "linux/termios.h" HAVE_STRUCT_TERMIOS2_C_OSPEED
)
