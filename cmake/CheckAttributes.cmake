include(CheckCSourceCompiles)

macro(check_attribute_exists attr var)
    set(CMAKE_C_FLAGS_BKP ${CMAKE_C_FLAGS})
    if(MSVC)
        set(CMAKE_C_FLAGS "-WX")
    else()
        set(CMAKE_C_FLAGS "-Werror")
    endif()
    check_c_source_compiles(
        "
        ${attr}
        void foo(void) {}
        int main(void) {return 0;}
        "
        ${var}
    )
    set(CMAKE_C_FLAGS ${CMAKE_C_FLAGS_BKP})
endmacro()

check_attribute_exists(
    "__attribute__((visibility(\"hidden\")))" HAVE_ATTRIBUTE
)

check_attribute_exists(
    "__declspec(dllexport)" HAVE_DECLSPEC
)

if(${HAVE_ATTRIBUTE})
    set(SP_API "__attribute__((visibility(\"default\")))")
    set(SP_PRIV "__attribute__((visibility(\"hidden\")))")
elseif(HAVE_DECLSPEC AND ${BUILD_SHARED_LIBS})
    set(SP_API "__declspec(dllexport)")
endif()
