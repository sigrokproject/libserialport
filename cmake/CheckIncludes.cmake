include(CheckIncludeFiles)

check_include_files("dlfcn.h"       HAVE_DLFCN_H        )
check_include_files("inttypes.h"    HAVE_INTTYPES_H     )
check_include_files("memory.h"      HAVE_MEMORY_H       )
check_include_files("stdint.h"      HAVE_STDINT_H       )
check_include_files("stdlib.h"      HAVE_STDLIB_H       )
check_include_files("strings.h"     HAVE_STRINGS_H      )
check_include_files("string.h"      HAVE_STRING_H       )
check_include_files("sys/stat.h"    HAVE_SYS_STAT_H     )
check_include_files("sys/types.h"   HAVE_SYS_TYPES_H    )
check_include_files("unistd.h"      HAVE_UNISTD_H       )
check_include_files("stddef.h"      HAVE_STDDEF_H       )

if (HAVE_STDLIB_H AND HAVE_STDDEF_H)
    set(STDC_HEADERS true) # is needed?
endif()
