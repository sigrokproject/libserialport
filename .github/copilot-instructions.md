# libserialport repository instructions

## Build and test

On Unix-like systems, this is an autotools project. Regenerate the build
system after changing `configure.ac` or `Makefile.am`, then configure and
build:

```sh
./autogen.sh
./configure
make
```

The native CMake build supports all platforms:

```sh
cmake -S . -B build
cmake --build build
ctest --test-dir build
```

Run the complete test suite with `make check`. Run one Automake test with,
for example, `make check TESTS=test_feature_guards`; the available tests are
`test_timing`, `test_feature_guards`, and `test_baud_termiox.sh`. To build and
run a compiled test directly, use `make test_timing && ./test_timing`.

There is no separate lint target. The autotools build compiles C99 code with
`-Wall -Wextra -pedantic -Wmissing-prototypes -Wshadow`. Doxygen documentation
is generated with `make doc` and written under `doxy/`.

Windows builds use the Visual Studio 2019 solution (`libserialport.sln`), whose
library project builds `serialport.c`, `serialport_win32.c`, `timing.c`, and
`windows.c`. The shared MSBuild properties enforce warning level 4,
warnings-as-errors, SDL checks, and conformance mode.

## Architecture

- `libserialport.h` is the documented, installed C API. It owns the opaque
  public types, `sp_` functions, `SP_` constants, API behavior, ownership, and
  error/thread-safety documentation.
- `serialport.c` implements shared public API behavior, including port/config
  lifetime, validation, errors, debug handling, and version functions.
  `serialport_posix.c` and `serialport_win32.c` implement the respective
  platform I/O, configuration, event, signal, and OS-error operations.
  `timing.c` provides the private timeout abstraction shared by blocking I/O
  and waiting behavior.
- `libserialport_internal.h` defines the private layouts of `sp_port` and
  `sp_port_config`, portability feature macros, tracing/error-return macros,
  timeout types, and the platform backend interface.
- Exactly one I/O implementation is selected by `configure.ac`/`Makefile.am`:
  `serialport_posix.c` or `serialport_win32.c`. The OS enumeration backends
  `linux.c`, `windows.c`, `macosx.c`, and `freebsd.c` supply `list_ports()` and
  `get_port_details()` where supported. Linux-specific termios/termiox
  compatibility helpers are isolated in `linux_termios.c`.
- CMake follows the same split: native Windows builds select
  `serialport_win32.c`, while POSIX targets select `serialport_posix.c`.
- Examples are independent consumers of the public API. `examples/Makefile`
  uses `pkg-config` against an installed library rather than the in-tree build.

## Project-specific conventions

- Keep public ABI declarations and Doxygen comments in `libserialport.h`.
  Public identifiers use `sp_`/`SP_`; internal functions use `SP_PRIV`, while
  exported definitions use `SP_API`.
- API functions conventionally begin with `TRACE`/`TRACE_VOID` and exit through
  `RETURN_*`/`SET_*` macros from `libserialport_internal.h`. Preserve these so
  debug handling and `enum sp_return` reporting remain consistent. Propagate
  a called API's status with `TRY()` or `RETURN_CODEVAL()`.
- `SP_ERR_ARG` is for invalid caller input, `SP_ERR_MEM` for allocation
  failures, `SP_ERR_SUPP` for unavailable platform/device functionality, and
  `SP_ERR_FAIL` for OS failures. Only `SP_ERR_FAIL` permits callers to retrieve
  an OS error via `sp_last_error_code()` or `sp_last_error_message()`.
- Platform additions must preserve the common `struct sp_port` contract and
  implement the two backend hooks. Guard OS-only behavior with the configure
  feature macros instead of assuming a particular Unix API is present.
- `config.h`, `configure`, `Makefile`, `Makefile.in`, `libserialport.pc`,
  `baudrates.h`, and the `autostuff/` directory are generated and ignored.
  Edit their source inputs (`configure.ac`, `Makefile.am`,
  `libserialport.pc.in`, or `baudrates.sh`) instead. `baudrates.sh` generates
  the portable baud-rate table during the autotools build.
- Updating package or shared-library versions requires `configure.ac`.
  The package version and libtool ABI `current:revision:age` are intentionally
  separate; follow the linked libtool guidance before changing the ABI values.
