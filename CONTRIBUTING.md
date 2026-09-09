# Contributing to libserialport

Contributions are welcome through the
[issue tracker](https://github.com/hpax/libserialport/issues) and pull
requests. Please keep each patch focused on one logical change and include
tests when the change has testable behavior.

## Preparing a patch

Use Linux-kernel-style commit messages:

- Begin with a short, imperative subject, prefixed by the affected subsystem
  where useful (for example, `linux: fix ...` or `serialport: add ...`).
- Follow the subject with a blank line and a prose body that explains the
  problem, why the change is correct, and relevant compatibility or
  platform-specific behavior. Describe the change's purpose rather than
  repeating the diff. Wrap body lines at approximately 72 columns.
- Add a `Signed-off-by:` trailer for every contributor certifying the patch:

  ```text
  Signed-off-by: Your Name <your.email@example.com>
  ```

  Create signed commits with `git commit -s`. Preserve existing trailers when
  revising a patch, and add your own sign-off if you make substantive changes
  to someone else's patch.

## Code style

Use the Linux kernel C coding style used by the existing sources:

- Indent with tabs (each tab is eight columns); align continuation lines with
  tabs and spaces as in nearby code.
- Put function opening braces on the following line; put control-statement
  opening braces on the same line. Keep `else` on the closing-brace line.
- Prefer lines of 80 columns or fewer when practical. Do not reformat
  unrelated code.
- Retain the existing LGPL copyright header in source files, adding your
  copyright line only when appropriate.
- Keep exported API declarations and Doxygen documentation in
  `libserialport.h`. Public identifiers use `sp_` for functions/types and
  `SP_` for constants/macros.

Use the existing `TRACE`/`TRACE_VOID` and `RETURN_*`/`SET_*` macros in public
API implementations so tracing and `enum sp_return` error reporting stay
consistent. Use `SP_ERR_ARG` for invalid caller input, `SP_ERR_MEM` for
allocation failures, `SP_ERR_SUPP` for unsupported functionality, and
`SP_ERR_FAIL` for OS-reported failures.

## Building and testing

On Unix-like systems, regenerate the build system after changing
`configure.ac` or `Makefile.am`, then configure and test:

```sh
./autogen.sh
./configure
make
make check
```

The native CMake build can be configured and tested with:

```sh
cmake -S . -B build
cmake --build build
ctest --test-dir build
```

Run an individual Automake test with, for example:

```sh
make check TESTS=test_feature_guards
```

The available tests are `test_timing`, `test_feature_guards`, and
`test_baud_termiox.sh`. The build uses C99 and treats its configured warning
set as the code-quality gate; there is no separate lint command.

Do not edit generated autotools artifacts or `baudrates.h` directly. Update
their sources instead: `configure.ac`, `Makefile.am`, `libserialport.pc.in`,
or `baudrates.sh`.

## Platform changes

The common implementation is in `serialport.c`; `serialport_posix.c` and
`serialport_win32.c` provide the platform I/O implementations selected by
`configure.ac`/`Makefile.am`. OS enumeration backends must preserve the
`libserialport_internal.h` contracts and implement `list_ports()` and
`get_port_details()` where enumeration and metadata are supported. Guard
OS-specific functionality with configure feature macros; do not assume a Unix
interface is available on every supported platform.
