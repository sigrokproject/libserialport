#!/bin/sh
# SPDX-License-Identifier: LGPL-3.0-or-later

set -eu

source_dir=${srcdir:-.}
tmp_dir=${TMPDIR:-/tmp}/libserialport-baud-termiox-$$
trap 'rm -rf "$tmp_dir"' EXIT HUP INT TERM
mkdir -p "$tmp_dir"

${CC:-cc} ${CPPFLAGS:-} ${CFLAGS:-} \
	-I"$source_dir/tests/baud-termiox" -I"$source_dir" \
	-c "$source_dir/linux_termios.c" -o "$tmp_dir/linux_termios.o"

${NM:-nm} "$tmp_dir/linux_termios.o" > "$tmp_dir/symbols"
grep -q ' get_termiox_size$' "$tmp_dir/symbols"
grep -q ' get_termiox_flow$' "$tmp_dir/symbols"
grep -q ' set_termiox_flow$' "$tmp_dir/symbols"
