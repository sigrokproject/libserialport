/* SPDX-License-Identifier: LGPL-3.0-or-later */

/* Exercise configure results whose macros are defined with a value of zero. */
#define HAVE_TERMIOS2_SPEED 1
#define HAVE_DECL_BOTHER 0
#define SP_PRIV

#include "libserialport_internal.h"

#ifdef USE_TERMIOS_SPEED
#error "USE_TERMIOS_SPEED must be disabled when HAVE_DECL_BOTHER is zero"
#endif

int main(void)
{
	return 0;
}
