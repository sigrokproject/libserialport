/* SPDX-License-Identifier: LGPL-3.0-or-later */

#include <libserialport.h>

int main(void)
{
	return sp_get_major_package_version() == SP_PACKAGE_VERSION_MAJOR ? 0 : 1;
}
