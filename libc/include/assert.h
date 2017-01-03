/*----------------------------------------------------------------------
 * Copyright (C) 2016, 2017 Pedro Falcato
 *
 * This file is part of Spartix, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/
#include <sys/cdefs.h>
#define __need_printf
#include <stdio.h>
#define __need_abort
#include <stdlib.h>

#ifdef NDEBUG
#define assert(ignore)	((void) 0)
#else
#define assert(expression)                                         \
if ((expression) == 0) {                                             \
printf("assertion failed: %s, line %u, function: %s()\n", __FILE__, __LINE__, __func__); \
abort();}

/* If the used C standard is C11 or higher, define static_assert */
#if defined(__STDC_VERSION__) && 201112L <= __STDC_VERSION__
#define static_assert _Static_assert
#endif

#endif
