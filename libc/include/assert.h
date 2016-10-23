/*----------------------------------------------------------------------
 * Copyright (C) 2016 Pedro Falcato
 *
 * This file is part of Spartix, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/

#include <stdio.h>
#include <stdlib.h>

#undef assert

#ifdef NDEBUG
#define assert(expression)	(void)0
#else
#define assert(expression)                                         \
if ((expression) == 0) {                                             \
printf("assertion failed: %s, line %i, function:%s()\n",__FILE__, __LINE__, __func__); \
abort();}
#endif
