/*----------------------------------------------------------------------
 * Copyright (C) 2016, 2017 Pedro Falcato
 *
 * This file is part of Onyx, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/

#ifndef _LIMITS_H
#define _LIMITS_H

/* 5.2.4.2.1 Sizes of integer types <limits.h> */

# define CHAR_BIT 8

#define SCHAR_MIN 	-127
#define SCHAR_MAX 	127
#define UCHAR_MAX 	255
#define MB_LEN_MAX 	1
#define SHRT_MIN 	-32767
#define SHRT_MAX 	32767
#define USHRT_MAX 	65535
#define INT_MIN   	-32767
#define INT_MAX 	32767
#define UINT_MAX 	65535
#define LONG_MIN	-2147483647
#define LONG_MAX	2147483647
#define ULONG_MAX	4294967295
#define LLONG_MIN	-9223372036854775807
#define LLONG_MAX	9223372036854775807
#define ULONG_MAX	18446744073709551615



#endif
