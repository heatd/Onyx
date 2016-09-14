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
#ifndef _TIME_H
#define _TIME_H
#include <stdint.h>
typedef uint64_t time_t;
typedef uint64_t suseconds_t;
struct timeval
{
	time_t      tv_sec;     /* seconds */
	suseconds_t tv_usec;    /* microseconds */
};
struct timezone
{
	int tz_minuteswest;     /* minutes west of Greenwich */
	int tz_dsttime;         /* type of DST correction */
};






#endif