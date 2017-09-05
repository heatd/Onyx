/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _KERNEL_CLOCK_H
#define _KERNEL_CLOCK_H

#include <time.h>

struct clock_source
{
	const char *clock_source;
	time_t (*get_posix_time)(void);
};

void register_clock_source(struct clock_source *clk);

#endif
