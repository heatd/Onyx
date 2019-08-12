/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _KERNEL_TIMER_H
#define _KERNEL_TIMER_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

uint64_t get_tick_count();
uint64_t get_microseconds();


void udelay(unsigned int us);
void ndelay(unsigned int ns);

#ifdef __cplusplus
}
#endif
#endif
