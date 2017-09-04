/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _PIT_H
#define _PIT_H

#include <stdint.h>

void pit_init(uint32_t hz);
uint64_t pit_get_tick_count();
void pit_deinit();
#endif
