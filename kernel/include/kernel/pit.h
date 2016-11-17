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
#ifndef _PIT_H
#define _PIT_H
#include <stdint.h>

void pit_init(uint32_t hz);
uint64_t pit_get_tick_count();
void pit_deinit();
#endif
