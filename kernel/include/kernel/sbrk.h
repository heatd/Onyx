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
#ifndef _SBRK_H
#define _SBRK_H
#include <stdint.h>
#include <stdint.h>
#include <kernel/mm.h>
void set_data_area(void *data_area);
int __brk(void *addr);
void* __sbrk(uint32_t inc);
void* get_end_data();
void* get_start_data();
#endif
