/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _PMM_H
#define _PMM_H

#include <stdint.h>
#include <stddef.h>

#define BOOTMEM_FLAG_LOW_MEM			(1 << 0)

void set_alloc_boot_page(void * (*f)(size_t nr, long flags));
void *alloc_boot_page(size_t nr_pgs, long flags);

#endif
