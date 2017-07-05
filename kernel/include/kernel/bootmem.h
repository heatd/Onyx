/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _PMM_H
#define _PMM_H

#include <stdint.h>
#include <stddef.h>
/* block size (4KiB) */
#define PMM_BLOCK_SIZE	4096

void bootmem_push(uintptr_t base, size_t size, size_t kernel_space_size);
void bootmem_init(size_t memory_size, uintptr_t stack_space);
void *bootmem_alloc(size_t blocks);
void *bootmem_get_pstack(size_t *);
size_t bootmem_get_memsize(void);
#endif
