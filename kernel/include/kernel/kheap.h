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
#ifndef _KHEAP_H
#define _KHEAP_H

#include <stdint.h>
#include <string.h>
typedef struct _KHEAPBLOCKBM {
	struct _KHEAPBLOCKBM	                *next;
	uint32_t					size;
	uint32_t					used;
	uint32_t					bsize;
        uint32_t                                  lfb;
} KHEAPBLOCKBM;

typedef struct _KHEAPBM
{
	KHEAPBLOCKBM			*fblock;
} KHEAPBM;

void k_heapBMFree(KHEAPBM *heap, void *ptr);

void *k_heapBMAlloc(KHEAPBM *heap, uint32_t size);

int k_heapBMAddBlock(KHEAPBM *heap, uintptr_t addr, uint32_t size, uint32_t bsize);

void k_heapBMInit(KHEAPBM *heap);

void InitHeap();

#endif
