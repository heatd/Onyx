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
 // TODO: VERY URGENT SUBSTITUTION
/**************************************************************************
 *
 *
 * File: kheap.c
 *
 * Description: Contains implementation of the kernel's heap
 *
 * Date: 4/3/2016
 *
 *
 **************************************************************************/
#include <stdint.h>
#include <stdio.h>
#include <kernel/kheap.h>
#include <kernel/compiler.h>
#include <stdlib.h>
#include <kernel/spinlock.h>
#include <kernel/panic.h>
#include <unistd.h>
#include <kernel/pmm.h>
#include <kernel/vmm.h>
#include <kernel/paging.h>
void k_heapBMInit(KHEAPBM * heap)
{
	heap->fblock = 0;
}

int k_heapBMAddBlock(KHEAPBM * heap, uintptr_t addr, uint32_t size,
		     uint32_t bsize)
{
	KHEAPBLOCKBM *b;
	uint32_t bcnt;
	uint32_t x;
	uint8_t *bm;

	b = (KHEAPBLOCKBM *) addr;
	b->size = size - sizeof(KHEAPBLOCKBM);
	b->bsize = bsize;

	b->next = heap->fblock;
	heap->fblock = b;

	bcnt = size / bsize;
	bm = (uint8_t *) & b[1];

	/* clear bitmap */
	for (x = 0; x < bcnt; ++x) {
		bm[x] = 0;
	}

	/* reserve room for bitmap */
	bcnt =
	    (bcnt / bsize) * bsize <
	    bcnt ? bcnt / bsize + 1 : bcnt / bsize;
	for (x = 0; x < bcnt; ++x) {
		bm[x] = 5;
	}

	b->lfb = bcnt - 1;

	b->used = bcnt;

	return 1;
}

static uint8_t k_heapBMGetNID(uint8_t a, uint8_t b)
{
	uint8_t c;
	for (c = a + 1; c == b || c == 0; ++c);
	return c;
}

void *k_heapBMAlloc(KHEAPBM * heap, uint32_t size)
{
	KHEAPBLOCKBM *b;
	uint8_t *bm;
	uint32_t bcnt;
	uint32_t x, y, z;
	uint32_t bneed;
	uint8_t nid;

	/* iterate blocks */
	for (b = heap->fblock; b; b = b->next) {
		/* check if block has enough room */
		if (b->size - (b->used * b->bsize) >= size) {

			bcnt = b->size / b->bsize;
			bneed =
			    (size / b->bsize) * b->bsize <
			    size ? size / b->bsize + 1 : size / b->bsize;
			bm = (uint8_t *) & b[1];

			for (x = (b->lfb + 1 >= bcnt ? 0 : b->lfb + 1);
			     x != b->lfb; ++x) {
				/* just wrap around */
				if (x >= bcnt) {
					x = 0;
				}

				if (bm[x] == 0) {
					/* count free blocks */
					for (y = 0;
					     bm[x + y] == 0 && y < bneed
					     && (x + y) < bcnt; ++y);

					/* we have enough, now allocate them */
					if (y == bneed) {
						/* find ID that does not match left or right */
						nid =
						    k_heapBMGetNID(bm
								   [x - 1],
								   bm[x +
								      y]);

						/* allocate by setting id */
						for (z = 0; z < y; ++z) {
							bm[x + z] = nid;
						}

						/* optimization */
						b->lfb = (x + bneed) - 2;

						/* count used blocks NOT bytes */
						b->used += y;

						return (void *) (x *
								 b->bsize +
								 (uintptr_t)
								 & b[1]);
					}

					/* x will be incremented by one ONCE more in our FOR loop */
					x += (y - 1);
					continue;
				}
			}
		}
	}

	return 0;
}

void k_heapBMFree(KHEAPBM * heap, void *ptr)
{
	KHEAPBLOCKBM *b;
	uintptr_t ptroff;
	uint32_t bi, x;
	uint8_t *bm;
	uint8_t id;
	uint32_t max;

	for (b = heap->fblock; b; b = b->next) {
		if ((uintptr_t) ptr > (uintptr_t) b
		    && (uintptr_t) ptr < (uintptr_t) b + b->size) {
			/* found block */
			ptroff = (uintptr_t) ptr - (uintptr_t) & b[1];	/* get offset to get block */
			/* block offset in BM */
			bi = ptroff / b->bsize;
			/* .. */
			bm = (uint8_t *) & b[1];
			/* clear allocation */
			id = bm[bi];
			/* oddly.. GCC did not optimize this */
			max = b->size / b->bsize;
			for (x = bi; bm[x] == id && x < max; ++x) {
				bm[x] = 0;
			}
			/* update free block count */
			b->used -= x - bi;
			return;
		}
	}

	/* this error needs to be raised or reported somehow */
	return;
}

uint32_t heap_extensions;
static KHEAPBM kheap;
void InitHeap()
{
	k_heapBMInit(&kheap);
	uintptr_t address = KERNEL_VIRTUAL_BASE - 0x10000000;
	for (uintptr_t i = 0;
	     i < 1024; i++) {
		paging_map_phys_to_virt(address, (uintptr_t)
				     pmalloc(1), 3);
		address+=0x1000;
	}
	printf("Mapped memory for the heap\n");
	k_heapBMAddBlock(&kheap, address - 0x400000,
			 0x400000, 16);
	heap_extensions = 0;
}
static spinlock_t spl;
void *malloc(size_t size)
{
	acquire(&spl);
	if (!size)
		return NULL;
	void *ptr = k_heapBMAlloc(&kheap, size);
	release(&spl);
	return ptr;
}

void free(void *ptr)
{
	if (!ptr)
		return;
	k_heapBMFree(&kheap, ptr);
}
