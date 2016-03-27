/* Copyright 2016 Pedro Falcato

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http ://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
#ifndef _KHEAP_H
#define _KHEAP_H

#include <kernel/vmm.h>
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

void* kmalloc(size_t size);

void kfree(void* ptr);

void init_heap();

#endif
