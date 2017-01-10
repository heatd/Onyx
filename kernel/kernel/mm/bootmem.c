/*----------------------------------------------------------------------
 * Copyright (C) 2016, 2017 Pedro Falcato
 *
 * This file is part of Spartix, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/
/**************************************************************************
 *
 *
 * File: bootmem.c
 *
 * Description: Contains the implementation of the kernel's boot memory manager
 *
 * Date: 4/12/2016
 *
 *
 **************************************************************************/
#include <stdio.h>
#include <string.h>

#include <kernel/bootmem.h>

/* size of physical memory */
static uint32_t pushed_blocks = 0;
static uintptr_t pmm_memory_size = 0;
/* Kernel addresses reserved for pmm stack */
static uintptr_t *pmm_stack_space = NULL;
extern uint32_t end;
static uint32_t last_entry = 0;
stack_t *stack = NULL;
void bootmem_push(uintptr_t base, size_t size, size_t kernel_space_size)
{
	if(base == 0)
	{
		base += 0x1000;
		size -= 0x1000;
	}
	/* Don't alloc the kernel */
	if (base == 0x100000)
		base += kernel_space_size;
	
	for (unsigned int i = 0; i < pushed_blocks + 1; i++)
		if (stack->next[i].base == 0 && stack->next[i].size == 0)
		{
			stack->next[i].base = base;
			stack->next[i].size = size;
			stack->next[i].magic = 0xFDFDFDFD;
			last_entry = i;
			break;
		}
	pushed_blocks++;
}
void bootmem_init(size_t memory_size, uintptr_t stack_space)
{
	pmm_memory_size = memory_size * 1024;
	pmm_stack_space = (uintptr_t *) stack_space;
	stack = (stack_t *) stack_space;
	memset(stack, 0, 4096);
	stack->next = (stack_entry_t *) (stack_space + sizeof(stack_t));
}
void *bootmem_alloc(size_t blocks)
{
	uintptr_t ret_addr = 0;
	for (unsigned int i = pushed_blocks-1; i; i--)
		if (stack->next[i].base != 0 && stack->next[i].size != 0 && stack->next[i].size >= PMM_BLOCK_SIZE * blocks)
		{
			if (stack->next[i].size >= blocks * PMM_BLOCK_SIZE)
			{
				ret_addr = stack->next[i].base;
				stack->next[i].base += PMM_BLOCK_SIZE * blocks;
				stack->next[i].size -= PMM_BLOCK_SIZE * blocks;
				return (void *) ret_addr;
			}
		}

	return NULL;
}

typedef struct
{
        char *start_address;
        char *end_address;
        size_t size; // Just for convinience
        struct buddy_block *top;
} memory_zone_t;

memory_zone_t dma = {0};
memory_zone_t high_mem = {0};
void pmm_init_new(size_t memory_size)
{
	pmm_memory_size = memory_size * 1024;
	
}
