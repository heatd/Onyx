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
/**************************************************************************
 *
 *
 * File: pmm.c
 *
 * Description: Contains the implementation of the kernel's PMM
 *
 * Date: 4/3/2016
 *
 *
 **************************************************************************/
#include <kernel/pmm.h>
#include <stdio.h>
#include <string.h>
namespace PhysicalMemoryManager
{
/* size of physical memory */
static size_t pmm_memory_size = 0;
static uint32_t pushed_blocks = 0;
/* Kernel addresses reserved for pmm stack */
static uintptr_t *pmm_stack_space = NULL;
extern uint32_t end;
static uint32_t last_entry = 0;
static size_t _used_mem = 0;
static bool is_initialized = false;
stack_t *stack = NULL;
size_t GetUsedMem()
{
	return _used_mem;
}
void Push(uintptr_t base, size_t size, size_t kernel_space_size)
{
	/* Don't alloc the kernel */
	if (base == 0x100000) {
		base += kernel_space_size;
	}
	for (unsigned int i = 0; i < pushed_blocks + 1; i++)
		if (stack->next[i].base == 0 && stack->next[i].size == 0) {
			stack->next[i].base = base;
			stack->next[i].size = size;
			stack->next[i].magic = 0xFDFDFDFD;
			last_entry = i;
			break;
		}
	pushed_blocks++;
}

void Pop()
{
	if (last_entry == 0)
		return;

	stack->next[last_entry].base = 0;
	stack->next[last_entry].size = 0;
	stack->next[last_entry].magic = 0xCDCDCDCD;
}

void Init(size_t memory_size, uintptr_t stack_space)
{
	if(is_initialized)
		return;
	pmm_memory_size = memory_size * 1024;
	pmm_stack_space = (uintptr_t *) stack_space;
	stack = (stack_t *) stack_space;
	memset(stack, 0, 4096);
	stack->next = (stack_entry_t *) (stack_space + sizeof(stack_t));
	is_initialized = true;
}

void *Alloc(size_t blocks)
{
	if(!is_initialized)
		return (void*)0xDEADDEADDEAD;
	uintptr_t retAddr = 0;
	for (unsigned int i = 0; i < pushed_blocks; i++)
		if (stack->next[i].base != 0 && stack->next[i].size != 0
		    && stack->next[i].size >= PMM_BLOCK_SIZE * blocks) {
			if (stack->next[i].size >= blocks * PMM_BLOCK_SIZE) {
				retAddr = stack->next[i].base;
				stack->next[i].base +=
				    PMM_BLOCK_SIZE * blocks;
				stack->next[i].size -=
				    PMM_BLOCK_SIZE * blocks;
				_used_mem += PMM_BLOCK_SIZE * blocks;
				return (void *)retAddr;
			}
		}

	return (void *) retAddr;
}

void Free(size_t blocks, void *p)
{
	if (!blocks)
		return;
	if (!p)
		return;
	memmove((void *) &stack->next[1], (void *) &stack->next[0],
		sizeof(stack_entry_t) * pushed_blocks);
	_used_mem -= PMM_BLOCK_SIZE * blocks;
	stack->next[0].base = (uintptr_t) p;
	stack->next[0].size = PMM_BLOCK_SIZE * blocks;
	stack->next[0].magic = 0xFDFDFDFD;
	pushed_blocks++;
}
};
