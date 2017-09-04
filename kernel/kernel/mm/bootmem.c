/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
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
#include <stdbool.h>

#include <multiboot2.h>
#include <onyx/bootmem.h>
#include <onyx/paging.h>
#include <onyx/vmm.h>
typedef struct stack_entry
{
	uintptr_t base;
	size_t size;
	size_t magic;
} stack_entry_t;
typedef struct stack
{
	stack_entry_t* next;
} stack_t;
/* size of physical memory */
static uint32_t pushed_blocks = 0;
static uintptr_t pmm_memory_size = 0;
/* Kernel addresses reserved for pmm stack */
static uintptr_t *pmm_stack_space = NULL;
extern uint32_t end;
static uint32_t last_entry = 0;
stack_t *stack = NULL;
size_t bootmem_get_memsize(void)
{
	return pmm_memory_size;
}
void bootmem_push_page(uintptr_t page)
{
	for(unsigned int i = 0; i < pushed_blocks + 1; i++)
	{	
		if(page - (stack->next[i].base + stack->next[i].size) == PAGE_SIZE)
		{
			stack->next[i].size += PAGE_SIZE;
			return;
		}
		if(stack->next[i].base == 0 && stack->next[i].size == 0)
		{
			stack->next[i].base = page;
			stack->next[i].size = PAGE_SIZE;
			stack->next[i].magic = 0xFDFDFDFD;
			last_entry = i;
			break;
		}
	}
	pushed_blocks++;
}
bool __check_used(uintptr_t page, uintptr_t start, uintptr_t end)
{
	if(start == page)
		return true;
	if(start < page && end > page)
		return true;
	return false;
}
extern uintptr_t kernel_end;
#define KERNEL_START		0x100000
bool check_used(uintptr_t page, struct multiboot_tag_module *module)
{
	if(page == 0)
		return true;
	if(__check_used(page, module->mod_start, module->mod_end) == true)
		return true;
	/* This part doesn't work, that's why we check for KERNEL_START - module->mod_end */
	if(__check_used(page, KERNEL_START, 0x400000) == true)
		return true;
	return false;
}
void bootmem_push(uintptr_t base, size_t size, struct multiboot_tag_module *module)
{
	size &= -PAGE_SIZE;
	for(uintptr_t p = base; p < base + size; p += PAGE_SIZE)
	{
		if(check_used(p, module) == false)
			bootmem_push_page(p);
	}
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
void *bootmem_get_pstack(size_t *nentries)
{
	*nentries = pushed_blocks;
	return stack;
}
void dump_bootmem(void)
{
	for (unsigned int i = 0; i < pushed_blocks; i--)
	{
		printk("[%p - %p]\n", stack->next[i].base, 
			stack->next[i].base + stack->next[i].size);
	}
}
