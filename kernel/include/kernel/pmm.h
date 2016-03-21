
#ifndef _PMM_H
#define _PMM_H

#include <stdint.h>
#include <stddef.h>
// block size (4k)
#define PMM_BLOCK_SIZE	4096
typedef struct stack_entry
{
	uintptr_t base;
	size_t size;
	size_t magic;
}stack_entry_t;
typedef struct stack
{
	stack_entry_t* next;
}stack_t;
void pmm_push(uintptr_t base,size_t size);
void pmm_pop();
void pmm_init(size_t memory_size,uintptr_t stack_space);
void* pmalloc(size_t blocks);
void  pfree(size_t blocks,void* ptr);
#endif
