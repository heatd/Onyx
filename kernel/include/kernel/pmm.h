
#pragma once

#include <stdint.h>
#include <stddef.h>
// block size (4k)
#define PMM_BLOCK_SIZE	4096
namespace PMM
{
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
void Push(uintptr_t base,size_t size);
void Pop();
void Init(size_t memory_size,uintptr_t stack_space);
size_t GetFreeMemory();
size_t GetUsedMemory();
};
void* pmalloc(size_t blocks);
void  pfree(size_t blocks,void* ptr);
