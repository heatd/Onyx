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
#include <kernel/pmm.h>
#include <string.h>
// size of physical memory
static	size_t	pmm_memory_size = 0;
// Kernel addresses reserved for pmm stack
static	uintptr_t*	pmm_stack_space = NULL;
extern uint32_t end;
static uint32_t last_entry = 0;
namespace PMM
{
	stack_t* stack = NULL;
void Push(uintptr_t base,size_t size)
{
	// Don't alloc the kernel
	if(base == 0x100000){
		base += 0x300000;
		base &= 0xFFFFFF000;
	}
	for(int i = 0;i < pmm_memory_size/PMM_BLOCK_SIZE ;i++)
		if(stack->next[i].base==0 && stack->next[i].size == 0){
			stack->next[i].base = base;
			stack->next[i].size = size;
			stack->next[i].magic= 0xFDFDFDFD;
			last_entry = i;
			break;
		}
}
void Pop()
{
	if(last_entry == 0)
		return;
	
	stack->next[last_entry].base = 0;
	stack->next[last_entry].size = 0;
	stack->next[last_entry].magic = 0xCDCDCDCD;
}
void Init(size_t memory_size,uintptr_t stack_space)
{
	pmm_memory_size = memory_size * 1024;
	pmm_stack_space = (uintptr_t*)stack_space;
	
	stack =(stack_t*)stack_space;
	memset(stack, 0,4096);
	stack->next=(stack_entry*)0x80200010;
}
};
void* pmalloc(size_t blocks)
{
	void* ret_addr = NULL;
	for(int i = 0;i < 12;i++)
		if(PMM::stack->next[i].base !=0 || PMM::stack->next[i].size != 0){
			if(PMM::stack->next[i].base >= blocks * PMM_BLOCK_SIZE){
				ret_addr =(void*)PMM::stack->next[i].base;
				PMM::stack->next[i].base+=PMM_BLOCK_SIZE * blocks;
				PMM::stack->next[i].size-=PMM_BLOCK_SIZE * blocks;
				return (void*)((uint32_t)ret_addr & 0xFFFFFF000);
			}
		}
	
	return ret_addr;
}
void pfree(size_t blocks,void* p)
{
	if(!blocks)
		return;
	if(!p)
		return;
	PMM::Push((uintptr_t)p,blocks * PMM_BLOCK_SIZE); // Maybe implement a better solution
}