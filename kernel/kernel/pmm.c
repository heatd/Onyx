#include <kernel/pmm.h>

// size of physical memory
static	size_t	pmm_memory_size = 0;
// Kernel addresses reserved for pmm stack
static	uintptr_t*	pmm_stack_space = NULL;

static stack_t* stack = NULL;

extern uint32_t end;
static uint32_t last_entry = 0;
void pmm_push(uintptr_t base,size_t size)
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
void pmm_pop()
{
	if(last_entry == 0)
		return;
	
	stack->next[last_entry].base = 0;
	stack->next[last_entry].size = 0;
	stack->next[last_entry].magic = 0xCDCDCDCD;
}
void* pmalloc(size_t blocks)
{
	void* ret_addr = NULL;
	for(int i = 0;i < 12;i++)
		if(stack->next[i].base !=0 || stack->next[i].size != 0){
			if(stack->next[i].base >= blocks * PMM_BLOCK_SIZE){
				ret_addr = stack->next[i].base;
				stack->next[i].base+=PMM_BLOCK_SIZE * blocks;
				stack->next[i].size-=PMM_BLOCK_SIZE * blocks;
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
	pmm_push(p,blocks * PMM_BLOCK_SIZE); // Maybe implement a better solution
}
void pmm_init(size_t memory_size,uintptr_t stack_space)
{
	pmm_memory_size = memory_size * 1024;
	pmm_stack_space = (uintptr_t*)stack_space;
	
	stack = stack_space;
	memset(stack, 0,4096);
	stack->next=0xC0200010;
}