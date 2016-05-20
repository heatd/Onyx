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
#include <kernel/Paging.h>

inline uint64_t make_pml4e(uint64_t base,uint64_t avl,uint64_t pcd,uint64_t pwt,uint64_t us,uint64_t rw,uint64_t p)
{
	return (uint64_t)( \
  		(base) | \
  		(avl << 9) | \
  		(pcd << 4) | \
  		(pwt << 3) | \
  		(us << 2) | \
  		(rw << 1) | \
  		p);
}
inline uint64_t make_pml3e(uint64_t base,uint64_t nx, uint64_t avl,uint64_t glbl,uint64_t pcd,uint64_t pwt,uint64_t us,uint64_t rw,uint64_t p)
{
	return (uint64_t)( \
  		(base) | \
  		(nx << 63) | \
  		(avl << 9) | \
  		(glbl << 8) | \
  		(pcd << 4) | \
  		(pwt << 3) | \
  		(us << 2) | \
  		(rw << 1) | \
  		p);
}
inline uint64_t make_pml2e(uint64_t base,uint64_t nx, uint64_t avl,uint64_t glbl,uint64_t pcd,uint64_t pwt,uint64_t us,uint64_t rw,uint64_t p)
{
	return (uint64_t)( \
  		(base) | \
  		(nx << 63) | \
  		(avl << 9) | \
  		(glbl << 8) | \
  		(pcd << 4) | \
  		(pwt << 3) | \
  		(us << 2) | \
  		(rw << 1) | \
  		p);
}
inline uint64_t make_pml1e(uint64_t base,uint64_t nx, uint64_t avl,uint64_t glbl,uint64_t pcd,uint64_t pwt,uint64_t us,uint64_t rw,uint64_t p)
{
	return (uint64_t)( \
  		(base) | \
  		(nx << 63) | \
  		(avl << 9) | \
  		(glbl << 8) | \
  		(pcd << 4) | \
  		(pwt << 3) | \
  		(us << 2) | \
  		(rw << 1) | \
  		p);
}	

typedef struct {
    uint64_t offsetFromPage :12;
    uint64_t pt :9;
    uint64_t pd :9;
    uint64_t pdpt :9;
    uint64_t pml4 :9;
    uint64_t rest :16;
} DecomposedAddr;
namespace Paging
{
PML4 *current_pml4 = nullptr;
void Init()
{
	// Get the current PML4 and store it
	asm volatile("movq %%cr3, %%rax\t\nmovq %%rax, %0":"=r"(current_pml4));
	//Set up recursive mapping
	uint64_t* entry = &current_pml4->entries[510];
	*entry = make_pml4e((uint64_t)current_pml4, 0, 0, 0, 0, 1, 1);
}
void* MapPhysToVirt(uint64_t virt, uint64_t phys, uint64_t prot)
{
	if(!current_pml4)
		return nullptr;
	DecomposedAddr decAddr;
	memcpy(&decAddr, &virt, sizeof(DecomposedAddr));
	uint64_t* entry = &current_pml4->entries[decAddr.pml4];
	PML3* pml3 = nullptr;
	PML2* pml2 = nullptr;
	PML1* pml1 = nullptr;
	// If its present, use that pml3
	if(*entry & 1) {
		pml3 = (PML3*)(*entry & 0x0FFFFFFFFFFFF000);
	}
	else { // Else create one
		pml3 = (PML3*)PhysicalMemoryManager::Alloc(1);
		if(!pml3)
			return nullptr;
		memset(pml3, 0, sizeof(PML3));
		*entry = make_pml4e((uint64_t)pml3, 0, 0, 0, 0, (prot & 1)? 1 : 0, 1);	
	}
	entry = &pml3->entries[decAddr.pdpt];
	if(*entry & 1) {
		pml2 = (PML2*)(*entry & 0x0FFFFFFFFFFFF000);
	}
	else {
		pml2 = (PML2*)PhysicalMemoryManager::Alloc(1);
		if(!pml2 )
			return nullptr;
		memset(pml2, 0, sizeof(PML2));
		*entry = make_pml3e( (uint64_t)pml2, 1, 0, (prot & 2)? 1 : 0, 0, 0, 0, (prot & 1)? 1 : 0, 1);
	}
	entry = &pml2->entries[decAddr.pd];
	if(*entry & 1) {
		pml1 = (PML1*)(*entry & 0x0FFFFFFFFFFFF000);
	}
	else {
		pml1 = (PML1*)PhysicalMemoryManager::Alloc(1);
		if(!pml1)
			return nullptr;
		memset(pml1, 0, sizeof(PML1));
		*entry = make_pml2e( (uint64_t)pml1, 1, 0, (prot & 2)? 1 : 0, 0, 0, 0, (prot & 1)? 1 : 0, 1);
	}
	entry = &pml1->entries[decAddr.pt];
	*entry = make_pml1e( phys, 1, 0, (prot & 0x2)? 1 : 0, 0, 0, 0, (prot & 1)? 1 : 0 , 1);
	return (void*)virt;
}
void UnmapMemory(void* memory)
{
	(void) memory;
}

};
