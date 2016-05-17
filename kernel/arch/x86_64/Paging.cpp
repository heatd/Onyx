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
}
void* MapPhysToVirt(uintptr_t virt, uintptr_t phys, uint64_t prot)
{
	if(!current_pml4)
		return nullptr;
	DecomposedAddr decAddr;
	memcpy(&decAddr, &virt, sizeof(DecomposedAddr));
	asm volatile("mov %0,%%r11"::"r"(decAddr.pdpt));
	while(1);
	uint64_t* entry = &current_pml4->entries[decAddr.pml4];
	PML3* pml3 = nullptr;
	PML2* pml2 = nullptr;
	PML1* pml1 = nullptr;
	// If its present, use that pml3
	if(*entry & 1) {
		pml3 = (PML3*)(*entry >> 12);
	}
	else { // Else create one
		pml3 = (PML3*)PhysicalMemoryManager::Alloc(1);
		if(!pml3)
			return nullptr;
		memset(pml3, 0, sizeof(PML3));
		*entry = MAKE_PML4E((uint64_t)pml3, 0, 0, 0, 0, 1, 1);
	}
	entry = &pml3->entries[decAddr.pdpt];
	if(*entry & 1) {
		pml2 = (PML2*)(*entry >> 12);
	}
	else {
		pml2 = (PML2*)PhysicalMemoryManager::Alloc(1);
		if(!pml2)
			return nullptr;
		memset(pml2, 0, sizeof(PML2));
		*entry = MAKE_PML3E( (uint64_t)pml2, 0, 0, 0, 0, 0, 1, 1);
	}
	entry = &pml2->entries[decAddr.pd];
	if(*entry & 1) {
		pml1 = (PML1*)(*entry >> 12);
	}
	else {
		pml1 = (PML1*)PhysicalMemoryManager::Alloc(1);
		if(!pml1)
			return nullptr;
		memset(pml1, 0, sizeof(PML1));
		*entry = MAKE_PML2E( (uint64_t)pml1, 0, 0, 0, 0, 0, 1, 1);
	}
	entry = &pml1->entries[decAddr.pt];
	*entry = MAKE_PML1E( phys, 0, 0, 0, 0, 0, 1, 1);
	asm volatile("invlpg %0"::"r"(virt));
	(void) prot;
	return (void*)virt;
}

};
