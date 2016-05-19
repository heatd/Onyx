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
#ifndef _PAGING_H
#define _PAGING_H

#include <stdint.h>
#include <string.h>
#include <kernel/pmm.h>
	
#define PAGE_WRITABLE 0x1
#define PAGE_GLOBAL 0x2
#define PAGE_KERNEL (PAGE_GLOBAL|PAGE_WRITABLE)
#define PAGES_PER_TABLE 512
typedef struct {uint64_t entries[512];} PML4;
typedef struct {uint64_t entries[512];} PML3;
typedef struct {uint64_t entries[512];} PML2;
typedef struct {uint64_t entries[512];} PML1;

namespace Paging
{
	void Init();
	void* MapPhysToVirt(uintptr_t virt, uintptr_t phys, uint64_t prot);
};
#endif