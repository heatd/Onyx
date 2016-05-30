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
#ifndef _VMM_H
#define _VMM_H

#if defined (__i386__)
	#define KERNEL_VIRTUAL_BASE 0xC0000000
#elif defined (__x86_64__)
	#define KERNEL_VIRTUAL_BASE 0xFFFFFFFF80000000
#endif
#include <stdint.h>
#include <stdlib.h>
typedef struct ventry
{
	uintptr_t baseAddress;
	size_t size;
	size_t sizeInPages;
	int rw;
	int nx;
	struct ventry* next;
} VasEntry;
#define VM_KERNEL (1)
#define VM_UPSIDEDOWN (2)
namespace VirtualMemoryManager
{
	void Init();
	void StartAddressBookkeeping(uintptr_t framebufferAddress);
	void* AllocateVirtAddress(uint64_t flags, size_t pages);
	void* MapRange(void* range, size_t pages);
};



#endif
