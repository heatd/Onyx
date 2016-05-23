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
#include <kernel/vmm.h>
#include <stdio.h>
namespace VirtualMemoryManager
{
bool isInitialized = false;
void Init()
{
	isInitialized = true;
	Paging::Init();
}
VasEntry list;
VasEntry framebufferEntry;
#ifdef __x86_64__
const uintptr_t highHalfAddress = 0xFFFF800000000000;
const uintptr_t lowerHalfMaxAddress = 0x00007fffffffffff;
const uintptr_t lowerHalfMinAddress = 0x600000;
#endif
void StartAddressBookkeeping(uintptr_t framebufferAddress)
{
	list.baseAddress = KERNEL_VIRTUAL_BASE;
	// Last 4GiB
	list.size = 1024LL * 0x400000LL;
	list.sizeInPages = 1024;
	list.rw = 1;
	list.nx = 0;
	list.next = &framebufferEntry;

	framebufferEntry.baseAddress = framebufferAddress;
	framebufferEntry.size = 0x400000;
	framebufferEntry.sizeInPages = 1024;
	framebufferEntry.rw = 1;
	framebufferEntry.nx = 1;
	framebufferEntry.next = nullptr;
}
void* AllocateVirtAddress(uint64_t flags)
{
	bool isKernel = false, allocUpsideDown = false;
	if(flags & 1)
	{
		isKernel = true;
	}
	if(flags & 2)
	{
		allocUpsideDown = true;
	}
	VasEntry* searchNode = &list;
	uintptr_t bestAddress = 0;
	do
	{
		if(allocUpsideDown)
		{
			if(searchNode->baseAddress + searchNode->size > bestAddress)
			{
				if(isKernel && searchNode->baseAddress + searchNode->size > highHalfAddress) 
					bestAddress = searchNode->baseAddress + searchNode->size;
				else if(!isKernel && searchNode->baseAddress + searchNode->size 
					< lowerHalfMaxAddress)
					bestAddress = searchNode->baseAddress + searchNode->size;
			}
		}
		else
		{
			// Same as above, just with an operator inverted
			if(searchNode->baseAddress + searchNode->size < bestAddress)
			{
				if(isKernel && searchNode->baseAddress + searchNode->size > highHalfAddress) 
					bestAddress = searchNode->baseAddress + searchNode->size;
				else if(!isKernel && searchNode->baseAddress + searchNode->size 
					< lowerHalfMaxAddress)
					bestAddress = searchNode->baseAddress + searchNode->size;
			}
		}
		if(searchNode->next == nullptr)
			break;
		searchNode = searchNode->next;
	}while(searchNode);
	VasEntry* newVas = new VasEntry;
	newVas->baseAddress = bestAddress;
	newVas->size = 0x1000;
	newVas->sizeInPages = 1;
	newVas->rw = 1;
	newVas->nx = 1;
	newVas->next = nullptr;
	searchNode->next = newVas;
	return (void*)newVas->baseAddress; 
}
}