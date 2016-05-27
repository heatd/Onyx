/*----------------------------------------------------------------------
 * Copyright (C) 2016 Pedro Falcato
 *
 * This file is part of Spartix, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/
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
const uintptr_t lowerHalfMinAddress = 0x800000;
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
void* AllocateVirtAddress(uint64_t flags, size_t pages)
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
	newVas->size = 0x1000 * pages;
	newVas->sizeInPages = pages;
	newVas->rw = 1;
	newVas->nx = 1;
	newVas->next = nullptr;
	searchNode->next = newVas;
	return (void*)newVas->baseAddress;
}
}
