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
#include <kernel/vfs.h>
#include <stdio.h>
// ***************************************
// Class VFS
// ***************************************
VFS::VFS()
{
	nodeList = new BaseInode;
}
VFS::~VFS()
{
	BaseInode* search = nodeList;
	for((void)search; search != nullptr; search = search->next)
	{
		delete search;
	}
}
BaseInode* VFS::FindNode(const char* path)
{
	BaseInode* search = nodeList;
	for((void)search; search != nullptr; search = search->next)
	{
		printf("search->name: %s\n",search->name);
		if(strcmp(search->name, (char*)path) == 0)
			return search;
	}
	return nullptr;
}
void VFS::RegisterNode(BaseInode* toBeAdded)
{
	BaseInode* search = nodeList;
	for((void)search; search != nullptr; search = search->next)
	{
		if(search->next == nullptr)
		{
			search->next = toBeAdded;
			return;
		}
	}
}
int VFS::DeregisterNode(BaseInode* toBeRemoved)
{
	BaseInode* search = nodeList;
	for((void)search; search != nullptr; search = search->next)
	{
		if(search->next == toBeRemoved)
		{
			// We found the node, return 0
			search->next = toBeRemoved->next;
			return 0;
		}
	}
	// If it was not found, return 1
	return 1;
}
// ***************************************
// Class BaseInode
// ***************************************

// All the base implementations go here

size_t BaseInode::read(size_t offset, size_t sizeOfReading, void* buffer)
{
	(void) offset;
	(void) buffer;
	return sizeOfReading;
}
size_t BaseInode::write(size_t offset, size_t sizeOfWriting, void* buffer)
{
	(void) offset;
	(void) buffer;
	return sizeOfWriting;

}
