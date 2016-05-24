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
