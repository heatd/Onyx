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
#ifndef _VFS_H
#define _VFS_H
#include <stdint.h>
#include <string.h>

#define VFS_TYPE_FILE 0
#define VFS_TYPE_DIR 1
#define VFS_TYPE_SYMLINK 3
#define VFS_TYPE_MOUNTPOINT 4
#define VFS_TYPE_DEV 5
class VFSNode
{
private:
public:
	int inode;
	int gid;
	int uid;
	int permitions;
	int GetPermitions() {return permitions;}
	int GetInode() {return inode;}
	int type;
	char* name;
	virtual ~VFSNode() {}
	virtual size_t read(size_t offset, size_t sizeOfReading, void* buffer) = 0;
	virtual size_t write(size_t offset, size_t sizeOfWriting, void* buffer) = 0;
};
class BaseInode : public VFSNode
{
public:
	BaseInode* next;
	BaseInode* link;
	virtual size_t read(size_t offset, size_t sizeOfReading, void* buffer);
	virtual size_t write(size_t offset, size_t sizeOfWriting, void* buffer);
};
class VFS
{
private:
	BaseInode* nodeList;
public:
	VFS();
	~VFS();
	BaseInode* FindNode(const char* path);
	void RegisterNode(BaseInode* toBeAdded);
	int DeregisterNode(BaseInode* toBeRemoved);
};
extern VFS* vfs;

#endif
