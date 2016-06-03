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
	virtual int open(uint8_t rw) = 0;
	virtual void close() = 0;
};
class BaseInode : public VFSNode
{
public:
	BaseInode* next;
	BaseInode* link;
	virtual size_t read(size_t offset, size_t sizeOfReading, void* buffer);
	virtual size_t write(size_t offset, size_t sizeOfWriting, void* buffer);
	virtual int open(uint8_t rw);
	virtual void close();
};
class VFS
{
private:
	BaseInode* nodeList;
	short fdlist[6550];
public:
	VFS();
	~VFS();
	BaseInode* FindNode(const char* path);
	void RegisterNode(BaseInode* toBeAdded);
	int DeregisterNode(BaseInode* toBeRemoved);
	int AllocateFileDescriptor();
};
extern VFS* vfs;

#endif
