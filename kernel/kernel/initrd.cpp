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
#include <kernel/initrd.h>
#include <kernel/vfs.h>
#include <stdio.h>
tar_header_t* headers[100] = {0};
size_t Tar::Parse(uintptr_t address)
{
	size_t i = 0;

	for (i = 0;; i++)
	{
		tar_header_t *header = (tar_header_t *) address;
		if (header->filename[0] == '\0')
			break;
		size_t size = GetSize(header->size);
		headers[i] = header;
		address += ((size / 512) + 1) * 512;
		if (size % 512)
			address += 512;
	}

	return i;
}
Initrd::Initrd()
{
	printf("Found an Initrd at %p\n",this);
	files = Tar::Parse(reinterpret_cast<uintptr_t>(this));
	printf("Found %d files in the Initrd\n", files);
}
Initrd::~Initrd()
{
}
int Initrd::LoadIntoRamfs()
{
	tar_header_t* iterate = headers[0];
	for(size_t i = 0; i < files; i++)
	{
		iterate = headers[i];
		TarInode* inode = new TarInode;
		inode->inode = i;
		char* str = new char[strlen(iterate->filename) + 1];
		memset(str,0,strlen(iterate->filename)+ 1);
		str[0] = '/';
		strcpy(str + 1,iterate->filename);
		inode->name = str;
		inode->gid = Tar::GetSize(iterate->gid);
		inode->uid = Tar::GetSize(iterate->gid);
		if(iterate->typeflag == TAR_TYPE_FILE)
			inode->type = VFS_TYPE_FILE;
		else if(iterate->typeflag == TAR_TYPE_DIR)
			inode->type = VFS_TYPE_DIR;
		vfs->RegisterNode(inode);
	}
	return 0;
}
size_t TarInode::read(size_t offset, size_t sizeOfReading, void* buffer)
{
	char* tempBuffer = (char*) headers[this->inode] + 512 + offset;
	memcpy(buffer, tempBuffer, sizeOfReading);
	return sizeOfReading;
}
size_t TarInode::write(size_t offset, size_t sizeOfWriting, void* buffer)
{
	(void) offset;
	(void) sizeOfWriting;
	(void) buffer;
	// You can not write to a tar file (usually results in corruption)
	return 0;
}
int TarInode::open(uint8_t rw)
{
	(void) rw;
	return vfs->AllocateFileDescriptor();
}
void TarInode::close()
{
	return;
}
