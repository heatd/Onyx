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
#include <stdlib.h>
tar_header_t *headers[100] = { 0 };

size_t tar_parse(uintptr_t address)
{
	size_t i = 0;

	for (i = 0;; i++) {
		tar_header_t *header = (tar_header_t *) address;
		if (header->filename[0] == '\0')
			break;
		size_t size = tar_get_size(header->size);
		headers[i] = header;
		address += ((size / 512) + 1) * 512;
		if (size % 512)
			address += 512;
	}
	return i;
}
int initrd_load_into_ramfs(size_t files);
void init_initrd(void *initrd)
{
	printf("Found an Initrd at %p\n", initrd);
	size_t n = tar_parse((uintptr_t) initrd);
	printf("Found %d files in the Initrd\n", n);
	initrd_load_into_ramfs(n);
}
size_t tar_read(size_t offset, size_t sizeOfReading, void *buffer, vfsnode_t *this)
{
	char *tempBuffer = (char *) headers[this->inode] + 512 + offset;
	memcpy(buffer, tempBuffer, sizeOfReading);
	return sizeOfReading;
}

size_t tar_write(size_t offset, size_t sizeOfWriting, void *buffer, vfsnode_t *this)
{
	(void) offset;
	(void) sizeOfWriting;
	(void) buffer;
	(void) this;
	// You can not write to a tar file (usually results in corruption)
	return 0;
}

int tar_open(uint8_t rw, vfsnode_t *this)
{
	(void) rw;
	(void) this;
	return vfs_allocate_fd();
}

void tar_close(vfsnode_t *this)
{
	(void) this;
	return;
}
int initrd_load_into_ramfs(size_t files)
{
	tar_header_t *iterate = headers[0];
	for (size_t i = 0; i < files; i++) {
		iterate = headers[i];
		vfsnode_t *inode = malloc(sizeof(vfsnode_t));
		inode->inode = i;
		char *str = malloc(strlen(iterate->filename) + 2);
		memset(str, 0, strlen(iterate->filename) + 2);
		str[0] = '/';
		strcpy(str + 1, iterate->filename);
		inode->name = str;
		inode->size = tar_get_size(iterate->size);
		inode->gid = tar_get_size(iterate->gid);
		inode->uid = tar_get_size(iterate->gid);
		inode->read = tar_read;
		inode->write = tar_write;
		inode->open = tar_open;
		inode->close = tar_close;
		if (iterate->typeflag == TAR_TYPE_FILE)
			inode->type = VFS_TYPE_FILE;
		else if (iterate->typeflag == TAR_TYPE_DIR)
			inode->type = VFS_TYPE_DIR;
		vfs_register_node(inode);
	}
	return 0;
}
