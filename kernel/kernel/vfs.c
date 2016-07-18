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
#include <errno.h>
#include <stdlib.h>
vfsnode_t* fs_root = NULL;
vfsnode_t *node_list = NULL;
_Bool fd_list[6550];
int vfs_init()
{
	node_list = malloc(sizeof(vfsnode_t));
	if(!node_list)
		return 1;
	node_list->name = malloc(sizeof(char)*2);
	node_list->type = VFS_TYPE_DIR;
	*node_list->name = '/';
	*(node_list->name+1) = '\0';
	return 0;
}
void vfs_fini()
{
	vfsnode_t *search = node_list;
	for ((void) search; search != NULL; search = search->next) {
		free(search);
	}
}

vfsnode_t* vfs_findnode(const char *path)
{
	vfsnode_t *search = node_list;
	for ((void) search; search != NULL; search = search->next) {
		if(search->name < (const char*)0x1000)
			continue;
		if (strcmp(search->name, (char *) path) == 0)
			return search;
	}
	return NULL;
}

void vfs_register_node(vfsnode_t *toBeAdded)
{
	if(!fs_root)
		fs_root = node_list;
	vfsnode_t *search = node_list;
	for ((void) search; search != NULL; search = search->next) {
		if (search->next == NULL) {
			search->next = toBeAdded;
			return;
		}
	}
}

int vfs_destroy_node(vfsnode_t *toBeRemoved)
{
	vfsnode_t *search = node_list;
	for ((void) search; search != NULL; search = search->next) {
		if (search->next == toBeRemoved) {
			// We found the node, return 0
			search->next = toBeRemoved->next;
			return 0;
		}
	}
	// If it was not found, return 1
	return 1;
}

int vfs_allocate_fd()
{
	/* Find a free file descriptor through the array
	   a free file desc will have its value set to 0
	   It's 1 otherwise */
	   for (int i = 0; i < 6550; i++) {
		   if (fd_list[i] == 0) {
			   fd_list[i] = 1;
			   return i;
		   }
	   }
	   return -1;
}
size_t read_vfs(size_t offset, size_t sizeofread, void* buffer, vfsnode_t* this)
{
	if(this->read != NULL)
		return this->read(offset,sizeofread,buffer,this);
	return errno = ENOSYS;
}
size_t write_vfs(size_t offset, size_t sizeofwrite, void* buffer, vfsnode_t* this)
{
	if(this->write != NULL)
		return this->write(offset,sizeofwrite,buffer,this);
	return errno = ENOSYS;
}
void close_vfs(vfsnode_t* this)
{
	if(this->close != NULL)
		this->close(this);
}
int open_vfs(uint8_t rw, vfsnode_t* this)
{
	if(this->open != NULL)
		return this->open(rw, this);
	return errno = ENOSYS;
}
struct dirent* readdir_fs(vfsnode_t* this, unsigned int index)
{
	if(this->type != VFS_TYPE_DIR)
		return errno = ENOTDIR, NULL;
	const char* base_path = this->name;
	size_t len = strlen(base_path);
	unsigned int index_count = 0;
	vfsnode_t* search = node_list;
	for ((void) search; search != NULL; search = search->next) {
		if (memcmp(search->name, base_path, len) == 0)
		{
			if(index_count == index)
				printf("search->name: %s\n", search->name);
			index_count++;
		}
	}
	return NULL;
}
