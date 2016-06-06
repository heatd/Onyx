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
vfsnode_t *node_list;
_Bool fd_list[6550];
int vfs_init()
{
	node_list = malloc(sizeof(vfsnode_t*));
	if(!node_list)
		return 1;
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
		if (strcmp(search->name, (char *) path) == 0)
			return search;
	}
	return NULL;
}

void vfs_register_node(vfsnode_t *toBeAdded)
{
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
