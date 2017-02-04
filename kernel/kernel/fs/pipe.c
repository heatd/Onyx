/*----------------------------------------------------------------------
 * Copyright (C) 2017 Pedro Falcato
 *
 * This file is part of Spartix, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

#include <kernel/pipe.h>
#include <kernel/spinlock.h>

static struct pipe *pipe_list = NULL;
struct pipe **__allocate_pipe_inode(ino_t *inode)
{
	if(!pipe_list)
	{
		*inode = 0;
		return &pipe_list;
	}
	ino_t ino = 1;
	struct pipe **pipe = &pipe_list->next;
	for(struct pipe *p = pipe_list; p->next; p = p->next, ino++)
	{
		pipe = &p->next;
	}
	*inode = ino;
	return pipe;
}
static spinlock_t pipespl;
vfsnode_t *pipe_create(void)
{
	acquire_spinlock(&pipespl);
	/* Create the node */
	vfsnode_t *node = malloc(sizeof(vfsnode_t));
	if(!node)
	{
		release_spinlock(&pipespl);
		return NULL;
	}
	memset(node, 0, sizeof(vfsnode_t));
	node->name = "";
	struct pipe **pipe_next = __allocate_pipe_inode(&node->inode);
	struct pipe *pipe = malloc(sizeof(struct pipe));
	if(!pipe)
	{
		free(node);
		release_spinlock(&pipespl);
		return NULL;
	}
	memset(pipe, 0, sizeof(struct pipe));

	/* Allocate the pipe buffer */
	pipe->buffer = malloc(UINT16_MAX);
	if(!pipe->buffer)
	{
		free(node);
		free(pipe);
		release_spinlock(&pipespl);
		return NULL;
	}
	/* Zero it out */
	memset(pipe->buffer, 0, UINT16_MAX);
	pipe->buf_size = UINT16_MAX;

	*pipe_next = pipe;
	release_spinlock(&pipespl);
	return node;
}