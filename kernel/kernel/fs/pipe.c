/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>

#include <kernel/pipe.h>
#include <kernel/spinlock.h>
#include <kernel/process.h>
#include <kernel/compiler.h>
#include <kernel/dev.h>
#include <kernel/panic.h>
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
struct pipe *get_pipe_from_inode(ino_t ino)
{
	struct pipe *pipe = pipe_list;
	while(ino--)
	{
		pipe = pipe->next;
	}
	return pipe;
}
size_t pipe_write(size_t offset, size_t sizeofwrite, void* buffer, struct inode* file)
{
	UNUSED_PARAMETER(offset);
	_Bool atomic_write = false;
	struct pipe *pipe = get_pipe_from_inode(file->inode);

	/* If readers == 0, this is a broken pipe */
	if(pipe->readers == 0)
	{
		kernel_raise_signal(SIGPIPE, get_current_process());
		return errno = EPIPE, (size_t) -1;
	}
	/* If sizeofwrite <= PIPE_BUF, the write is atomic */
	if(sizeofwrite <= PIPE_BUF)
		atomic_write = true;

	if(atomic_write)
		mutex_lock(&pipe->pipe_lock);

	if(atomic_write)
	{
		while(pipe->buf_size < pipe->curr_size + sizeofwrite)
		{
			sched_yield();
		}
		memcpy(pipe->buffer + pipe->curr_size, buffer, sizeofwrite);
		pipe->curr_size += sizeofwrite;
	}
	else
	{
		while(pipe->buf_size < pipe->curr_size + sizeofwrite && sizeofwrite)
		{
			size_t to_write = (pipe->buf_size - pipe->curr_size) > sizeofwrite ? sizeofwrite : (pipe->buf_size - pipe->curr_size);
			memcpy(pipe->buffer + pipe->curr_size, buffer, to_write);
			pipe->curr_size += to_write;
			sizeofwrite -= to_write;
			sched_yield();
		}
	}

	if(atomic_write)
		mutex_unlock(&pipe->pipe_lock);
	return pipe->curr_size;
}
size_t pipe_read(int flags, size_t offset, size_t sizeofread, void* buffer, struct inode* file)
{
	(void) flags;
	UNUSED_PARAMETER(offset);

	/* Get the pipe */
	struct pipe *pipe = get_pipe_from_inode(file->inode);

	/* Lock the pipe */
	mutex_lock(&pipe->pipe_lock);
	size_t to_read = pipe->curr_size < sizeofread ? pipe->curr_size : sizeofread;
	memcpy(buffer, pipe->buffer, to_read);
	memmove(pipe->buffer, pipe->buffer + pipe->curr_size, pipe->buf_size - pipe->curr_size);

	mutex_unlock(&pipe->pipe_lock);
	return to_read;
}
static struct file_ops pipe_file_ops = 
{
	.write = pipe_write,
	.read = pipe_read
};
static struct minor_device *pipedev = NULL;
static spinlock_t pipespl;
struct inode *pipe_create(void)
{
	acquire_spinlock(&pipespl);
	/* Create the node */
	struct inode *node = malloc(sizeof(struct inode));
	if(!node)
	{
		release_spinlock(&pipespl);
		return NULL;
	}
	memset(node, 0, sizeof(struct inode));
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
	pipe->readers = 1;
	*pipe_next = pipe;
	node->dev = pipedev->majorminor;
	node->type = VFS_TYPE_FIFO;
	release_spinlock(&pipespl);
	return node;
}
__init void pipe_register_device(void)
{
	pipedev = dev_register(0, 0);
	if(!pipedev)
		panic("could not allocate pipedev!\n");

	pipedev->fops = &pipe_file_ops;
}
