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
#include <stdio.h>

#include <onyx/pipe.h>
#include <onyx/spinlock.h>
#include <onyx/process.h>
#include <onyx/compiler.h>
#include <onyx/dev.h>
#include <onyx/panic.h>
#include <onyx/list.hpp>
#include <onyx/utils.h>

static struct dev *pipedev = NULL;
static atomic<ino_t> current_inode_number = 0; 

constexpr pipe::pipe() : refcountable(2), buffer(nullptr), buf_size(0), pos(0),
	pipe_lock{}, write_cond{}, read_cond{}, reader_count{1}, writer_count{1}
{

}

pipe::~pipe()
{
	free((void *) buffer);
}

bool pipe::allocate_pipe_buffer(unsigned long buf_size)
{
	buffer = zalloc(buf_size);
	if(buffer)
	{
		this->buf_size = buf_size;
		return true;
	}

	return false;
}

bool pipe::is_full() const
{
	return buf_size == pos;
}

size_t pipe::available_space() const
{
	return buf_size - pos;
}

ssize_t pipe::read(int flags, size_t len, void *buf)
{
	ssize_t been_read = 0;
	
	mutex_lock(&pipe_lock);

	while(been_read != (ssize_t) len)
	{
		if(pos == 0)
		{
			if(writer_count == 0)
			{
				mutex_unlock(&pipe_lock);
				return 0;
			}

			/* buffer empty */
			if(flags & O_NONBLOCK)
			{
				return errno = EAGAIN, -1;
			}

			condvar_wait(&read_cond, &pipe_lock);
		}
		else
		{
			size_t to_read = min(len, pos);
			memcpy((void *) ((char *) buf + been_read), buffer, to_read);
			/* move the rest of the buffer back to the beginning if we have to */
			if(pos - to_read != 0)
				memmove(buffer, (const void *) ((char *) buffer + to_read), pos - to_read);
			pos -= to_read;
			been_read += to_read;
			condvar_broadcast(&write_cond);
		}
	}

	mutex_unlock(&pipe_lock);
	return been_read;
}

ssize_t pipe::write(int flags, size_t len, const void *buf)
{
	bool is_atomic_write = len <= PIPE_BUF;
	ssize_t written = 0;

	mutex_lock(&pipe_lock);

	while(written != (ssize_t) len)
	{
		if(reader_count == 0)
		{
			kernel_raise_signal(SIGPIPE, get_current_process());
			mutex_unlock(&pipe_lock);
			return errno = EPIPE, -1;
		}

		if((available_space() < len && is_atomic_write) || is_full())
		{
			if(written != 0)
			{
				/* now that we're blocking, might as well signal readers */
				condvar_broadcast(&read_cond);
			}

			if(flags & O_NONBLOCK)
			{
				mutex_unlock(&pipe_lock);
				return errno = EAGAIN, -1;
			}

			condvar_wait(&write_cond, &pipe_lock);
		}
		else
		{
			size_t to_write = min(len - written, available_space());
			/* sigh - sometimes C++ really gets in the way */
			memcpy((void *)((char *) buffer + pos), (const void *) ((char *) buf + written),
				to_write);
			pos += to_write;
			written += to_write;
		}
	}

	/* After finishing the write, signal any possible readers */
	condvar_broadcast(&read_cond);

	mutex_unlock(&pipe_lock);
	return written;
}

#define PIPE_WRITEABLE			0x1

pipe *get_pipe(void *helper)
{
	unsigned long raw = (unsigned long) helper;

	return (pipe *) ((void *) (raw & ~PIPE_WRITEABLE));
}

size_t pipe_read(int flags, size_t offset, size_t sizeofread, void* buffer, struct inode* file)
{
	(void) offset;
	pipe *p = get_pipe(file->i_helper);
	return p->read(flags, sizeofread, buffer);
}

size_t pipe_write(size_t offset, size_t sizeofwrite, void* buffer, struct inode* file)
{
	(void) offset;
	pipe *p = get_pipe(file->i_helper);
	return p->write(0, sizeofwrite, buffer);
}

void pipe::close_read_end()
{
	/* wake up any possibly-blocked readers */
	mutex_lock(&pipe_lock);
	condvar_broadcast(&read_cond);
	mutex_unlock(&pipe_lock);
}

void pipe::close_write_end()
{
	mutex_lock(&pipe_lock);
	condvar_broadcast(&write_cond);
	mutex_unlock(&pipe_lock);
}

void pipe_close(struct inode* file)
{
	bool is_writeable = ((unsigned long) file->i_helper) & PIPE_WRITEABLE;
	pipe *p = get_pipe(file->i_helper);

	if(is_writeable)
	{
		if(--p->writer_count == 0)
		{
			p->close_write_end();
		}
	}
	else
	{
		if(--p->reader_count == 0)
		{
			p->close_read_end();
		}
	}
	
	p->unref();
}

int pipe_create(struct inode **pipe_readable, struct inode **pipe_writeable)
{
	/* Create the node */
	struct inode *node0 = nullptr, *node1 = nullptr; 
	pipe *new_pipe = nullptr;
	node0 = inode_create();
	if(!node0)
		return errno = ENOMEM, -1;
	
	node1 = inode_create();
	if(!node1)
		goto err0;

	new_pipe = new pipe;
	if(!new_pipe)
	{
		goto err0;
	}

	if(!new_pipe->allocate_pipe_buffer())
	{
		goto err1;
	}

	node0->i_dev = pipedev->majorminor;
	node0->i_type = VFS_TYPE_CHAR_DEVICE;
	node0->i_inode = current_inode_number++;
	node0->i_helper = (void *) new_pipe;
	node0->i_fops.write = pipe_write;
	node0->i_fops.read = pipe_read;
	node0->i_fops.close = pipe_close;

	memcpy(node1, node0, sizeof(*node0));

	*pipe_readable = node0;
	*pipe_writeable = node1;

	/* since malloc returns 16-byte aligned memory we can use the lower bits for stuff like this */
	node1->i_helper = (void *)((unsigned long) new_pipe | PIPE_WRITEABLE);
	return 0;
err1:
	if(new_pipe)
	{
		delete new_pipe;
	}
err0:
	if(node0)	free(node0);
	if(node1)	free(node1);
	errno = ENOMEM;

	return -1;
}

__init void pipe_register_device(void)
{
	pipedev = dev_register(0, 0, (char *) "pipe");
	if(!pipedev)
		panic("could not allocate pipedev!\n");
}
